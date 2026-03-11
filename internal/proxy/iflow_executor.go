package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gpt-load/internal/channel"
	app_errors "gpt-load/internal/errors"
	"gpt-load/internal/models"
	"gpt-load/internal/ratelimit"
	"gpt-load/internal/response"
	"gpt-load/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func (ps *ProxyServer) executeIFlowWithQueue(
	c *gin.Context,
	channelHandler channel.ChannelProxy,
	originalGroup *models.Group,
	group *models.Group,
	bodyBytes []byte,
	isStream bool,
	startTime time.Time,
) {
	cfg := group.EffectiveConfig

	queueTimeoutSeconds := cfg.IFlowQueueTimeoutSeconds
	if queueTimeoutSeconds <= 0 {
		queueTimeoutSeconds = 600
	}

	apiKey, err := ps.keyProvider.SelectKey(group.ID)
	if err != nil {
		response.Error(c, app_errors.NewAPIError(app_errors.ErrNoKeysAvailable, err.Error()))
		ps.logRequest(c, originalGroup, group, nil, startTime, http.StatusServiceUnavailable, err, isStream, "", channelHandler, bodyBytes, models.RequestTypeFinal)
		return
	}

	retryCount := 0

outer:
	for {
		queueCtx, cancelQueue := context.WithTimeout(c.Request.Context(), time.Duration(queueTimeoutSeconds)*time.Second)
		slot, acquireErr := ps.iflowQueue.Acquire(queueCtx, apiKey.ID)
		cancelQueue()
		if acquireErr != nil {
			status := http.StatusGatewayTimeout
			errMsg := "请求排队超时"
			ps.logRequest(c, originalGroup, group, apiKey, startTime, status, acquireErr, isStream, "", channelHandler, bodyBytes, models.RequestTypeFinal)
			c.JSON(status, gin.H{
				"error": gin.H{
					"message": errMsg,
					"type":    "queue_timeout",
					"code":    status,
				},
			})
			return
		}

		if c.Request.Context().Err() != nil {
			slot.Release()
			return
		}

		immediateRetryUsed := false

		for {
			// Channel-level rate limit check (do not do this before queueing to avoid counting queued requests).
			if cfg.RateLimitScope == "channel" && (cfg.RpmLimit > 0 || cfg.DailyLimit > 0) {
				if err := ps.rateLimiter.CheckChannel(group.ID, cfg); err != nil {
					slot.Release()
					ps.logRequest(c, originalGroup, group, apiKey, startTime, 408, err, isStream, "", channelHandler, bodyBytes, models.RequestTypeFinal)
					c.JSON(408, gin.H{
						"error": gin.H{
							"message": "额度已用尽，请明天再试",
							"type":    "rate_limit_exceeded",
							"code":    408,
						},
					})
					return
				}
			}

			// Key-level rate limit check (after queueing so RPM is accounted at execution time).
			if cfg.RateLimitScope == "key" && (cfg.RpmLimit > 0 || cfg.DailyLimit > 0) {
				if exceeded, _ := ps.rateLimiter.CheckKey(apiKey.ID, cfg); exceeded {
					slot.Release()
					if retryCount >= cfg.MaxRetries {
						ps.logRequest(c, originalGroup, group, apiKey, startTime, 408, ratelimit.ErrRateLimitExceeded, isStream, "", channelHandler, bodyBytes, models.RequestTypeFinal)
						c.JSON(408, gin.H{
							"error": gin.H{
								"message": "额度已用尽，请明天再试",
								"type":    "rate_limit_exceeded",
								"code":    408,
							},
						})
						return
					}

					retryCount++
					apiKey, err = ps.keyProvider.SelectKey(group.ID)
					if err != nil {
						response.Error(c, app_errors.NewAPIError(app_errors.ErrNoKeysAvailable, err.Error()))
						ps.logRequest(c, originalGroup, group, nil, startTime, http.StatusServiceUnavailable, err, isStream, "", channelHandler, bodyBytes, models.RequestTypeFinal)
						return
					}
					continue outer
				}
			}

			upstreamURL, err := channelHandler.BuildUpstreamURL(c.Request.URL, originalGroup.Name)
			if err != nil {
				slot.Release()
				response.Error(c, app_errors.NewAPIError(app_errors.ErrInternalServer, fmt.Sprintf("Failed to build upstream URL: %v", err)))
				return
			}

			var reqCtx context.Context
			var cancel context.CancelFunc
			if isStream {
				reqCtx, cancel = context.WithCancel(c.Request.Context())
			} else {
				timeout := time.Duration(cfg.RequestTimeout) * time.Second
				reqCtx, cancel = context.WithTimeout(c.Request.Context(), timeout)
			}

			req, err := http.NewRequestWithContext(reqCtx, c.Request.Method, upstreamURL, bytes.NewReader(bodyBytes))
			if err != nil {
				cancel()
				slot.Release()
				logrus.Errorf("Failed to create upstream request: %v", err)
				response.Error(c, app_errors.ErrInternalServer)
				return
			}
			req.ContentLength = int64(len(bodyBytes))
			req.Header = c.Request.Header.Clone()

			// Clean up client auth key.
			req.Header.Del("Authorization")
			req.Header.Del("X-Api-Key")
			req.Header.Del("X-Goog-Api-Key")

			finalBodyBytes, err := channelHandler.ApplyModelRedirect(req, bodyBytes, group)
			if err != nil {
				cancel()
				slot.Release()
				response.Error(c, app_errors.NewAPIError(app_errors.ErrBadRequest, err.Error()))
				ps.logRequest(c, originalGroup, group, apiKey, startTime, http.StatusBadRequest, err, isStream, upstreamURL, channelHandler, bodyBytes, models.RequestTypeFinal)
				return
			}

			if !bytes.Equal(finalBodyBytes, bodyBytes) {
				req.Body = io.NopCloser(bytes.NewReader(finalBodyBytes))
				req.ContentLength = int64(len(finalBodyBytes))
			}

			if preparer, ok := channelHandler.(channel.RequestPreparer); ok {
				if err := preparer.PrepareRequest(req, apiKey, group); err != nil {
					cancel()
					ps.rollbackRateLimit(group, apiKey, cfg)

					parsedError := err.Error()
					ps.keyProvider.UpdateStatus(apiKey, group, false, parsedError)

					isLastAttempt := retryCount >= cfg.MaxRetries
					requestType := models.RequestTypeRetry
					if isLastAttempt {
						requestType = models.RequestTypeFinal
					}

					ps.logRequest(c, originalGroup, group, apiKey, startTime, 500, errors.New(parsedError), isStream, upstreamURL, channelHandler, bodyBytes, requestType)

					if isLastAttempt {
						slot.Release()
						response.Error(c, app_errors.NewAPIErrorWithUpstream(500, "UPSTREAM_ERROR", parsedError))
						return
					}

					hasWaiters := slot.HasWaiting()
					retryCount++
					if hasWaiters && !immediateRetryUsed {
						immediateRetryUsed = true
						cancel()
						continue
					}
					if hasWaiters {
						cancel()
						slot.Release()
						continue outer
					}
					cancel()
					continue
				}
			}

			channelHandler.ModifyRequest(req, apiKey, group)

			// Apply custom header rules.
			if len(group.HeaderRuleList) > 0 {
				headerKey := apiKey
				if bearer := strings.TrimSpace(req.Header.Get("Authorization")); strings.HasPrefix(bearer, "Bearer ") {
					runtime := *apiKey
					runtime.KeyValue = strings.TrimSpace(strings.TrimPrefix(bearer, "Bearer "))
					headerKey = &runtime
				}
				headerCtx := utils.NewHeaderVariableContextFromGin(c, group, headerKey)
				utils.ApplyHeaderRules(req, group.HeaderRuleList, headerCtx)
			}

			var client *http.Client
			if isStream {
				client = channelHandler.GetStreamClient()
				req.Header.Set("X-Accel-Buffering", "no")
			} else {
				client = channelHandler.GetHTTPClient()
			}

			resp, err := client.Do(req)

			if err != nil || (resp != nil && resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound) {
				ps.rollbackRateLimit(group, apiKey, cfg)

				if err != nil && app_errors.IsIgnorableError(err) {
					logrus.Debugf("Client-side ignorable error for key %s, aborting retries: %v", utils.MaskAPIKey(apiKey.KeyValue), err)
					ps.logRequest(c, originalGroup, group, apiKey, startTime, 499, err, isStream, upstreamURL, channelHandler, bodyBytes, models.RequestTypeFinal)
					cancel()
					slot.Release()
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
					return
				}

				var statusCode int
				var errorMessage string
				var parsedError string

				if err != nil {
					statusCode = 500
					errorMessage = err.Error()
					parsedError = errorMessage
					logrus.Debugf("Request failed (attempt %d/%d) for key %s: %v", retryCount+1, cfg.MaxRetries, utils.MaskAPIKey(apiKey.KeyValue), err)
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
				} else {
					statusCode = resp.StatusCode
					errorBody, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						logrus.Errorf("Failed to read error body: %v", readErr)
						errorBody = []byte("Failed to read error body")
					}

					errorBody = handleGzipCompression(resp, errorBody)
					errorMessage = string(errorBody)
					parsedError = app_errors.ParseUpstreamError(errorBody)
					logrus.Debugf("Request failed with status %d (attempt %d/%d) for key %s. Parsed Error: %s", statusCode, retryCount+1, cfg.MaxRetries, utils.MaskAPIKey(apiKey.KeyValue), parsedError)
					_ = resp.Body.Close()
				}

				ps.keyProvider.UpdateStatus(apiKey, group, false, parsedError)

				isLastAttempt := retryCount >= cfg.MaxRetries
				requestType := models.RequestTypeRetry
				if isLastAttempt {
					requestType = models.RequestTypeFinal
				}

				ps.logRequest(c, originalGroup, group, apiKey, startTime, statusCode, errors.New(parsedError), isStream, upstreamURL, channelHandler, bodyBytes, requestType)

				if isLastAttempt {
					slot.Release()
					cancel()
					var errorJSON map[string]any
					if err := json.Unmarshal([]byte(errorMessage), &errorJSON); err == nil {
						c.JSON(statusCode, errorJSON)
					} else {
						response.Error(c, app_errors.NewAPIErrorWithUpstream(statusCode, "UPSTREAM_ERROR", errorMessage))
					}
					return
				}

				hasWaiters := slot.HasWaiting()
				retryCount++

				if hasWaiters && !immediateRetryUsed {
					immediateRetryUsed = true
					cancel()
					continue
				}

				if hasWaiters {
					cancel()
					slot.Release()
					continue outer
				}

				cancel()
				continue
			}

			logrus.Debugf("Request for group %s succeeded on attempt %d with key %s", group.Name, retryCount+1, utils.MaskAPIKey(apiKey.KeyValue))

			if shouldInterceptModelList(c.Request.URL.Path, c.Request.Method) {
				ps.handleModelListResponse(c, resp, group, channelHandler)
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
			} else {
				for key, values := range resp.Header {
					for _, value := range values {
						c.Header(key, value)
					}
				}
				c.Status(resp.StatusCode)

				if isStream {
					ps.handleStreamingResponse(c, resp)
				} else {
					ps.handleNormalResponse(c, resp)
				}
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
			}

			ps.logRequest(c, originalGroup, group, apiKey, startTime, resp.StatusCode, nil, isStream, upstreamURL, channelHandler, bodyBytes, models.RequestTypeFinal)
			cancel()
			slot.Release()
			return
		}
	}
}
