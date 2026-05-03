package iflow

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"gpt-load/internal/httpclient"
	"gpt-load/internal/models"

	"github.com/sirupsen/logrus"
)

const (
	defaultAPIKeyEndpoint = "https://platform.iflow.cn/api/openapi/apikey"
	expireTimeLayout      = "2006-01-02 15:04"
	refreshLeadTime       = 48 * time.Hour
)

type Credential struct {
	APIKey    string
	Name      string
	ExpireRaw string
	ExpireAt  time.Time
}

type CredentialManager struct {
	clientManager  *httpclient.HTTPClientManager
	apiKeyEndpoint string

	mu      sync.Mutex
	entries map[uint]*credentialCache
}

type credentialCache struct {
	mu        sync.Mutex
	rawBXAuth string
	cred      *Credential
}

type apiKeyResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    apiKeyData  `json:"data"`
	Extra   interface{} `json:"extra"`
}

type apiKeyData struct {
	HasExpired bool   `json:"hasExpired"`
	ExpireTime string `json:"expireTime"`
	Name       string `json:"name"`
	APIKey     string `json:"apiKey"`
	APIKeyMask string `json:"apiKeyMask"`
}

type refreshRequest struct {
	Name string `json:"name"`
}

func NewCredentialManager(clientManager *httpclient.HTTPClientManager) *CredentialManager {
	return &CredentialManager{
		clientManager:  clientManager,
		apiKeyEndpoint: defaultAPIKeyEndpoint,
		entries:        make(map[uint]*credentialCache),
	}
}

func (m *CredentialManager) Resolve(ctx context.Context, group *models.Group, apiKey *models.APIKey) (*Credential, error) {
	if apiKey == nil {
		return nil, fmt.Errorf("iflow credential: api key is nil")
	}

	rawBXAuth := NormalizeBXAuthValue(apiKey.KeyValue)
	if rawBXAuth == "" {
		return nil, fmt.Errorf("iflow credential: BXAuth is empty")
	}

	if apiKey.ID == 0 {
		return m.refreshCredential(ctx, group, rawBXAuth, nil)
	}

	cache := m.getCache(apiKey.ID)
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.rawBXAuth != rawBXAuth {
		cache.rawBXAuth = rawBXAuth
		cache.cred = nil
	}

	if cache.cred != nil && !needsRefresh(cache.cred.ExpireAt) {
		return cloneCredential(cache.cred), nil
	}

	cred, err := m.refreshCredential(ctx, group, rawBXAuth, cache.cred)
	if err != nil {
		return nil, err
	}
	cache.cred = cloneCredential(cred)
	return cloneCredential(cache.cred), nil
}

func (m *CredentialManager) getCache(keyID uint) *credentialCache {
	m.mu.Lock()
	defer m.mu.Unlock()

	cache, ok := m.entries[keyID]
	if !ok {
		cache = &credentialCache{}
		m.entries[keyID] = cache
	}
	return cache
}

func (m *CredentialManager) refreshCredential(
	ctx context.Context,
	group *models.Group,
	rawBXAuth string,
	existing *Credential,
) (*Credential, error) {
	client := m.clientForGroup(group)
	name := ""
	if existing != nil {
		name = strings.TrimSpace(existing.Name)
	}

	if name == "" {
		data, err := m.fetchAPIKeyInfo(ctx, client, rawBXAuth)
		if err != nil {
			return nil, err
		}

		name = strings.TrimSpace(data.Name)
		if name == "" {
			return nil, fmt.Errorf("iflow credential: missing key name")
		}

		if hasUsableAPIKey(data) {
			expireAt, err := parseExpireTime(data.ExpireTime)
			if err == nil && !needsRefresh(expireAt) {
				return &Credential{
					APIKey:    strings.TrimSpace(data.APIKey),
					Name:      name,
					ExpireRaw: strings.TrimSpace(data.ExpireTime),
					ExpireAt:  expireAt,
				}, nil
			}
		}
	}

	refreshed, err := m.refreshAPIKey(ctx, client, rawBXAuth, name)
	if err != nil {
		return nil, err
	}

	expireAt, err := parseExpireTime(refreshed.ExpireTime)
	if err != nil {
		return nil, err
	}

	apiKey := strings.TrimSpace(refreshed.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("iflow credential: empty api key returned")
	}

	return &Credential{
		APIKey:    apiKey,
		Name:      strings.TrimSpace(refreshed.Name),
		ExpireRaw: strings.TrimSpace(refreshed.ExpireTime),
		ExpireAt:  expireAt,
	}, nil
}

func (m *CredentialManager) clientForGroup(group *models.Group) *http.Client {
	if group == nil {
		return m.clientManager.GetClient(&httpclient.Config{
			ConnectTimeout:        15 * time.Second,
			RequestTimeout:        30 * time.Second,
			IdleConnTimeout:       120 * time.Second,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   10,
			ResponseHeaderTimeout: 30 * time.Second,
			DisableCompression:    false,
			WriteBufferSize:       32 * 1024,
			ReadBufferSize:        32 * 1024,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		})
	}

	timeoutSeconds := group.EffectiveConfig.RequestTimeout
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	return m.clientManager.GetClient(&httpclient.Config{
		ConnectTimeout:        time.Duration(group.EffectiveConfig.ConnectTimeout) * time.Second,
		RequestTimeout:        time.Duration(timeoutSeconds) * time.Second,
		IdleConnTimeout:       time.Duration(group.EffectiveConfig.IdleConnTimeout) * time.Second,
		MaxIdleConns:          max(group.EffectiveConfig.MaxIdleConns, 10),
		MaxIdleConnsPerHost:   max(group.EffectiveConfig.MaxIdleConnsPerHost, 10),
		ResponseHeaderTimeout: time.Duration(group.EffectiveConfig.ResponseHeaderTimeout) * time.Second,
		DisableCompression:    false,
		WriteBufferSize:       32 * 1024,
		ReadBufferSize:        32 * 1024,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ProxyURL:              group.EffectiveConfig.ProxyURL,
	})
}

func (m *CredentialManager) fetchAPIKeyInfo(ctx context.Context, client *http.Client, rawBXAuth string) (*apiKeyData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.apiKeyEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("iflow credential: create GET request failed: %w", err)
	}

	applyCookieHeaders(req, rawBXAuth)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	body, err := doAndRead(client, req)
	if err != nil {
		return nil, fmt.Errorf("iflow credential: GET api key info failed: %w", err)
	}

	var resp apiKeyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("iflow credential: decode GET response failed: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("iflow credential: GET request not successful: %s", strings.TrimSpace(resp.Message))
	}

	return &resp.Data, nil
}

func (m *CredentialManager) refreshAPIKey(
	ctx context.Context,
	client *http.Client,
	rawBXAuth string,
	name string,
) (*apiKeyData, error) {
	payload, err := json.Marshal(refreshRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("iflow credential: marshal refresh request failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.apiKeyEndpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("iflow credential: create POST request failed: %w", err)
	}

	applyCookieHeaders(req, rawBXAuth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://platform.iflow.cn")
	req.Header.Set("Referer", "https://platform.iflow.cn/")

	body, err := doAndRead(client, req)
	if err != nil {
		return nil, fmt.Errorf("iflow credential: refresh api key failed: %w", err)
	}

	var resp apiKeyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("iflow credential: decode POST response failed: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("iflow credential: POST request not successful: %s", strings.TrimSpace(resp.Message))
	}

	return &resp.Data, nil
}

func doAndRead(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("create gzip reader failed: %w", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logrus.Debugf("iflow credential request failed: status=%d body=%s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return body, nil
}

func applyCookieHeaders(req *http.Request, rawBXAuth string) {
	req.Header.Set("Cookie", BuildCookieValue(rawBXAuth))
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Connection", "keep-alive")
}

func NormalizeBXAuthValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	parts := strings.Split(trimmed, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(part), "bxauth=") {
			segments := strings.SplitN(part, "=", 2)
			if len(segments) == 2 {
				return strings.Trim(strings.TrimSpace(segments[1]), ";")
			}
		}
	}

	return strings.Trim(strings.TrimSpace(trimmed), ";")
}

func BuildCookieValue(rawBXAuth string) string {
	return "BXAuth=" + NormalizeBXAuthValue(rawBXAuth) + ";"
}

func parseExpireTime(raw string) (time.Time, error) {
	expireRaw := strings.TrimSpace(raw)
	if expireRaw == "" {
		return time.Time{}, fmt.Errorf("iflow credential: expire time is empty")
	}

	expireAt, err := time.ParseInLocation(expireTimeLayout, expireRaw, time.Local)
	if err != nil {
		return time.Time{}, fmt.Errorf("iflow credential: parse expire time failed: %w", err)
	}
	return expireAt, nil
}

func needsRefresh(expireAt time.Time) bool {
	if expireAt.IsZero() {
		return true
	}
	return expireAt.Before(time.Now().Add(refreshLeadTime))
}

func hasUsableAPIKey(data *apiKeyData) bool {
	apiKey := strings.TrimSpace(data.APIKey)
	return apiKey != "" && !strings.Contains(apiKey, "*")
}

func cloneCredential(cred *Credential) *Credential {
	if cred == nil {
		return nil
	}
	cloned := *cred
	return &cloned
}
