package channel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	app_errors "gpt-load/internal/errors"
	iflowcred "gpt-load/internal/iflow"
	"gpt-load/internal/models"
	"gpt-load/internal/utils"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func init() {
	Register("iflow", newIFlowChannel)
}

type IFlowChannel struct {
	*OpenAIChannel
	credentialManager *iflowcred.CredentialManager
}

func newIFlowChannel(f *Factory, group *models.Group) (ChannelProxy, error) {
	base, err := f.newBaseChannel("iflow", group)
	if err != nil {
		return nil, err
	}

	return &IFlowChannel{
		OpenAIChannel: &OpenAIChannel{
			BaseChannel: base,
		},
		credentialManager: f.iflowManager,
	}, nil
}

// ModifyRequest is intentionally a no-op because iFlow uses a runtime-derived
// short-lived API key instead of the persisted BXAuth value.
func (ch *IFlowChannel) ModifyRequest(req *http.Request, apiKey *models.APIKey, group *models.Group) {
}

func (ch *IFlowChannel) PrepareRequest(req *http.Request, apiKey *models.APIKey, group *models.Group) error {
	if req == nil {
		return fmt.Errorf("iflow channel: request is nil")
	}

	cred, err := ch.credentialManager.Resolve(req.Context(), group, apiKey)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+cred.APIKey)
	return nil
}

func (ch *IFlowChannel) ValidateKey(ctx context.Context, apiKey *models.APIKey, group *models.Group) (bool, error) {
	upstreamURL := ch.getUpstreamURL()
	if upstreamURL == nil {
		return false, fmt.Errorf("no upstream URL configured for channel %s", ch.Name)
	}

	cred, err := ch.credentialManager.Resolve(ctx, group, apiKey)
	if err != nil {
		return false, err
	}

	endpointURL, err := url.Parse(ch.ValidationEndpoint)
	if err != nil {
		return false, fmt.Errorf("failed to parse validation endpoint: %w", err)
	}

	finalURL := *upstreamURL
	finalURL.Path = strings.TrimRight(finalURL.Path, "/") + endpointURL.Path
	finalURL.RawQuery = endpointURL.RawQuery

	payload := gin.H{
		"model": ch.TestModel,
		"messages": []gin.H{
			{"role": "user", "content": "hi"},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal validation payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, finalURL.String(), bytes.NewBuffer(body))
	if err != nil {
		return false, fmt.Errorf("failed to create validation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cred.APIKey)
	req.Header.Set("Content-Type", "application/json")

	if len(group.HeaderRuleList) > 0 {
		runtimeKey := *apiKey
		runtimeKey.KeyValue = cred.APIKey
		headerCtx := utils.NewHeaderVariableContext(group, &runtimeKey)
		utils.ApplyHeaderRules(req, group.HeaderRuleList, headerCtx)
	}

	resp, err := ch.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send validation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, nil
	}

	errorBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("key is invalid (status %d), but failed to read error body: %w", resp.StatusCode, err)
	}

	parsedError := app_errors.ParseUpstreamError(errorBody)
	return false, fmt.Errorf("[status %d] %s", resp.StatusCode, parsedError)
}
