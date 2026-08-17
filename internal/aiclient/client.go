// Package aiclient provides a minimal OpenAI-compatible chat completions
// client used by the AI analysis pipeline.
package aiclient

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
)

// Client calls an OpenAI-compatible /chat/completions endpoint. The same
// client serves every AI role (selector, route extractor, secret detector);
// the roles differ only in prompts.
type Client struct {
	baseURL string
	model   string
	apiKey  string
	http    *http.Client
}

// New builds a client from endpoint settings. Values are trimmed; a bare host
// base URL gains the conventional /v1 prefix.
func New(baseURL, model, apiKey string) *Client {
	return &Client{
		baseURL: NormalizeBaseURL(baseURL),
		model:   strings.TrimSpace(model),
		apiKey:  strings.TrimSpace(apiKey),
		http:    &http.Client{Timeout: 5 * time.Minute},
	}
}

// Configured reports whether the endpoint settings are complete.
func Configured(baseURL, model, apiKey string) bool {
	return strings.TrimSpace(baseURL) != "" && strings.TrimSpace(model) != "" && strings.TrimSpace(apiKey) != ""
}

// NormalizeBaseURL trims the value and appends /v1 when the user supplies a
// bare scheme://host without a path.
func NormalizeBaseURL(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return ""
	}
	rest := trimmed
	if index := strings.Index(trimmed, "://"); index >= 0 {
		rest = trimmed[index+3:]
	}
	if !strings.Contains(rest, "/") {
		trimmed += "/v1"
	}
	return trimmed
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat sends a system+user prompt pair and returns the assistant content.
func (c *Client) Chat(ctx context.Context, system, user string) (string, error) {
	if c == nil || c.baseURL == "" || c.model == "" || c.apiKey == "" {
		return "", errors.New("AI 未配置：请先在 AI 设置中填写 Base URL、模型和 API Key")
	}
	payload, err := json.Marshal(chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	response, err := c.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("AI 接口返回 HTTP %d: %s", response.StatusCode, truncate(string(data), 300))
	}
	var parsed chatResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("解析 AI 响应失败: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return "", errors.New("AI 接口错误: " + parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("AI 接口未返回任何结果")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
