package proxy

import (
	"encoding/json"
	"strings"
)

type apiRequest struct {
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"` // string or array of content parts
	} `json:"messages"`
	Stream bool   `json:"stream"`
	Prompt string `json:"prompt"` // OpenAI legacy
	Input  string `json:"input"`  // generic
}

// IsStreaming reports whether the request uses SSE streaming.
func IsStreaming(body []byte) bool {
	var req struct {
		Stream bool `json:"stream"`
	}
	json.Unmarshal(body, &req)
	return req.Stream
}

// ExtractPrompts returns only the user content from the current turn —
// messages after the last assistant message. Skips system/tool messages.
// For Copilot, extracts only the <user_query> content when present.
func ExtractPrompts(body []byte) []string {
	var req apiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	// Find index of last assistant message.
	lastAssistant := -1
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "assistant" {
			lastAssistant = i
			break
		}
	}

	var out []string
	for i := lastAssistant + 1; i < len(req.Messages); i++ {
		if req.Messages[i].Role != "user" {
			continue
		}
		out = append(out, extractContent(req.Messages[i].Content)...)
	}

	if req.Prompt != "" {
		out = append(out, req.Prompt)
	}
	if req.Input != "" {
		out = append(out, req.Input)
	}
	return out
}

// extractContent decodes a content field (string or array of content parts)
// and returns text fragments. For Copilot's context-wrapped messages it
// extracts only the <user_query> portion when present.
func extractContent(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}

	// Try string.
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return userQueryOrFull(s)
	}

	// Try array of content parts (Anthropic / OpenAI vision format).
	var parts []struct {
		Type    string          `json:"type"`
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"` // nested content (tool_result)
	}
	if json.Unmarshal(raw, &parts) != nil {
		return nil
	}

	var out []string
	for _, p := range parts {
		if p.Text != "" {
			out = append(out, userQueryOrFull(p.Text)...)
		}
		// Recursively handle nested content blocks (e.g. tool_result).
		if len(p.Content) > 0 {
			out = append(out, extractContent(p.Content)...)
		}
	}
	return out
}

// userQueryOrFull extracts only the text inside <user_query>...</user_query>
// when that tag is present (Copilot's format).
// If no user_query tag is found but the content starts with an XML tag (e.g.
// Copilot's <context> / <editorContext> injections), it is skipped — those are
// system-injected context, not the user's actual message.
func userQueryOrFull(text string) []string {
	const open, close = "<user_query>", "</user_query>"
	if start := strings.Index(text, open); start >= 0 {
		rest := text[start+len(open):]
		if end := strings.Index(rest, close); end >= 0 {
			q := strings.TrimSpace(rest[:end])
			if q != "" {
				return []string{q}
			}
		}
	}
	trimmed := strings.TrimSpace(text)
	// Skip system-injected XML blocks (start with '<').
	if strings.HasPrefix(trimmed, "<") {
		return nil
	}
	if trimmed != "" {
		return []string{trimmed}
	}
	return nil
}
