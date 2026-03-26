package proxy

import "encoding/json"

// apiRequest covers the common shapes of OpenAI, Anthropic, and Copilot requests.
type apiRequest struct {
	// OpenAI / Copilot chat
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"` // string or []content part
	} `json:"messages"`
	// OpenAI legacy
	Prompt string `json:"prompt"`
	// Anthropic
	System string `json:"system"`
	// Generic
	Input string `json:"input"`
}

// ExtractPrompts parses an AI API request body and returns all text content fragments.
func ExtractPrompts(body []byte) []string {
	var req apiRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil
	}

	var out []string

	for _, msg := range req.Messages {
		switch v := msg.Content.(type) {
		case string:
			if v != "" {
				out = append(out, v)
			}
		case []interface{}:
			// Vision / multi-part content: [{type:"text", text:"..."}, ...]
			for _, part := range v {
				if m, ok := part.(map[string]interface{}); ok {
					if t, ok := m["text"].(string); ok && t != "" {
						out = append(out, t)
					}
				}
			}
		}
	}

	if req.Prompt != "" {
		out = append(out, req.Prompt)
	}
	if req.System != "" {
		out = append(out, req.System)
	}
	if req.Input != "" {
		out = append(out, req.Input)
	}

	return out
}
