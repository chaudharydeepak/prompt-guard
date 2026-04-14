package proxy

import "testing"

func TestIsTarget_DefaultHosts(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// Anthropic
		{"api.anthropic.com", true},
		{"api.anthropic.com:443", true},
		// OpenAI
		{"api.openai.com", true},
		{"api.openai.com:443", true},
		// GitHub Copilot — shared (legacy)
		{"api.githubcopilot.com", true},
		// GitHub Copilot — plan-specific hosts (individual/business/enterprise)
		{"api.individual.githubcopilot.com", true},
		{"api.business.githubcopilot.com", true},
		{"api.enterprise.githubcopilot.com", true},
		// Copilot proxy
		{"copilot-proxy.githubusercontent.com", true},
		// Claude web
		{"claude.ai", true},
		// Should NOT be intercepted
		{"github.com", false},
		{"google.com", false},
		{"http-intake.logs.us5.datadoghq.com", false},
		{"api.github.com", false},
	}

	for _, tc := range cases {
		got := isTarget(tc.host)
		if got != tc.want {
			t.Errorf("isTarget(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
