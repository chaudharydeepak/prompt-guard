package inspector

import "regexp"

type Severity string
type Mode string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"

	ModeTrack Mode = "track"
	ModeBlock Mode = "block"
)

type Rule struct {
	ID          string
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Severity    Severity
	Mode        Mode
}

type Match struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Mode     string `json:"mode"`
	Snippet  string `json:"snippet"`
}

var BuiltinRules = []Rule{
	{
		ID:          "aws-access-key",
		Name:        "AWS Access Key",
		Description: "AWS access key ID (AKIA...)",
		Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "aws-secret-key",
		Name:        "AWS Secret Key",
		Description: "AWS secret access key pattern",
		Pattern:     regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['"]?([0-9a-zA-Z/+]{40})['"]?`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "anthropic-key",
		Name:        "Anthropic API Key",
		Description: "Anthropic API key (sk-ant-...)",
		Pattern:     regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{20,}`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "openai-key",
		Name:        "OpenAI API Key",
		Description: "OpenAI API key (sk-...)",
		Pattern:     regexp.MustCompile(`sk-[a-zA-Z0-9T]{20,}`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "github-token",
		Name:        "GitHub Token",
		Description: "GitHub personal access / OAuth / app token",
		Pattern:     regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36,}`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "private-key",
		Name:        "Private Key Material",
		Description: "PEM-encoded private key block",
		Pattern:     regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "ssn",
		Name:        "Social Security Number",
		Description: "US Social Security Number (NNN-NN-NNNN)",
		Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "credit-card",
		Name:        "Credit Card Number",
		Description: "Visa / Mastercard / Amex / Discover 16-digit pattern",
		Pattern:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		Severity:    SeverityHigh,
		Mode:        ModeBlock,
	},
	{
		ID:          "jwt-token",
		Name:        "JWT Token",
		Description: "JSON Web Token (three base64 segments)",
		Pattern:     regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
		Severity:    SeverityMedium,
		Mode:        ModeTrack,
	},
	{
		ID:          "generic-secret",
		Name:        "Generic Secret / Password",
		Description: "Password/secret keyword followed by a value (any separator)",
		Pattern:     regexp.MustCompile(`(?i)(secret|password|passwd|api_key|apikey)\s*(?:is|=|:|\s)\s*['"]?[a-zA-Z0-9+/!@#$%^&*]{4,}['"]?`),
		Severity:    SeverityMedium,
		Mode:        ModeTrack,
	},
	{
		ID:          "email",
		Name:        "Email Address",
		Description: "Email address",
		Pattern:     regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
		Severity:    SeverityLow,
		Mode:        ModeTrack,
	},
	{
		ID:          "internal-ip",
		Name:        "Internal IP Address",
		Description: "RFC-1918 private IPv4 address",
		Pattern:     regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		Severity:    SeverityLow,
		Mode:        ModeTrack,
	},
}
