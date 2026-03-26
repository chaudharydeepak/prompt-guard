package inspector

import "sync"

// Result is the outcome of inspecting a prompt.
type Result struct {
	Matches []Match
	Blocked bool
}

// Engine runs all active rules against text and returns matches.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

func New() *Engine {
	rules := make([]Rule, len(BuiltinRules))
	copy(rules, BuiltinRules)
	return &Engine{rules: rules}
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// SetMode updates the mode of a rule by ID. Returns false if rule not found.
func (e *Engine) SetMode(ruleID string, mode Mode) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == ruleID {
			e.rules[i].Mode = mode
			return true
		}
	}
	return false
}

// RedactText replaces all track-mode rule matches in the extracted prompt text.
// Returns the redacted text and one Match per rule that fired.
func (e *Engine) RedactText(text string) (string, []Match) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := text
	var matches []Match
	for _, rule := range e.rules {
		if rule.Mode != ModeTrack {
			continue
		}
		if !rule.Pattern.MatchString(result) {
			continue
		}
		result = rule.Pattern.ReplaceAllString(result, rule.Replacement)
		matches = append(matches, Match{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: string(rule.Severity),
			Mode:     string(rule.Mode),
			Snippet:  "[REDACTED]",
		})
	}
	return result, matches
}

// RedactBodyForForwarding applies all track-mode replacements to the raw request body.
func (e *Engine) RedactBodyForForwarding(body []byte) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	s := string(body)
	for _, rule := range e.rules {
		if rule.Mode == ModeTrack {
			s = rule.Pattern.ReplaceAllString(s, rule.Replacement)
		}
	}
	return []byte(s)
}

func (e *Engine) Inspect(text string) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result Result
	for _, rule := range e.rules {
		if rule.Mode != ModeBlock {
			continue
		}
		locs := rule.Pattern.FindStringIndex(text)
		if locs == nil {
			continue
		}
		start, end := locs[0], locs[1]
		snipStart := start - 20
		if snipStart < 0 {
			snipStart = 0
		}
		snipEnd := end + 20
		if snipEnd > len(text) {
			snipEnd = len(text)
		}
		snippet := text[snipStart:snipEnd]
		if snipStart > 0 {
			snippet = "…" + snippet
		}
		if snipEnd < len(text) {
			snippet = snippet + "…"
		}
		result.Matches = append(result.Matches, Match{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: string(rule.Severity),
			Mode:     string(rule.Mode),
			Snippet:  snippet,
		})
		if rule.Mode == ModeBlock {
			result.Blocked = true
		}
	}
	return result
}
