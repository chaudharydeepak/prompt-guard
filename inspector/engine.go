package inspector

// Engine runs all active rules against text and returns matches.
type Engine struct {
	rules []Rule
}

func New() *Engine {
	return &Engine{rules: BuiltinRules}
}

func (e *Engine) Rules() []Rule {
	return e.rules
}

func (e *Engine) Inspect(text string) []Match {
	var matches []Match
	for _, rule := range e.rules {
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
		matches = append(matches, Match{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Severity: string(rule.Severity),
			Snippet:  snippet,
		})
	}
	return matches
}
