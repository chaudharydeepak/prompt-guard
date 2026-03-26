package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	"github.com/chaudharydeepak/prompt-guard/store"
)

// Start runs the web dashboard on the given port. Non-blocking.
func Start(port int, db *store.Store, eng *inspector.Engine) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/prompts", func(w http.ResponseWriter, r *http.Request) {
		apiPrompts(w, r, db)
	})
	mux.HandleFunc("/api/prompts/", func(w http.ResponseWriter, r *http.Request) {
		apiPromptDetail(w, r, db)
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		apiRules(w, r, eng)
	})
	mux.HandleFunc("/api/rules/", func(w http.ResponseWriter, r *http.Request) {
		apiRuleMode(w, r, db, eng)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		apiStats(w, r, db)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, dashboardHTML)
	})

	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	log.Printf("dashboard: http://localhost:%d", port)
	go func() { log.Fatal(srv.ListenAndServe()) }()
}

// ── API handlers ─────────────────────────────────────────────────────────────

func apiPrompts(w http.ResponseWriter, r *http.Request, db *store.Store) {
	statusFilter := r.URL.Query().Get("status")
	prompts, err := db.ListPrompts(statusFilter, 500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type row struct {
		ID       int64             `json:"id"`
		Time     string            `json:"time"`
		Host     string            `json:"host"`
		Path     string            `json:"path"`
		Status   string            `json:"status"`
		Rules    []string          `json:"rules"`
		Severity string            `json:"severity"`
		Matches  []inspector.Match `json:"matches"`
		Prompt   string            `json:"prompt"`
	}
	out := make([]row, 0, len(prompts))
	for _, p := range prompts {
		rules := make([]string, 0, len(p.Matches))
		maxSev := ""
		for _, m := range p.Matches {
			rules = append(rules, m.RuleName)
			if m.Severity == "high" {
				maxSev = "high"
			} else if m.Severity == "medium" && maxSev != "high" {
				maxSev = "medium"
			} else if maxSev == "" {
				maxSev = m.Severity
			}
		}
		out = append(out, row{
			ID:       p.ID,
			Time:     p.Timestamp.Format("Jan 02 15:04:05"),
			Host:     p.Host,
			Path:     p.Path,
			Status:   string(p.Status),
			Rules:    rules,
			Severity: maxSev,
			Matches:  p.Matches,
			Prompt:   truncate(p.Prompt, 400),
		})
	}
	jsonResponse(w, out)
}

func apiPromptDetail(w http.ResponseWriter, r *http.Request, db *store.Store) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p, err := db.GetPrompt(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	jsonResponse(w, p)
}

// POST /api/rules/{id}/mode  body: {"mode":"track"|"block"}
func apiRuleMode(w http.ResponseWriter, r *http.Request, db *store.Store, eng *inspector.Engine) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// path: /api/rules/{id}/mode
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}
	ruleID := parts[2]
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Mode != "track" && body.Mode != "block") {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	if !eng.SetMode(ruleID, inspector.Mode(body.Mode)) {
		http.NotFound(w, r)
		return
	}
	if err := db.SetRuleMode(ruleID, body.Mode); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiRules(w http.ResponseWriter, _ *http.Request, eng *inspector.Engine) {
	type ruleOut struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Mode        string `json:"mode"`
	}
	rules := eng.Rules()
	out := make([]ruleOut, len(rules))
	for i, r := range rules {
		out[i] = ruleOut{r.ID, r.Name, r.Description, string(r.Severity), string(r.Mode)}
	}
	jsonResponse(w, out)
}

func apiStats(w http.ResponseWriter, _ *http.Request, db *store.Store) {
	jsonResponse(w, db.Stats())
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ── Dashboard HTML ────────────────────────────────────────────────────────────

var dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prompt Guard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<script>
  var t = localStorage.getItem('pg-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
</script>
<style>
  :root { color-scheme: dark; }
  [data-theme=dark] {
    --bg-base:    #0d0f12;
    --bg-surface: #13161b;
    --bg-raised:  #1a1e25;
    --border:     #272c36;
    --border-sub: #1f2330;
    --text-1:     #e8ecf3;
    --text-2:     #9aa3b5;
    --text-3:     #5c6476;
    --accent:     #4f7fff;
    --danger:     #f45b69;
    --warning:    #f5a623;
    --success:    #3ecf8e;
    --blocked-bg: rgba(244,91,105,.08);
    --flagged-bg: rgba(245,166,35,.06);
  }
  [data-theme=light] {
    --bg-base:    #f0f2f5;
    --bg-surface: #ffffff;
    --bg-raised:  #f7f8fa;
    --border:     #dde1ea;
    --border-sub: #eaecf0;
    --text-1:     #111827;
    --text-2:     #4b5563;
    --text-3:     #9ca3af;
    --accent:     #2563eb;
    --danger:     #dc2626;
    --warning:    #d97706;
    --success:    #059669;
    --blocked-bg: rgba(220,38,38,.06);
    --flagged-bg: rgba(217,119,6,.05);
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg-base); color: var(--text-1); font-size: 13px; min-height: 100vh; }

  /* Header */
  .pg-header { display: flex; align-items: center; gap: 12px; padding: 0 24px; height: 52px; background: var(--bg-surface); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100; }
  .pg-logo { font-weight: 700; font-size: 15px; letter-spacing: -.3px; }
  .pg-logo span { color: var(--accent); }
  .pg-divider { width: 1px; height: 20px; background: var(--border); }
  .pg-meta { color: var(--text-3); font-size: 11.5px; }
  .pg-spacer { flex: 1; }
  .pg-btn { border: 1px solid var(--border); background: var(--bg-raised); color: var(--text-2); border-radius: 6px; padding: 5px 10px; font-size: 12px; cursor: pointer; font-family: inherit; }
  .pg-btn:hover { background: var(--border); color: var(--text-1); }

  /* Layout */
  .pg-main { padding: 20px 24px; max-width: 1400px; margin: 0 auto; }

  /* Metric tiles */
  .metric-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px; }
  @media(max-width:1000px) { .metric-row { grid-template-columns: repeat(3,1fr); } }
  .metric-tile { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; }
  .mt-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; color: var(--text-3); margin-bottom: 6px; }
  .mt-value { font-size: 28px; font-weight: 700; color: var(--text-1); line-height: 1; }
  .mt-value.blocked { color: var(--danger); }
  .mt-value.flagged  { color: var(--warning); }
  .mt-value.clean    { color: var(--success); }
  .mt-sub { font-size: 11.5px; color: var(--text-3); margin-top: 4px; }

  /* Cols */
  .pg-cols { display: grid; grid-template-columns: 1fr 320px; gap: 16px; align-items: start; }
  @media(max-width:1100px) { .pg-cols { grid-template-columns: 1fr; } }

  /* Panel */
  .pg-panel { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; margin-bottom: 16px; }
  .pg-panel-header { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .pg-panel-title { font-weight: 600; font-size: 13px; }
  .pg-panel-count { background: var(--bg-raised); border: 1px solid var(--border); border-radius: 20px; padding: 1px 8px; font-size: 11px; color: var(--text-2); font-weight: 600; }

  /* Filter tabs */
  .filter-tabs { display: flex; gap: 4px; margin-left: auto; }
  .filter-tab { border: 1px solid var(--border); background: transparent; color: var(--text-3); border-radius: 5px; padding: 3px 10px; font-size: 11px; font-weight: 600; cursor: pointer; font-family: inherit; text-transform: uppercase; letter-spacing: .3px; }
  .filter-tab:hover { color: var(--text-1); background: var(--bg-raised); }
  .filter-tab.active { background: var(--accent); border-color: var(--accent); color: #fff; }

  /* Table */
  .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .pg-table { width: 100%; border-collapse: collapse; }
  .pg-table th { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .4px; color: var(--text-3); padding: 8px 14px; border-bottom: 1px solid var(--border); background: var(--bg-raised); white-space: nowrap; text-align: left; }
  .pg-table td { padding: 9px 14px; border-bottom: 1px solid var(--border-sub); color: var(--text-1); vertical-align: middle; white-space: nowrap; }
  .pg-table tr:last-child td { border-bottom: none; }
  .pg-table tbody tr { cursor: pointer; }
  .pg-table tbody tr:hover td { background: var(--bg-raised); }
  .pg-table .muted { color: var(--text-3); }
  .pg-table .mono { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11.5px; }
  .pg-table .empty td { color: var(--text-3); text-align: center; padding: 32px; font-style: italic; cursor: default; }
  .pg-table tr.row-blocked td { background: var(--blocked-bg); }
  .pg-table tr.row-flagged td { background: var(--flagged-bg); }

  /* Expandable detail */
  .detail-row td { background: var(--bg-raised) !important; padding: 0 !important; white-space: normal !important; cursor: default !important; }
  .detail-inner { padding: 14px 16px; }
  .detail-prompt { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11.5px; color: var(--text-2); background: var(--bg-base); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; white-space: pre-wrap; word-break: break-word; max-height: 200px; overflow-y: auto; }
  .match-list { display: flex; flex-direction: column; gap: 6px; }
  .match-item { display: flex; align-items: flex-start; gap: 10px; background: var(--bg-surface); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; }
  .match-snippet { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11px; color: var(--text-2); flex: 1; word-break: break-all; }
  .match-mode { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 1px 5px; border-radius: 3px; }
  .match-mode.block { background: rgba(244,91,105,.15); color: var(--danger); }
  .match-mode.track { background: rgba(79,127,255,.12); color: var(--accent); }

  /* Tags */
  .tag { display: inline-block; border-radius: 4px; padding: 2px 7px; font-size: 10.5px; font-weight: 600; letter-spacing: .2px; text-transform: uppercase; }
  .tag-high    { background: rgba(244,91,105,.15); color: var(--danger);  border: 1px solid rgba(244,91,105,.3); }
  .tag-medium  { background: rgba(245,166,35,.12); color: var(--warning); border: 1px solid rgba(245,166,35,.3); }
  .tag-low     { background: rgba(79,127,255,.12); color: var(--accent);  border: 1px solid rgba(79,127,255,.3); }
  .tag-blocked { background: rgba(244,91,105,.15); color: var(--danger);  border: 1px solid rgba(244,91,105,.4); }
  .tag-flagged { background: rgba(245,166,35,.12); color: var(--warning); border: 1px solid rgba(245,166,35,.4); }
  .tag-clean   { background: rgba(62,207,142,.10); color: var(--success); border: 1px solid rgba(62,207,142,.3); }

  /* Rules panel */
  .rule-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--border-sub); }
  .rule-item:last-child { border-bottom: none; }
  .rule-name { font-weight: 600; font-size: 12px; margin-bottom: 2px; }
  .rule-desc { color: var(--text-3); font-size: 11px; }
  .rule-badges { display: flex; gap: 4px; }
  .mode-toggle { border: none; border-radius: 5px; padding: 4px 10px; font-size: 11px; font-weight: 600; cursor: pointer; font-family: inherit; white-space: nowrap; }
  .mode-block { background: rgba(244,91,105,.15); color: var(--danger); border: 1px solid rgba(244,91,105,.35); }
  .mode-track { background: rgba(79,127,255,.12); color: var(--accent); border: 1px solid rgba(79,127,255,.3); }
  .mode-toggle:hover { opacity: .8; }
</style>
</head>
<body>

<header class="pg-header">
  <div class="pg-logo">Prompt<span>Guard</span></div>
  <div class="pg-divider"></div>
  <div class="pg-meta" id="meta">loading…</div>
  <div class="pg-spacer"></div>
  <button class="pg-btn" onclick="toggleTheme()"><i id="theme-icon" class="bi bi-sun"></i></button>
</header>

<main class="pg-main">

  <div class="metric-row">
    <div class="metric-tile">
      <div class="mt-label">Total Prompts</div>
      <div class="mt-value" id="tile-total">—</div>
      <div class="mt-sub">intercepted</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Clean</div>
      <div class="mt-value clean" id="tile-clean">—</div>
      <div class="mt-sub">no rules hit</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Flagged</div>
      <div class="mt-value flagged" id="tile-flagged">—</div>
      <div class="mt-sub">tracked, forwarded</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Blocked</div>
      <div class="mt-value blocked" id="tile-blocked">—</div>
      <div class="mt-sub">stopped at proxy</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Top Host</div>
      <div class="mt-value" style="font-size:13px;padding-top:6px" id="tile-host">—</div>
      <div class="mt-sub">most flagged/blocked</div>
    </div>
  </div>

  <div class="pg-cols">
    <div>
      <div class="pg-panel">
        <div class="pg-panel-header">
          <span class="pg-panel-title">Prompts</span>
          <span class="pg-panel-count" id="prompt-count">0</span>
          <div class="filter-tabs">
            <button class="filter-tab active" onclick="setFilter('all',this)">All</button>
            <button class="filter-tab" onclick="setFilter('blocked',this)">Blocked</button>
            <button class="filter-tab" onclick="setFilter('flagged',this)">Flagged</button>
            <button class="filter-tab" onclick="setFilter('clean',this)">Clean</button>
          </div>
        </div>
        <div class="table-wrap">
          <table class="pg-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Status</th>
                <th>Host</th>
                <th>Path</th>
                <th>Rules Hit</th>
              </tr>
            </thead>
            <tbody id="prompts-body">
              <tr class="empty"><td colspan="5">No prompts intercepted yet</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div>
      <div class="pg-panel">
        <div class="pg-panel-header">
          <span class="pg-panel-title">Rules</span>
          <span class="pg-panel-count" id="rules-count">0</span>
        </div>
        <div id="rules-list"></div>
      </div>
    </div>
  </div>

</main>

<script>
var currentFilter = 'all';
var openRow = null;

function toggleTheme() {
  var html = document.documentElement;
  var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('pg-theme', next);
  updateThemeIcon();
}
function updateThemeIcon() {
  var icon = document.getElementById('theme-icon');
  if (icon) icon.className = document.documentElement.getAttribute('data-theme') === 'dark' ? 'bi bi-sun' : 'bi bi-moon';
}
updateThemeIcon();

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function statusTag(s) {
  return '<span class="tag tag-' + esc(s) + '">' + esc(s) + '</span>';
}
function sevTag(s) {
  return s ? '<span class="tag tag-' + esc(s) + '">' + esc(s) + '</span>' : '';
}
function modeTag(m) {
  return '<span class="match-mode ' + esc(m) + '">' + esc(m) + '</span>';
}

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-tab').forEach(function(b) { b.classList.remove('active'); });
  btn.classList.add('active');
  refresh();
}

function toggleDetail(id) {
  if (openRow !== null) {
    var old = document.getElementById('detail-' + openRow);
    if (old) old.remove();
    if (openRow === id) { openRow = null; return; }
  }
  openRow = id;
  var anchor = document.getElementById('row-' + id);
  if (!anchor) return;

  var p = (window._promptData || {})[id] || {};
  var prompt  = p.prompt  || '';
  var matches = p.matches || [];
  var status  = p.status  || '';

  var matchHTML = matches.length === 0
    ? '<div style="color:var(--text-3);font-size:12px">No rules matched</div>'
    : matches.map(function(m) {
        return '<div class="match-item">' +
          '<div style="display:flex;flex-direction:column;gap:4px;min-width:80px">' + sevTag(m.severity) + modeTag(m.mode) + '</div>' +
          '<div><div style="font-weight:600;font-size:12px;margin-bottom:3px">' + esc(m.rule_name) + '</div>' +
          '<div class="match-snippet">' + esc(m.snippet) + '</div></div>' +
          '</div>';
      }).join('');

  var blockedBanner = status === 'blocked'
    ? '<div style="background:rgba(244,91,105,.12);border:1px solid rgba(244,91,105,.3);border-radius:6px;padding:8px 12px;margin-bottom:10px;color:var(--danger);font-size:12px;font-weight:600">&#x26D4; Prompt was blocked — not forwarded to AI</div>'
    : '';

  var detail = document.createElement('tr');
  detail.id = 'detail-' + id;
  detail.className = 'detail-row';
  detail.innerHTML = '<td colspan="5"><div class="detail-inner">' +
    blockedBanner +
    '<div class="detail-prompt">' + esc(prompt) + '</div>' +
    '<div class="match-list">' + matchHTML + '</div>' +
    '</div></td>';
  anchor.after(detail);
}

async function refresh() {
  try {
    var url = '/api/prompts' + (currentFilter !== 'all' ? '?status=' + currentFilter : '');
    var [promptsRes, statsRes, rulesRes] = await Promise.all([
      fetch(url),
      fetch('/api/stats'),
      fetch('/api/rules'),
    ]);
    var prompts = await promptsRes.json();
    var stats   = await statsRes.json();
    var rules   = await rulesRes.json();

    document.getElementById('meta').textContent = 'updated ' + new Date().toLocaleTimeString();

    document.getElementById('tile-total').textContent   = stats.total   || 0;
    document.getElementById('tile-clean').textContent   = stats.clean   || 0;
    document.getElementById('tile-flagged').textContent = stats.flagged || 0;
    document.getElementById('tile-blocked').textContent = stats.blocked || 0;
    document.getElementById('tile-host').textContent    = stats.most_flagged_host || '—';

    var pc = document.getElementById('prompt-count');
    pc.textContent = prompts.length;

    // Store prompt detail data by ID to avoid HTML-attribute encoding issues.
    window._promptData = {};
    prompts.forEach(function(p) { window._promptData[p.id] = p; });
    var wasOpen = openRow;

    document.getElementById('prompts-body').innerHTML = prompts.length === 0
      ? '<tr class="empty"><td colspan="5">No prompts' + (currentFilter !== 'all' ? ' with status "' + currentFilter + '"' : '') + '</td></tr>'
      : prompts.map(function(p) {
          var rowClass = 'row-' + p.status;
          var rulesStr = (p.rules || []).join(', ') || '—';
          return '<tr id="row-' + p.id + '" class="' + rowClass + '" onclick="toggleDetail(' + p.id + ')">' +
            '<td class="mono muted">' + esc(p.time) + '</td>' +
            '<td>' + statusTag(p.status) + '</td>' +
            '<td style="font-weight:600">' + esc(p.host) + '</td>' +
            '<td class="mono muted">' + esc(p.path) + '</td>' +
            '<td>' + esc(rulesStr) + '</td>' +
            '</tr>';
        }).join('');

    document.getElementById('rules-count').textContent = rules.length;
    document.getElementById('rules-list').innerHTML = rules.map(function(r) {
      var isBlock = r.mode === 'block';
      return '<div class="rule-item">' +
        '<div style="flex:1"><div class="rule-name">' + esc(r.name) + '</div>' +
        '<div class="rule-desc">' + esc(r.description) + '</div>' +
        '<div class="rule-badges" style="margin-top:4px">' + sevTag(r.severity) + '</div>' +
        '</div>' +
        '<div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;min-width:90px">' +
        '<button class="mode-toggle ' + (isBlock ? 'mode-block' : 'mode-track') + '" onclick="toggleMode(\'' + esc(r.id) + '\',\'' + (isBlock ? 'track' : 'block') + '\',this)">' +
        (isBlock ? '🚫 block' : '👁 track') +
        '</button></div>' +
        '</div>';
    }).join('');

    // Re-expand previously open row after table rebuild.
    if (wasOpen !== null && window._promptData[wasOpen]) {
      openRow = null; // reset so toggleDetail re-inserts it
      toggleDetail(wasOpen);
    }

  } catch(e) {
    document.getElementById('meta').textContent = 'error: ' + e.message;
  }
}

async function toggleMode(ruleID, newMode, btn) {
  btn.disabled = true;
  try {
    await fetch('/api/rules/' + ruleID + '/mode', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({mode: newMode}),
    });
    await refresh(); // re-render rules list with updated modes
  } finally {
    btn.disabled = false;
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
`

var _ = time.Now
