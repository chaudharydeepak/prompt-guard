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
	mux.HandleFunc("/api/flags", func(w http.ResponseWriter, r *http.Request) {
		apiFlags(w, r, db)
	})
	mux.HandleFunc("/api/flags/", func(w http.ResponseWriter, r *http.Request) {
		apiFlagDetail(w, r, db)
	})
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		apiRules(w, r, eng)
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

func apiFlags(w http.ResponseWriter, _ *http.Request, db *store.Store) {
	flags, err := db.ListFlags(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type row struct {
		ID       int64             `json:"id"`
		Time     string            `json:"time"`
		Host     string            `json:"host"`
		Path     string            `json:"path"`
		Rules    []string          `json:"rules"`
		Severity string            `json:"severity"`
		Matches  []inspector.Match `json:"matches"`
		Prompt   string            `json:"prompt"`
	}
	out := make([]row, 0, len(flags))
	for _, f := range flags {
		rules := make([]string, 0, len(f.Matches))
		maxSev := "low"
		for _, m := range f.Matches {
			rules = append(rules, m.RuleName)
			if m.Severity == "high" {
				maxSev = "high"
			} else if m.Severity == "medium" && maxSev != "high" {
				maxSev = "medium"
			}
		}
		out = append(out, row{
			ID:       f.ID,
			Time:     f.Timestamp.Format("Jan 02 15:04:05"),
			Host:     f.Host,
			Path:     f.Path,
			Rules:    rules,
			Severity: maxSev,
			Matches:  f.Matches,
			Prompt:   truncate(f.Prompt, 300),
		})
	}
	jsonResponse(w, out)
}

func apiFlagDetail(w http.ResponseWriter, r *http.Request, db *store.Store) {
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
	f, err := db.GetFlag(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	jsonResponse(w, f)
}

func apiRules(w http.ResponseWriter, _ *http.Request, eng *inspector.Engine) {
	type ruleOut struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}
	rules := eng.Rules()
	out := make([]ruleOut, len(rules))
	for i, r := range rules {
		out[i] = ruleOut{r.ID, r.Name, r.Description, string(r.Severity)}
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
    --accent-dim: #1e3a7a;
    --danger:     #f45b69;
    --warning:    #f5a623;
    --success:    #3ecf8e;
    --high:       #f45b69;
    --medium:     #f5a623;
    --low:        #4f7fff;
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
    --accent-dim: #dbeafe;
    --danger:     #dc2626;
    --warning:    #d97706;
    --success:    #059669;
    --high:       #dc2626;
    --medium:     #d97706;
    --low:        #2563eb;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    background: var(--bg-base);
    color: var(--text-1);
    font-size: 13px;
    min-height: 100vh;
  }

  /* ── Header ── */
  .pg-header {
    display: flex; align-items: center; gap: 12px;
    padding: 0 24px;
    height: 52px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
  }
  .pg-logo { font-weight: 700; font-size: 15px; letter-spacing: -.3px; }
  .pg-logo span { color: var(--accent); }
  .pg-divider { width: 1px; height: 20px; background: var(--border); }
  .pg-meta { color: var(--text-3); font-size: 11.5px; }
  .pg-spacer { flex: 1; }
  .pg-btn {
    border: 1px solid var(--border);
    background: var(--bg-raised);
    color: var(--text-2);
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    cursor: pointer;
    font-family: inherit;
  }
  .pg-btn:hover { background: var(--border); color: var(--text-1); }

  /* ── Layout ── */
  .pg-main { padding: 20px 24px; max-width: 1400px; margin: 0 auto; }

  /* ── Metric tiles ── */
  .metric-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 20px;
  }
  @media(max-width:900px) { .metric-row { grid-template-columns: repeat(2,1fr); } }
  .metric-tile {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
  }
  .mt-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; color: var(--text-3); margin-bottom: 6px; }
  .mt-value { font-size: 28px; font-weight: 700; color: var(--text-1); line-height: 1; }
  .mt-sub   { font-size: 11.5px; color: var(--text-3); margin-top: 4px; }

  /* ── Two-column layout ── */
  .pg-cols { display: grid; grid-template-columns: 1fr 340px; gap: 16px; align-items: start; }
  @media(max-width:1100px) { .pg-cols { grid-template-columns: 1fr; } }

  /* ── Panel ── */
  .pg-panel {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 16px;
  }
  .pg-panel-header {
    display: flex; align-items: center; gap: 10px;
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
  }
  .pg-panel-title { font-weight: 600; font-size: 13px; }
  .pg-panel-count {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 1px 8px;
    font-size: 11px;
    color: var(--text-2);
    font-weight: 600;
  }
  .pg-panel-count.hot { background: var(--danger); border-color: var(--danger); color: #fff; }

  /* ── Table ── */
  .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
  .pg-table { width: 100%; border-collapse: collapse; }
  .pg-table th {
    font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: .4px; color: var(--text-3);
    padding: 8px 14px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-raised);
    white-space: nowrap;
    text-align: left;
  }
  .pg-table td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-sub);
    color: var(--text-1);
    vertical-align: top;
    white-space: nowrap;
  }
  .pg-table tr:last-child td { border-bottom: none; }
  .pg-table tbody tr { cursor: pointer; }
  .pg-table tbody tr:hover td { background: var(--bg-raised); }
  .pg-table .muted { color: var(--text-3); }
  .pg-table .mono  { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11.5px; }
  .pg-table .empty td { color: var(--text-3); text-align: center; padding: 32px; font-style: italic; cursor: default; }

  /* Expandable detail row */
  .detail-row td {
    background: var(--bg-raised) !important;
    padding: 0 !important;
    white-space: normal !important;
    cursor: default !important;
  }
  .detail-inner { padding: 14px 16px; }
  .detail-prompt {
    font-family: 'SF Mono','Fira Code',Menlo,monospace;
    font-size: 11.5px;
    color: var(--text-2);
    background: var(--bg-base);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    margin-bottom: 10px;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 200px;
    overflow-y: auto;
  }
  .match-list { display: flex; flex-direction: column; gap: 6px; }
  .match-item {
    display: flex; align-items: flex-start; gap: 10px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
  }
  .match-snippet { font-family: 'SF Mono','Fira Code',Menlo,monospace; font-size: 11px; color: var(--text-2); flex: 1; word-break: break-all; }

  /* ── Severity tags ── */
  .tag {
    display: inline-block;
    border-radius: 4px;
    padding: 2px 7px;
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: .2px;
    text-transform: uppercase;
  }
  .tag-high    { background: rgba(244,91,105,.15); color: var(--high); border: 1px solid rgba(244,91,105,.3); }
  .tag-medium  { background: rgba(245,166,35,.12); color: var(--medium); border: 1px solid rgba(245,166,35,.3); }
  .tag-low     { background: rgba(79,127,255,.12); color: var(--low); border: 1px solid rgba(79,127,255,.3); }

  /* ── Rules panel ── */
  .rule-item {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-sub);
  }
  .rule-item:last-child { border-bottom: none; }
  .rule-name { font-weight: 600; font-size: 12px; margin-bottom: 2px; }
  .rule-desc { color: var(--text-3); font-size: 11px; }
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

  <!-- Stats -->
  <div class="metric-row">
    <div class="metric-tile">
      <div class="mt-label">Total Flagged</div>
      <div class="mt-value" id="tile-total">—</div>
      <div class="mt-sub">all time</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Today</div>
      <div class="mt-value" id="tile-today">—</div>
      <div class="mt-sub">flagged prompts</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Most Flagged Host</div>
      <div class="mt-value" style="font-size:16px;padding-top:4px" id="tile-host">—</div>
      <div class="mt-sub">&nbsp;</div>
    </div>
    <div class="metric-tile">
      <div class="mt-label">Active Rules</div>
      <div class="mt-value" id="tile-rules">—</div>
      <div class="mt-sub">monitoring</div>
    </div>
  </div>

  <div class="pg-cols">
    <!-- Flagged prompts -->
    <div>
      <div class="pg-panel">
        <div class="pg-panel-header">
          <span class="pg-panel-title">Flagged Prompts</span>
          <span class="pg-panel-count" id="flag-count">0</span>
        </div>
        <div class="table-wrap">
          <table class="pg-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Host</th>
                <th>Path</th>
                <th>Rules Hit</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody id="flags-body">
              <tr class="empty"><td colspan="5">No flagged prompts yet</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Rules sidebar -->
    <div>
      <div class="pg-panel">
        <div class="pg-panel-header">
          <span class="pg-panel-title">Active Rules</span>
          <span class="pg-panel-count" id="rules-count">0</span>
        </div>
        <div id="rules-list"></div>
      </div>
    </div>
  </div>

</main>

<script>
function toggleTheme() {
  var html = document.documentElement;
  var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('pg-theme', next);
  updateThemeIcon();
}
function updateThemeIcon() {
  var icon = document.getElementById('theme-icon');
  if (icon) icon.className = document.documentElement.getAttribute('data-theme') === 'dark'
    ? 'bi bi-sun' : 'bi bi-moon';
}
updateThemeIcon();

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function sevTag(sev) {
  return '<span class="tag tag-' + esc(sev) + '">' + esc(sev) + '</span>';
}

var openRow = null;

function toggleDetail(id, prompt, matches) {
  // Close previously open row
  if (openRow !== null) {
    var old = document.getElementById('detail-' + openRow);
    if (old) old.remove();
    if (openRow === id) { openRow = null; return; }
  }
  openRow = id;

  var anchor = document.getElementById('row-' + id);
  if (!anchor) return;

  var matchHTML = (matches || []).map(function(m) {
    return '<div class="match-item">' +
      '<span>' + sevTag(m.severity) + '</span>' +
      '<div><div style="font-weight:600;font-size:12px;margin-bottom:3px">' + esc(m.rule_name) + '</div>' +
      '<div class="match-snippet">' + esc(m.snippet) + '</div></div>' +
      '</div>';
  }).join('');

  var detail = document.createElement('tr');
  detail.id = 'detail-' + id;
  detail.className = 'detail-row';
  detail.innerHTML = '<td colspan="5"><div class="detail-inner">' +
    '<div class="detail-prompt">' + esc(prompt) + '</div>' +
    '<div class="match-list">' + matchHTML + '</div>' +
    '</div></td>';

  anchor.after(detail);
}

async function refresh() {
  try {
    var [flagsRes, statsRes, rulesRes] = await Promise.all([
      fetch('/api/flags'),
      fetch('/api/stats'),
      fetch('/api/rules'),
    ]);
    var flags = await flagsRes.json();
    var stats = await statsRes.json();
    var rules = await rulesRes.json();

    // Meta
    document.getElementById('meta').textContent = 'updated ' + new Date().toLocaleTimeString();

    // Stats tiles
    document.getElementById('tile-total').textContent = stats.total || 0;
    document.getElementById('tile-today').textContent = stats.today || 0;
    document.getElementById('tile-host').textContent  = stats.most_flagged_host || '—';
    document.getElementById('tile-rules').textContent = rules.length;

    // Flag count badge
    var fc = document.getElementById('flag-count');
    fc.textContent = flags.length;
    fc.className = 'pg-panel-count' + (flags.length > 0 ? ' hot' : '');

    // Flags table
    document.getElementById('flags-body').innerHTML = flags.length === 0
      ? '<tr class="empty"><td colspan="5">No flagged prompts yet — prompts are inspected in real time</td></tr>'
      : flags.map(function(f) {
          var rulesStr = (f.rules || []).join(', ') || '—';
          return '<tr id="row-' + f.id + '" onclick="toggleDetail(' + f.id + ',' +
            JSON.stringify(f.prompt) + ',' + JSON.stringify(f.matches) + ')">' +
            '<td class="mono muted">' + esc(f.time) + '</td>' +
            '<td style="font-weight:600">' + esc(f.host) + '</td>' +
            '<td class="mono muted">' + esc(f.path) + '</td>' +
            '<td>' + esc(rulesStr) + '</td>' +
            '<td>' + sevTag(f.severity) + '</td>' +
            '</tr>';
        }).join('');

    // Rules sidebar
    document.getElementById('rules-count').textContent = rules.length;
    document.getElementById('rules-list').innerHTML = rules.map(function(r) {
      return '<div class="rule-item">' +
        '<div style="padding-top:2px">' + sevTag(r.severity) + '</div>' +
        '<div><div class="rule-name">' + esc(r.name) + '</div>' +
        '<div class="rule-desc">' + esc(r.description) + '</div></div>' +
        '</div>';
    }).join('');

  } catch(e) {
    document.getElementById('meta').textContent = 'error: ' + e.message;
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
`

// Ensure the timestamp is accessible for testing
var _ = time.Now
