package store

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/chaudharydeepak/prompt-guard/inspector"
	_ "modernc.org/sqlite"
)

// FlaggedPrompt is a prompt that triggered at least one rule.
type FlaggedPrompt struct {
	ID        int64
	Timestamp time.Time
	Host      string
	Path      string
	Prompt    string
	Matches   []inspector.Match
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: single writer
	s := &Store{db: db}
	return s, s.migrate()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS flagged_prompts (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			host      TEXT    NOT NULL,
			path      TEXT    NOT NULL,
			prompt    TEXT    NOT NULL,
			matches   TEXT    NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_ts ON flagged_prompts(timestamp);
	`)
	return err
}

func (s *Store) SaveFlag(f FlaggedPrompt) error {
	b, _ := json.Marshal(f.Matches)
	_, err := s.db.Exec(
		`INSERT INTO flagged_prompts (timestamp, host, path, prompt, matches) VALUES (?,?,?,?,?)`,
		f.Timestamp.Unix(), f.Host, f.Path, f.Prompt, string(b),
	)
	return err
}

func (s *Store) ListFlags(limit int) ([]FlaggedPrompt, error) {
	rows, err := s.db.Query(
		`SELECT id, timestamp, host, path, prompt, matches
		 FROM flagged_prompts ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FlaggedPrompt
	for rows.Next() {
		var f FlaggedPrompt
		var ts int64
		var matchJSON string
		if err := rows.Scan(&f.ID, &ts, &f.Host, &f.Path, &f.Prompt, &matchJSON); err != nil {
			return nil, err
		}
		f.Timestamp = time.Unix(ts, 0)
		_ = json.Unmarshal([]byte(matchJSON), &f.Matches)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetFlag(id int64) (*FlaggedPrompt, error) {
	row := s.db.QueryRow(
		`SELECT id, timestamp, host, path, prompt, matches
		 FROM flagged_prompts WHERE id = ?`, id,
	)
	var f FlaggedPrompt
	var ts int64
	var matchJSON string
	if err := row.Scan(&f.ID, &ts, &f.Host, &f.Path, &f.Prompt, &matchJSON); err != nil {
		return nil, err
	}
	f.Timestamp = time.Unix(ts, 0)
	_ = json.Unmarshal([]byte(matchJSON), &f.Matches)
	return &f, nil
}

type Stats struct {
	Total         int    `json:"total"`
	Today         int    `json:"today"`
	MostFlaggedHost string `json:"most_flagged_host"`
	TopRule       string `json:"top_rule"`
}

func (s *Store) Stats() Stats {
	var st Stats
	s.db.QueryRow(`SELECT COUNT(*) FROM flagged_prompts`).Scan(&st.Total)
	today := time.Now().Truncate(24 * time.Hour).Unix()
	s.db.QueryRow(`SELECT COUNT(*) FROM flagged_prompts WHERE timestamp >= ?`, today).Scan(&st.Today)
	s.db.QueryRow(
		`SELECT host FROM flagged_prompts GROUP BY host ORDER BY COUNT(*) DESC LIMIT 1`,
	).Scan(&st.MostFlaggedHost)
	return st
}
