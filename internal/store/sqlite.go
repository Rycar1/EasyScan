// Package store persists analysis summaries and explicit active-task history.
// Request and response bodies are intentionally not saved here.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/easyscan/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(filename string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil && filepath.Dir(filename) != "." {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, payload TEXT NOT NULL, observed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assets (host TEXT PRIMARY KEY, payload TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS active_tasks (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_results (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL, observed_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_task_results_task ON task_results(task_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, task_id TEXT, payload TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_audit_events_task ON audit_events(task_id, created_at DESC);`)
	if err != nil {
		return fmt.Errorf("migrate SQLite database: %w", err)
	}
	return nil
}

func (s *Store) SaveSnapshot(findings []model.Finding, assets []model.Asset) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, finding := range findings {
		payload, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO findings(id,payload,observed_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, observed_at=excluded.observed_at`, finding.ID, payload, finding.ObservedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	for _, asset := range assets {
		payload, err := json.Marshal(asset)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO assets(host,payload,last_seen) VALUES(?,?,?) ON CONFLICT(host) DO UPDATE SET payload=excluded.payload,last_seen=excluded.last_seen`, asset.Host, payload, asset.LastSeen.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LoadSnapshot() ([]model.Finding, []model.Asset, error) {
	findings, err := loadJSON[model.Finding](s.db, `SELECT payload FROM findings ORDER BY observed_at`)
	if err != nil {
		return nil, nil, err
	}
	assets, err := loadJSON[model.Asset](s.db, `SELECT payload FROM assets ORDER BY host`)
	return findings, assets, err
}

// ClearAnalysisSnapshot removes only the persisted passive-analysis result.
// Active-task history and audit events intentionally remain available across
// desktop sessions.
func (s *Store) ClearAnalysisSnapshot() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM findings`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM assets`); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteFindingsByRulePrefix removes retired detector results after an upgrade.
// It is deliberately prefix based so users' unrelated custom findings remain.
func (s *Store) DeleteFindingsByRulePrefix(prefixes ...string) error {
	rows, err := s.db.Query(`SELECT id,payload FROM findings`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		var payload []byte
		if err := rows.Scan(&id, &payload); err != nil {
			return err
		}
		var finding model.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return err
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(finding.RuleID, prefix) {
				ids = append(ids, id)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := s.db.Exec(`DELETE FROM findings WHERE id=?`, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateTask(task model.ActiveTask) error { return s.saveTask(task) }
func (s *Store) UpdateTask(task model.ActiveTask) error { return s.saveTask(task) }
func (s *Store) saveTask(task model.ActiveTask) error {
	payload, err := json.Marshal(task)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO active_tasks(id,payload,created_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload`, task.ID, payload, task.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ListTasks(limit int) ([]model.ActiveTask, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	return loadJSON[model.ActiveTask](s.db, `SELECT payload FROM active_tasks ORDER BY created_at DESC LIMIT `+fmt.Sprint(limit))
}
func (s *Store) AddTaskResult(result model.TaskResult) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO task_results(id,task_id,payload,observed_at) VALUES(?,?,?,?)`, result.ID, result.TaskID, payload, result.ObservedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ListTaskResults(taskID string, limit int) ([]model.TaskResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	return loadJSONArgs[model.TaskResult](s.db, `SELECT payload FROM task_results WHERE task_id=? ORDER BY observed_at DESC LIMIT `+fmt.Sprint(limit), taskID)
}
func (s *Store) AddAudit(event model.AuditEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO audit_events(id,task_id,payload,created_at) VALUES(?,?,?,?)`, event.ID, event.TaskID, payload, event.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ListAudit(limit int) ([]model.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	return loadJSON[model.AuditEvent](s.db, `SELECT payload FROM audit_events ORDER BY created_at DESC LIMIT `+fmt.Sprint(limit))
}

func loadJSON[T any](db *sql.DB, query string) ([]T, error) { return loadJSONArgs[T](db, query) }
func loadJSONArgs[T any](db *sql.DB, query string, args ...any) ([]T, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []T
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var value T
		if err := json.Unmarshal(payload, &value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}
