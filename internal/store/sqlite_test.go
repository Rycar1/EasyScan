package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/example/easyscan/internal/model"
)

func TestStorePersistsSnapshotAndTaskHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "easyscan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Second)
	finding := model.Finding{ID: "f-1", RuleID: "test.rule", URL: "https://app.example.test/", ObservedAt: now}
	asset := model.Asset{Host: "app.example.test", URLs: []string{"https://app.example.test/"}, LastSeen: now}
	if err := s.SaveSnapshot([]model.Finding{finding}, []model.Asset{asset}); err != nil {
		t.Fatal(err)
	}
	findings, assets, err := s.LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ID != "f-1" || len(assets) != 1 || assets[0].Host != "app.example.test" {
		t.Fatalf("unexpected snapshot: %#v %#v", findings, assets)
	}
	task := model.ActiveTask{ID: "task-1", Kind: "port_scan", Target: "app.example.test", Status: "queued", CreatedAt: now, Summary: map[string]int{}}
	if err := s.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTaskResult(model.TaskResult{ID: "result-1", TaskID: task.ID, Kind: task.Kind, Target: task.Target, Status: "open", ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAudit(model.AuditEvent{ID: "audit-1", TaskID: task.ID, Action: "active_task_created", Outcome: "accepted", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	tasks, err := s.ListTasks(10)
	if err != nil {
		t.Fatal(err)
	}
	results, err := s.ListTaskResults(task.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := s.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || len(results) != 1 || len(audit) != 1 {
		t.Fatalf("unexpected history: %#v %#v %#v", tasks, results, audit)
	}
}

func TestDeleteFindingsByRulePrefix(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "easyscan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	findings := []model.Finding{{ID: "cors", RuleID: "passive.cors.wildcard-origin", ObservedAt: now}, {ID: "keep", RuleID: "passive.exposure.private-key", ObservedAt: now}}
	if err := s.SaveSnapshot(findings, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFindingsByRulePrefix("passive.cors."); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "keep" {
		t.Fatalf("unexpected retained findings: %#v", got)
	}
}

func TestClearAnalysisSnapshotRetainsTaskHistory(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "easyscan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Second)
	if err := s.SaveSnapshot(
		[]model.Finding{{ID: "finding-1", RuleID: "passive.test", URL: "https://app.example.test/", ObservedAt: now}},
		[]model.Asset{{Host: "app.example.test", Fingerprints: []string{"CDN · Cloudflare"}, LastSeen: now}},
	); err != nil {
		t.Fatal(err)
	}
	task := model.ActiveTask{ID: "task-1", Kind: "web_crawl", Target: "https://app.example.test/", Status: "completed", CreatedAt: now}
	if err := s.CreateTask(task); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAudit(model.AuditEvent{ID: "audit-1", TaskID: task.ID, Action: "task_created", Outcome: "accepted", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	if err := s.ClearAnalysisSnapshot(); err != nil {
		t.Fatal(err)
	}
	findings, assets, err := s.LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 || len(assets) != 0 {
		t.Fatalf("expected cleared findings and assets, got %#v %#v", findings, assets)
	}
	tasks, err := s.ListTasks(10)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := s.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].ID != task.ID || len(audit) != 1 || audit[0].ID != "audit-1" {
		t.Fatalf("analysis reset must retain task/audit history, got %#v %#v", tasks, audit)
	}
}
