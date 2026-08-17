package report

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/easyscan/internal/model"
)

func TestWriteHTMLSeparatesVulnerabilitiesAndFingerprints(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "result.html")
	err := WriteHTML(filename,
		[]model.Finding{{
			ID:          "finding-1",
			RuleID:      "test.rule",
			Title:       "<script>alert(1)</script>",
			Severity:    "high",
			URL:         "https://app.example.test/login",
			Method:      "GET",
			Description: "test finding",
			Tags:        []string{"test"},
			ObservedAt:  time.Now().UTC(),
		}},
		[]model.Asset{{
			Host:         "app.example.test",
			URLs:         []string{"https://app.example.test/login"},
			Fingerprints: []string{"KScan · Example Gateway"},
			LastSeen:     time.Now().UTC(),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, want := range []string{"漏洞结果", "指纹识别", "test.rule", "Example Gateway", "&lt;script&gt;alert(1)&lt;/script&gt;"} {
		if !strings.Contains(text, want) {
			t.Fatalf("report does not contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "KScan · Example Gateway") {
		t.Fatalf("historical KScan prefix should not be rendered: %s", text)
	}
	if strings.Contains(text, "<script>alert(1)</script>") {
		t.Fatalf("untrusted finding title was not escaped: %s", text)
	}
}

func TestWriteHTMLEmptySnapshotStillHasBothSections(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "empty.html")
	if err := WriteHTML(filename, nil, nil); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	for _, want := range []string{"漏洞结果", "指纹识别", "暂无漏洞结果", "暂无指纹识别结果"} {
		if !strings.Contains(text, want) {
			t.Fatalf("empty report does not contain %q", want)
		}
	}
}

func TestAutoHTMLDebouncesToNewestSnapshot(t *testing.T) {
	var mu sync.Mutex
	var writes []string
	writer := func(_ string, _ []model.Finding, assets []model.Asset) error {
		value := "empty"
		if len(assets) > 0 {
			value = assets[0].Host
		}
		mu.Lock()
		writes = append(writes, value)
		mu.Unlock()
		return nil
	}
	reporter := newAutoHTML("ignored.html", 35*time.Millisecond, writer)
	reporter.Schedule(nil, []model.Asset{{Host: "old.example.test"}})
	time.Sleep(8 * time.Millisecond)
	reporter.Schedule(nil, []model.Asset{{Host: "new.example.test"}})

	eventually(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(writes) == 1
	})
	mu.Lock()
	if writes[0] != "new.example.test" {
		t.Fatalf("expected newest snapshot, got %#v", writes)
	}
	mu.Unlock()

	// Let an incorrectly retained first timer fire if one exists.
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	if len(writes) != 1 {
		t.Fatalf("expected one debounced write before close, got %#v", writes)
	}
	mu.Unlock()
	if err := reporter.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoHTMLCloseCommitsNewestSnapshotAfterRunningWrite(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var writes []string
	writer := func(_ string, _ []model.Finding, assets []model.Asset) error {
		value := "empty"
		if len(assets) > 0 {
			value = assets[0].Host
		}
		mu.Lock()
		first := len(writes) == 0
		mu.Unlock()
		if first {
			close(started)
			<-release
		}
		mu.Lock()
		writes = append(writes, value)
		mu.Unlock()
		return nil
	}
	reporter := newAutoHTML("ignored.html", 0, writer)
	reporter.Schedule(nil, []model.Asset{{Host: "old.example.test"}})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first report write")
	}
	reporter.Schedule(nil, []model.Asset{{Host: "new.example.test"}})
	closed := make(chan error, 1)
	go func() { closed <- reporter.Close() }()
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for final report flush")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 2 || writes[len(writes)-1] != "new.example.test" {
		t.Fatalf("close did not leave the newest snapshot last: %#v", writes)
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met before timeout")
	}
}
