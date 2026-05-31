package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogWritesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := NewLogger(path)

	status := 200
	l.Log(Entry{
		Timestamp:    time.Now(),
		Method:       "GET",
		Path:         "/repos/o/r/pulls",
		Repo:         "o/r",
		Resource:     "pulls",
		Access:       "read",
		PolicyResult: "allowed",
		GitHubStatus: &status,
		DurationMs:   42,
		Mode:         "ghe",
		TokenName:    "test-token",
	})

	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("parsing audit entry: %v", err)
	}

	if entry["method"] != "GET" {
		t.Errorf("method = %v, want GET", entry["method"])
	}
	if entry["repo"] != "o/r" {
		t.Errorf("repo = %v, want o/r", entry["repo"])
	}
	if entry["resource"] != "pulls" {
		t.Errorf("resource = %v, want pulls", entry["resource"])
	}
	if entry["policy_result"] != "allowed" {
		t.Errorf("policy_result = %v, want allowed", entry["policy_result"])
	}
	if entry["token_name"] != "test-token" {
		t.Errorf("token_name = %v, want test-token", entry["token_name"])
	}
	if int(entry["github_status"].(float64)) != 200 {
		t.Errorf("github_status = %v, want 200", entry["github_status"])
	}
}

func TestOmitemptyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := NewLogger(path)

	l.Log(Entry{
		Timestamp:    time.Now(),
		Method:       "GET",
		Path:         "/user",
		Access:       "read",
		PolicyResult: "allowed",
		DurationMs:   1,
		Mode:         "socket",
	})

	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	line := strings.TrimSpace(string(data))
	if strings.Contains(line, `"repo"`) {
		t.Error("empty repo should be omitted")
	}
	if strings.Contains(line, `"resource"`) {
		t.Error("empty resource should be omitted")
	}
	if strings.Contains(line, `"unscoped_category"`) {
		t.Error("empty unscoped_category should be omitted")
	}
	if strings.Contains(line, `"token_name"`) {
		t.Error("empty token_name should be omitted")
	}
}

func TestMultipleEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := NewLogger(path)

	for i := 0; i < 5; i++ {
		l.Log(Entry{
			Timestamp:    time.Now(),
			Method:       "GET",
			Path:         "/test",
			Access:       "read",
			PolicyResult: "allowed",
			DurationMs:   int64(i),
			Mode:         "socket",
		})
	}

	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}

	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}
}

func TestConcurrentLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := NewLogger(path)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Log(Entry{
				Timestamp:    time.Now(),
				Method:       "GET",
				Path:         "/test",
				Access:       "read",
				PolicyResult: "allowed",
				Mode:         "socket",
			})
		}()
	}
	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Fatalf("expected 50 lines, got %d", len(lines))
	}
}

func TestUnscopedCategoryInEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := NewLogger(path)

	l.Log(Entry{
		Timestamp:        time.Now(),
		Method:           "GET",
		Path:             "/user",
		UnscopedCategory: "user",
		Access:           "read",
		PolicyResult:     "allowed",
		Mode:             "socket",
	})

	time.Sleep(100 * time.Millisecond)

	data, _ := os.ReadFile(path)
	var entry map[string]any
	json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry)

	if entry["unscoped_category"] != "user" {
		t.Errorf("unscoped_category = %v, want user", entry["unscoped_category"])
	}
}

func TestGitHubStatusNilOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := NewLogger(path)

	l.Log(Entry{
		Timestamp:    time.Now(),
		Method:       "GET",
		Path:         "/test",
		Access:       "read",
		PolicyResult: "denied: no token",
		Mode:         "ghe",
		GitHubStatus: nil,
	})

	time.Sleep(100 * time.Millisecond)

	data, _ := os.ReadFile(path)
	line := strings.TrimSpace(string(data))

	var entry map[string]any
	json.Unmarshal([]byte(line), &entry)
	if entry["github_status"] != nil {
		t.Errorf("nil GitHubStatus should serialize as null, got %v", entry["github_status"])
	}
}
