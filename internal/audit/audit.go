package audit

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

type Entry struct {
	Timestamp        time.Time `json:"ts"`
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	Repo             string    `json:"repo,omitempty"`
	Resource         string    `json:"resource,omitempty"`
	UnscopedCategory string    `json:"unscoped_category,omitempty"`
	Access           string    `json:"access"`
	PolicyResult     string    `json:"policy_result"`
	GitHubStatus     *int      `json:"github_status"`
	DurationMs       int64     `json:"duration_ms"`
	Mode             string    `json:"mode"`
	TokenName        string    `json:"token_name,omitempty"`
}

type Logger struct {
	ch chan Entry
}

func NewLogger(path string) *Logger {
	l := &Logger{ch: make(chan Entry, 1024)}
	go l.writer(path)
	return l
}

func (l *Logger) Log(e Entry) {
	select {
	case l.ch <- e:
	default:
		slog.Warn("audit log channel full, dropping entry")
	}
}

func (l *Logger) writer(path string) {
	for e := range l.ch {
		line, err := json.Marshal(e)
		if err != nil {
			slog.Error("failed to marshal audit entry", "err", err)
			continue
		}
		line = append(line, '\n')

		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			slog.Error("failed to open audit log", "path", path, "err", err)
			continue
		}
		_, _ = f.Write(line)
		f.Close()
	}
}
