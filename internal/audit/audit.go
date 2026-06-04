package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

type Entry struct {
	Timestamp        time.Time `json:"ts"`
	Method           string    `json:"method"`
	Path             string    `json:"path"`
	Repo             string    `json:"repo,omitempty"`
	Org              string    `json:"org,omitempty"`
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
	ch      chan Entry
	dropped atomic.Int64
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
		n := l.dropped.Add(1)
		slog.Warn("audit log channel full, dropping entry", "total_dropped", n)
	}
}

func (l *Logger) Dropped() int64 {
	return l.dropped.Load()
}

func (l *Logger) writer(path string) {
	var lastReportedDropped int64
	for e := range l.ch {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			slog.Error("failed to open audit log", "path", path, "err", err)
			continue
		}

		if d := l.dropped.Load(); d > lastReportedDropped {
			warning := Entry{
				Timestamp:    time.Now(),
				Method:       "SYSTEM",
				Path:         "",
				Access:       "",
				PolicyResult: fmt.Sprintf("WARNING: %d audit entries dropped", d),
				Mode:         "system",
			}
			if wline, werr := json.Marshal(warning); werr == nil {
				wline = append(wline, '\n')
				_, _ = f.Write(wline)
			}
			lastReportedDropped = d
		}

		line, err := json.Marshal(e)
		if err != nil {
			slog.Error("failed to marshal audit entry", "err", err)
			f.Close()
			continue
		}
		line = append(line, '\n')
		_, _ = f.Write(line)
		f.Close()
	}
}
