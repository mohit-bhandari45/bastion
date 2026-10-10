package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

type Logger struct {
	level  Level
	format string
}

func New(level, format string) *Logger {
	return &Logger{
		level:  Level(level),
		format: format,
	}
}

func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     string(level),
		"message":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}

	if l.format == "json" {
		b, _ := json.Marshal(entry)
		fmt.Fprintln(os.Stdout, string(b))
	} else {
		fmt.Fprintf(os.Stdout, "[%s] %s %s\n", entry["timestamp"], level, msg)
	}
}

func (l *Logger) Info(msg string, fields map[string]interface{}) {
	l.log(LevelInfo, msg, fields)
}

func (l *Logger) Warn(msg string, fields map[string]interface{}) {
	l.log(LevelWarn, msg, fields)
}

func (l *Logger) Error(msg string, fields map[string]interface{}) {
	l.log(LevelError, msg, fields)
}

func (l *Logger) Debug(msg string, fields map[string]interface{}) {
	if l.level == LevelDebug {
		l.log(LevelDebug, msg, fields)
	}
}

// SecurityEvent is a structured security log entry (perfect for SIEM ingestion)
type SecurityEvent struct {
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	ClientIP    string                 `json:"client_ip"`
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	UserAgent   string                 `json:"user_agent"`
	UserID      string                 `json:"user_id,omitempty"`
	Reason      string                 `json:"reason"`
	StatusCode  int                    `json:"status_code"`
	RequestID   string                 `json:"request_id"`
	Timestamp   string                 `json:"timestamp"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

func (l *Logger) Security(event SecurityEvent) {
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	b, _ := json.Marshal(event)
	fmt.Fprintln(os.Stdout, string(b))
}
