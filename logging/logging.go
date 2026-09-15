// Package logging provides a minimal severity filter for the DNS server.
//
// The server logged every query, every blocklist hit and all sync chatter
// unconditionally, which on a busy resolver meant thousands of synchronous
// journald writes per hour. Per-query detail is still available, but it is
// now opt-in via the DNS_LOG_LEVEL environment variable.
package logging

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

type Level int32

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

var current atomic.Int32

func init() {
	SetLevel(ParseLevel(os.Getenv("DNS_LOG_LEVEL")))
}

// ParseLevel maps a name to a Level. Unrecognised or empty values yield
// LevelInfo, which keeps startup and error output but drops per-query noise.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return LevelError
	case "warn", "warning":
		return LevelWarn
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	default:
		return LevelInfo
	}
}

func SetLevel(l Level) { current.Store(int32(l)) }

func GetLevel() Level { return Level(current.Load()) }

// Enabled reports whether l should be emitted at the current level.
func Enabled(l Level) bool { return l <= GetLevel() }

func Debugf(format string, v ...any) {
	if Enabled(LevelDebug) {
		log.Printf(format, v...)
	}
}

func Infof(format string, v ...any) {
	if Enabled(LevelInfo) {
		log.Printf(format, v...)
	}
}

func Warnf(format string, v ...any) {
	if Enabled(LevelWarn) {
		log.Printf(format, v...)
	}
}

func Errorf(format string, v ...any) {
	if Enabled(LevelError) {
		log.Printf(format, v...)
	}
}

func (l Level) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	case LevelDebug:
		return "debug"
	default:
		return "info"
	}
}
