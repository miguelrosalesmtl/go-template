// Package logger builds the application's structured logger from settings.
package logger

import (
	"log/slog"
	"os"
	"strings"

	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// New returns a slog.Logger configured according to settings. In debug mode it
// emits human-readable text; otherwise it emits JSON suitable for log
// aggregation (Loki, ELK, Cloud Logging).
func New(s *settings.Settings) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(s.App.LogLevel)}

	var handler slog.Handler
	if s.App.Debug {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	log := slog.New(handler)
	if s.App.InstanceID != "" {
		log = log.With(slog.String("instance_id", s.App.InstanceID))
	}
	return log.With(slog.String("env", s.App.Environment))
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
