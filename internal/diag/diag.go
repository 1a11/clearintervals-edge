// Package diag carries the verbose diagnostic log, which is off unless the operator asks for it.
//
// Normal logs carry bounded values and never contain labels, tokens, stream keys or measurements. Verbose
// mode deliberately does the opposite: it exists to answer "why is my sample not arriving", so it logs the
// Authorization header, token digests, stream keys, received labels, sample values and the exact descriptor
// payload. It is meant for a short debugging session, not for a production log pipeline.
package diag

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

var (
	on     atomic.Bool
	mu     sync.RWMutex
	logger *slog.Logger
)

// Set installs the logger verbose events are written to and turns them on or off. Passing nil turns them off.
func Set(l *slog.Logger, enabled bool) {
	mu.Lock()
	logger = l
	mu.Unlock()
	on.Store(enabled && l != nil)
}

// Enabled reports whether verbose events are being written, so callers can skip expensive formatting.
func Enabled() bool { return on.Load() }

// Event writes one verbose event. It is a no-op when verbose mode is off.
func Event(name string, attrs ...any) {
	if !on.Load() {
		return
	}
	mu.RLock()
	l := logger
	mu.RUnlock()
	if l == nil {
		return
	}
	l.Info(name, attrs...)
}
