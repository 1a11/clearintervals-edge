package main

import (
	"context"
	"crypto/x509"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1a11/clearintervals-edge/internal/clock"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/identity"
)

// clockSkewError stops first enrollment when the host clock is too far off.
type clockSkewError struct{ offset float64 }

func (e *clockSkewError) Error() string { return "clock_skew" }

// roundOffset keeps logged offsets short and stable.
func roundOffset(seconds float64) float64 { return math.Round(seconds*1000) / 1000 }

const (
	reasonUnknownKey     = "unknown_key"
	reasonDigestMismatch = "digest_mismatch"
	streamKeyHint        = "The cloud does not know this binding's stream key. Copy the current binding from the product into bindings[]; data for it stays buffered."
	digestHint           = "The configured streamKey does not match the licence roster: the key was rotated or the wrong key was copied. Update bindings[] with the current key from the product; data for this binding stays buffered."
)

// rejectedBinding is one configured binding the cloud or the licence roster
// does not accept. It never holds a stream key.
type rejectedBinding struct {
	ID, Kind, SourceID, Reason string
}

// diagnostics carries non-fatal uplink findings to /metrics, /healthz and the
// monitor loop. Drift and rejected keys are surfaced, never fatal.
type diagnostics struct {
	offsetMillis atomic.Int64
	skew         atomic.Bool
	rejected     atomic.Int64
	mu           sync.Mutex
	findings     []rejectedBinding
}

// observeClock records the local-minus-cloud offset and logs it past the
// runtime thresholds.
func (d *diagnostics) observeClock(offsetSeconds float64, source string) {
	d.offsetMillis.Store(int64(math.Round(offsetSeconds * 1000)))
	skew := math.Abs(offsetSeconds) > clock.FailThreshold.Seconds()
	d.skew.Store(skew)
	switch {
	case skew:
		logger.Error("clock_skew", "source", source, "offsetSeconds", roundOffset(offsetSeconds), "hint", "The host clock differs from the cloud by more than 30 seconds, so the cloud refuses captures. Run NTP (chrony or systemd-timesyncd) on the host.")
	case math.Abs(offsetSeconds) > clock.WarnThreshold.Seconds():
		logger.Warn("ntp_drift", "source", source, "offsetSeconds", roundOffset(offsetSeconds), "hint", "The host clock differs from the cloud. Run NTP on the host.")
	}
}

// observeWelcome applies the cloud's own clock comparison and the keys it did
// not recognize.
func (d *diagnostics) observeWelcome(offsetMillis int64, unknownKeys []string, bindings []config.Binding) {
	d.observeClock(float64(offsetMillis)/1000, "welcome")
	d.observeUnknownKeys(unknownKeys, bindings)
}

func (d *diagnostics) observeUnknownKeys(unknown []string, bindings []config.Binding) {
	list := []rejectedBinding{}
	for _, b := range bindings {
		if slices.Contains(unknown, b.StreamKey) {
			list = append(list, rejectedBinding{ID: b.ID, Kind: b.Kind, SourceID: b.SourceID, Reason: reasonUnknownKey})
		}
	}
	if !d.replace(reasonUnknownKey, list) {
		return
	}
	for _, v := range list {
		logger.Error("stream_keys_rejected", "bindingId", v.ID, "kind", v.Kind, "sourceId", v.SourceID, "hint", streamKeyHint)
	}
}

// observeDigestMismatches surfaces bindings whose key no longer matches the
// licence roster. A rotated key can lag the edge configuration, so it does not
// stop the gateway.
func (d *diagnostics) observeDigestMismatches(mismatches []identity.RosterMismatch) {
	list := make([]rejectedBinding, len(mismatches))
	for i, m := range mismatches {
		list[i] = rejectedBinding{ID: m.BindingID, Kind: m.Kind, SourceID: m.SourceID, Reason: reasonDigestMismatch}
	}
	if !d.replace(reasonDigestMismatch, list) {
		return
	}
	for _, v := range list {
		logger.Error("stream_key_digest_mismatch", "bindingId", v.ID, "kind", v.Kind, "sourceId", v.SourceID, "hint", digestHint)
	}
}

// replace swaps the findings of one reason and reports whether the visible set
// changed, so a reconnecting session does not repeat the same ERROR line.
func (d *diagnostics) replace(reason string, list []rejectedBinding) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := make([]rejectedBinding, 0, len(d.findings)+len(list))
	for _, v := range d.findings {
		if v.Reason != reason {
			next = append(next, v)
		}
	}
	next = append(next, list...)
	sort.Slice(next, func(i, j int) bool { return next[i].ID < next[j].ID })
	changed := !slices.Equal(next, d.findings)
	d.findings = next
	d.rejected.Store(int64(len(next)))
	return changed
}

func (d *diagnostics) snapshot() (offsetSeconds float64, alarm, rejected int) {
	return float64(d.offsetMillis.Load()) / 1000, boolInt(d.skew.Load()), int(d.rejected.Load())
}

func (d *diagnostics) rejectedBindings() []rejectedBinding {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.findings)
}

// degraded names the non-fatal findings /healthz surfaces without failing.
func (d *diagnostics) degraded() string {
	parts := []string{}
	if d.skew.Load() {
		parts = append(parts, "clock_skew")
	}
	if d.rejected.Load() > 0 {
		parts = append(parts, "stream_keys_rejected")
	}
	return strings.Join(parts, ",")
}

// rosterBindings narrows configured bindings to what the licence roster checks.
func rosterBindings(list []config.Binding) []identity.Binding {
	v := make([]identity.Binding, len(list))
	for i, b := range list {
		v[i] = identity.Binding{ID: b.ID, Kind: b.Kind, SourceID: b.SourceID, StreamKey: b.StreamKey}
	}
	return v
}

// probeClock compares the host clock with the ingest origin once.
func probeClock(ctx context.Context, d *diagnostics, ingestURL string, roots *x509.CertPool, source string) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	offset, e := clock.Probe(probeCtx, ingestURL, roots)
	if e != nil {
		logger.Warn("clock_probe_failed", "problem", bounded(e.Error()), "hint", "The gateway could not compare its clock with the cloud. Check DNS and outbound HTTPS; the gateway keeps running.")
		return
	}
	d.observeClock(offset, source)
}

// clockMonitor re-probes the ingest origin roughly hourly. immediate is false
// when startup already probed before the first enrollment.
func clockMonitor(ctx context.Context, d *diagnostics, ingestURL string, roots *x509.CertPool, every time.Duration, immediate bool) {
	if immediate {
		probeClock(ctx, d, ingestURL, roots, "probe")
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			probeClock(ctx, d, ingestURL, roots, "probe")
		}
	}
}
