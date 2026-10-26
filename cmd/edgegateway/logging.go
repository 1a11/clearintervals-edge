package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/identity"
	"github.com/1a11/clearintervals-edge/internal/uplink"
)

// Logs are one JSON object per line on stdout. "event" is a fixed snake_case
// name and "hint" a fixed sentence for the operator. Attributes carry only
// bounded values the gateway itself chose (enums, counts, local paths and
// addresses). Labels, measurements, tokens, digests, stream keys, keys and
// proxy credentials never reach a log line.
var logger = newLogger(os.Stdout)

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.MessageKey {
			a.Key = "event"
		}
		return a
	}}))
}

var errRevoked = errors.New("revoked")

const ownershipHint = "The container runs as UID/GID 65532: make the state volume writable by that user, e.g. chown -R 65532:65532 on the host directory."

// stopAttrs explains why the process is exiting.
func stopAttrs(e error) []any {
	var cfg *config.Problem
	var id *identity.Problem
	var path *fs.PathError
	var op *net.OpError
	switch {
	case errors.As(e, &cfg):
		return []any{"reason", "configuration_invalid", "field", cfg.Field, "problem", cfg.Reason, "hint", "Fix the field and validate with: edgegateway -config <path> -check"}
	case errors.As(e, &id):
		return []any{"reason", "identity_invalid", "problem", id.Reason}
	case errors.Is(e, errRevoked):
		return []any{"reason", "revoked", "hint", "This gateway was revoked in the product. It will not send again; the local buffer is kept. Ask your Clear Intervals administrator for a new licence."}
	case errors.Is(e, durable.ErrLocked):
		return []any{"reason", "state_directory_locked", "hint", "Another edgegateway process uses this state directory. Run one process per state volume and never copy a state volume."}
	case errors.Is(e, buffer.ErrIntegrity):
		return []any{"reason", "buffer_integrity", "hint", "A buffer write or segment check failed. Check disk health and free space; corrupt segments are quarantined as .bad files in the buffer directory."}
	case errors.Is(e, fs.ErrPermission) && errors.As(e, &path):
		return []any{"reason", "permission_denied", "path", path.Path, "operation", path.Op, "hint", ownershipHint}
	case errors.As(e, &op) && op.Op == "listen":
		return []any{"reason", "listen_failed", "address", op.Addr.String(), "problem", op.Err.Error(), "hint", "Another service may already use this port, or the address is not on this host."}
	case errors.As(e, &path):
		return []any{"reason", "file_error", "path", path.Path, "operation", path.Op, "problem", path.Err.Error()}
	}
	return []any{"reason", "internal", "problem", bounded(e.Error())}
}

func bounded(s string) string {
	if len(s) > 256 {
		return s[:256] + "..."
	}
	return s
}

var refusalHints = map[string]string{
	"revoked":                "This gateway was revoked in the product.",
	"organization_suspended": "The organization is suspended. New input is dropped and counted; earlier backlog is kept until it is active again.",
	"entitlement_inactive":   "The edge gateway add-on is not active for this organization. Data stays buffered.",
	"clock_skew":             "The host clock differs from the cloud. Run NTP on the host.",
	"update_required":        "The cloud no longer accepts this release. Deploy a newer verified image.",
	"duplicate_session":      "Another process is connected with this gateway identity. A copied state volume shares one identity.",
	"invalid_token":          "The enrollment licence was refused. Download a new licence from the product.",
	"enrollment_expired":     "The enrollment licence expired. Download a new licence from the product.",
	"invalid_enrollment":     "The enrollment licence was refused. Download a new licence from the product.",
	"invalid_credential":     "The cloud did not accept this gateway's certificate. If it persists, re-license the gateway.",
	"binding_revoked":        "A configured binding was revoked in the product. Remove it from bindings.",
	"rate_limited":           "The cloud is at capacity. The gateway retries at the time the cloud asked for.",
	"core_unavailable":       "The cloud is temporarily unavailable. Data stays buffered.",
	"server_draining":        "The cloud server is restarting. Data stays buffered.",
}

var transportHints = map[string]string{
	"dns_lookup_failed":            "Cannot resolve the ingest host. Check the host's DNS.",
	"connection_refused":           "Outbound TCP 443 to the ingest host was refused. Check the firewall.",
	"connect_timeout":              "Outbound TCP 443 to the ingest host timed out. Check the firewall or set uplink.proxy.",
	"network_unreachable":          "The ingest host is unreachable from this network. Check routing or set uplink.proxy.",
	"proxy_dns_lookup_failed":      "Cannot resolve the HTTP proxy host in uplink.proxy / HTTPS_PROXY.",
	"proxy_connection_refused":     "The HTTP proxy refused the connection. Check uplink.proxy / HTTPS_PROXY.",
	"proxy_connect_timeout":        "The HTTP proxy did not answer. Check uplink.proxy / HTTPS_PROXY.",
	"proxy_connect_http_403":       "The HTTP proxy forbids CONNECT to the ingest host. Allow it on port 443.",
	"proxy_connect_http_407":       "The HTTP proxy requires authentication. Put user:password in uplink.proxy.",
	"server_certificate_untrusted": "The ingest server certificate is not signed by the licence trust anchors. A TLS-intercepting proxy or firewall is the usual cause: exempt the ingest host from inspection.",
	"server_name_mismatch":         "The server certificate does not match the ingest host. A TLS-intercepting proxy or a wrong DNS entry is the usual cause.",
	"server_certificate_invalid":   "The ingest server certificate is not valid now. Check the host clock (NTP).",
	"tls_rejected_by_server":       "The cloud rejected the TLS handshake. If it persists, the gateway certificate may be revoked or expired.",
}

func retryAttrs(err error, delay time.Duration) []any {
	reason := "internal"
	attrs := []any{}
	var failure *uplink.Failure
	var transport *uplink.TransportError
	if errors.As(err, &failure) {
		reason = "server_refusal"
		switch failure.Code {
		case "revoked", "organization_suspended", "rate_limited", "invalid_session", "core_unavailable", "server_draining", "stale_policy", "invalid_credential", "duplicate_session", "update_required", "clock_skew", "invalid_frame", "invalid_csr", "result_unavailable", "invalid_token", "enrollment_expired",
			"entitlement_inactive", "invalid_enrollment", "invalid_proof", "operation_cancelled", "operation_conflict", "binding_revoked", "result_proof_required", "stream_closed":
			reason = failure.Code
		}
		if hint, ok := refusalHints[reason]; ok {
			attrs = append(attrs, "hint", hint)
		}
	} else if errors.As(err, &transport) {
		reason = "transport"
		attrs = append(attrs, "stage", transport.Stage)
		hint, ok := transportHints[transport.Stage]
		if !ok && strings.HasPrefix(transport.Stage, "proxy_") {
			hint, ok = "The HTTP proxy could not open a tunnel to the ingest host. Check uplink.proxy / HTTPS_PROXY.", true
		}
		if ok {
			attrs = append(attrs, "hint", hint)
		}
	} else if errors.Is(err, uplink.ErrTransport) {
		reason = "transport"
	} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		reason = "eof"
	}
	return append([]any{"reason", reason, "retryAfterSeconds", delay.Seconds()}, attrs...)
}

func uplinkRetryEvent(err error, delay time.Duration) {
	logger.Warn("uplink_retry", retryAttrs(err, delay)...)
}

var dropHints = map[string]string{
	"unmapped":  "Input matched no binding selector and was discarded. Check the labels in bindings[].selector.",
	"suspended": "The organization is suspended; valid input was discarded.",
	"too_old":   "Records older than the buffer age limit were discarded.",
	"evicted":   "The buffer is full: the oldest context series were evicted. Check the uplink and buffer.maxBytes.",
	"invalid":   "Writers sent invalid input (non-finite values, malformed requests).",
	"too_large": "Writers sent requests above the size limits. Reduce their batch size.",
}

// monitor turns counter changes into log lines, so operators without a
// Prometheus scraper still learn about dropped data and integrity alarms.
func monitor(ctx context.Context, q *buffer.Queue, every, summary time.Duration) {
	last, _, _ := q.Snapshot()
	tick := time.NewTicker(every)
	defer tick.Stop()
	lastSummary := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now, size, segments := q.Snapshot()
		for _, reason := range []string{"unmapped", "suspended", "too_old", "evicted", "invalid", "too_large"} {
			if n := now.Drops[reason] - last.Drops[reason]; n > 0 {
				logger.Warn("records_dropped", "dropReason", reason, "count", n, "hint", dropHints[reason])
			}
		}
		if now.Integrity && !last.Integrity {
			logger.Error("buffer_integrity_alarm", "hint", "A buffer segment failed its checksum or a write failed. Check disk health; /healthz now reports 503.")
		}
		if now.Suspended != last.Suspended {
			if now.Suspended {
				logger.Warn("organization_suspended", "hint", refusalHints["organization_suspended"])
			} else {
				logger.Info("organization_active")
			}
		}
		if time.Since(lastSummary) >= summary {
			lastSummary = time.Now()
			logger.Info("buffer_status", "bufferBytes", size, "segments", segments, "acceptedTotal", now.Accepted, "rejectedTotal", now.Rejected)
		}
		last = now
	}
}
