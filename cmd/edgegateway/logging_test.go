package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/uplink"
)

func TestLogLinesAreJSONWithAnEventKey(t *testing.T) {
	var out bytes.Buffer
	newLogger(&out).Warn("uplink_retry", retryAttrs(&uplink.TransportError{Stage: "server_certificate_untrusted"}, 5*time.Second)...)
	var line map[string]any
	if e := json.Unmarshal(out.Bytes(), &line); e != nil {
		t.Fatal(e)
	}
	if line["event"] != "uplink_retry" || line["reason"] != "transport" || line["stage"] != "server_certificate_untrusted" || line["hint"] == nil {
		t.Fatalf("unexpected line: %s", out.String())
	}
}

func TestRefusalLogsCodeReasonRefAndSupportHint(t *testing.T) {
	var out bytes.Buffer
	newLogger(&out).Warn("uplink_retry", retryAttrs(&uplink.Failure{Code: "invalid_token", Retry: 5 * time.Second, Reason: "enrollment token already used", Ref: "diag-7f3a"}, 5*time.Second)...)
	var line map[string]any
	if e := json.Unmarshal(out.Bytes(), &line); e != nil {
		t.Fatal(e)
	}
	if line["reason"] != "server_refusal" || line["code"] != "invalid_token" || line["serverReason"] != "enrollment token already used" || line["ref"] != "diag-7f3a" {
		t.Fatalf("refusal detail lost: %s", out.String())
	}
	if hint, _ := line["hint"].(string); !strings.Contains(hint, "ref") {
		t.Fatalf("support hint missing: %s", out.String())
	}
}

func TestUnknownRefusalCodeIsLoggedVerbatim(t *testing.T) {
	var out bytes.Buffer
	newLogger(&out).Warn("uplink_retry", retryAttrs(&uplink.Failure{Code: "new_cloud_code", Retry: time.Second}, time.Second)...)
	var line map[string]any
	if e := json.Unmarshal(out.Bytes(), &line); e != nil {
		t.Fatal(e)
	}
	if line["code"] != "new_cloud_code" || line["reason"] != "server_refusal" {
		t.Fatalf("unknown code collapsed: %s", out.String())
	}
}

func TestPreciseRefusalCodesHaveHints(t *testing.T) {
	for _, code := range []string{"gateway_not_pending", "enrollment_token_missing", "enrollment_token_expired", "enrollment_token_mismatch", "gateway_not_active", "credential_fingerprint_mismatch", "credential_key_reuse", "operation_mismatch", "operation_stale", "gateway_not_found"} {
		if refusalHints[code] == "" {
			t.Fatalf("no hint for refusal code %s", code)
		}
	}
}

func TestStopReasonsAreSpecific(t *testing.T) {
	attrs := stopAttrs(fmt.Errorf("loading: %w", &config.Problem{Field: "stateDir", Reason: "is required"}))
	if attrs[1] != "configuration_invalid" || attrs[3] != "stateDir" {
		t.Fatalf("configuration problem lost: %v", attrs)
	}
	if attrs := stopAttrs(errRevoked); attrs[1] != "revoked" {
		t.Fatalf("revocation not named: %v", attrs)
	}
	if attrs := stopAttrs(errors.New("boom")); attrs[1] != "internal" {
		t.Fatalf("fallback reason: %v", attrs)
	}
	if attrs := stopAttrs(&clockSkewError{offset: 95}); attrs[1] != "clock_skew" || attrs[3] != 95.0 {
		t.Fatalf("clock skew not named: %v", attrs)
	}
}

func TestDialNamesTheFailedStage(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	_, e = uplink.Dial(context.Background(), "https://"+addr, "", &tls.Config{}, true)
	var transport *uplink.TransportError
	if !errors.As(e, &transport) || transport.Stage != "connection_refused" || !errors.Is(e, uplink.ErrTransport) {
		t.Fatalf("unexpected dial error: %v", e)
	}
}
