package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
