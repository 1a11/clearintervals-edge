package clock

import (
	"context"
	"crypto/x509"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func probeServer(t *testing.T, skew time.Duration, status int) (string, *x509.CertPool) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", time.Now().Add(skew).UTC().Format(http.TimeFormat))
		w.WriteHeader(status)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server.URL, roots
}

func TestProbeReadsTheServerDateHeader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		skew   time.Duration
		status int
		want   float64
	}{
		{"local ahead", -90 * time.Second, http.StatusForbidden, 90},
		{"local behind", 90 * time.Second, http.StatusNoContent, -90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, roots := probeServer(t, tc.skew, tc.status)
			offset, e := Probe(context.Background(), base, roots)
			if e != nil {
				t.Fatal(e)
			}
			if math.Abs(offset-tc.want) > 2 {
				t.Fatalf("offset=%v want=%v", offset, tc.want)
			}
		})
	}
}

func TestProbeRejectsPlainHTTPAndMissingDate(t *testing.T) {
	if _, e := Probe(context.Background(), "http://ingest.example"); !errors.Is(e, ErrProbe) {
		t.Fatalf("plain HTTP accepted: %v", e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil
		w.WriteHeader(http.StatusOK)
	}))
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	if _, e := Probe(context.Background(), server.URL, roots); !errors.Is(e, ErrProbe) {
		t.Fatalf("response without Date accepted: %v", e)
	}
}
