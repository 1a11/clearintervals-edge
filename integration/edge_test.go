//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/identity"
	"github.com/1a11/clearintervals-edge/internal/uplink"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	URL             string
	RootsFile       string
	Controller      string
	ControllerToken string
	Licences        map[string]json.RawMessage
	Bindings        map[string]struct {
		ID        string `json:"id"`
		StreamKey string `json:"streamKey"`
		SourceID  string `json:"deviceId"`
	}
}

func load(t *testing.T) *fixture {
	t.Helper()
	path := os.Getenv("CI_GATEWAY_FIXTURE")
	if path == "" {
		t.Skip("run integration/fixture.py against disposable core/cloud services")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	f := new(fixture)
	if json.Unmarshal(raw, f) != nil {
		t.Fatal("invalid fixture")
	}
	return f
}
func admin(t *testing.T, f *fixture, path string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	r, _ := http.NewRequest(http.MethodPost, f.Controller+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+f.ControllerToken)
	res, e := (&http.Client{Timeout: 30 * time.Second}).Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(path, res.Status)
	}
	v := map[string]any{}
	if json.NewDecoder(res.Body).Decode(&v) != nil {
		t.Fatal("invalid controller result")
	}
	return v
}
func manager(t *testing.T, f *fixture, name string) *identity.Manager {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "license.json")
	if e := os.WriteFile(path, f.Licences[name], 0600); e != nil {
		t.Fatal(e)
	}
	m, e := identity.Open(filepath.Join(dir, "identity"), path)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	return m
}
func dial(t *testing.T, m *identity.Manager, bootstrap, h3 bool) *uplink.Connection {
	t.Helper()
	cfg := m.TLS(time.Now())
	if bootstrap {
		cfg = &tls.Config{RootCAs: m.Roots, MinVersion: tls.VersionTLS13}
	}
	c, e := uplink.Dial(context.Background(), m.Trust.IngestURL, "", cfg, !h3)
	if e != nil {
		t.Fatal(e)
	}
	if h3 && c.Kind != "h3" {
		c.Close()
		t.Fatal("QUIC not exercised")
	}
	return c
}
func issue(t *testing.T, m *identity.Manager) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		c, e := uplink.Dial(context.Background(), m.Trust.IngestURL, "", m.TLS(time.Now()), true)
		if e == nil {
			e = m.Issue(context.Background(), c)
			c.Close()
		}
		if e == nil {
			return
		}
		last = e
		c, e = uplink.Dial(context.Background(), m.Trust.IngestURL, "", &tls.Config{RootCAs: m.Roots, MinVersion: tls.VersionTLS13}, true)
		if e == nil {
			e = m.Retrieve(context.Background(), c)
			c.Close()
			if e == nil {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal(last)
}
func point(f *fixture, binding, id string, at time.Time) *pb.Item {
	b := f.Bindings[binding]
	i := &pb.Item{Id: id, SourceId: b.SourceID, StreamKey: b.StreamKey, BindingId: b.ID, Body: &pb.Item_Point{Point: &pb.Point{Timestamp: at.UTC().Format(time.RFC3339Nano), Value: 1480}}}
	i.Hash, _ = wire.Hash(i)
	return i
}
func drain(t *testing.T, m *identity.Manager, q *buffer.Queue, h3 bool, capacityRelease func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c := dial(t, m, false, h3)
	defer c.Close()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, q, m.Trust.GatewayID, m.Active.Generation, nil, time.Now().Add(time.Hour)) }()
	if capacityRelease != nil {
		time.AfterFunc(6*time.Second, capacityRelease)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case e := <-done:
			t.Fatal("uplink ended before drain", e)
		case <-ctx.Done():
			t.Fatal("buffer did not drain")
		case <-ticker.C:
			_, _, n := q.Snapshot()
			if n == 0 {
				cancel()
				c.Close()
				<-done
				return
			}
		}
	}
}
func TestRealCoreLostIssuanceReplyRedundancyZeroCreditAndQUIC(t *testing.T) {
	f := load(t)
	baseline := admin(t, f, "/stats", nil)["gateway_series"].(float64)
	m := manager(t, f, "primary")
	p := m.Pending
	c := dial(t, m, true, false)
	reply, e := c.Unary(context.Background(), "enroll", &pb.Lifecycle{GatewayId: m.Trust.GatewayID, OperationId: p.Operation, Generation: p.Generation, CsrPem: p.CSR, Token: p.Token})
	c.Close()
	if e != nil {
		t.Fatal(e)
	}
	committed := reply.GetCredential()
	if committed == nil {
		t.Fatal("no committed certificate")
	}
	// Model process death after commit but before saving the response.
	m, e = identity.Open(m.Dir, m.LicensePath)
	if e != nil {
		t.Fatal(e)
	}
	c = dial(t, m, true, false)
	e = m.Retrieve(context.Background(), c)
	c.Close()
	if e != nil || m.Active.Certificate != committed.CertificatePem {
		t.Fatal("exact result recovery failed", e)
	}
	// Renew with a fresh key; replay is completed using the persisted new key.
	oldKey := m.Active.Key
	if e = m.Prepare(time.Now().Add(13 * time.Hour)); e != nil || m.Pending == nil {
		t.Fatal(e)
	}
	issue(t, m)
	if oldKey == m.Active.Key {
		t.Fatal("renewal reused key")
	}
	time.Sleep(6 * time.Second) // Cloud's bounded change-feed poll must observe the committed generation.
	q, e := buffer.Open(filepath.Join(t.TempDir(), "buffer"), 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now().Truncate(time.Microsecond)
	i := point(f, "pointPrimary", "canonical-point", at)
	if e = q.Enqueue([]*pb.Item{i}, time.Now()); e != nil {
		t.Fatal(e)
	}
	admin(t, f, "/queue", map[string]any{"full": true})
	drain(t, m, q, false, func() { admin(t, f, "/queue", map[string]any{"full": false}) })
	stats := admin(t, f, "/stats", nil)
	if stats["gateway_series"] != baseline+1 {
		t.Fatal("real core point missing", stats)
	}
	redundant := manager(t, f, "redundant")
	issue(t, redundant)
	time.Sleep(6 * time.Second)
	q, e = buffer.Open(t.TempDir(), 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Enqueue([]*pb.Item{point(f, "pointRedundant", "canonical-point", at)}, time.Now()); e != nil {
		t.Fatal(e)
	}
	drain(t, redundant, q, true, nil)
	stats = admin(t, f, "/stats", nil)
	if stats["gateway_series"] != baseline+1 {
		t.Fatal("redundant gateway duplicated point", stats)
	}
	// Revocation remains a retry outcome: data stays locally available.
	q, e = buffer.Open(t.TempDir(), 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Enqueue([]*pb.Item{point(f, "pointPrimary", "after-revoke", time.Now())}, time.Now()); e != nil {
		t.Fatal(e)
	}
	admin(t, f, "/revoke", map[string]any{"name": "primary"})
	if conn, e := uplink.Dial(context.Background(), m.Trust.IngestURL, "", m.TLS(time.Now()), true); e == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		e = conn.Run(ctx, q, m.Trust.GatewayID, m.Active.Generation, nil, time.Now().Add(time.Hour))
		cancel()
		conn.Close()
		if e == nil {
			t.Fatal("revoked identity admitted")
		}
	}
	_, _, n := q.Snapshot()
	if n != 1 {
		t.Fatal("revoked backlog lost")
	}
}
func TestRealCoreExpiredIdentityRecovery(t *testing.T) {
	f := load(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "license.json")
	if e := os.WriteFile(path, f.Licences["legacy"], 0600); e != nil {
		t.Fatal(e)
	}
	var legacy struct {
		CertificateFile, KeyFile string
		Generation               uint64
	}
	if json.Unmarshal(f.Licences["legacy"], &legacy) != nil {
		t.Fatal("invalid legacy fixture")
	}
	m, e := identity.Open(filepath.Join(dir, "identity"), path)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := os.ReadFile(legacy.CertificateFile)
	if e != nil {
		t.Fatal(e)
	}
	key, e := os.ReadFile(legacy.KeyFile)
	if e != nil {
		t.Fatal(e)
	}
	parts := strings.SplitAfter(string(cert), "-----END CERTIFICATE-----\n")
	b := identity.Bundle{Operation: "legacy", Certificate: parts[0], Issuer: strings.Join(parts[1:], ""), Key: string(key), Generation: legacy.Generation}
	raw, _ := json.Marshal(b)
	if e = durable.Write(filepath.Join(m.Dir, "legacy.json"), raw); e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(map[string]string{"Operation": "legacy"})
	if e = durable.Write(filepath.Join(m.Dir, "active.json"), raw); e != nil {
		t.Fatal(e)
	}
	m, e = identity.Open(m.Dir, path)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(time.Now()); e != nil || m.Pending.Kind != "recover" {
		t.Fatal(e)
	}
	issue(t, m)
	if m.Active.Generation != legacy.Generation+1 {
		t.Fatal("recovery generation wrong")
	}
}
