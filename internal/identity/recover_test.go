package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/testkit"
	"github.com/1a11/clearintervals-edge/internal/uplink"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
)

// cloud records lifecycle calls. /challenge is answered with a well-formed
// frame so proof() reaches its local checks; every other call is refused with
// result_unavailable, as the core does for an operation it never registered.
type cloud struct {
	mu          sync.Mutex
	requests    []*pb.Lifecycle
	path        []string
	fingerprint string
}

func (c *cloud) server(t *testing.T, p *testkit.PKI) *httptest.Server {
	t.Helper()
	now := time.Now()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, _, e := wire.Read(r.Body, wire.MaxControl, nil)
		if e != nil {
			t.Error(e)
			return
		}
		q := f.GetLifecycle()
		c.mu.Lock()
		c.requests = append(c.requests, q)
		c.path = append(c.path, r.URL.Path)
		c.mu.Unlock()
		var body *pb.Frame
		if r.URL.Path == "/uplink/v1/challenge" {
			// The client validates the exact transcript, so answer it verbatim.
			challenge := "challenge-1"
			var fingerprint any
			if q.Purpose == "recover" {
				fingerprint = c.fingerprint
			}
			payload, _ := json.Marshal([]any{"clearintervals-core-proof-v1", challenge, "gateway", "ru", q.Purpose, q.OperationId, q.Generation, hex.EncodeToString(q.CsrHash), fingerprint})
			body = &pb.Frame{Body: &pb.Frame_Challenge{Challenge: &pb.Challenge{
				Challenge:      challenge,
				ExpiresAt:      now.Add(30 * time.Second).UTC().Format(time.RFC3339Nano),
				SigningPayload: payload,
			}}}
		} else {
			body = &pb.Frame{Body: &pb.Frame_Failure{Failure: &pb.Failure{Code: "result_unavailable"}}}
		}
		_ = wire.Write(w, body)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{p.Leaf(t, "", "127.0.0.1", now.Add(-time.Minute), now.Add(time.Hour))}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func (c *cloud) seen() ([]*pb.Lifecycle, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*pb.Lifecycle(nil), c.requests...), append([]string(nil), c.path...)
}

func (c *cloud) dial(t *testing.T, p *testkit.PKI, server *httptest.Server) *uplink.Connection {
	t.Helper()
	conn, e := uplink.Dial(context.Background(), server.URL, "", &tls.Config{RootCAs: p.Roots}, true)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(conn.Close)
	return conn
}

// stranded writes the state a crash leaves behind: a recover-pending journal
// whose active bundle no longer exists.
func stranded(t *testing.T, m *Manager) *Pending {
	t.Helper()
	p := *m.Pending
	p.Kind, p.Generation = "recover", 7
	raw, _ := json.Marshal(&p)
	if e := durable.Write(filepath.Join(m.Dir, "pending.json"), raw); e != nil {
		t.Fatal(e)
	}
	m.Pending, m.Active = &p, nil
	return &p
}

// recovered writes a recover-pending journal while the active bundle is usable.
// Only the journal says recover; the credential it proves is intact.
func recovered(t *testing.T, m *Manager) *Pending {
	t.Helper()
	if m.Pending == nil {
		// Nothing was journaled: reuse the installed credential's operation so
		// Install still accepts the answer, with a fresh key and CSR.
		u, _ := url.Parse(m.URI())
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{u}}, k)
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.Sum256(der)
		m.Pending = &Pending{Operation: m.Active.Operation, Kind: "recover", Key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})), CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), Hash: hex.EncodeToString(hash[:]), Generation: m.Active.Generation}
	}
	p := *m.Pending
	p.Kind, p.Generation = "recover", m.Active.Generation
	raw, _ := json.Marshal(&p)
	if e := durable.Write(filepath.Join(m.Dir, "pending.json"), raw); e != nil {
		t.Fatal(e)
	}
	m.Pending = &p
	return &p
}

const token = "a_one_time_enrollment_token_with_256_bits_123456789"

func licence(t *testing.T, m *Manager, p *testkit.PKI, token string, expires time.Time) {
	t.Helper()
	raw, _ := json.Marshal(License{FormatVersion: 1, GatewayID: "gateway", Region: "ru", IngestURL: "https://ingest.example", TrustAnchors: []string{string(p.CertPEM)}, Token: token, Generation: 9, ExpiresAt: expires.UTC().Format(time.RFC3339Nano)})
	if e := os.WriteFile(m.LicensePath, raw, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestRecoverWithoutActiveEnrollsWithLicence(t *testing.T) {
	m, p := manager(t)
	pending := stranded(t, m)
	licence(t, m, p, token, time.Now().Add(time.Hour))
	c := &cloud{}
	conn := c.dial(t, p, c.server(t, p))
	var refused *uplink.Failure
	if e := m.Issue(context.Background(), conn); !errors.As(e, &refused) || refused.Code != "result_unavailable" {
		t.Fatalf("enrollment not attempted: %v", e)
	}
	requests, paths := c.seen()
	if len(requests) != 2 || paths[0] != "/uplink/v1/challenge" || paths[1] != "/uplink/v1/enroll" {
		t.Fatalf("unexpected calls: %v %v", paths, requests)
	}
	got := requests[1]
	if got.OperationId != pending.Operation || got.Generation != 9 || got.CsrPem != pending.CSR || got.Token != token || got.Challenge != "" || got.SignatureDer != nil || got.OldCertificatePem != "" {
		t.Fatalf("enrollment request does not match the licence and journal: %+v", got)
	}
	if m.Pending == nil || m.Pending.Kind != "enroll" || m.Pending.Generation != 9 || m.Pending.Token != token {
		t.Fatal("pending journal not rewritten as an enrollment")
	}
	again, e := Open(m.Dir, m.LicensePath)
	if e != nil || again.Pending == nil || again.Pending.Kind != "enroll" || again.Pending.Token != token || again.Pending.Operation != pending.Operation {
		t.Fatalf("rewritten journal not durable: %v", e)
	}
}
func TestRecoverWithoutActiveStopsWithoutUsableLicence(t *testing.T) {
	for name, write := range map[string]func(*testing.T, *Manager, *testkit.PKI){
		"missing": func(t *testing.T, m *Manager, p *testkit.PKI) { _ = os.Remove(m.LicensePath) },
		"expired": func(t *testing.T, m *Manager, p *testkit.PKI) {
			licence(t, m, p, token, time.Now().Add(-time.Minute))
		},
		"foreign": func(t *testing.T, m *Manager, p *testkit.PKI) {
			raw, _ := json.Marshal(License{FormatVersion: 1, GatewayID: "other", Region: "ru", IngestURL: "https://ingest.example", TrustAnchors: []string{string(p.CertPEM)}, Token: token, Generation: 9, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
			if e := os.WriteFile(m.LicensePath, raw, 0600); e != nil {
				t.Fatal(e)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, p := manager(t)
			pending := stranded(t, m)
			write(t, m, p)
			c := &cloud{}
			conn := c.dial(t, p, c.server(t, p))
			var impossible *Problem
			if e := m.Issue(context.Background(), conn); !errors.As(e, &impossible) || !errors.Is(e, ErrIdentity) {
				t.Fatalf("recovery without a usable licence did not stop: %v", e)
			}
			requests, paths := c.seen()
			if len(requests) != 1 || paths[0] != "/uplink/v1/challenge" {
				t.Fatalf("request sent past the challenge without a usable licence: %v", paths)
			}
			if m.Pending == nil || *m.Pending != *pending {
				t.Fatal("pending journal changed")
			}
		})
	}
}
func TestRecoverWithActiveCredentialUnchanged(t *testing.T) {
	m, p := manager(t)
	if e := m.Install(credential(t, m, p, false, false)); e != nil {
		t.Fatal(e)
	}
	// Prepare journals a renew for a fresh credential; recover is what the
	// gateway writes when that credential has expired.
	pending := recovered(t, m)
	licence(t, m, p, token, time.Now().Add(time.Hour))
	cert, e := m.Certificate()
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(cert.Leaf.Raw)
	c := &cloud{fingerprint: hex.EncodeToString(sum[:])}
	conn := c.dial(t, p, c.server(t, p))
	var refused *uplink.Failure
	if e := m.Issue(context.Background(), conn); !errors.As(e, &refused) || refused.Code != "result_unavailable" {
		t.Fatalf("recovery not attempted: %v", e)
	}
	requests, paths := c.seen()
	if len(requests) != 2 || paths[0] != "/uplink/v1/challenge" || paths[1] != "/uplink/v1/recover" || requests[1].OperationId != pending.Operation || requests[1].Challenge != "challenge-1" || len(requests[1].SignatureDer) == 0 || requests[1].OldCertificatePem != m.Active.Certificate {
		t.Fatalf("recovery changed: %v %+v", paths, requests)
	}
	if m.Pending.Kind != "recover" {
		t.Fatal("pending journal changed")
	}
}
