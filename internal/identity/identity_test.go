package identity

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/testkit"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func manager(t *testing.T) (*Manager, *testkit.PKI) {
	t.Helper()
	p := testkit.New(t)
	dir := t.TempDir()
	license := filepath.Join(dir, "license.json")
	l := License{FormatVersion: 1, GatewayID: "gateway", Region: "ru", IngestURL: "https://ingest.example", TrustAnchors: []string{string(p.CertPEM)}, Token: "a_one_time_enrollment_token_with_256_bits_123456789", Generation: 7, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(l)
	if e := os.WriteFile(license, raw, 0600); e != nil {
		t.Fatal(e)
	}
	m, e := Open(filepath.Join(dir, "identity"), license)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	return m, p
}
func credential(t *testing.T, m *Manager, p *testkit.PKI, wrongKey, wrongIdentity bool) *pb.Credential {
	t.Helper()
	block, _ := pem.Decode([]byte(m.Pending.CSR))
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(m.URI())
	if wrongIdentity {
		u, _ = url.Parse("spiffe://clearintervals/ru/gateway/foreign")
	}
	pub := csr.PublicKey
	if wrongKey {
		pub = p.Key.Public()
	}
	from := time.Now().Add(-time.Minute).Truncate(time.Second)
	to := from.Add(24 * time.Hour)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: from, NotAfter: to, URIs: []*url.URL{u}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, p.CA, pub, p.Key)
	if e != nil {
		t.Fatal(e)
	}
	return &pb.Credential{OperationId: m.Pending.Operation, Generation: m.Pending.Generation + 1, CertificatePem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), IssuerPem: string(p.CertPEM), ExpiresAt: to.UTC().Format(time.RFC3339Nano)}
}
func TestPendingOperationSurvivesRestartWithoutNewCSR(t *testing.T) {
	m, _ := manager(t)
	before := *m.Pending
	again, e := Open(m.Dir, m.LicensePath)
	if e != nil {
		t.Fatal(e)
	}
	if e = again.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	if *again.Pending != before {
		t.Fatal("pending key or CSR replaced")
	}
	stat, e := os.Stat(filepath.Join(m.Dir, "pending.json"))
	if e != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("pending key permissions")
	}
	stat, _ = os.Stat(m.Dir)
	if stat.Mode().Perm() != 0700 {
		t.Fatal("identity directory permissions")
	}
}
func TestCredentialValidationBeforeManifestActivation(t *testing.T) {
	for _, bad := range []string{"key", "identity", "generation", "operation", "expiry"} {
		t.Run(bad, func(t *testing.T) {
			m, p := manager(t)
			c := credential(t, m, p, bad == "key", bad == "identity")
			switch bad {
			case "generation":
				c.Generation++
			case "operation":
				c.OperationId = "foreign"
			case "expiry":
				c.ExpiresAt = time.Now().Format(time.RFC3339Nano)
			}
			if m.Install(c) == nil {
				t.Fatal("substituted credential installed")
			}
			if _, e := os.Stat(filepath.Join(m.Dir, "active.json")); !os.IsNotExist(e) {
				t.Fatal("manifest changed on invalid response")
			}
			if m.Pending == nil {
				t.Fatal("pending key lost")
			}
		})
	}
}
func TestManifestCrashRecoveryAndLicenseDeletion(t *testing.T) {
	m, p := manager(t)
	pending := *m.Pending
	c := credential(t, m, p, false, false)
	if e := m.Install(c); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(m.LicensePath); !os.IsNotExist(e) {
		t.Fatal("licence retained")
	}
	raw, _ := json.Marshal(pending)
	if e := durable.Write(filepath.Join(m.Dir, "pending.json"), raw); e != nil {
		t.Fatal(e)
	}
	again, e := Open(m.Dir, m.LicensePath)
	if e != nil {
		t.Fatal(e)
	}
	if again.Pending != nil || again.Active.Generation != 8 {
		t.Fatal("manifest completion did not recover")
	}
	cert, e := again.Certificate()
	if e != nil || len(cert.Certificate) != 2 {
		t.Fatal(e)
	}
}
func TestTamperedPendingCSRRejected(t *testing.T) {
	m, _ := manager(t)
	m.Pending.Hash = "wrong"
	raw, _ := json.Marshal(m.Pending)
	if e := durable.Write(filepath.Join(m.Dir, "pending.json"), raw); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(m.Dir, m.LicensePath); e == nil {
		t.Fatal("changed pending CSR accepted")
	}
}
