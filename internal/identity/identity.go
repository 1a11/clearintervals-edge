// Package identity journals each key and CSR before any credential operation.
package identity

import (
	"bytes"
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
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/uplink"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrIdentity = errors.New("identity_state_invalid")

// Problem explains why local identity state cannot be used. It never holds
// the enrollment token or key material.
type Problem struct{ Reason string }

func (p *Problem) Error() string  { return "identity_state_invalid: " + p.Reason }
func (p *Problem) Unwrap() error  { return ErrIdentity }
func problem(reason string) error { return &Problem{reason} }

type License struct {
	FormatVersion int      `json:"formatVersion"`
	GatewayID     string   `json:"gatewayId"`
	Region        string   `json:"region"`
	IngestURL     string   `json:"ingestUrl"`
	TrustAnchors  []string `json:"trustAnchors"`
	Token         string   `json:"enrollmentToken,omitempty"`
	ExpiresAt     string   `json:"expiresAt,omitempty"`
	Generation    uint64   `json:"credentialGeneration"`
}
type Pending struct {
	Operation, Kind, Key, CSR, Hash string
	Generation                      uint64
	Token                           string
}
type Bundle struct {
	Operation, Key, Certificate, Issuer string
	Generation                          uint64
}
type Manager struct {
	Dir, LicensePath string
	Trust            License
	Roots            *x509.CertPool
	Active           *Bundle
	Pending          *Pending
}

func limitedJSON(path string, v any) error {
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(raw) > 128<<10 {
		return ErrIdentity
	}
	return json.Unmarshal(raw, v)
}
func Open(dir, licensePath string) (*Manager, error) {
	if e := durable.Directory(dir); e != nil {
		return nil, e
	}
	m := &Manager{Dir: dir, LicensePath: licensePath}
	e := limitedJSON(filepath.Join(dir, "trust.json"), &m.Trust)
	if errors.Is(e, os.ErrNotExist) {
		if e = limitedJSON(licensePath, &m.Trust); errors.Is(e, os.ErrNotExist) {
			return nil, problem("this state directory has no identity yet and no enrollment licence exists at " + licensePath + "; download a licence for this gateway from the product")
		} else if e != nil {
			return nil, problem("the enrollment licence at " + licensePath + " cannot be read or is not the JSON file downloaded from the product")
		}
		trust := m.Trust
		trust.Token = ""
		raw, _ := json.Marshal(trust)
		if e = durable.Write(filepath.Join(dir, "trust.json"), raw); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, problem("identity/trust.json in the state directory is unreadable or corrupt")
	}
	if m.Trust.FormatVersion != 1 {
		return nil, problem("unsupported licence formatVersion; this release reads format 1")
	}
	if !wire.ValidID(m.Trust.GatewayID) || !wire.ValidID(m.Trust.Region) {
		return nil, problem("the licence gatewayId or region is missing or malformed")
	}
	if len(m.Trust.TrustAnchors) == 0 || len(m.Trust.TrustAnchors) > 8 {
		return nil, problem("the licence must carry 1-8 trustAnchors")
	}
	u, e := url.Parse(m.Trust.IngestURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, problem("the licence ingestUrl must be https://host[:port] with no path")
	}
	m.Roots = x509.NewCertPool()
	for _, v := range m.Trust.TrustAnchors {
		if !m.Roots.AppendCertsFromPEM([]byte(v)) {
			return nil, problem("a licence trust anchor is not a PEM certificate")
		}
	}
	var manifest struct{ Operation string }
	e = limitedJSON(filepath.Join(dir, "active.json"), &manifest)
	if e == nil {
		if !wire.ValidID(manifest.Operation) {
			return nil, problem("identity/active.json is corrupt")
		}
		b := new(Bundle)
		if limitedJSON(filepath.Join(dir, manifest.Operation+".json"), b) != nil || b.Operation != manifest.Operation {
			return nil, problem("the credential named by identity/active.json is missing or corrupt")
		}
		if _, e = m.validate(b, time.Time{}); e != nil {
			return nil, e
		}
		m.Active = b
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, problem("identity/active.json is unreadable or corrupt")
	}
	p := new(Pending)
	e = limitedJSON(filepath.Join(dir, "pending.json"), p)
	if e == nil {
		if e = validatePending(p, m.URI()); e != nil {
			return nil, problem("identity/pending.json does not match this gateway or is corrupt")
		}
		m.Pending = p
		if m.Active != nil && m.Active.Operation == p.Operation {
			if e = m.finish(); e != nil {
				return nil, e
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, problem("identity/pending.json is unreadable or corrupt")
	}
	return m, nil
}
func (m *Manager) URI() string {
	return "spiffe://clearintervals/" + m.Trust.Region + "/gateway/" + m.Trust.GatewayID
}
func key(raw string) (*ecdsa.PrivateKey, error) {
	p, rest := pem.Decode([]byte(raw))
	if p == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrIdentity
	}
	var v *ecdsa.PrivateKey
	var e error
	if p.Type == "PRIVATE KEY" {
		var k any
		k, e = x509.ParsePKCS8PrivateKey(p.Bytes)
		if e == nil {
			var ok bool
			v, ok = k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, ErrIdentity
			}
		}
	} else {
		v, e = x509.ParseECPrivateKey(p.Bytes)
	}
	if e != nil || v.Curve != elliptic.P256() {
		return nil, ErrIdentity
	}
	return v, nil
}
func validatePending(p *Pending, uri string) error {
	if !wire.ValidID(p.Operation) || p.Kind != "enroll" && p.Kind != "renew" && p.Kind != "recover" || p.Generation == 0 {
		return ErrIdentity
	}
	k, e := key(p.Key)
	if e != nil {
		return e
	}
	block, _ := pem.Decode([]byte(p.CSR))
	if block == nil {
		return ErrIdentity
	}
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	hash := sha256.Sum256(block.Bytes)
	if e != nil || csr.CheckSignature() != nil || len(csr.URIs) != 1 || csr.URIs[0].String() != uri || hex.EncodeToString(hash[:]) != p.Hash {
		return ErrIdentity
	}
	if !k.PublicKey.Equal(csr.PublicKey) {
		return ErrIdentity
	}
	return nil
}
func (m *Manager) Prepare(now time.Time) error {
	if m.Pending != nil {
		return nil
	}
	kind := "enroll"
	generation := m.Trust.Generation
	token := m.Trust.Token
	if m.Active != nil {
		generation = m.Active.Generation
		kind = "renew"
		cert, e := m.Certificate()
		if e != nil {
			return e
		}
		if now.Before(cert.Leaf.NotBefore.Add(cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) / 2)) {
			return nil
		}
		if !now.Before(cert.Leaf.NotAfter) {
			kind = "recover"
		}
	}
	if kind == "enroll" {
		var l License
		if e := limitedJSON(m.LicensePath, &l); e != nil {
			return problem("enrollment needs the licence at " + m.LicensePath + ", which is missing or unreadable")
		}
		if l.GatewayID != m.Trust.GatewayID || l.Region != m.Trust.Region || l.IngestURL != m.Trust.IngestURL {
			return problem("the licence belongs to a different gateway than identity/trust.json; use a fresh state directory or that gateway's licence")
		}
		if l.Generation == 0 || l.Generation > 1<<50 || len(l.Token) < 40 || len(l.Token) > 100 {
			return problem("the licence has no usable enrollment token; download a new one from the product")
		}
		expiry, e := time.Parse(time.RFC3339Nano, l.ExpiresAt)
		if e != nil {
			return problem("the licence expiresAt is not an RFC 3339 time")
		}
		if !now.Before(expiry) {
			return problem("the enrollment licence expired at " + expiry.UTC().Format(time.RFC3339) + "; download a new one from the product")
		}
		generation = l.Generation
		token = l.Token
	}
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	raw, e := x509.MarshalECPrivateKey(k)
	if e != nil {
		return e
	}
	u, _ := url.Parse(m.URI())
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{u}}, k)
	if e != nil {
		return e
	}
	hash := sha256.Sum256(der)
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return e
	}
	p := &Pending{Operation: hex.EncodeToString(id[:]), Kind: kind, Key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})), CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), Hash: hex.EncodeToString(hash[:]), Generation: generation, Token: token}
	data, _ := json.Marshal(p)
	if e = durable.Write(filepath.Join(m.Dir, "pending.json"), data); e != nil {
		return e
	}
	m.Pending = p
	return nil
}
func (m *Manager) TLS(now time.Time) *tls.Config {
	c := &tls.Config{RootCAs: m.Roots, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if m.Active != nil {
		cert, e := m.Certificate()
		if e == nil && now.Before(cert.Leaf.NotAfter) && !now.Before(cert.Leaf.NotBefore) {
			c.Certificates = []tls.Certificate{*cert}
		}
	}
	return c
}
func (m *Manager) Certificate() (*tls.Certificate, error) {
	if m.Active == nil {
		return nil, ErrIdentity
	}
	return m.validate(m.Active, time.Time{})
}
func (m *Manager) validate(b *Bundle, now time.Time) (*tls.Certificate, error) {
	cert, e := tls.X509KeyPair([]byte(b.Certificate+b.Issuer), []byte(b.Key))
	if e != nil || len(cert.Certificate) < 2 {
		return nil, ErrIdentity
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, ErrIdentity
	}
	cert.Leaf = leaf
	k, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() || leaf.IsCA || !leaf.BasicConstraintsValid || len(leaf.URIs) != 1 || leaf.URIs[0].String() != m.URI() || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 || leaf.KeyUsage != x509.KeyUsageDigitalSignature || leaf.NotAfter.Sub(leaf.NotBefore) > 24*time.Hour || b.Generation == 0 {
		return nil, ErrIdentity
	}
	intermediates := x509.NewCertPool()
	for _, v := range cert.Certificate[1:] {
		c, e := x509.ParseCertificate(v)
		if e != nil {
			return nil, ErrIdentity
		}
		intermediates.AddCert(c)
	}
	if now.IsZero() {
		now = leaf.NotBefore.Add(time.Second)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: m.Roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return nil, ErrIdentity
	}
	return &cert, nil
}
func (m *Manager) proof(ctx context.Context, c *uplink.Connection, purpose string) (string, []byte, error) {
	p := m.Pending
	hash, _ := hex.DecodeString(p.Hash)
	q := &pb.Lifecycle{GatewayId: m.Trust.GatewayID, OperationId: p.Operation, Generation: p.Generation, CsrHash: hash, Purpose: purpose}
	f, e := c.Unary(ctx, "challenge", q)
	if e != nil {
		return "", nil, e
	}
	v := f.GetChallenge()
	if v == nil {
		return "", nil, ErrIdentity
	}
	var fingerprint any
	signer, e := key(p.Key)
	if e != nil {
		return "", nil, e
	}
	if purpose == "recover" {
		if m.Active == nil {
			return "", nil, ErrIdentity
		}
		signer, e = key(m.Active.Key)
		if e != nil {
			return "", nil, e
		}
		cert, e := m.Certificate()
		if e != nil {
			return "", nil, e
		}
		h := sha256.Sum256(cert.Leaf.Raw)
		fingerprint = hex.EncodeToString(h[:])
	}
	expected, _ := json.Marshal([]any{"clearintervals-core-proof-v1", v.Challenge, m.Trust.GatewayID, m.Trust.Region, purpose, p.Operation, p.Generation, p.Hash, fingerprint})
	expiry, e := time.Parse(time.RFC3339Nano, v.ExpiresAt)
	if e != nil || !time.Now().Before(expiry) || expiry.After(time.Now().Add(65*time.Second)) || len(v.Challenge) < 1 || len(v.Challenge) > 100 || !bytes.Equal(expected, v.SigningPayload) {
		return "", nil, ErrIdentity
	}
	digest := sha256.Sum256(v.SigningPayload)
	sig, e := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	return v.Challenge, sig, e
}
func (m *Manager) Retrieve(ctx context.Context, c *uplink.Connection) error {
	p := m.Pending
	if p == nil {
		return nil
	}
	// Retrieval first covers a crash after cloud commit and before local activation.
	challenge, sig, e := m.proof(ctx, c, "result")
	if e != nil {
		return e
	}
	f, e := c.Unary(ctx, "operations/result", &pb.Lifecycle{GatewayId: m.Trust.GatewayID, OperationId: p.Operation, Generation: p.Generation, Challenge: challenge, SignatureDer: sig})
	if e == nil {
		return m.Install(f.GetCredential())
	}
	return e
}
func (m *Manager) Issue(ctx context.Context, c *uplink.Connection) error {
	p := m.Pending
	if p == nil {
		return nil
	}
	var challenge string
	var sig []byte
	var e error
	request := &pb.Lifecycle{GatewayId: m.Trust.GatewayID, OperationId: p.Operation, Generation: p.Generation, CsrPem: p.CSR, Token: p.Token}
	if p.Kind == "recover" {
		challenge, sig, e = m.proof(ctx, c, "recover")
		if e != nil {
			return e
		}
		request.Challenge = challenge
		request.SignatureDer = sig
		request.OldCertificatePem = m.Active.Certificate
	}
	f, e := c.Unary(ctx, p.Kind, request)
	if e != nil {
		return e
	}
	return m.Install(f.GetCredential())
}
func (m *Manager) Install(c *pb.Credential) error {
	p := m.Pending
	if p == nil || c == nil || c.OperationId != p.Operation || c.Generation != p.Generation+1 {
		return ErrIdentity
	}
	b := &Bundle{Operation: p.Operation, Key: p.Key, Certificate: c.CertificatePem, Issuer: c.IssuerPem, Generation: c.Generation}
	cert, e := m.validate(b, time.Now())
	if e != nil {
		return e
	}
	expiry, e := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if e != nil || !expiry.Equal(cert.Leaf.NotAfter) {
		return ErrIdentity
	}
	raw, _ := json.Marshal(b)
	if e = durable.Write(filepath.Join(m.Dir, p.Operation+".json"), raw); e != nil {
		return e
	}
	manifest, _ := json.Marshal(struct{ Operation string }{p.Operation})
	if e = durable.Write(filepath.Join(m.Dir, "active.json"), manifest); e != nil {
		return e
	}
	m.Active = b
	return m.finish()
}
func (m *Manager) finish() error {
	if e := durable.Remove(filepath.Join(m.Dir, "pending.json")); e != nil {
		return e
	}
	m.Pending = nil
	m.Trust.Token = ""
	// The manifest is durable, so obsolete private keys need no indefinite retention.
	files, e := os.ReadDir(m.Dir)
	if e != nil {
		return e
	}
	for _, f := range files {
		stem := strings.TrimSuffix(f.Name(), ".json")
		if len(stem) == 32 && wire.ValidID(stem) && stem != m.Active.Operation && strings.HasSuffix(f.Name(), ".json") {
			if e = durable.Remove(filepath.Join(m.Dir, f.Name())); e != nil {
				return e
			}
		}
	}
	if m.LicensePath != "" {
		if e := durable.Remove(m.LicensePath); e != nil {
			return e
		}
	}
	return nil
}
