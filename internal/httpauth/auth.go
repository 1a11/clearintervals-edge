// Package httpauth shares bounded writer authentication across local sink modules.
package httpauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"github.com/1a11/clearintervals-edge/internal/auth"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/diag"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Gate struct {
	mu       sync.Mutex
	window   time.Time
	failures map[string]int
	total    int
	workers  chan struct{}
}

func New() *Gate { return &Gate{workers: make(chan struct{}, 2), failures: map[string]int{}} }
func (m *Gate) Authenticate(r *http.Request, principals []config.Principal) (string, int) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !m.allowed(host, false) {
		authenticated(r, principals, "", 429)
		return "", 429
	}
	p := principal(r, principals)
	if username, password, ok := r.BasicAuth(); ok {
		select {
		case m.workers <- struct{}{}:
		default:
			authenticated(r, principals, p, 429)
			return "", 429
		}
		for _, candidate := range principals {
			if candidate.ID == username && candidate.PasswordHash != "" && auth.Verify(candidate.PasswordHash, password) {
				p = candidate.ID
				break
			}
		}
		<-m.workers
	}
	if p == "" {
		m.allowed(host, true)
		authenticated(r, principals, "", 401)
		return "", 401
	}
	authenticated(r, principals, p, 0)
	return p, 0
}

// authenticated writes the verbose authentication decision: the presented credential, the digests the gateway
// computed, each configured principal's expected digest, and the outcome. Normal logs never carry these values.
func authenticated(r *http.Request, principals []config.Principal, matched string, status int) {
	if !diag.Enabled() {
		return
	}
	authorization := r.Header.Get("Authorization")
	_, _, basicOK := r.BasicAuth()
	method := "none"
	switch {
	case strings.HasPrefix(authorization, "Bearer "):
		method = "bearer"
	case basicOK && strings.HasPrefix(strings.ToLower(authorization), "basic "):
		method = "basic"
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if method == "none" {
			method = "certificate"
		} else {
			method += "+certificate"
		}
	}
	var tokenHash, certHash [32]byte
	hasToken := strings.HasPrefix(authorization, "Bearer ")
	if hasToken {
		tokenHash = sha256.Sum256([]byte(strings.TrimPrefix(authorization, "Bearer ")))
	}
	hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	if hasCert {
		certHash = sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	}
	comparisons := make([]map[string]any, 0, len(principals))
	for _, p := range principals {
		entry := map[string]any{"id": p.ID, "tokenSha256": p.TokenSHA256, "certificateSha256": p.CertificateSHA256, "passwordHashSet": p.PasswordHash != ""}
		if hasToken && p.TokenSHA256 != "" {
			expected, _ := hex.DecodeString(p.TokenSHA256)
			entry["tokenMatch"] = subtle.ConstantTimeCompare(tokenHash[:], expected) == 1
		}
		if hasCert && p.CertificateSHA256 != "" {
			expected, _ := hex.DecodeString(p.CertificateSHA256)
			entry["certificateMatch"] = subtle.ConstantTimeCompare(certHash[:], expected) == 1
		}
		comparisons = append(comparisons, entry)
	}
	attrs := []any{
		"remoteAddr", r.RemoteAddr, "method", method, "authorization", authorization,
		"status", status, "matchedPrincipal", matched, "principals", comparisons,
	}
	if hasToken {
		attrs = append(attrs, "bearerSha256", hex.EncodeToString(tokenHash[:]))
	}
	if hasCert {
		attrs = append(attrs, "certificateSha256", hex.EncodeToString(certHash[:]))
	}
	diag.Event("verbose_writer_auth", attrs...)
}
func (m *Gate) allowed(host string, failed bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Since(m.window) >= time.Minute {
		m.window = time.Now()
		m.failures = map[string]int{}
		m.total = 0
	}
	if m.total >= 100 || m.failures[host] >= 10 {
		return false
	}
	if failed {
		if len(m.failures) >= 1000 {
			return false
		}
		m.failures[host]++
		m.total++
	}
	return true
}
func principal(r *http.Request, principals []config.Principal) string {
	var tokenHash, certHash [32]byte
	auth := r.Header.Get("Authorization")
	hasToken := strings.HasPrefix(auth, "Bearer ") && len(auth) >= 50 && len(auth) <= 256
	if hasToken {
		tokenHash = sha256.Sum256([]byte(strings.TrimPrefix(auth, "Bearer ")))
	}
	hasCert := r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0
	if hasCert {
		leaf := r.TLS.PeerCertificates[0]
		hasCert = !leaf.IsCA && len(leaf.ExtKeyUsage) == 1 && leaf.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth && len(leaf.UnknownExtKeyUsage) == 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature != 0
		certHash = sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	}
	found := ""
	for _, p := range principals {
		if hasToken && p.TokenSHA256 != "" {
			expected, _ := hex.DecodeString(p.TokenSHA256)
			if subtle.ConstantTimeCompare(tokenHash[:], expected) == 1 {
				found = p.ID
			}
		}
		if hasCert && p.CertificateSHA256 != "" {
			expected, _ := hex.DecodeString(p.CertificateSHA256)
			if subtle.ConstantTimeCompare(certHash[:], expected) == 1 {
				found = p.ID
			}
		}
	}
	return found
}
func TLS(l config.Listener) (*tls.Config, error) {
	if l.Certificate == "" {
		if !config.Loopback(l.Listen) {
			return nil, &config.Problem{Field: "listen", Reason: "a non-loopback listener requires certificate and key (TLS)"}
		}
		return nil, nil
	}
	cert, e := tls.LoadX509KeyPair(l.Certificate, l.Key)
	if e != nil {
		// The loader reports paths and PEM structure, never key material.
		return nil, &config.Problem{Field: "certificate", Reason: "cannot load the certificate/key pair: " + e.Error()}
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true}
	if l.WriterCA != "" {
		raw, e := os.ReadFile(l.WriterCA)
		if e != nil {
			return nil, &config.Problem{Field: "writerCa", Reason: e.Error()}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, &config.Problem{Field: "writerCa", Reason: "contains no PEM certificates"}
		}
		c.ClientCAs = pool
		c.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return c, nil
}
