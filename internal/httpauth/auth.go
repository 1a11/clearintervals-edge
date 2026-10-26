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
		return "", 429
	}
	p := principal(r, principals)
	if username, password, ok := r.BasicAuth(); ok {
		select {
		case m.workers <- struct{}{}:
		default:
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
		return "", 401
	}
	return p, 0
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
