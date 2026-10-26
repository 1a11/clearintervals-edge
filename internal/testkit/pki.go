// Package testkit supplies isolated ephemeral identities for transport tests.
package testkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

type PKI struct {
	CA              *x509.Certificate
	Key             *ecdsa.PrivateKey
	CertPEM, KeyPEM []byte
	Roots           *x509.CertPool
}

func New(t testing.TB) *PKI {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test offline root"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test regional issuer"}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, root, key.Public(), rootKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &PKI{ca, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}), roots}
}
func (p *PKI) Leaf(t testing.TB, uri, host string, from, to time.Time) tls.Certificate {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sn, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: sn, NotBefore: from, NotAfter: to, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if uri != "" {
		u, e := url.Parse(uri)
		if e != nil {
			t.Fatal(e)
		}
		c.URIs = []*url.URL{u}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if host != "" {
		if ip := net.ParseIP(host); ip != nil {
			c.IPAddresses = []net.IP{ip}
		} else {
			c.DNSNames = []string{host}
		}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, e := x509.CreateCertificate(rand.Reader, c, p.CA, key.Public(), p.Key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
func CSR(t testing.TB, uri string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(uri)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{u}}, key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}
