package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/testkit"
)

func rosterLicence(t *testing.T, dir string, p *testkit.PKI, roster []StreamBinding) string {
	t.Helper()
	path := filepath.Join(dir, "license.json")
	l := License{FormatVersion: 1, GatewayID: "gateway", Region: "ru", IngestURL: "https://ingest.example", TrustAnchors: []string{string(p.CertPEM)}, Token: "a_one_time_enrollment_token_with_256_bits_123456789", Generation: 7, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), StreamBindings: roster}
	raw, e := json.Marshal(l)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path
}

func digest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func TestLicenceRosterAuthorizesConfiguredBindings(t *testing.T) {
	p := testkit.New(t)
	dir := t.TempDir()
	key := strings.Repeat("k", 43)
	path := rosterLicence(t, dir, p, []StreamBinding{{ID: "b1", Kind: "series", DeviceID: "d1", KeyDigest: digest(key)}})
	m, e := Open(filepath.Join(dir, "identity"), path)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(m.Dir, "trust.json"))
	if e != nil {
		t.Fatal(e)
	}
	var trust License
	if json.Unmarshal(raw, &trust) != nil || len(trust.StreamBindings) != 1 || trust.StreamBindings[0].ID != "b1" {
		t.Fatal("licence roster not copied into trust.json")
	}
	if e = m.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = m.CheckBindings([]Binding{{ID: "b1", Kind: "series", SourceID: "s1", StreamKey: key}}); e != nil {
		t.Fatal(e)
	}
	_, e = m.CheckBindings([]Binding{{ID: "b2", Kind: "series", SourceID: "s2", StreamKey: key}})
	if e == nil || !strings.Contains(e.Error(), "b2") || !strings.Contains(e.Error(), "gateway") {
		t.Fatalf("binding outside the roster accepted: %v", e)
	}
	mismatches, e := m.CheckBindings([]Binding{{ID: "b1", Kind: "series", SourceID: "s1", StreamKey: strings.Repeat("x", 43)}})
	if e != nil || len(mismatches) != 1 || mismatches[0].BindingID != "b1" {
		t.Fatalf("digest mismatch not reported as non-fatal: %v %v", mismatches, e)
	}
}

func TestRotatedLicenceRefreshesRoster(t *testing.T) {
	p := testkit.New(t)
	dir := t.TempDir()
	key := strings.Repeat("k", 43)
	path := rosterLicence(t, dir, p, []StreamBinding{{ID: "b1", Kind: "series", DeviceID: "d1", KeyDigest: digest(key)}})
	m, e := Open(filepath.Join(dir, "identity"), path)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = m.Install(credential(t, m, p, false, false)); e != nil {
		t.Fatal(e)
	}
	// A rotation with the same roster keeps the same stream keys working.
	rosterLicence(t, dir, p, []StreamBinding{{ID: "b1", Kind: "series", DeviceID: "d1", KeyDigest: digest(key)}})
	if e = m.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e = m.CheckBindings([]Binding{{ID: "b1", Kind: "series", SourceID: "s1", StreamKey: key}}); e != nil {
		t.Fatal(e)
	}
	// A rotation that drops a configured binding is fatal.
	rosterLicence(t, dir, p, []StreamBinding{{ID: "other", Kind: "series", DeviceID: "d2", KeyDigest: digest(key)}})
	if e = m.Prepare(time.Now()); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(m.Dir, "trust.json"))
	if e != nil {
		t.Fatal(e)
	}
	var trust License
	if json.Unmarshal(raw, &trust) != nil || len(trust.StreamBindings) != 1 || trust.StreamBindings[0].ID != "other" {
		t.Fatal("rotated roster not persisted")
	}
	if _, e = m.CheckBindings([]Binding{{ID: "b1", Kind: "series", SourceID: "s1", StreamKey: key}}); e == nil {
		t.Fatal("binding missing from the rotated roster accepted")
	}
}
