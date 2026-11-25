package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func valid(t *testing.T) *Config {
	t.Helper()
	t.Setenv("HTTPS_PROXY", "")
	c := new(Config)
	c.StateDir = "/state"
	c.StatusListen = "127.0.0.1:9081"
	c.Modules.RemoteWrite.Listen = "127.0.0.1:8429"
	c.Modules.RemoteWrite.Enabled = true
	digest := sha256.Sum256([]byte("test writer secret"))
	c.Modules.RemoteWrite.Principals = []Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(digest[:])}}
	return c
}
func load(t *testing.T, c *Config) (*Config, error) {
	t.Helper()
	raw, e := yaml.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return Load(path)
}
func TestRejectUnsafeListenersAndSecrets(t *testing.T) {
	for _, mode := range []string{"public_plaintext", "public_status", "duplicate_secret", "missing_auth"} {
		t.Run(mode, func(t *testing.T) {
			c := valid(t)
			c.Buffer.MaxAgeDays = 7
			c.Buffer.MaxBytes = 1 << 20
			c.Buffer.MaxSegments = 100
			if _, e := load(t, c); e != nil {
				t.Fatal("valid baseline rejected", e)
			}
			switch mode {
			case "public_plaintext":
				c.Modules.RemoteWrite.Listen = "0.0.0.0:8429"
			case "public_status":
				c.StatusListen = "0.0.0.0:9081"
			case "duplicate_secret":
				p := c.Modules.RemoteWrite.Principals[0]
				p.ID = "second"
				c.Modules.RemoteWrite.Principals = append(c.Modules.RemoteWrite.Principals, p)
			case "missing_auth":
				c.Modules.RemoteWrite.Principals = nil
			}
			if _, e := load(t, c); e == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
func TestAtomicReloadCannotRepointImmutableBindings(t *testing.T) {
	c := valid(t)
	c.Bindings = []Binding{{ID: "v1", SourceID: "source", Kind: "series", StreamKey: "original-key", Scale: 1}}
	store := New(c)
	next := *c
	next.Bindings = append([]Binding{}, c.Bindings...)
	next.Bindings[0].StreamKey = "replacement"
	if store.Reload(&next) == nil || store.Get() != c {
		t.Fatal("binding repointed")
	}
	next.Bindings[0].ID = "v2"
	if e := store.Reload(&next); e != nil {
		t.Fatal(e)
	}
	old := store.Get()
	changed := *old
	changed.StateDir = "/other"
	if store.Reload(&changed) == nil || store.Get() != old {
		t.Fatal("restart setting reloaded")
	}
}

func TestCaptureBindingsUseTheirOwnAuthenticatedListener(t *testing.T) {
	c := valid(t)
	c.Buffer.MaxAgeDays = 7
	c.Buffer.MaxBytes = 1 << 20
	c.Buffer.MaxSegments = 100
	c.Modules.Captures = Listener{Enabled: true, Listen: "127.0.0.1:8430", Principals: c.Modules.RemoteWrite.Principals}
	c.Bindings = []Binding{{ID: "capture_binding", SourceID: "sensor", Kind: "captures", StreamKey: strings.Repeat("k", 43), Principals: []string{"writer"}}}
	if _, err := load(t, c); err != nil {
		t.Fatal("capture configuration rejected", err)
	}
	c.Bindings[0].Scale = 1
	if _, err := load(t, c); err == nil {
		t.Fatal("capture scale must not silently transform raw samples")
	}
	c.Bindings[0].Scale = 0
	c.Modules.Captures.Principals = nil
	if _, err := load(t, c); err == nil {
		t.Fatal("capture listener accepted without authentication")
	}
	c.Modules.Captures.Principals = c.Modules.RemoteWrite.Principals
	c.Modules.Captures.Listen = "0.0.0.0:8430"
	if _, err := load(t, c); err == nil {
		t.Fatal("public capture listener accepted without TLS")
	}
}

func TestProblemsNameTheFieldButNeverTheValue(t *testing.T) {
	c := valid(t)
	c.Buffer.MaxAgeDays = 7
	c.Buffer.MaxBytes = 1 << 20
	c.Buffer.MaxSegments = 100
	secret := strings.Repeat("ab", 31) + "zz"
	c.Modules.RemoteWrite.Principals[0].TokenSHA256 = secret
	_, e := load(t, c)
	var p *Problem
	if !errors.As(e, &p) || !errors.Is(e, ErrConfig) || p.Field != "modules.remoteWrite.principals[0].tokenSha256" {
		t.Fatalf("unexpected problem: %v", e)
	}
	if strings.Contains(e.Error(), secret) {
		t.Fatal("credential digest leaked into the error")
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(path, []byte("stateDir: /state\nbuffer:\n  maxBytes: hunter2-secret-value\n"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e = Load(path)
	if !errors.As(e, &p) || p.Field != "line 3" || strings.Contains(e.Error(), "hunter2") {
		t.Fatalf("YAML error must keep the line and drop the value: %v", e)
	}
}

// A gateway enrolled from the fixed download configuration has no bindings of
// its own. The cloud descriptors become its streams, so the operator never
// repeats principals or a scale per stream.
func TestDescriptorsSyncInstallsCloudBindings(t *testing.T) {
	c := valid(t)
	store := New(c)
	if store.DescriptorsSynced() {
		t.Fatal("bindings reported before any source")
	}
	d := Binding{ID: "d1", StreamKey: strings.Repeat("k", 43), SourceID: "source", Kind: "series", Selector: map[string]string{"__name__": "rpm"}}
	if !store.SyncDescriptors([]Binding{d}) {
		t.Fatal("first sync did not change the store")
	}
	if !store.DescriptorsSynced() {
		t.Fatal("completed sync not reported")
	}
	saved := store.Get().Bindings
	if len(saved) != 1 || saved[0].ID != "d1" || saved[0].Scale != 1 || len(saved[0].Principals) != 1 || saved[0].Principals[0] != "writer" {
		t.Fatalf("descriptor not normalized: %+v", saved)
	}
	if store.SyncDescriptors([]Binding{d}) {
		t.Fatal("identical sync rewrote the active snapshot")
	}
	// Rotating a principal must not erase the cloud streams.
	next := *c
	next.Modules.RemoteWrite.Principals = []Principal{{ID: "writer", TokenSHA256: strings.Repeat("ab", 32)}}
	if e := store.Reload(&next); e != nil {
		t.Fatal(e)
	}
	if b := store.Get().Bindings; len(b) != 1 || b[0].ID != "d1" {
		t.Fatalf("reload erased cloud bindings: %+v", b)
	}
}

// A binding written in config.yaml outranks the descriptor for the same ID.
func TestDescriptorSyncKeepsFileBindingsAuthoritative(t *testing.T) {
	c := valid(t)
	c.Bindings = []Binding{{ID: "shared", SourceID: "source", Kind: "series", StreamKey: strings.Repeat("f", 43), Selector: map[string]string{"__name__": "file"}, Principals: []string{"writer"}, Scale: 2}}
	store := New(c)
	if !store.DescriptorsSynced() {
		t.Fatal("file bindings not reported")
	}
	store.SyncDescriptors([]Binding{
		{ID: "shared", SourceID: "other", Kind: "series", StreamKey: strings.Repeat("c", 43), Selector: map[string]string{"__name__": "cloud"}, Scale: 1},
		{ID: "fresh", SourceID: "source", Kind: "series", StreamKey: strings.Repeat("d", 43), Selector: map[string]string{"__name__": "cloud"}},
	})
	b := store.Get().Bindings
	if len(b) != 2 {
		t.Fatalf("unexpected bindings: %+v", b)
	}
	if b[0].ID != "shared" || b[0].Selector["__name__"] != "file" || b[0].Scale != 2 {
		t.Fatalf("cloud descriptor replaced the file binding: %+v", b[0])
	}
	if b[1].ID != "fresh" || b[1].Scale != 1 || len(b[1].Principals) != 1 {
		t.Fatalf("cloud descriptor not installed: %+v", b[1])
	}
}

// An empty answer still completes the wait: the cloud has named no streams, so
// remote write must stop holding its first batch.
func TestDescriptorsSyncWithNoDescriptorsCompletesTheWait(t *testing.T) {
	store := New(valid(t))
	if store.DescriptorsSynced() {
		t.Fatal("bindings reported before any source")
	}
	if store.SyncDescriptors(nil) {
		t.Fatal("empty sync changed the snapshot")
	}
	if !store.DescriptorsSynced() {
		t.Fatal("empty sync did not complete the wait")
	}
}

// Verbose mode is off unless the file, the environment or the CLI asks for it. The environment wins, so a
// debugging session can turn it on without editing the configuration.
func TestVerboseFromFileAndEnvironment(t *testing.T) {
	c := valid(t)
	c.Buffer.MaxAgeDays = 7
	c.Buffer.MaxBytes = 1 << 20
	c.Buffer.MaxSegments = 100
	c.Verbose = true
	loaded, e := load(t, c)
	if e != nil || !loaded.Verbose {
		t.Fatalf("verbose: true not loaded: %v %v", loaded, e)
	}
	for value, want := range map[string]bool{"1": true, "true": true, "TRUE": true, "0": false, "false": false} {
		t.Setenv("EDGE_VERBOSE", value)
		loaded, e = load(t, c)
		if e != nil || loaded.Verbose != want {
			t.Fatalf("EDGE_VERBOSE=%q gave verbose=%v (%v), want %v", value, loaded.Verbose, e, want)
		}
	}
	// The environment can also turn verbose off when the file enables it.
	t.Setenv("EDGE_VERBOSE", "0")
	c.Verbose = true
	if loaded, e = load(t, c); e != nil || loaded.Verbose {
		t.Fatalf("EDGE_VERBOSE=0 did not override verbose: true: %v %v", loaded, e)
	}
}

// The remote-write request limits follow the file, then the environment, then the defaults, and a reload may
// change them without a restart.
func TestRemoteWriteLimitsDefaultsOverridesAndReload(t *testing.T) {
	base := func() *Config {
		c := valid(t)
		c.Buffer.MaxAgeDays = 7
		c.Buffer.MaxBytes = 1 << 20
		c.Buffer.MaxSegments = 100
		return c
	}
	loaded, e := load(t, base())
	if e != nil {
		t.Fatal(e)
	}
	l := loaded.Modules.RemoteWrite
	if l.MaxSamples != 250000 || l.MaxBodyBytes != 16<<20 || l.MaxDecodedBytes != 64<<20 {
		t.Fatalf("defaults: %d %d %d", l.MaxSamples, l.MaxBodyBytes, l.MaxDecodedBytes)
	}

	t.Setenv("EDGE_REMOTEWRITE_MAX_SAMPLES", "400000")
	t.Setenv("EDGE_REMOTEWRITE_MAX_BODY_BYTES", "33554432")
	t.Setenv("EDGE_REMOTEWRITE_MAX_DECODED_BYTES", "134217728")
	if loaded, e = load(t, base()); e != nil {
		t.Fatal(e)
	}
	l = loaded.Modules.RemoteWrite
	if l.MaxSamples != 400000 || l.MaxBodyBytes != 33554432 || l.MaxDecodedBytes != 134217728 {
		t.Fatalf("environment overrides: %d %d %d", l.MaxSamples, l.MaxBodyBytes, l.MaxDecodedBytes)
	}

	t.Setenv("EDGE_REMOTEWRITE_MAX_SAMPLES", "10000001")
	if _, e = load(t, base()); e == nil {
		t.Fatal("maxSamples above the bound accepted")
	}
	t.Setenv("EDGE_REMOTEWRITE_MAX_SAMPLES", "")
	c := base()
	c.Modules.RemoteWrite.MaxSamples = -1
	if _, e = load(t, c); e == nil {
		t.Fatal("negative maxSamples accepted")
	}

	t.Setenv("EDGE_REMOTEWRITE_MAX_SAMPLES", "400000")
	store := New(loaded)
	next := *loaded
	next.Modules.RemoteWrite.MaxSamples = 500000
	next.Modules.RemoteWrite.MaxDecodedBytes = 128 << 20
	if e = store.Reload(&next); e != nil {
		t.Fatalf("reload refused a limit change: %v", e)
	}
	if store.Get().Modules.RemoteWrite.MaxSamples != 500000 {
		t.Fatal("reload did not apply the new limit")
	}
}
