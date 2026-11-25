// Package config validates complete snapshots before an atomic reload.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/1a11/clearintervals-edge/internal/auth"
	"github.com/1a11/clearintervals-edge/internal/wire"
	"gopkg.in/yaml.v3"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrConfig = errors.New("invalid_configuration")

// Problem names the configuration field that failed and why. It never holds
// the field's value, which may be a credential digest or a stream key.
type Problem struct{ Field, Reason string }

func (p *Problem) Error() string         { return "invalid_configuration: " + p.Field + ": " + p.Reason }
func (p *Problem) Unwrap() error         { return ErrConfig }
func problem(field, reason string) error { return &Problem{field, reason} }

// Prefix places a listener-relative problem under its module path.
func Prefix(prefix string, e error) error {
	var p *Problem
	if errors.As(e, &p) {
		return &Problem{prefix + "." + p.Field, p.Reason}
	}
	return e
}

type Binding struct {
	ID         string            `yaml:"id"`
	StreamKey  string            `yaml:"streamKey"`
	SourceID   string            `yaml:"sourceId"`
	Kind       string            `yaml:"kind"`
	Selector   map[string]string `yaml:"selector"`
	Scale      float64           `yaml:"scale"`
	Principals []string          `yaml:"principals"`
}
type Principal struct {
	ID                string `yaml:"id"`
	TokenSHA256       string `yaml:"tokenSha256"`
	CertificateSHA256 string `yaml:"certificateSha256"`
	PasswordHash      string `yaml:"passwordHash"`
}
type Listener struct {
	Enabled     bool        `yaml:"enabled"`
	Listen      string      `yaml:"listen"`
	Certificate string      `yaml:"certificate"`
	Key         string      `yaml:"key"`
	WriterCA    string      `yaml:"writerCa"`
	Principals  []Principal `yaml:"principals"`
	// Remote-write request bounds. Zero selects the default. Captures ignores them.
	MaxSamples      int   `yaml:"maxSamples"`
	MaxBodyBytes    int64 `yaml:"maxBodyBytes"`
	MaxDecodedBytes int64 `yaml:"maxDecodedBytes"`
}
type Config struct {
	DeploymentLicensePath string `yaml:"deploymentLicensePath"`
	StateDir              string `yaml:"stateDir"`
	StatusListen          string `yaml:"statusListen"`
	// Verbose writes detailed, unredacted diagnostic events (labels, tokens, stream keys, sample values).
	Verbose bool `yaml:"verbose"`
	Buffer  struct {
		MaxBytes    int64 `yaml:"maxBytes"`
		MaxAgeDays  int   `yaml:"maxAgeDays"`
		MaxSegments int   `yaml:"maxSegments"`
	} `yaml:"buffer"`
	Modules struct {
		RemoteWrite Listener `yaml:"remoteWrite"`
		Captures    Listener `yaml:"captures"`
	} `yaml:"modules"`
	Uplink struct {
		ForceTCP bool   `yaml:"forceTcp"`
		Proxy    string `yaml:"proxy"`
	} `yaml:"uplink"`
	Bindings []Binding `yaml:"bindings"`
}

// remoteWriteLimits applies the defaults and bounds of the remote-write request limits. A cluster with tens of
// thousands of series needs a larger request than the defaults, and vmagent drops a block it cannot send, so the
// bound is configurable rather than fixed.
func remoteWriteLimits(c *Config) error {
	l := &c.Modules.RemoteWrite
	samples := int64(l.MaxSamples)
	if samples < 0 {
		return problem("modules.remoteWrite.maxSamples", "must not be negative")
	}
	if samples == 0 {
		samples = 250000
	}
	if samples > 10000000 {
		return problem("modules.remoteWrite.maxSamples", "must be at most 10000000")
	}
	l.MaxSamples = int(samples)
	switch {
	case l.MaxBodyBytes < 0:
		return problem("modules.remoteWrite.maxBodyBytes", "must not be negative")
	case l.MaxBodyBytes == 0:
		l.MaxBodyBytes = 16 << 20
	case l.MaxBodyBytes > 256<<20:
		return problem("modules.remoteWrite.maxBodyBytes", "must be at most 268435456 (256 MiB)")
	}
	switch {
	case l.MaxDecodedBytes < 0:
		return problem("modules.remoteWrite.maxDecodedBytes", "must not be negative")
	case l.MaxDecodedBytes == 0:
		l.MaxDecodedBytes = 64 << 20
	case l.MaxDecodedBytes > 512<<20:
		return problem("modules.remoteWrite.maxDecodedBytes", "must be at most 536870912 (512 MiB)")
	}
	return nil
}

func Loopback(addr string) bool {
	host, _, e := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return e == nil && ip != nil && ip.IsLoopback()
}
func Load(path string) (*Config, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, problem("config file", e.Error())
	}
	if len(raw) > 1<<20 {
		return nil, problem("config file", "is larger than 1 MiB")
	}
	c := new(Config)
	c.StatusListen = "127.0.0.1:9081"
	c.Modules.RemoteWrite.Listen = "127.0.0.1:8429"
	c.Modules.Captures.Listen = "127.0.0.1:8430"
	c.Buffer.MaxBytes = 10 << 30
	c.Buffer.MaxAgeDays = 7
	c.Buffer.MaxSegments = 100000
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if e = d.Decode(c); e != nil {
		return nil, yamlProblem(e)
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return nil, problem("config file", "must contain exactly one YAML document")
	}
	if v := os.Getenv("EDGE_STATE_DIR"); v != "" {
		c.StateDir = v
	}
	if v := os.Getenv("EDGE_LICENSE_PATH"); v != "" {
		c.DeploymentLicensePath = v
	}
	if v := strings.TrimSpace(os.Getenv("EDGE_VERBOSE")); v != "" {
		c.Verbose = v == "1" || strings.EqualFold(v, "true")
	}
	for _, override := range []struct {
		env   string
		field string
		set   func(int64)
	}{
		{"EDGE_REMOTEWRITE_MAX_SAMPLES", "modules.remoteWrite.maxSamples", func(n int64) { c.Modules.RemoteWrite.MaxSamples = int(n) }},
		{"EDGE_REMOTEWRITE_MAX_BODY_BYTES", "modules.remoteWrite.maxBodyBytes", func(n int64) { c.Modules.RemoteWrite.MaxBodyBytes = n }},
		{"EDGE_REMOTEWRITE_MAX_DECODED_BYTES", "modules.remoteWrite.maxDecodedBytes", func(n int64) { c.Modules.RemoteWrite.MaxDecodedBytes = n }},
	} {
		value := strings.TrimSpace(os.Getenv(override.env))
		if value == "" {
			continue
		}
		n, e := strconv.ParseInt(value, 10, 64)
		if e != nil {
			return nil, problem(override.field, override.env+" must be a whole number")
		}
		override.set(n)
	}
	if c.Uplink.Proxy == "" {
		c.Uplink.Proxy = os.Getenv("HTTPS_PROXY")
	}
	if e := remoteWriteLimits(c); e != nil {
		return nil, e
	}
	switch {
	case c.StateDir == "":
		return nil, problem("stateDir", "is required (or set EDGE_STATE_DIR)")
	case c.Buffer.MaxBytes < 1<<20:
		return nil, problem("buffer.maxBytes", "must be at least 1048576 (1 MiB)")
	case c.Buffer.MaxAgeDays < 1 || c.Buffer.MaxAgeDays > 7:
		return nil, problem("buffer.maxAgeDays", "must be between 1 and 7")
	case c.Buffer.MaxSegments < 1 || c.Buffer.MaxSegments > 100000:
		return nil, problem("buffer.maxSegments", "must be between 1 and 100000")
	case !Loopback(c.StatusListen):
		return nil, problem("statusListen", "must be a literal loopback address such as 127.0.0.1:9081")
	case len(c.Bindings) > 100:
		return nil, problem("bindings", "at most 100 bindings are supported")
	}
	if c.Uplink.Proxy != "" {
		// Never echo the proxy URL: it may carry user:password.
		u, e := url.Parse(c.Uplink.Proxy)
		if e != nil || u.Scheme != "http" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, problem("uplink.proxy", "must be http://[user:password@]host[:port] with no path (also checked for HTTPS_PROXY)")
		}
	}
	byKind := map[string]map[string]bool{}
	for _, m := range []struct {
		kind, field string
		l           Listener
	}{{"series", "modules.remoteWrite", c.Modules.RemoteWrite}, {"captures", "modules.captures", c.Modules.Captures}} {
		principals, e := validateListener(m.l)
		if e != nil {
			return nil, Prefix(m.field, e)
		}
		byKind[m.kind] = principals
	}
	if c.Modules.Captures.Enabled && c.Modules.RemoteWrite.Enabled && c.Modules.Captures.Listen == c.Modules.RemoteWrite.Listen {
		return nil, problem("modules.captures.listen", "must differ from modules.remoteWrite.listen")
	}
	ids := map[string]bool{}
	keys := map[string]bool{}
	for i, b := range c.Bindings {
		// Bindings are named by position: stream keys must not reach logs.
		field := fmt.Sprintf("bindings[%d]", i)
		switch {
		case !wire.ValidID(b.ID):
			return nil, problem(field+".id", "must be the binding ID copied from the product")
		case ids[b.ID]:
			return nil, problem(field+".id", "is used by an earlier binding")
		case !wire.ValidID(b.SourceID):
			return nil, problem(field+".sourceId", "must be the canonical source ID copied from the product")
		case len(b.StreamKey) < 40 || len(b.StreamKey) > 100:
			return nil, problem(field+".streamKey", "must be the 40-100 character stream key copied from the product")
		case keys[b.StreamKey]:
			return nil, problem(field+".streamKey", "is used by an earlier binding")
		case b.Kind != "series" && b.Kind != "captures":
			return nil, problem(field+".kind", "must be series or captures")
		case len(b.Principals) == 0:
			return nil, problem(field+".principals", "must list at least one writer principal")
		case b.Kind == "series" && (len(b.Selector) == 0 || len(b.Selector) > 64):
			return nil, problem(field+".selector", "a series binding needs 1-64 exact labels")
		case b.Kind == "series" && (b.Scale == 0 || math.IsNaN(b.Scale) || math.IsInf(b.Scale, 0)):
			return nil, problem(field+".scale", "a series binding needs a finite, non-zero scale")
		case b.Kind == "captures" && len(b.Selector) != 0:
			return nil, problem(field+".selector", "is not allowed on a captures binding")
		case b.Kind == "captures" && b.Scale != 0:
			return nil, problem(field+".scale", "is not allowed on a captures binding: samples are never rescaled")
		}
		ids[b.ID] = true
		keys[b.StreamKey] = true
		for k, v := range b.Selector {
			if len(k) == 0 || len(k) > 128 || len(v) > 1024 {
				return nil, problem(field+".selector", "label names must be 1-128 bytes and values at most 1024 bytes")
			}
		}
		for _, p := range b.Principals {
			if !byKind[b.Kind][p] {
				module := "modules.remoteWrite"
				if b.Kind == "captures" {
					module = "modules.captures"
				}
				return nil, problem(field+".principals", "names a principal that is not defined in "+module+".principals")
			}
		}
	}
	return c, nil
}
func validateListener(l Listener) (map[string]bool, error) {
	if _, _, e := net.SplitHostPort(l.Listen); e != nil && (l.Enabled || l.Listen != "") {
		return nil, problem("listen", "must be host:port")
	}
	if l.Enabled && !Loopback(l.Listen) && (l.Certificate == "" || l.Key == "") {
		return nil, problem("listen", "a non-loopback listener requires certificate and key (TLS)")
	}
	if l.Enabled && len(l.Principals) == 0 {
		return nil, problem("principals", "an enabled module needs at least one writer principal")
	}
	if (l.Key == "") != (l.Certificate == "") {
		return nil, problem("certificate", "certificate and key must be set together")
	}
	if len(l.Principals) > 100 {
		return nil, problem("principals", "at most 100 principals are supported")
	}
	principals := map[string]bool{}
	credentials := map[string]bool{}
	for i, p := range l.Principals {
		field := fmt.Sprintf("principals[%d]", i)
		methods := 0
		for _, v := range []string{p.TokenSHA256, p.CertificateSHA256, p.PasswordHash} {
			if v != "" {
				methods++
			}
		}
		switch {
		case !wire.ValidID(p.ID):
			return nil, problem(field+".id", "must be a short identifier (letters, digits, '-', '_')")
		case principals[p.ID]:
			return nil, problem(field+".id", "is used by an earlier principal")
		case methods != 1:
			return nil, problem(field, "set exactly one of tokenSha256, certificateSha256 or passwordHash")
		}
		principals[p.ID] = true
		if p.PasswordHash != "" {
			if _, _, e := auth.Parse(p.PasswordHash); e != nil {
				return nil, problem(field+".passwordHash", "is not an accepted Argon2id hash; generate it with edgegateway -hash-password")
			}
			continue
		}
		v, name := p.TokenSHA256, ".tokenSha256"
		if v == "" {
			v, name = p.CertificateSHA256, ".certificateSha256"
			if l.WriterCA == "" {
				return nil, problem(field+name, "requires writerCa to validate client certificates")
			}
		}
		digest, e := hex.DecodeString(v)
		if e != nil || len(digest) != 32 {
			return nil, problem(field+name, "must be 64 hexadecimal characters (a SHA-256 digest)")
		}
		canonical := hex.EncodeToString(digest)
		if credentials[canonical] {
			return nil, problem(field+name, "repeats another principal's credential")
		}
		credentials[canonical] = true
	}
	return principals, nil
}

var yamlLine = regexp.MustCompile(`line (\d+)`)
var yamlUnknown = regexp.MustCompile(`field ([A-Za-z0-9_.-]{1,64}) not found`)

// yamlProblem keeps the line number and the kind of mistake. YAML error text
// can quote the offending value, which may be a secret, so it is not passed on.
func yamlProblem(e error) error {
	text := e.Error()
	field := "config file"
	if m := yamlLine.FindStringSubmatch(text); m != nil {
		field = "line " + m[1]
	}
	switch {
	case yamlUnknown.MatchString(text):
		return problem(field, "unknown key "+yamlUnknown.FindStringSubmatch(text)[1]+" (keys are case-sensitive)")
	case strings.Contains(text, "cannot unmarshal"):
		return problem(field, "value has the wrong type for this key")
	}
	return problem(field, "is not valid YAML")
}
func (c *Config) MaxAge() time.Duration { return time.Duration(c.Buffer.MaxAgeDays) * 24 * time.Hour }

type Store struct {
	current atomic.Pointer[Config]
	mu      sync.RWMutex
	history map[string]Binding
	// static holds the configuration-file bindings; the local file stays
	// authoritative over cloud descriptors.
	static []Binding
	// dynamic is the most recent cloud descriptor set. It survives reloads, so
	// rotating a principal in config.yaml does not erase the stream setup.
	dynamic []Binding
	synced  atomic.Bool
}

func New(c *Config) *Store {
	s := &Store{history: map[string]Binding{}, static: c.Bindings}
	for _, b := range c.Bindings {
		s.history[b.ID] = b
	}
	if len(c.Bindings) > 0 {
		s.synced.Store(true)
	}
	s.current.Store(c)
	return s
}
func (s *Store) Get() *Config { return s.current.Load() }

// DescriptorsSynced reports whether stream bindings are known: either from the
// configuration file at startup or from a completed cloud descriptor sync.
// Remote write answers 503 while it is false, so a first batch is not dropped
// as unmapped before the cloud has named the streams.
func (s *Store) DescriptorsSynced() bool { return s.synced.Load() }

// SyncDescriptors installs the stream descriptors fetched from the cloud. It is
// safe to call while writers read the store. Configuration-file bindings win on
// an ID or stream-key collision; a series descriptor that names no principals
// gets every configured remote-write principal, and a series descriptor without
// a scale gets 1, so the operator never repeats that per stream.
func (s *Store) SyncDescriptors(descriptors []Binding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A sync that yields no descriptors still completes the wait: the cloud
	// has answered and there is no series to accept, so remote write must stop
	// holding the batch.
	s.synced.Store(true)
	current := s.Get()
	principals := make([]string, 0, len(current.Modules.RemoteWrite.Principals))
	for _, p := range current.Modules.RemoteWrite.Principals {
		principals = append(principals, p.ID)
	}
	clean := make([]Binding, 0, len(descriptors))
	ids := map[string]bool{}
	keys := map[string]bool{}
	for _, b := range descriptors {
		b = normalizeDescriptor(b, principals)
		if !descriptorValid(b) || ids[b.ID] || keys[b.StreamKey] {
			continue
		}
		ids[b.ID] = true
		keys[b.StreamKey] = true
		clean = append(clean, b)
	}
	s.dynamic = clean
	merged := mergeBindings(s.static, clean)
	if reflect.DeepEqual(current.Bindings, merged) {
		return false
	}
	next := *current
	next.Bindings = merged
	s.current.Store(&next)
	return true
}

// normalizeDescriptor fills the fields the cloud leaves to the gateway.
func normalizeDescriptor(b Binding, principals []string) Binding {
	if b.Kind == "series" && len(b.Principals) == 0 {
		b.Principals = append([]string(nil), principals...)
	}
	if b.Kind == "series" && b.Scale == 0 {
		b.Scale = 1
	}
	return b
}

// descriptorValid keeps a malformed or unexpected descriptor out of the active
// configuration; the same rules the configuration file is held to apply.
func descriptorValid(b Binding) bool {
	if !wire.ValidID(b.ID) || !wire.ValidID(b.SourceID) || len(b.StreamKey) < 40 || len(b.StreamKey) > 100 {
		return false
	}
	switch b.Kind {
	case "series":
		return len(b.Selector) > 0 && len(b.Selector) <= 64 && !math.IsNaN(b.Scale) && !math.IsInf(b.Scale, 0)
	case "captures":
		return len(b.Selector) == 0 && b.Scale == 0
	}
	return false
}

// mergeBindings layers cloud descriptors below the configuration-file bindings.
// It returns source unchanged when no descriptor adds a binding.
func mergeBindings(source, dynamic []Binding) []Binding {
	if len(dynamic) == 0 {
		return source
	}
	merged := make([]Binding, 0, len(source)+len(dynamic))
	ids := map[string]bool{}
	keys := map[string]bool{}
	for _, b := range source {
		merged = append(merged, b)
		ids[b.ID] = true
		keys[b.StreamKey] = true
	}
	for _, b := range dynamic {
		if ids[b.ID] || keys[b.StreamKey] {
			continue
		}
		merged = append(merged, b)
		ids[b.ID] = true
		keys[b.StreamKey] = true
	}
	if len(merged) == len(source) {
		return source
	}
	return merged
}

func (s *Store) Reload(c *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.Get()
	a, b := *old, *c
	a.Bindings = nil
	b.Bindings = nil
	a.Modules.RemoteWrite.Principals = nil
	b.Modules.RemoteWrite.Principals = nil
	// Request limits are reloadable; everything else stays restart-only.
	a.Modules.RemoteWrite.MaxSamples, b.Modules.RemoteWrite.MaxSamples = 0, 0
	a.Modules.RemoteWrite.MaxBodyBytes, b.Modules.RemoteWrite.MaxBodyBytes = 0, 0
	a.Modules.RemoteWrite.MaxDecodedBytes, b.Modules.RemoteWrite.MaxDecodedBytes = 0, 0
	a.Modules.Captures.Principals = nil
	b.Modules.Captures.Principals = nil
	if !reflect.DeepEqual(a, b) {
		return problem("config file", "only principals and bindings can change on reload; restart for other settings")
	}
	for _, x := range s.history {
		for i, y := range c.Bindings {
			if x.ID == y.ID && !reflect.DeepEqual(x, y) {
				return problem(fmt.Sprintf("bindings[%d]", i), "changes an existing binding version; create a new version in the product instead")
			}
		}
	}
	s.static = c.Bindings
	if len(c.Bindings) > 0 {
		s.synced.Store(true)
	}
	merged := mergeBindings(c.Bindings, s.dynamic)
	next := c
	if len(merged) != len(c.Bindings) {
		copied := *c
		copied.Bindings = merged
		next = &copied
	}
	s.current.Store(next)
	for _, b := range c.Bindings {
		s.history[b.ID] = b
	}
	return nil
}

// Admit holds reload out until the authenticated snapshot has durably committed.
func (s *Store) Admit(c *Config, fn func() error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Get() != c {
		return ErrConfig
	}
	return fn()
}
