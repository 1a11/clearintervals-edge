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
}
type Config struct {
	DeploymentLicensePath string `yaml:"deploymentLicensePath"`
	StateDir              string `yaml:"stateDir"`
	StatusListen          string `yaml:"statusListen"`
	Buffer                struct {
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
	if c.Uplink.Proxy == "" {
		c.Uplink.Proxy = os.Getenv("HTTPS_PROXY")
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
}

func New(c *Config) *Store {
	s := &Store{history: map[string]Binding{}}
	for _, b := range c.Bindings {
		s.history[b.ID] = b
	}
	s.current.Store(c)
	return s
}
func (s *Store) Get() *Config { return s.current.Load() }
func (s *Store) Reload(c *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.Get()
	a, b := *old, *c
	a.Bindings = nil
	b.Bindings = nil
	a.Modules.RemoteWrite.Principals = nil
	b.Modules.RemoteWrite.Principals = nil
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
	s.current.Store(c)
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
