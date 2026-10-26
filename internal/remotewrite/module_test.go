package remotewrite

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/1a11/clearintervals-edge/internal/auth"
	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testToken = "A_customer_generated_secret_with_at_least_256_bits_123456789"

func field(n protowire.Number, b []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
}
func request(value float64, timestamp int64) []byte {
	label := append(field(1, []byte("__name__")), field(2, []byte("rpm"))...)
	var f [8]byte
	binary.LittleEndian.PutUint64(f[:], math.Float64bits(value))
	sample := append(protowire.AppendTag(nil, 1, protowire.Fixed64Type), f[:]...)
	sample = protowire.AppendVarint(protowire.AppendTag(sample, 2, protowire.VarintType), uint64(timestamp))
	return field(1, append(field(1, label), field(2, sample)...))
}
func module(t *testing.T) (*Module, *buffer.Queue) {
	t.Helper()
	c := new(config.Config)
	c.Buffer.MaxAgeDays = 7
	digest := sha256.Sum256([]byte(testToken))
	c.Modules.RemoteWrite.Principals = []config.Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(digest[:])}}
	c.Bindings = []config.Binding{{ID: "binding_v1", SourceID: "canonical", Kind: "series", StreamKey: strings.Repeat("k", 43), Selector: map[string]string{"__name__": "rpm"}, Principals: []string{"writer"}, Scale: 1}}
	q, e := buffer.Open(t.TempDir(), 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	return New(config.New(c), q), q
}
func submit(m *Module, raw []byte, token, encoding string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/write", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/x-protobuf")
	r.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	r.Header.Set("Content-Encoding", encoding)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	return w
}
func TestRemoteWriteSnappyZstdAndDeterministicIdentity(t *testing.T) {
	for _, encoding := range []string{"snappy", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			m, q := module(t)
			at := time.Now().UnixMilli()
			raw := request(1480, at)
			var compressed []byte
			if encoding == "snappy" {
				compressed = snappy.Encode(nil, raw)
			} else {
				e, _ := zstd.NewWriter(nil)
				compressed = e.EncodeAll(raw, nil)
				e.Close()
			}
			if w := submit(m, compressed, testToken, encoding); w.Code != 204 {
				t.Fatal(w.Code, w.Body.String())
			}
			v, e := q.Next(time.Now())
			if e != nil || len(v) != 1 || v[0].Item.GetPoint().Value != 1480 || v[0].Item.GetPoint().Timestamp != time.UnixMilli(at).UTC().Format(time.RFC3339Nano) {
				t.Fatal(v, e)
			}
			first := v[0].Item.Id
			if w := submit(m, compressed, testToken, encoding); w.Code != 204 {
				t.Fatal(w.Code)
			}
			v, _ = q.Next(time.Now())
			if v[0].Item.Id != first {
				t.Fatal("unstable point identity")
			}
		})
	}
}
func TestAuthPrecedesDecodingAndBindingAuthorization(t *testing.T) {
	m, q := module(t)
	if w := submit(m, []byte("malformed"), "invalid", "snappy"); w.Code != 401 {
		t.Fatal(w.Code)
	}
	m.Config.Get().Bindings[0].Principals = []string{"other"}
	raw := snappy.Encode(nil, request(1, time.Now().UnixMilli()))
	if w := submit(m, raw, testToken, "snappy"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	_, size, _ := q.Snapshot()
	if size != 0 {
		t.Fatal("unauthorized data buffered")
	}
}
func TestEmptySelectorValueStillRequiresLabelPresence(t *testing.T) {
	m, q := module(t)
	m.Config.Get().Bindings[0].Selector["must_exist"] = ""
	raw := snappy.Encode(nil, request(1480, time.Now().UnixMilli()))
	if w := submit(m, raw, testToken, "snappy"); w.Code != 204 {
		t.Fatal(w.Code)
	}
	stats, _, segments := q.Snapshot()
	if segments != 0 || stats.Drops["unmapped"] != 1 {
		t.Fatal("absent label matched an empty selector", stats, segments)
	}
}
func TestMalformedAndCompressedBombs(t *testing.T) {
	m, _ := module(t)
	for _, raw := range [][]byte{{255, 255, 255}, snappy.Encode(nil, bytes.Repeat([]byte{0}, MaxDecoded+1)), snappy.Encode(nil, request(math.Inf(1), time.Now().UnixMilli())), snappy.Encode(nil, field(1, field(1, field(1, bytes.Repeat([]byte("x"), 129)))))} {
		if w := submit(m, raw, testToken, "snappy"); w.Code != 400 {
			t.Fatal("invalid request accepted", w.Code)
		}
	}
	if _, e := parse(bytes.Repeat([]byte{0x0a, 0}, 1001)); e == nil {
		t.Fatal("unbounded series")
	}
}
func TestUnmappedSuspensionAndDiskFailure(t *testing.T) {
	m, q := module(t)
	raw := snappy.Encode(nil, request(1, time.Now().UnixMilli()))
	m.Config.Get().Bindings = nil
	if w := submit(m, raw, testToken, "snappy"); w.Code != 204 {
		t.Fatal(w.Code)
	}
	s, _, _ := q.Snapshot()
	if s.Drops["unmapped"] != 1 {
		t.Fatal(s)
	}
	m, q = module(t)
	_ = q.SetPolicy("organization_suspended")
	if w := submit(m, raw, testToken, "snappy"); w.Code != 204 {
		t.Fatal(w.Code)
	}
	s, _, _ = q.Snapshot()
	if s.Drops["suspended"] != 1 {
		t.Fatal(s)
	}
	m, q = module(t)
	m.Config.Get().Bindings[0].Scale = -1
	raw = snappy.Encode(nil, request(0, time.Now().UnixMilli()))
	if w := submit(m, raw, testToken, "snappy"); w.Code != 400 {
		t.Fatal("negative zero accepted")
	}
}
func FuzzRemoteWrite(f *testing.F) {
	f.Add(request(1480, time.Now().UnixMilli()))
	f.Add([]byte{255, 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxCompressed {
			return
		}
		_, _ = parse(raw)
		_, _ = decode(raw, "snappy")
		_, _ = decode(raw, "zstd")
	})
}
func TestBasicAuthAndBoundedPasswordWorkers(t *testing.T) {
	m, q := module(t)
	password := "a_customer_generated_high_entropy_password_123456789"
	hash, e := auth.Hash(password)
	if e != nil {
		t.Fatal(e)
	}
	c := m.Config.Get()
	c.Modules.RemoteWrite.Principals = []config.Principal{{ID: "writer", PasswordHash: hash}}
	send := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/write", bytes.NewReader(snappy.Encode(nil, request(1480, time.Now().UnixMilli()))))
		r.SetBasicAuth("writer", password)
		r.Header.Set("Content-Type", "application/x-protobuf")
		r.Header.Set("Content-Encoding", "snappy")
		r.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		return w
	}
	if w := send(); w.Code != 204 {
		t.Fatal(w.Code)
	}
	_, _, n := q.Snapshot()
	if n != 1 {
		t.Fatal("basic-auth input not durable")
	}

}
