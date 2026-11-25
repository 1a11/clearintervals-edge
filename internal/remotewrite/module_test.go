package remotewrite

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	// A non-finite sample is data, not framing: it is discarded sample by sample in ServeHTTP, not here.
	for _, raw := range [][]byte{{255, 255, 255}, snappy.Encode(nil, bytes.Repeat([]byte{0}, DefaultMaxDecodedBytes+1)), snappy.Encode(nil, field(1, field(1, field(1, bytes.Repeat([]byte("x"), 129)))))} {
		if w := submit(m, raw, testToken, "snappy"); w.Code != 400 {
			t.Fatal("invalid request accepted", w.Code)
		}
	}
	over := make([][]byte, 0, DefaultMaxSamples+1)
	for i := 0; i <= DefaultMaxSamples; i++ {
		over = append(over, timeSeries(map[string]string{"__name__": "metric"}, 1, 0))
	}
	if _, e := parse(bytes.Join(over, nil), DefaultMaxSamples); e == nil {
		t.Fatal("series cap not enforced")
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
	// A negative scale turning 0 into -0.0 is normalised, not refused: one bad sample must not drop a block.
	m, q = module(t)
	m.Config.Get().Bindings[0].Scale = -1
	raw = snappy.Encode(nil, request(0, time.Now().UnixMilli()))
	if w := submit(m, raw, testToken, "snappy"); w.Code != 204 {
		t.Fatalf("negative zero reply: %d", w.Code)
	}
	v, e := q.Next(time.Now())
	if e != nil || len(v) != 1 || v[0].Item.GetPoint().Value != 0 || math.Signbit(v[0].Item.GetPoint().Value) {
		t.Fatalf("negative zero normalisation: %v %v", v, e)
	}
}

// A Kubernetes batch from vmagent is one block with thousands of series, almost all of them unmapped here. A
// stale NaN marker, an Inf sample or the sheer count must not turn the block into a 400 that vmagent drops.
func TestLargeBatchWithUnmappedAndNonFiniteSamplesIsAccepted(t *testing.T) {
	m, q := module(t)
	at := time.Now().UnixMilli()
	batch := make([][]byte, 0, 2500)
	for i := 0; i < 2499; i++ {
		value := 1.0
		if i == 0 {
			value = math.NaN() // Prometheus StaleNaN after a target disappears
		}
		batch = append(batch, timeSeries(map[string]string{
			"__name__": "kube_pod_info", "namespace": "default", "pod": fmt.Sprintf("pod-%d", i),
		}, value, at))
	}
	batch = append(batch, timeSeries(map[string]string{"__name__": "rpm"}, 1480, at))
	if w := submit(m, snappy.Encode(nil, bytes.Join(batch, nil)), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("large batch refused: %d %s", w.Code, w.Body.String())
	}
	v, e := q.Next(time.Now())
	if e != nil || len(v) != 1 || v[0].Item.GetPoint().Value != 1480 {
		t.Fatalf("matched sample not queued: %v %v", v, e)
	}
	stats, _, _ := q.Snapshot()
	if stats.Drops["unmapped"] != 2499 {
		t.Fatalf("unmapped accounting: %v", stats.Drops)
	}
}

// More than one queue transaction's worth of matched samples is committed in chunks instead of being refused.
func TestMatchedBatchOverTheQueueChunkIsAccepted(t *testing.T) {
	m, q := module(t)
	at := time.Now().UnixMilli()
	batch := make([][]byte, 0, 1501)
	for i := 0; i < 1501; i++ {
		batch = append(batch, timeSeries(map[string]string{"__name__": "rpm", "instance": fmt.Sprintf("i-%d", i)}, float64(i), at))
	}
	if w := submit(m, snappy.Encode(nil, bytes.Join(batch, nil)), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("chunked batch refused: %d", w.Code)
	}
	// 1,501 matched items exceed one queue transaction (wire.MaxItems = 1,000), so they are committed as two
	// segments. Queue entries are not drained here: without an ack the same segment stays readable.
	if _, size, segments := q.Snapshot(); segments != 2 || size == 0 {
		t.Fatalf("segments %d, size %d, want 2 non-empty segments", segments, size)
	}
}

// A block whose repeated label names and values compress far better than 20:1 is still a normal block.
func TestHighlyCompressedBlockIsDecoded(t *testing.T) {
	raw := bytes.Repeat([]byte{0}, 4<<20)
	compressed := snappy.Encode(nil, raw)
	if len(compressed)*20 >= len(raw) {
		t.Skip("snappy did not reach a ratio above 20 for this payload")
	}
	decoded, e := decode(compressed, "snappy", DefaultMaxDecodedBytes)
	if e != nil || len(decoded) != len(raw) {
		t.Fatalf("highly compressed block refused: %v", e)
	}
}

// vmagent adds fields this sink does not read (WriteRequest.metadata, TimeSeries.exemplars and histograms). They
// must be skipped, not turned into a 400 that loses the whole block.
func TestUnknownProtobufFieldsAreSkipped(t *testing.T) {
	m, q := module(t)
	at := time.Now().UnixMilli()
	label := append(field(1, []byte("__name__")), field(2, []byte("rpm"))...)
	var f [8]byte
	binary.LittleEndian.PutUint64(f[:], math.Float64bits(1480))
	sample := append(protowire.AppendTag(nil, 1, protowire.Fixed64Type), f[:]...)
	sample = protowire.AppendVarint(protowire.AppendTag(sample, 2, protowire.VarintType), uint64(at))
	series := append(field(1, label), field(2, sample)...)
	series = append(series, field(3, []byte("exemplar"))...)  // TimeSeries.exemplars
	series = append(series, field(4, []byte("histogram"))...) // TimeSeries.histograms
	raw := append(field(1, series), field(3, []byte("metadata"))...)
	if w := submit(m, snappy.Encode(nil, raw), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("unknown fields refused: %d %s", w.Code, w.Body.String())
	}
	if v, e := q.Next(time.Now()); e != nil || len(v) != 1 || v[0].Item.GetPoint().Value != 1480 {
		t.Fatalf("point not queued: %v %v", v, e)
	}
}

// timeSeries builds one TimeSeries with any label set, for batches that look like vmagent's.
func timeSeries(labels map[string]string, value float64, timestamp int64) []byte {
	body := []byte{}
	for name, val := range labels {
		label := append(field(1, []byte(name)), field(2, []byte(val))...)
		body = append(body, field(1, label)...)
	}
	var f [8]byte
	binary.LittleEndian.PutUint64(f[:], math.Float64bits(value))
	sample := append(protowire.AppendTag(nil, 1, protowire.Fixed64Type), f[:]...)
	sample = protowire.AppendVarint(protowire.AppendTag(sample, 2, protowire.VarintType), uint64(timestamp))
	return field(1, append(body, field(2, sample)...))
}
func FuzzRemoteWrite(f *testing.F) {
	f.Add(request(1480, time.Now().UnixMilli()))
	f.Add([]byte{255, 255})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > DefaultMaxBodyBytes {
			return
		}
		_, _ = parse(raw, DefaultMaxSamples)
		_, _ = decode(raw, "snappy", DefaultMaxDecodedBytes)
		_, _ = decode(raw, "zstd", DefaultMaxDecodedBytes)
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

// Before the cloud has named the streams, an unmapped sample must be held, not
// dropped: vmagent retries the 503 from its WAL once the descriptors arrive.
func TestUnmappedSamplesWaitForTheDescriptorSync(t *testing.T) {
	c := new(config.Config)
	c.Buffer.MaxAgeDays = 7
	digest := sha256.Sum256([]byte(testToken))
	c.Modules.RemoteWrite.Principals = []config.Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(digest[:])}}
	q, e := buffer.Open(t.TempDir(), 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	m := New(config.New(c), q)
	raw := snappy.Encode(nil, request(1, time.Now().UnixMilli()))
	w := submit(m, raw, testToken, "snappy")
	if w.Code != 503 || w.Header().Get("Retry-After") != "15" {
		t.Fatalf("first batch not held: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	if s, _, _ := q.Snapshot(); s.Drops["unmapped"] != 0 {
		t.Fatal("held batch counted as dropped", s)
	}
	m.Config.SyncDescriptors(nil)
	if w := submit(m, raw, testToken, "snappy"); w.Code != 204 {
		t.Fatalf("sync completed but write still held: %d", w.Code)
	}
	if s, _, _ := q.Snapshot(); s.Drops["unmapped"] != 1 {
		t.Fatal("unmapped sample not accounted after the sync", s)
	}
}
