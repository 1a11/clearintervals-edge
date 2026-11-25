// Package remotewrite implements the bounded Prometheus remote write 1.0 sink.
package remotewrite

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/diag"
	"github.com/1a11/clearintervals-edge/internal/httpauth"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	"io"
	"math"
	"net/http"
	"slices"
	"sort"
	"time"
	"unicode/utf8"
)

// Defaults for modules.remoteWrite limits when the configuration leaves them unset. vmagent sends up to 10,000
// rows per block, and a cluster with tens of thousands of series needs a larger request, so the limits are
// configurable (maxSamples, maxBodyBytes, maxDecodedBytes) and these are only the fallbacks.
const (
	DefaultMaxSamples      = 250000
	DefaultMaxBodyBytes    = 16 << 20
	DefaultMaxDecodedBytes = 64 << 20
)

// requestLimits returns the effective bounds of one remote-write request.
func requestLimits(c *config.Config) (maxSamples, maxCompressed, maxDecoded int) {
	l := c.Modules.RemoteWrite
	maxSamples, maxCompressed, maxDecoded = l.MaxSamples, int(l.MaxBodyBytes), int(l.MaxDecodedBytes)
	if maxSamples <= 0 {
		maxSamples = DefaultMaxSamples
	}
	if maxCompressed <= 0 {
		maxCompressed = DefaultMaxBodyBytes
	}
	if maxDecoded <= 0 {
		maxDecoded = DefaultMaxDecodedBytes
	}
	return maxSamples, maxCompressed, maxDecoded
}

type sample struct {
	at    int64
	value float64
}
type series struct {
	labels  map[string]string
	samples []sample
}
type Module struct {
	Config *config.Store
	Queue  *buffer.Queue
	slots  chan struct{}
	auth   *httpauth.Gate
}

func New(c *config.Store, q *buffer.Queue) *Module {
	return NewWithAuth(c, q, httpauth.New())
}

// NewWithAuth lets sinks share the password and failure admission budgets.
func NewWithAuth(c *config.Store, q *buffer.Queue, gate *httpauth.Gate) *Module {
	return &Module{Config: c, Queue: q, slots: make(chan struct{}, 16), auth: gate}
}
func fail(w http.ResponseWriter, status int) {
	if status == 429 || status == 503 {
		if w.Header().Get("Retry-After") == "" {
			w.Header().Set("Retry-After", "5")
		}
	}
	http.Error(w, http.StatusText(status), status)
}
func (m *Module) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := m.Config.Get()
	maxSamples, maxCompressed, maxDecoded := requestLimits(c)
	if diag.Enabled() {
		diag.Event("verbose_remotewrite_request",
			"remoteAddr", r.RemoteAddr, "method", r.Method, "uri", r.RequestURI, "proto", r.Proto,
			"path", r.URL.Path, "query", r.URL.RawQuery, "headers", headerMap(r),
			"contentType", r.Header.Get("Content-Type"), "contentEncoding", r.Header.Get("Content-Encoding"),
			"remoteWriteVersion", r.Header.Get("X-Prometheus-Remote-Write-Version"), "contentLength", r.ContentLength,
			"authorization", r.Header.Get("Authorization"),
			"bearerSha256", bearerDigest(r),
			"principals", authComparisons(c.Modules.RemoteWrite.Principals, r))
	}
	// reject records why a POST is about to be refused before the caller sees only a status code.
	reject := func(status int, stage string, extra ...any) {
		diag.Event("verbose_remotewrite_rejected", append([]any{"status", status, "stage", stage,
			"remoteAddr", r.RemoteAddr, "authorization", r.Header.Get("Authorization")}, extra...)...)
		fail(w, status)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/write" || r.URL.RawQuery != "" {
		reject(404, "method_or_path")
		return
	}
	p, status := m.auth.Authenticate(r, c.Modules.RemoteWrite.Principals)
	if diag.Enabled() {
		reason := "accepted"
		if status != 0 {
			reason = authReason(r)
		}
		diag.Event("verbose_remotewrite_auth", "remoteAddr", r.RemoteAddr, "status", status, "principal", p,
			"authorization", r.Header.Get("Authorization"), "bearerSha256", bearerDigest(r), "basicUser", basicUser(r),
			"principals", authComparisons(c.Modules.RemoteWrite.Principals, r), "reason", reason)
	}
	if status != 0 {
		reject(status, "authentication")
		return
	}

	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		reject(429, "busy")
		return
	}
	if r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" {
		reject(415, "unsupported_format")
		return
	}
	if r.ContentLength > int64(maxCompressed) {
		reject(413, "content_length", "limit", maxCompressed)
		return
	}
	ctl := http.NewResponseController(w)
	_ = ctl.SetReadDeadline(time.Now().Add(30 * time.Second))
	_ = ctl.SetWriteDeadline(time.Now().Add(30 * time.Second))
	compressed, e := io.ReadAll(io.LimitReader(&progressReader{reader: r.Body, controller: ctl, deadline: time.Now().Add(30 * time.Second)}, int64(maxCompressed)+1))
	if e != nil {
		diag.Event("verbose_remotewrite_payload", "stage", "read", "encoding", r.Header.Get("Content-Encoding"), "error", e.Error())
		reject(400, "body_read", "error", e.Error())
		return
	}
	if len(compressed) > maxCompressed {
		diag.Event("verbose_remotewrite_payload", "stage", "size", "compressedBytes", len(compressed), "limit", maxCompressed)
		reject(413, "compressed_size", "limit", maxCompressed, "received", len(compressed))
		return
	}
	raw, e := decode(compressed, r.Header.Get("Content-Encoding"), maxDecoded)
	if e != nil {
		diag.Event("verbose_remotewrite_payload", "stage", "decompress", "compressedBytes", len(compressed),
			"encoding", r.Header.Get("Content-Encoding"), "error", e.Error())
		reject(400, "decompression", "encoding", r.Header.Get("Content-Encoding"), "error", e.Error())
		return
	}
	data, e := parse(raw, maxSamples)
	if e != nil {
		diag.Event("verbose_remotewrite_payload", "stage", "parse", "compressedBytes", len(compressed),
			"decompressedBytes", len(raw), "encoding", r.Header.Get("Content-Encoding"), "error", e.Error())
		reject(400, "protobuf_parse", "decodedBytes", len(raw), "error", e.Error())
		return
	}
	totalSamples := 0
	for _, v := range data {
		totalSamples += len(v.samples)
	}
	diag.Event("verbose_remotewrite_payload", "stage", "decoded", "compressedBytes", len(compressed),
		"encoding", r.Header.Get("Content-Encoding"), "decompressedBytes", len(raw),
		"decodedSeriesCount", len(data), "totalSamples", totalSamples)
	items := []*pb.Item{}
	unmapped := uint64(0)
	old := uint64(0)
	now := time.Now()
	// A cluster block carries tens of thousands of unmapped series. Logging each one would flood stdout, so
	// only the first few and any near-miss on a configured metric are logged in full; the rest are summarized.
	const unmappedFullLimit = 20
	watchedMetrics := map[string]bool{}
	for _, b := range c.Bindings {
		if name := b.Selector["__name__"]; name != "" {
			watchedMetrics[name] = true
		}
	}
	unmappedSeriesTotal, unmappedSamplesTotal, unmappedLogged := 0, 0, 0
	unmappedMetricNames := map[string]bool{}
	for _, s := range data {
		matches := []config.Binding{}
		for _, b := range c.Bindings {
			if b.Kind != "series" {
				continue
			}
			match := true
			for k, v := range b.Selector {
				actual, present := s.labels[k]
				if !present || actual != v {
					match = false
					break
				}
			}
			if match {
				matches = append(matches, b)
			}
		}
		if len(matches) > 1 {
			diag.Event("verbose_remotewrite_series", "receivedLabels", s.labels, "labels", s.labels,
				"sampleCount", len(s.samples), "samples", sampleValues(s.samples), "outcome", "rejected",
				"status", 400, "reason", "more than one binding matches these labels", "bindingIds", bindingIDs(matches))
			reject(400, "ambiguous_selector", "receivedLabels", s.labels, "bindingIds", bindingIDs(matches))
			return
		}
		if len(matches) == 0 {
			if !m.Config.DescriptorsSynced() {
				// The cloud has not named the streams yet. Answering 503 keeps
				// the first batch in vmagent's WAL; dropping it as unmapped
				// before the initial descriptor sync would lose those samples.
				diag.Event("verbose_remotewrite_series", "receivedLabels", s.labels, "labels", s.labels,
					"sampleCount", len(s.samples), "samples", sampleValues(s.samples),
					"outcome", "held_503_awaiting_descriptors", "bindingDiffs", bindingDiffs(c.Bindings, s.labels))
				w.Header().Set("Retry-After", "15")
				reject(503, "descriptors_pending", "receivedLabels", s.labels)
				return
			}
			unmappedSeriesTotal++
			unmappedSamplesTotal += len(s.samples)
			metric := s.labels["__name__"]
			if metric != "" && len(unmappedMetricNames) < 50 {
				unmappedMetricNames[metric] = true
			}
			if unmappedLogged < unmappedFullLimit || watchedMetrics[metric] {
				unmappedLogged++
				diag.Event("verbose_remotewrite_series", "receivedLabels", s.labels, "labels", s.labels,
					"sampleCount", len(s.samples), "samples", sampleValues(s.samples), "outcome", "unmapped",
					"bindingDiffs", bindingDiffs(c.Bindings, s.labels))
			}
			unmapped += uint64(len(s.samples))
			continue
		}
		b := matches[0]
		if !slices.Contains(b.Principals, p) {
			diag.Event("verbose_remotewrite_series", "receivedLabels", s.labels, "labels", s.labels,
				"sampleCount", len(s.samples), "samples", sampleValues(s.samples), "outcome", "rejected",
				"status", 403, "reason", "the authenticated principal is not allowed on the matched binding",
				"bindingId", b.ID, "principal", p, "allowedPrincipals", b.Principals)
			reject(403, "principal_not_on_binding", "principal", p, "bindingId", b.ID,
				"allowedPrincipals", b.Principals, "receivedLabels", s.labels)
			return
		}
		accepted := make([]map[string]any, 0, len(s.samples))
		skipped := 0
		for _, v := range s.samples {
			at := time.UnixMilli(v.at).UTC()
			if now.Sub(at) > c.MaxAge() {
				old++
				continue
			}
			if at.After(now.Add(5 * time.Minute)) {
				diag.Event("verbose_remotewrite_series", "receivedLabels", s.labels, "labels", s.labels,
					"sampleCount", len(s.samples), "samples", sampleValues(s.samples), "outcome", "rejected",
					"status", 400, "reason", "sample timestamp is more than 5 minutes in the future",
					"timestamp", at.Format(time.RFC3339Nano), "bindingId", b.ID)
				reject(400, "timestamp_in_future", "timestamp", at.Format(time.RFC3339Nano),
					"bindingId", b.ID, "receivedLabels", s.labels)
				return
			}
			if math.IsNaN(v.value) || math.IsInf(v.value, 0) {
				// A stale marker or an Inf sample is discarded alone; the rest of the request still commits.
				unmapped++
				skipped++
				continue
			}
			value := v.value * b.Scale
			if value == 0 {
				value = 0 // normalise -0.0 so the wire never carries negative zero
			}
			timestamp := at.Format(time.RFC3339Nano)
			accepted = append(accepted, map[string]any{"timestamp": timestamp, "value": v.value, "scaledValue": value})
			id := sha256.Sum256([]byte(b.SourceID + "\x00" + timestamp))
			i := &pb.Item{Id: hex.EncodeToString(id[:]), StreamKey: b.StreamKey, BindingId: b.ID, SourceId: b.SourceID, Body: &pb.Item_Point{Point: &pb.Point{Timestamp: timestamp, Value: value}}}
			i.Hash, _ = wire.Hash(i)
			items = append(items, i)
		}
		diag.Event("verbose_remotewrite_series", "receivedLabels", s.labels, "labels", s.labels,
			"sampleCount", len(s.samples), "samples", accepted, "skippedSamples", skipped, "outcome", "matched",
			"bindingId", b.ID, "sourceId", b.SourceID, "streamKey", b.StreamKey, "selector", b.Selector, "scale", b.Scale)
	}
	if unmappedSeriesTotal > unmappedLogged {
		names := make([]string, 0, len(unmappedMetricNames))
		for name := range unmappedMetricNames {
			names = append(names, name)
		}
		sort.Strings(names)
		diag.Event("verbose_remotewrite_unmapped_summary", "totalUnmappedSeries", unmappedSeriesTotal,
			"totalUnmappedSamples", unmappedSamplesTotal, "loggedInFull", unmappedLogged, "sampleMetricNames", names)
	}
	e = m.Config.Admit(c, func() error {
		if unmapped > 0 {
			if e = m.Queue.Drop("unmapped", unmapped); e != nil {
				return e
			}
		}
		if old > 0 {
			if e = m.Queue.Drop("too_old", old); e != nil {
				return e
			}
		}
		// A request carries several thousand series; the queue commits at most wire.MaxItems per transaction.
		for i := 0; i < len(items); i += wire.MaxItems {
			end := min(i+wire.MaxItems, len(items))
			if e = m.Queue.Enqueue(items[i:end], now); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		reject(503, "admission", "error", e.Error(), "items", len(items))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type progressReader struct {
	reader     io.Reader
	controller *http.ResponseController
	deadline   time.Time
}

func (r *progressReader) Read(b []byte) (int, error) {
	_ = r.controller.SetReadDeadline(minTime(r.deadline, time.Now().Add(10*time.Second)))
	return r.reader.Read(b)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// decode decompresses one request. The decoded size is bounded by maxDecoded alone: a cluster block with many
// repeated label names and values compresses far better than the old 20:1 ratio guess, and refusing it by ratio
// made vmagent drop the whole block.
func decode(b []byte, encoding string, maxDecoded int) ([]byte, error) {
	switch encoding {
	case "snappy":
		n, e := snappy.DecodedLen(b)
		if e != nil || n > maxDecoded {
			return nil, wire.ErrFrame
		}
		return snappy.Decode(make([]byte, 0, n), b)
	case "zstd":
		d, e := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(maxDecoded)), zstd.WithDecoderMaxWindow(uint64(maxDecoded)))
		if e != nil {
			return nil, e
		}
		defer d.Close()
		raw, e := io.ReadAll(io.LimitReader(d, int64(maxDecoded)+1))
		if e != nil || len(raw) > maxDecoded {
			return nil, wire.ErrFrame
		}
		return raw, nil
	default:
		return nil, wire.ErrFrame
	}
}
func fields(raw []byte, fn func(protowire.Number, protowire.Type, []byte) error) error {
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 || num <= 0 {
			return wire.ErrFrame
		}
		raw = raw[n:]
		size := protowire.ConsumeFieldValue(num, typ, raw)
		if size < 0 || typ == protowire.StartGroupType || typ == protowire.EndGroupType {
			return wire.ErrFrame
		}
		value := raw[:size]
		if typ == protowire.BytesType {
			var k int
			value, k = protowire.ConsumeBytes(raw)
			if k < 0 {
				return wire.ErrFrame
			}
		}
		if e := fn(num, typ, value); e != nil {
			return e
		}
		raw = raw[size:]
	}
	return nil
}
func parse(raw []byte, maxSamples int) ([]series, error) {
	out := []series{}
	count := 0
	err := fields(raw, func(n protowire.Number, t protowire.Type, b []byte) error {
		if n != 1 || t != protowire.BytesType {
			// WriteRequest.metadata and any future top-level field are not part of this sink.
			return nil
		}
		if len(out) >= maxSamples {
			return wire.ErrFrame
		}
		s := series{labels: map[string]string{}}
		e := fields(b, func(n protowire.Number, t protowire.Type, b []byte) error {
			switch n {
			case 1, 2:
				if t != protowire.BytesType {
					return wire.ErrFrame
				}
			default:
				// exemplars (3), histograms (4) and future fields are skipped, not refused.
				return nil
			}
			switch n {
			case 1:
				if len(s.labels) >= 64 {
					return wire.ErrFrame
				}
				name, value := "", ""
				seen := map[protowire.Number]bool{}
				e := fields(b, func(n protowire.Number, t protowire.Type, b []byte) error {
					if t != protowire.BytesType || seen[n] || !utf8.Valid(b) {
						return wire.ErrFrame
					}
					seen[n] = true
					switch n {
					case 1:
						if len(b) < 1 || len(b) > 128 {
							return wire.ErrFrame
						}
						name = string(b)
					case 2:
						if len(b) > 1024 {
							return wire.ErrFrame
						}
						value = string(b)
					default:
						return wire.ErrFrame
					}
					return nil
				})
				if e != nil || name == "" {
					return wire.ErrFrame
				}
				if _, ok := s.labels[name]; ok {
					return wire.ErrFrame
				}
				s.labels[name] = value
			case 2:
				if count >= maxSamples {
					return wire.ErrFrame
				}
				v := sample{}
				seen := map[protowire.Number]bool{}
				e := fields(b, func(n protowire.Number, t protowire.Type, b []byte) error {
					if seen[n] {
						return wire.ErrFrame
					}
					seen[n] = true
					switch n {
					case 1:
						if t != protowire.Fixed64Type {
							return wire.ErrFrame
						}
						v.value = math.Float64frombits(binary.LittleEndian.Uint64(b))
					case 2:
						if t != protowire.VarintType {
							return wire.ErrFrame
						}
						u, k := protowire.ConsumeVarint(b)
						if k < 0 {
							return wire.ErrFrame
						}
						v.at = int64(u)
					default:
						return wire.ErrFrame
					}
					return nil
				})
				// A stale NaN marker or an Inf value is data, not a framing error: the series that carries it is
				// discarded in ServeHTTP. Refusing the whole block here would make vmagent drop every other
				// series in the same request, which is the common case for a cluster with any stale target.
				if e != nil {
					return wire.ErrFrame
				}
				s.samples = append(s.samples, v)
				count++
			default:
				return wire.ErrFrame
			}
			return nil
		})
		if e != nil || len(s.labels) == 0 || len(s.samples) == 0 {
			return wire.ErrFrame
		}
		out = append(out, s)
		return nil
	})
	return out, err
}
func TLS(l config.Listener) (*tls.Config, error) { return httpauth.TLS(l) }
