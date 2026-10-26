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
	"time"
	"unicode/utf8"
)

const MaxCompressed = 4 << 20
const MaxDecoded = 16 << 20

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
		w.Header().Set("Retry-After", "5")
	}
	http.Error(w, http.StatusText(status), status)
}
func (m *Module) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/v1/write" || r.URL.RawQuery != "" {
		fail(w, 404)
		return
	}
	c := m.Config.Get()
	p, status := m.auth.Authenticate(r, c.Modules.RemoteWrite.Principals)
	if status != 0 {
		fail(w, status)
		return
	}

	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		fail(w, 429)
		return
	}
	if r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("X-Prometheus-Remote-Write-Version") != "0.1.0" {
		fail(w, 415)
		return
	}
	if r.ContentLength > MaxCompressed {
		fail(w, 413)
		return
	}
	ctl := http.NewResponseController(w)
	_ = ctl.SetReadDeadline(time.Now().Add(30 * time.Second))
	_ = ctl.SetWriteDeadline(time.Now().Add(30 * time.Second))
	compressed, e := io.ReadAll(io.LimitReader(&progressReader{reader: r.Body, controller: ctl, deadline: time.Now().Add(30 * time.Second)}, MaxCompressed+1))
	if e != nil {
		fail(w, 400)
		return
	}
	if len(compressed) > MaxCompressed {
		fail(w, 413)
		return
	}
	raw, e := decode(compressed, r.Header.Get("Content-Encoding"))
	if e != nil {
		fail(w, 400)
		return
	}
	data, e := parse(raw)
	if e != nil {
		fail(w, 400)
		return
	}
	items := []*pb.Item{}
	unmapped := uint64(0)
	old := uint64(0)
	now := time.Now()
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
			fail(w, 400)
			return
		}
		if len(matches) == 0 {
			unmapped += uint64(len(s.samples))
			continue
		}
		b := matches[0]
		if !slices.Contains(b.Principals, p) {
			fail(w, 403)
			return
		}
		for _, v := range s.samples {
			at := time.UnixMilli(v.at).UTC()
			if now.Sub(at) > c.MaxAge() {
				old++
				continue
			}
			if at.After(now.Add(5 * time.Minute)) {
				fail(w, 400)
				return
			}
			value := v.value * b.Scale
			if math.IsNaN(value) || math.IsInf(value, 0) || value == 0 && math.Signbit(value) {
				fail(w, 400)
				return
			}
			timestamp := at.Format(time.RFC3339Nano)
			id := sha256.Sum256([]byte(b.SourceID + "\x00" + timestamp))
			i := &pb.Item{Id: hex.EncodeToString(id[:]), StreamKey: b.StreamKey, BindingId: b.ID, SourceId: b.SourceID, Body: &pb.Item_Point{Point: &pb.Point{Timestamp: timestamp, Value: value}}}
			i.Hash, _ = wire.Hash(i)
			items = append(items, i)
		}
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
		return m.Queue.Enqueue(items, now)
	})
	if e != nil {
		fail(w, 503)
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
func decode(b []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "snappy":
		n, e := snappy.DecodedLen(b)
		if e != nil || n > MaxDecoded || n > 20*len(b) {
			return nil, wire.ErrFrame
		}
		return snappy.Decode(make([]byte, 0, n), b)
	case "zstd":
		d, e := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxDecoded), zstd.WithDecoderMaxWindow(MaxDecoded))
		if e != nil {
			return nil, e
		}
		defer d.Close()
		limit := min(MaxDecoded, 20*len(b))
		raw, e := io.ReadAll(io.LimitReader(d, int64(limit)+1))
		if e != nil || len(raw) > limit {
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
func parse(raw []byte) ([]series, error) {
	out := []series{}
	count := 0
	err := fields(raw, func(n protowire.Number, t protowire.Type, b []byte) error {
		if n != 1 || t != protowire.BytesType || len(out) >= 1000 {
			return wire.ErrFrame
		}
		s := series{labels: map[string]string{}}
		e := fields(b, func(n protowire.Number, t protowire.Type, b []byte) error {
			if t != protowire.BytesType {
				return wire.ErrFrame
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
				if count >= 1000 {
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
				if e != nil || math.IsNaN(v.value) || math.IsInf(v.value, 0) {
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
