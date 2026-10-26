package captures

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/httpauth"
)

const token = "A_customer_generated_secret_with_at_least_256_bits_123456789"

func fixture(t *testing.T) (*Module, *buffer.Queue, string) {
	t.Helper()
	c := new(config.Config)
	c.Buffer.MaxAgeDays = 7
	hash := sha256.Sum256([]byte(token))
	c.Modules.Captures.Principals = []config.Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(hash[:])}}
	c.Bindings = []config.Binding{{ID: "binding_v1", SourceID: "sensor_1", Kind: "captures", StreamKey: strings.Repeat("k", 43), Principals: []string{"writer"}}}
	dir := t.TempDir()
	q, err := buffer.Open(dir, 64<<20, 7*24*time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	return New(config.New(c), q, httpauth.New()), q, dir
}
func payload(t *testing.T, count uint32) []byte {
	t.Helper()
	header, err := json.Marshal(map[string]any{"metadata": map[string]any{"captureId": "capture_1", "tier": "M", "axes": []string{"x", "y", "z"}, "fsNominalHz": 25600, "startTimeUtc": time.Now().UTC().Format(time.RFC3339Nano)}, "count": count})
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 4+len(header)+int(count)*12)
	binary.LittleEndian.PutUint32(raw, uint32(len(header)))
	copy(raw[4:], header)
	return raw
}
func send(m *Module, raw []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/captures/binding_v1", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	return w
}
func TestWaveformAcknowledgedOnlyAfterDurableEnqueue(t *testing.T) {
	m, _, dir := fixture(t)
	raw := payload(t, 256000)
	if w := send(m, raw); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	reopened, err := buffer.Open(dir, 64<<20, 7*24*time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := reopened.Next(time.Now())
	if err != nil || len(entries) != 1 {
		t.Fatal(err, len(entries))
	}
	item := entries[0].Item
	if item.SourceId != "sensor_1" || item.GetCapture().Count != 256000 || len(item.GetCapture().SamplesLeF32) != 3072000 {
		t.Fatal("waveform did not survive restart")
	}
}
func TestWaveformInvalidInputNeverEnqueued(t *testing.T) {
	for _, mode := range []string{"short", "extra", "nan", "huge_header", "bad_count"} {
		t.Run(mode, func(t *testing.T) {
			m, q, _ := fixture(t)
			raw := payload(t, 2)
			switch mode {
			case "short":
				raw = raw[:len(raw)-1]
			case "extra":
				raw = append(raw, 0)
			case "nan":
				binary.LittleEndian.PutUint32(raw[len(raw)-4:], math.Float32bits(float32(math.NaN())))
			case "huge_header":
				binary.LittleEndian.PutUint32(raw, MaxHeaderBytes+1)
			case "bad_count":
				raw = payload(t, 1)
			}
			if w := send(m, raw); w.Code != 400 {
				t.Fatal(w.Code)
			}
			_, _, segments := q.Snapshot()
			if segments != 0 {
				t.Fatal("invalid waveform enqueued")
			}
		})
	}
}

type unreadable struct{ t *testing.T }

func (b unreadable) Read([]byte) (int, error) {
	b.t.Error("body read before admission")
	return 0, io.EOF
}
func TestWaveformAuthenticationAndMemoryAdmissionPrecedeBodyRead(t *testing.T) {
	m, _, _ := fixture(t)
	for _, mode := range []string{"unauthorized", "forbidden", "busy"} {
		t.Run(mode, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/captures/binding_v1", nil)
			r.Body = io.NopCloser(unreadable{t})
			r.ContentLength = -1
			r.Header.Set("Content-Type", "application/octet-stream")
			expected := 401
			if mode != "unauthorized" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			if mode == "forbidden" {
				r.URL.Path = "/api/v1/captures/other_binding"
				expected = 403
			}
			if mode == "busy" {
				m.slots <- struct{}{}
				m.slots <- struct{}{}
				defer func() { <-m.slots; <-m.slots }()
				expected = 429
			}
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			if w.Code != expected {
				t.Fatal(w.Code)
			}
		})
	}
}
func TestSuspendedWaveformIsNotAcknowledgedAsDurable(t *testing.T) {
	m, q, _ := fixture(t)
	if err := q.SetPolicy("organization_suspended"); err != nil {
		t.Fatal(err)
	}
	if w := send(m, payload(t, 2)); w.Code != 503 {
		t.Fatal(w.Code)
	}
	_, _, n := q.Snapshot()
	if n != 0 {
		t.Fatal(n)
	}
}

// The response must arrive before request EOF. This exercises Go's actual HTTP/1
// full-duplex path, not a ResponseRecorder which always permits early writes.
func TestWindowStreamAcknowledgesBeforeRequestEndsAndReleasesIdleSlot(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			m, q, _ := fixture(t)
			server := httptest.NewUnstartedServer(m)
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			source, sink := io.Pipe()
			defer source.Close()
			defer sink.Close()
			req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/streams/captures/binding_v1", source)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/vnd.clearintervals.waveforms.v1")
			client := server.Client()
			client.Timeout = 5 * time.Second
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/x-ndjson" {
				t.Fatal(res.StatusCode)
			}
			decoder := json.NewDecoder(res.Body)
			first := payload(t, 2)
			for n := 0; n < 2; n++ {
				written := make(chan error, 1)
				go func() { _, err := sink.Write(first); written <- err }()
				var ack map[string]any
				if err = decoder.Decode(&ack); err != nil {
					t.Fatal("no durable window ACK before request EOF", err)
				}
				if ack["captureId"] != "capture_1" || ack["status"] != "queued" {
					t.Fatal(ack)
				}
				if err = <-written; err != nil {
					t.Fatal(err)
				}
				if len(m.slots) != 0 {
					t.Fatal("idle stream retained a waveform slot")
				}
			}
			if w := send(m, payload(t, 2)); w.Code != 202 {
				t.Fatal("idle stream blocked finite producer", w.Code)
			}
			if err = sink.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = io.Copy(io.Discard, res.Body); err != nil {
				t.Fatal(err)
			}
			_, _, n := q.Snapshot()
			if n != 3 {
				t.Fatal("windows not durably saved", n)
			}
		})
	}
}
func TestInterruptedWindowRetainsOnlyAcknowledgedPredecessor(t *testing.T) {
	m, q, dir := fixture(t)
	server := httptest.NewServer(m)
	defer server.Close()
	raw := payload(t, 2)
	body := append(append([]byte{}, raw...), raw[:len(raw)-1]...)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/streams/captures/binding_v1", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.clearintervals.waveforms.v1")
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	decoder := json.NewDecoder(res.Body)
	var ack, rejection map[string]any
	if err = decoder.Decode(&ack); err != nil {
		t.Fatal(err)
	}
	if err = decoder.Decode(&rejection); err != nil {
		t.Fatal(err)
	}
	if ack["status"] != "queued" || rejection["status"] != "retry" || rejection["code"] != "incomplete_window" {
		t.Fatal(ack, rejection)
	}
	_, _, n := q.Snapshot()
	if n != 1 || len(m.slots) != 0 {
		t.Fatal("partial window was acknowledged or leaked a slot", n)
	}
	reopened, err := buffer.Open(dir, 64<<20, 7*24*time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := reopened.Next(time.Now())
	if err != nil || len(entries) != 1 {
		t.Fatal("acknowledged predecessor lost", err, len(entries))
	}
}

func TestWindowStreamReloadAndBusyAdmissionNeverAcknowledge(t *testing.T) {
	for _, mode := range []string{"reload", "busy"} {
		t.Run(mode, func(t *testing.T) {
			m, q, _ := fixture(t)
			server := httptest.NewServer(m)
			defer server.Close()
			source, sink := io.Pipe()
			defer source.Close()
			defer sink.Close()
			req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/streams/captures/binding_v1", source)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/vnd.clearintervals.waveforms.v1")
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if mode == "reload" {
				next := *m.config.Get()
				next.Bindings = nil
				if err = m.config.Reload(&next); err != nil {
					t.Fatal(err)
				}
			} else {
				m.slots <- struct{}{}
				m.slots <- struct{}{}
				defer func() { <-m.slots; <-m.slots }()
			}
			raw := payload(t, 2)
			go func() { _, _ = sink.Write(raw) }()
			var reply map[string]any
			if err = json.NewDecoder(res.Body).Decode(&reply); err != nil {
				t.Fatal(err)
			}
			if reply["status"] != "retry" {
				t.Fatal("refused window was acknowledged", reply)
			}
			expected := "buffer_unavailable"
			if mode == "busy" {
				expected = "rate_limited"
			}
			if reply["code"] != expected {
				t.Fatal(reply)
			}
			_, _, n := q.Snapshot()
			if n != 0 {
				t.Fatal("refused window enqueued", n)
			}
		})
	}
}
func TestWindowStreamCountIsBoundedBeforeBodyRead(t *testing.T) {
	m, _, _ := fixture(t)
	for n := 0; n < cap(m.streams); n++ {
		m.streams <- struct{}{}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/streams/captures/binding_v1", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/vnd.clearintervals.waveforms.v1")
	r.Body = io.NopCloser(unreadable{t})
	r.ContentLength = -1
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
}
