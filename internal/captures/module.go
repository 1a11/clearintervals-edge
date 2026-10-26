// Package captures implements the native, durable waveform HTTP sink.
package captures

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/httpauth"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
)

const MaxSamplesBytes = 12000000
const MaxHeaderBytes = 16384

// Two producers may hold a maximum-size waveform at once. Admission happens
// before a finite body or streaming window: a fan-in burst cannot allocate one
// waveform buffer per connected sensor. Idle streams hold at most a small prefix.
type Module struct {
	config  *config.Store
	queue   *buffer.Queue
	auth    *httpauth.Gate
	slots   chan struct{}
	streams chan struct{}
}

func New(c *config.Store, q *buffer.Queue, gate *httpauth.Gate) *Module {
	return &Module{config: c, queue: q, auth: gate, slots: make(chan struct{}, 2), streams: make(chan struct{}, 128)}
}
func fail(w http.ResponseWriter, status int) {
	if status == 429 || status == 503 {
		w.Header().Set("Retry-After", "1")
	}
	http.Error(w, http.StatusText(status), status)
}
func (m *Module) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := "/api/v1/captures/"
	streaming := strings.HasPrefix(r.URL.Path, "/api/v1/streams/captures/")
	if streaming {
		prefix = "/api/v1/streams/captures/"
	}
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, prefix) || r.URL.RawQuery != "" {
		fail(w, 404)
		return
	}
	bid := strings.TrimPrefix(r.URL.Path, prefix)
	if !wire.ValidID(bid) {
		fail(w, 404)
		return
	}
	c := m.config.Get()
	principal, status := m.auth.Authenticate(r, c.Modules.Captures.Principals)
	if status != 0 {
		fail(w, status)
		return
	}
	var binding *config.Binding
	for i := range c.Bindings {
		b := &c.Bindings[i]
		if b.ID == bid && b.Kind == "captures" {
			binding = b
			break
		}
	}
	if binding == nil || !slices.Contains(binding.Principals, principal) {
		fail(w, 403)
		return
	}
	contentType := "application/octet-stream"
	if streaming {
		contentType = "application/vnd.clearintervals.waveforms.v1"
	}
	if r.Header.Get("Content-Type") != contentType || r.Header.Get("Content-Encoding") != "" {
		fail(w, 415)
		return
	}
	if streaming {
		m.stream(w, r, c, binding)
		return
	}
	if r.ContentLength > 4+MaxHeaderBytes+MaxSamplesBytes {
		fail(w, 413)
		return
	}
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		fail(w, 429)
		return
	}
	controller := http.NewResponseController(w)
	deadline := time.Now().Add(30 * time.Second)
	_ = controller.SetWriteDeadline(deadline)
	reader := &progressReader{r.Body, controller, deadline}
	item, status := readWindow(reader, r.ContentLength, true, c, binding)
	if status != 0 {
		fail(w, status)
		return
	}
	now := time.Now()
	err := m.config.Admit(c, func() error { return m.queue.Enqueue([]*pb.Item{item}, now) })
	if err != nil {
		fail(w, 503)
		return
	}
	// Acknowledgement means fsync'd at the edge, not processed by core DSP.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"captureId": item.Id, "status": "queued"})
}

func readWindow(reader io.Reader, contentLength int64, exactEOF bool, c *config.Config, binding *config.Binding) (*pb.Item, int) {
	readFailure := 400
	if !exactEOF {
		readFailure = 408
	}
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, readFailure
	}
	n := binary.LittleEndian.Uint32(length[:])
	if n == 0 || n > MaxHeaderBytes {
		return nil, 400
	}
	rawHeader := make([]byte, int(n))
	if _, err := io.ReadFull(reader, rawHeader); err != nil {
		return nil, readFailure
	}
	var header struct {
		Metadata map[string]any `json:"metadata"`
		Count    uint32         `json:"count"`
	}
	decoder := json.NewDecoder(bytes.NewReader(rawHeader))
	decoder.DisallowUnknownFields()
	var tail any
	if decoder.Decode(&header) != nil || decoder.Decode(&tail) != io.EOF || header.Count < 2 || header.Count > 1000000 || header.Metadata == nil {
		return nil, 400
	}
	axes, ok := header.Metadata["axes"].([]any)
	if !ok || len(axes) < 1 || len(axes) > 3 {
		return nil, 400
	}
	size := int(header.Count) * len(axes) * 4
	if size > MaxSamplesBytes || contentLength >= 0 && contentLength != int64(4+n)+int64(size) {
		return nil, 400
	}
	id, ok := header.Metadata["captureId"].(string)
	if !ok || !wire.ValidID(id) {
		return nil, 400
	}
	metadata, err := json.Marshal(header.Metadata)
	if err != nil {
		return nil, 400
	}
	samples := make([]byte, size)
	if _, err := io.ReadFull(reader, samples); err != nil {
		return nil, readFailure
	}
	if exactEOF {
		var extra [1]byte
		if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
			return nil, 400
		}
	}
	item := &pb.Item{Id: id, BindingId: binding.ID, SourceId: binding.SourceID, StreamKey: binding.StreamKey, Body: &pb.Item_Capture{Capture: &pb.Capture{MetadataJson: metadata, Count: header.Count, SamplesLeF32: samples}}}
	item.Hash, err = wire.Hash(item)
	if err != nil || wire.Validate(item, "captures") != nil {
		return nil, 400
	}
	now := time.Now()
	at, _ := time.Parse(time.RFC3339Nano, header.Metadata["startTimeUtc"].(string))
	if now.Sub(at) > c.MaxAge() || at.After(now.Add(5*time.Minute)) {
		return nil, 400
	}
	return item, 0
}

type progressReader struct {
	body       io.Reader
	controller *http.ResponseController
	deadline   time.Time
}

func (r *progressReader) Read(b []byte) (int, error) {
	next := time.Now().Add(10 * time.Second)
	if r.deadline.Before(next) {
		next = r.deadline
	}
	_ = r.controller.SetReadDeadline(next)
	return r.body.Read(b)
}

// stream owns only a small prefix while idle. Full waveform slots are acquired
// per window, never for the lifetime of the HTTP connection.
func (m *Module) stream(w http.ResponseWriter, r *http.Request, c *config.Config, binding *config.Binding) {
	select {
	case m.streams <- struct{}{}:
		defer func() { <-m.streams }()
	default:
		fail(w, 429)
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.EnableFullDuplex(); err != nil && r.ProtoMajor < 2 {
		fail(w, 505)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	encoder := json.NewEncoder(w)
	rejected := func(status int) {
		reason := "invalid_frame"
		if status == 429 {
			reason = "rate_limited"
		}
		if status == 503 {
			reason = "buffer_unavailable"
		}
		if status == 408 {
			reason = "incomplete_window"
		}
		_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		result := map[string]any{"status": "rejected", "code": reason}
		if status == 429 || status == 503 || status == 408 {
			result["status"] = "retry"
			result["retryAfterSeconds"] = 1
		}
		_ = encoder.Encode(result)
		_ = controller.Flush()
	}
	for {
		// Reading four bytes does not allocate or reserve a full waveform. A silent
		// writer cannot monopolize either of the two active window slots.
		_ = controller.SetReadDeadline(time.Now().Add(60 * time.Second))
		var prefix [4]byte
		n, err := io.ReadFull(r.Body, prefix[:])
		reader := &progressReader{r.Body, controller, time.Now().Add(30 * time.Second)}
		if err != nil && n == 0 {
			return
		}
		if err != nil {
			rejected(408)
			return
		}
		select {
		case m.slots <- struct{}{}:
		default:
			rejected(429)
			return
		}
		item, status := func() (*pb.Item, int) {
			defer func() { <-m.slots }()
			item, status := readWindow(io.MultiReader(bytes.NewReader(prefix[:]), reader), -1, false, c, binding)
			if status != 0 {
				return nil, status
			}
			// Admission checks the authenticated snapshot at every window. Reload or
			// principal removal closes the stream before another durable acknowledgement.
			if err := m.config.Admit(c, func() error { return m.queue.Enqueue([]*pb.Item{item}, time.Now()) }); err != nil {
				return nil, 503
			}
			return item, 0
		}()
		if status != 0 {
			rejected(status)
			return
		}
		_ = controller.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if encoder.Encode(map[string]string{"captureId": item.Id, "status": "queued"}) != nil {
			return
		}
		if controller.Flush() != nil {
			return
		}
	}
}
