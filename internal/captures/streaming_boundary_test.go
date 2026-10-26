package captures

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type observedBody struct {
	io.ReadCloser
	remaining int
	received  chan struct{}
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.remaining > 0 {
		b.remaining -= n
		if b.remaining <= 0 {
			close(b.received)
		}
	}
	return n, err
}

// An open HTTP body is duplex, but a partial waveform is not yet a queued item.
// Keep the final sample absent after observing all preceding bytes at the server.
func TestPartialWaveformIsReceivedButNotDurableUntilWindowComplete(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			m, q, _ := fixture(t)
			frame := payload(t, 1024)
			received := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = &observedBody{r.Body, len(frame) - 4, received}
				m.ServeHTTP(w, r)
			}))
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/streams/captures/binding_v1", reader)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/vnd.clearintervals.waveforms.v1")
			client := server.Client()
			client.Timeout = 5 * time.Second
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			expected := 1
			if h2 {
				expected = 2
			}
			if res.ProtoMajor != expected {
				t.Fatalf("negotiated %s, want HTTP/%d", res.Proto, expected)
			}
			written := make(chan error, 1)
			go func() {
				for offset := 0; offset < len(frame)-4; {
					end := min(offset+256, len(frame)-4)
					if _, err := writer.Write(frame[offset:end]); err != nil {
						written <- err
						return
					}
					offset = end
				}
				written <- nil
			}()
			select {
			case <-received:
			case <-time.After(3 * time.Second):
				t.Fatal("partial body did not reach server")
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			_, _, queued := q.Snapshot()
			if queued != 0 {
				t.Fatal("partial waveform became a durable item")
			}
			type answer struct {
				ack map[string]any
				err error
			}
			acked := make(chan answer, 1)
			go func() { var a map[string]any; err := json.NewDecoder(res.Body).Decode(&a); acked <- answer{a, err} }()
			select {
			case answer := <-acked:
				t.Fatalf("acknowledged incomplete window: %+v", answer)
			default:
			}
			if _, err := writer.Write(frame[len(frame)-4:]); err != nil {
				t.Fatal(err)
			}
			select {
			case answer := <-acked:
				if answer.err != nil || answer.ack["status"] != "queued" {
					t.Fatalf("complete window: %+v", answer)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("complete window not acknowledged before HTTP EOF")
			}
			_, _, queued = q.Snapshot()
			if queued != 1 {
				t.Fatalf("queued %d, want 1", queued)
			}
			t.Logf("%s: 256-byte writes reached server incrementally; durable item/ACK required final sample; request remained open", res.Proto)
		})
	}
}
