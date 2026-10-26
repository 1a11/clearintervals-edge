package uplink

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/testkit"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"github.com/quic-go/quic-go/http3"
)

func TestProductionDialStreamsSmallMessagesOverQUICAndTCPFallback(t *testing.T) {
	for _, mode := range []string{"quic", "udp-blackhole-h2-fallback"} {
		t.Run(mode, func(t *testing.T) {
			ca := testkit.New(t)
			now := time.Now()
			serverCert := ca.Leaf(t, "", "127.0.0.1", now.Add(-time.Minute), now.Add(time.Hour))
			clientCert := ca.Leaf(t, "spiffe://clearintervals/ru/gateway/gateway", "", now.Add(-time.Minute), now.Add(time.Hour))
			expected := 3
			if mode != "quic" {
				expected = 2
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != expected || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
					t.Error("wrong transport or missing mTLS")
					return
				}
				for {
					frame, _, err := wire.Read(r.Body, wire.MaxControl, nil)
					if err != nil {
						if err != io.EOF && r.Context().Err() == nil {
							t.Logf("stream closed: %v", err)
						}
						return
					}
					if err = wire.Write(w, frame); err != nil {
						return
					}
					if http.NewResponseController(w).Flush() != nil {
						return
					}
				}
			})
			tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Roots}
			var base string
			if mode == "quic" {
				listener, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				server := &http3.Server{TLSConfig: tlsConfig, Handler: handler}
				go func() { _ = server.Serve(listener) }()
				t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
				base = "https://" + listener.LocalAddr().String()
			} else {
				server := httptest.NewUnstartedServer(handler)
				server.EnableHTTP2 = true
				server.TLS = tlsConfig
				server.StartTLS()
				t.Cleanup(server.Close)
				base = server.URL
				blackhole, err := net.ListenPacket("udp", strings.TrimPrefix(base, "https://"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = blackhole.Close() })
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			started := time.Now()
			conn, err := Dial(ctx, base, "", &tls.Config{RootCAs: ca.Roots, Certificates: []tls.Certificate{clientCert}}, false)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			want := "h3"
			if expected == 2 {
				want = "h2"
			}
			if conn.Kind != want {
				t.Fatalf("kind %s, want %s", conn.Kind, want)
			}
			dialTime := time.Since(started)
			channel, first, err := conn.Open(ctx, "control", &pb.Frame{Body: &pb.Frame_Hello{Hello: &pb.Hello{GatewayId: "gateway"}}})
			if err != nil || first.GetHello() == nil {
				t.Fatalf("open: %v %v", first, err)
			}
			defer channel.Close()
			largest := 0
			for n := uint64(1); n <= 20; n++ {
				frame := &pb.Frame{Body: &pb.Frame_Heartbeat{Heartbeat: &pb.Heartbeat{Records: n}}}
				var raw bytes.Buffer
				if err := wire.Write(&raw, frame); err != nil {
					t.Fatal(err)
				}
				largest = max(largest, raw.Len())
				reply, err := channel.Exchange(frame)
				if err != nil || reply.GetHeartbeat() == nil || reply.GetHeartbeat().Records != n {
					t.Fatalf("message %d: %v %v", n, reply, err)
				}
			}
			if largest >= 1024 {
				t.Fatalf("unexpected large message %d", largest)
			}
			t.Logf("production %s connection: 20 ordered duplex replies before EOF, max message %d bytes, dial=%s", conn.Kind, largest, dialTime)
		})
	}
}
