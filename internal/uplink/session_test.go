package uplink

import (
	"context"
	"crypto/tls"
	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/testkit"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreditCumulativeCeilingsAndEpochIsolation(t *testing.T) {
	old := &pb.Credit{SessionId: "s", Epoch: "e", Grant: 2, Bytes: 100, Items: 10}
	if e := acceptCredit(old, "s", "e", "", old); e != nil {
		t.Fatal(e)
	}
	for _, v := range []*pb.Credit{{SessionId: "s", Epoch: "other", Grant: 2, Bytes: 100, Items: 10}, {SessionId: "s", Epoch: "e", Grant: 1, Bytes: 100, Items: 10}, {SessionId: "s", Epoch: "e", Grant: 2, Bytes: 200, Items: 10}, {SessionId: "s", Epoch: "e", Grant: 3, Bytes: 99, Items: 10}} {
		if acceptCredit(v, "s", "e", "", old) == nil {
			t.Fatal("invalid cumulative credit accepted")
		}
	}
}
func TestSinglePhysicalH2ConnectionAndVerifiedServer(t *testing.T) {
	p := testkit.New(t)
	now := time.Now()
	serverCert := p.Leaf(t, "", "127.0.0.1", now.Add(-time.Minute), now.Add(time.Hour))
	clientCert := p.Leaf(t, "spiffe://clearintervals/ru/gateway/gateway", "", now.Add(-time.Minute), now.Add(time.Hour))
	peers := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers <- r.RemoteAddr
		if r.ProtoMajor != 2 || len(r.TLS.PeerCertificates) != 1 {
			t.Error("missing mTLS or HTTP/2")
		}
		f, _, e := wire.Read(r.Body, wire.MaxControl, nil)
		if e != nil {
			t.Error(e)
			return
		}
		_ = wire.Write(w, f)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Roots}
	server.StartTLS()
	defer server.Close()
	conn, e := Dial(context.Background(), server.URL, "", &tls.Config{RootCAs: p.Roots, Certificates: []tls.Certificate{clientCert}}, true)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	for j := 0; j < 2; j++ {
		if _, e = conn.Unary(context.Background(), "challenge", &pb.Lifecycle{GatewayId: "gateway"}); e != nil {
			t.Fatal(e)
		}
	}
	if <-peers != <-peers {
		t.Fatal("requests changed physical connection")
	}
	if bad, e := Dial(context.Background(), server.URL, "", &tls.Config{}, true); e == nil {
		bad.Close()
		t.Fatal("untrusted cloud accepted")
	}
}
func TestZeroCreditPollResumesAndRetainsUntilMatchedAck(t *testing.T) {
	p := testkit.New(t)
	now := time.Now()
	cert := p.Leaf(t, "", "127.0.0.1", now.Add(-time.Minute), now.Add(time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	q, e := buffer.Open(t.TempDir(), 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	i := &pb.Item{Id: "point", SourceId: "canonical", BindingId: "v1", StreamKey: strings.Repeat("k", 43), Body: &pb.Item_Point{Point: &pb.Point{Timestamp: now.UTC().Format(time.RFC3339Nano), Value: 1}}}
	i.Hash, _ = wire.Hash(i)
	if e = q.Enqueue([]*pb.Item{i}, now); e != nil {
		t.Fatal(e)
	}
	var hellos, opens, heartbeats atomic.Int32
	completed := make(chan struct{})
	released := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, _, e := wire.Read(r.Body, wire.MaxControl, nil)
		if e != nil {
			return
		}
		reply := func(f *pb.Frame) { _ = wire.Write(w, f); _ = http.NewResponseController(w).Flush() }
		if f.GetHello() != nil {
			hellos.Add(1)
			reply(&pb.Frame{Body: &pb.Frame_Welcome{Welcome: &pb.Welcome{SessionId: "session", Generation: 2, MaxStreams: 16, MaxFrameBytes: wire.MaxFrame}}})
			for {
				f, _, e = wire.Read(r.Body, wire.MaxControl, nil)
				if e != nil {
					return
				}
				if f.GetHeartbeat() != nil {
					switch heartbeats.Add(1) {
					case 1:
						reply(&pb.Frame{Body: &pb.Frame_Failure{Failure: &pb.Failure{Code: "rate_limited", RetryAfterSeconds: 5}}})
					case 2:
						reply(&pb.Frame{Body: &pb.Frame_Failure{Failure: &pb.Failure{Code: "core_unavailable", RetryAfterSeconds: 5}}})
					default:
						reply(&pb.Frame{Body: &pb.Frame_Policy{Policy: &pb.Policy{State: "active"}}})
					}
				}
				if c := f.GetCreditRequest(); c != nil {
					reply(&pb.Frame{Body: &pb.Frame_Credit{Credit: &pb.Credit{SessionId: "session", Epoch: c.Epoch, RequestId: c.RequestId, Grant: 1, Bytes: wire.MaxFrame, Items: 1000}}})
				}
			}
		}
		if o := f.GetOpen(); o != nil {
			if opens.Add(1) == 1 {
				reply(&pb.Frame{Body: &pb.Frame_Failure{Failure: &pb.Failure{Code: "rate_limited", RetryAfterSeconds: 5}}})
				return
			}
			reply(&pb.Frame{Body: &pb.Frame_Credit{Credit: &pb.Credit{SessionId: "session", Epoch: o.Epoch}}})
			f, _, e = wire.Read(r.Body, wire.MaxFrame, nil)
			if e != nil {
				return
			}
			b := f.GetBatch()
			if b == nil {
				t.Error("no batch")
				return
			}
			reply(&pb.Frame{Body: &pb.Frame_Ack{Ack: &pb.Ack{SessionId: "session", Epoch: o.Epoch, Sequence: b.Sequence, Results: []*pb.Result{{Id: i.Id, Hash: i.Hash, Outcome: pb.Outcome_ACCEPTED}}}}})
			close(completed)
			_, _ = io.Copy(io.Discard, r.Body)
			close(released)
		}
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	conn, e := Dial(ctx, server.URL, "", &tls.Config{RootCAs: p.Roots}, true)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { done <- conn.run(ctx, q, "gateway", 2, nil, now.Add(time.Hour), 20*time.Millisecond) }()
	select {
	case <-completed:
	case <-ctx.Done():
		t.Fatal("zero credit never progressed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		v, e := q.Next(time.Now())
		if e != nil {
			t.Fatal(e)
		}
		if len(v) == 0 && heartbeats.Load() >= 3 {
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("drained stream retained its cloud credit reservation")
			}
			cancel()
			<-done
			if hellos.Load() != 1 || opens.Load() != 2 || !conn.Established {
				t.Fatalf("temporary pressure churned control: hellos=%d opens=%d", hellos.Load(), opens.Load())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("matched terminal acknowledgement not reclaimed")
}
