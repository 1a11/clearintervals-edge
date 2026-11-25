// Package uplink implements one physical outbound connection with multiplexed streams.
package uplink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/1a11/clearintervals-edge/internal/diag"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
)

var ErrTransport = errors.New("uplink_unavailable")

// TransportError names the step at which the outbound connection failed, as a
// fixed token that is safe to log.
type TransportError struct{ Stage string }

func (t *TransportError) Error() string { return "uplink_unavailable: " + t.Stage }
func (t *TransportError) Unwrap() error { return ErrTransport }
func stage(s string) error              { return &TransportError{s} }

func dialStage(e error) string {
	var dns *net.DNSError
	var timeout interface{ Timeout() bool }
	switch {
	case errors.As(e, &dns):
		return "dns_lookup_failed"
	case errors.Is(e, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(e, syscall.ENETUNREACH) || errors.Is(e, syscall.EHOSTUNREACH):
		return "network_unreachable"
	case errors.As(e, &timeout) && timeout.Timeout():
		return "connect_timeout"
	}
	return "connect_failed"
}
func tlsStage(e error) string {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var alert tls.AlertError
	switch {
	case errors.As(e, &unknown):
		// Typical cause: a proxy or firewall intercepting TLS.
		return "server_certificate_untrusted"
	case errors.As(e, &hostname):
		return "server_name_mismatch"
	case errors.As(e, &invalid):
		return "server_certificate_invalid"
	case errors.As(e, &alert):
		return "tls_rejected_by_server"
	}
	return "tls_handshake_failed"
}

// Failure is a cloud refusal. Reason and Ref are server-supplied diagnostics:
// Reason is human-readable and Ref is the reference id to quote to support.
type Failure struct {
	Code   string
	Retry  time.Duration
	Reason string
	Ref    string
}

func (f *Failure) Error() string { return f.Code }

type Connection struct {
	client      *http.Client
	close       func()
	base        string
	Kind        string
	Established bool
}

func (c *Connection) Close() { c.close() }
func Dial(ctx context.Context, base, proxy string, cfg *tls.Config, forceTCP bool) (*Connection, error) {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, stage("invalid_ingest_url")
	}
	base = "https://" + u.Host
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	tc := cfg.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.ServerName = u.Hostname()
	tc.ClientSessionCache = nil
	tc.SessionTicketsDisabled = true
	diag.Event("verbose_uplink_dial", "event", "start", "url", base, "host", u.Host, "address", addr,
		"proxy", proxy, "forceTcp", forceTCP)
	if !forceTCP && proxy == "" {
		tc.NextProtos = []string{http3.NextProtoH3}
		diag.Event("verbose_uplink_dial", "attempt", "h3", "address", addr, "sni", u.Hostname())
		hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, e := quic.DialAddr(hctx, addr, tc, &quic.Config{HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 180 * time.Second, MaxIncomingStreams: 0, MaxIncomingUniStreams: 8})
		cancel()
		if e == nil {
			cs := conn.ConnectionState().TLS
			attrs := append([]any{"attempt", "h3", "result", "connected", "tlsVersion", tlsVersionName(cs.Version),
				"tlsCipher", tls.CipherSuiteName(cs.CipherSuite), "alpn", cs.NegotiatedProtocol}, peerCertAttrs(cs)...)
			diag.Event("verbose_uplink_dial", attrs...)
			tr := &http3.Transport{MaxResponseHeaderBytes: 8192, DisableCompression: true}
			client := tr.NewClientConn(conn)
			return &Connection{client: &http.Client{Transport: client, CheckRedirect: noRedirect}, close: func() { _ = conn.CloseWithError(0, "") }, base: base, Kind: "h3"}, nil
		}
		diag.Event("verbose_uplink_dial", "attempt", "h3", "address", addr, "result", "failed", "stage", dialStage(e), "error", e.Error())
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	target := addr
	var pu *url.URL
	if proxy != "" {
		pu, e = url.Parse(proxy)
		if e != nil || pu.Scheme != "http" {
			return nil, stage("invalid_proxy_url")
		}
		target = pu.Host
		if pu.Port() == "" {
			target = net.JoinHostPort(pu.Hostname(), "80")
		}
	}
	diag.Event("verbose_uplink_dial", "attempt", "h2", "target", target, "proxy", pu != nil)
	conn, e := d.DialContext(ctx, "tcp", target)
	if e != nil {
		diag.Event("verbose_uplink_dial", "attempt", "h2", "target", target, "result", "failed", "stage", dialStage(e), "error", e.Error())
		if pu != nil {
			return nil, stage("proxy_" + dialStage(e))
		}
		return nil, stage(dialStage(e))
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if pu != nil {
		req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
		if pu.User != nil {
			pass, _ := pu.User.Password()
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pass)))
		}
		diag.Event("verbose_uplink_dial", "attempt", "proxy_connect", "proxy", pu.Host, "target", addr)
		if e = req.Write(conn); e != nil {
			diag.Event("verbose_uplink_dial", "attempt", "proxy_connect", "result", "failed", "error", e.Error())
			return nil, stage("proxy_connect_failed")
		}
		br := bufio.NewReaderSize(io.LimitReader(conn, 8192), 8192)
		res, e := http.ReadResponse(br, req)
		if e != nil || br.Buffered() != 0 {
			diag.Event("verbose_uplink_dial", "attempt", "proxy_connect", "result", "failed", "error", fmt.Sprint(e))
			return nil, stage("proxy_connect_failed")
		}
		diag.Event("verbose_uplink_dial", "attempt", "proxy_connect", "result", "answered", "status", res.StatusCode)
		if res.StatusCode != 200 {
			return nil, stage(fmt.Sprintf("proxy_connect_http_%d", res.StatusCode))
		}
	}
	tc.NextProtos = []string{"h2"}
	secure := tls.Client(conn, tc)
	if e = secure.HandshakeContext(ctx); e != nil {
		diag.Event("verbose_uplink_dial", "attempt", "tls", "sni", u.Hostname(), "result", "failed",
			"stage", tlsStage(e), "error", e.Error())
		return nil, stage(tlsStage(e))
	}
	cs := secure.ConnectionState()
	attrs := append([]any{"attempt", "tls", "sni", u.Hostname(), "result", "handshake_complete",
		"tlsVersion", tlsVersionName(cs.Version), "tlsCipher", tls.CipherSuiteName(cs.CipherSuite), "alpn", cs.NegotiatedProtocol},
		peerCertAttrs(cs)...)
	diag.Event("verbose_uplink_dial", attrs...)
	if cs.NegotiatedProtocol != "h2" {
		diag.Event("verbose_uplink_dial", "attempt", "tls", "result", "failed", "stage", "http2_not_negotiated", "alpn", cs.NegotiatedProtocol)
		return nil, stage("http2_not_negotiated")
	}
	_ = conn.SetDeadline(time.Time{})
	tr := &http2.Transport{ReadIdleTimeout: 30 * time.Second, PingTimeout: 10 * time.Second, MaxHeaderListSize: 8192, DisableCompression: true}
	client, e := tr.NewClientConn(secure)
	if e != nil {
		return nil, stage("http2_setup_failed")
	}
	ok = true
	return &Connection{client: &http.Client{Transport: client, CheckRedirect: noRedirect}, close: func() { _ = client.Close(); _ = secure.Close() }, base: base, Kind: "h2"}, nil
}
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
func (c *Connection) Unary(ctx context.Context, path string, v *pb.Lifecycle) (*pb.Frame, error) {
	return c.unary(ctx, path, v, wire.MaxControl)
}

// unary is Unary with an explicit decoded-length limit, for answers that are
// larger than an ordinary control frame.
func (c *Connection) unary(ctx context.Context, path string, v *pb.Lifecycle, limit int) (*pb.Frame, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var raw bytes.Buffer
	if e := wire.Write(&raw, &pb.Frame{Body: &pb.Frame_Lifecycle{Lifecycle: v}}); e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/uplink/v1/"+path, &raw)
	if e != nil {
		return nil, stage("request_failed")
	}
	req.Header.Set("Content-Type", "application/x-clearintervals-protobuf")
	diag.Event("verbose_uplink_frame_send", "path", path, "frame", frameName(&pb.Frame{Body: &pb.Frame_Lifecycle{Lifecycle: v}}),
		"operationId", v.OperationId, "purpose", v.Purpose, "generation", v.Generation, "bytes", raw.Len())
	res, e := c.client.Do(req)
	if e != nil {
		diag.Event("verbose_uplink_frame_send", "path", path, "error", e.Error())
		return nil, stage("request_failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		diag.Event("verbose_uplink_frame_recv", "path", path, "httpStatus", res.StatusCode, "error", "unexpected status")
		return nil, stage(fmt.Sprintf("http_status_%d", res.StatusCode))
	}
	f, _, e := wire.Read(res.Body, limit, nil)
	if e != nil {
		diag.Event("verbose_uplink_frame_recv", "path", path, "httpStatus", res.StatusCode, "error", e.Error())
		return nil, stage("invalid_response_frame")
	}
	diag.Event("verbose_uplink_frame_recv", "path", path, "httpStatus", res.StatusCode, "frame", frameName(f),
		"items", frameItems(f), "failureCode", f.GetFailure().GetCode(), "failureReason", f.GetFailure().GetReason(),
		"failureRef", f.GetFailure().GetRef())
	var tail [1]byte
	if n, e := res.Body.Read(tail[:]); n != 0 || e != io.EOF {
		return nil, stage("trailing_response")
	}
	return checked(f)
}
func checked(f *pb.Frame) (*pb.Frame, error) {
	if f.GetFailure() != nil {
		v := f.GetFailure()
		return nil, &Failure{Code: v.Code, Retry: time.Duration(min(v.RetryAfterSeconds, 900)) * time.Second, Reason: v.Reason, Ref: v.Ref}
	}
	return f, nil
}

// Descriptor is one stream the cloud resolved from the promql the operator
// configured. It reaches the gateway only in the answer to a request the
// gateway itself sent; no local writer ever receives it.
type Descriptor struct {
	ID        string            `json:"id"`
	StreamKey string            `json:"streamKey"`
	SourceID  string            `json:"sourceId"`
	Kind      string            `json:"kind"`
	Selector  map[string]string `json:"selector"`
	Scale     float64           `json:"scale"`
	Metric    string            `json:"metric"`
}

// descriptorsLimit bounds the descriptor answer: 100 descriptors of a few
// hundred JSON bytes each exceed an ordinary control frame, while the wire
// still caps the frame itself at MaxFrame.
const descriptorsLimit = 256 << 10

// Descriptors asks the cloud for the stream descriptors behind the configured
// promql. The request is outbound only: the gateway is the only party that
// talks, and the answer is applied locally and never answered upstream.
func (c *Connection) Descriptors(ctx context.Context, gid string, generation uint64) ([]Descriptor, error) {
	f, e := c.unary(ctx, "descriptors", &pb.Lifecycle{GatewayId: gid, OperationId: id(), Generation: generation, Purpose: "descriptors"}, descriptorsLimit)
	if e != nil {
		return nil, e
	}
	payload := f.GetChallenge().GetSigningPayload()
	if len(payload) == 0 {
		return nil, nil
	}
	var body struct {
		Items []Descriptor `json:"items"`
	}
	if e = json.Unmarshal(payload, &body); e != nil {
		return nil, stage("invalid_descriptors")
	}
	return body.Items, nil
}

type Channel struct {
	writer *io.PipeWriter
	body   io.ReadCloser
	cancel context.CancelFunc
	mu     sync.Mutex
}

func (c *Connection) Open(ctx context.Context, path string, first *pb.Frame) (*Channel, *pb.Frame, error) {
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(30*time.Second, cancel)
	defer timer.Stop()
	r, w := io.Pipe()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/uplink/v1/"+path, r)
	if e != nil {
		cancel()
		return nil, nil, stage("request_failed")
	}
	req.Header.Set("Content-Type", "application/x-clearintervals-protobuf")
	diag.Event("verbose_uplink_frame_send", "path", path, "frame", frameName(first), "items", frameItems(first),
		"sessionId", first.GetOpen().GetSessionId(), "epoch", first.GetOpen().GetEpoch(), "kind", first.GetOpen().GetKind())
	go func() {
		if e := wire.Write(w, first); e != nil {
			_ = w.CloseWithError(e)
		}
	}()
	res, e := c.client.Do(req)
	if e != nil {
		diag.Event("verbose_uplink_frame_send", "path", path, "error", e.Error())
		cancel()
		w.Close()
		return nil, nil, stage("request_failed")
	}
	ch := &Channel{writer: w, body: res.Body, cancel: cancel}
	if res.StatusCode != 200 {
		diag.Event("verbose_uplink_frame_recv", "path", path, "httpStatus", res.StatusCode, "error", "unexpected status")
		ch.Close()
		return nil, nil, stage(fmt.Sprintf("http_status_%d", res.StatusCode))
	}
	f, _, e := wire.Read(&progressBody{reader: ch.body, cancel: ch.cancel}, wire.MaxControl, nil)
	if e != nil {
		diag.Event("verbose_uplink_frame_recv", "path", path, "httpStatus", res.StatusCode, "error", e.Error())
		ch.Close()
		return nil, nil, stage("invalid_response_frame")
	}
	diag.Event("verbose_uplink_frame_recv", "path", path, "httpStatus", res.StatusCode, "frame", frameName(f),
		"items", frameItems(f), "failureCode", f.GetFailure().GetCode(), "failureReason", f.GetFailure().GetReason(),
		"failureRef", f.GetFailure().GetRef(), "creditGrant", f.GetCredit().GetGrant())
	f, e = checked(f)
	if e != nil {
		ch.Close()
		return nil, nil, e
	}
	return ch, f, nil
}
func (c *Channel) Close() { c.cancel(); c.writer.Close(); c.body.Close() }
func (c *Channel) Exchange(f *pb.Frame) (*pb.Frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := time.AfterFunc(30*time.Second, c.cancel)
	defer timer.Stop()
	diag.Event("verbose_uplink_frame_send", "stream", true, "frame", frameName(f), "items", frameItems(f),
		"sequence", f.GetBatch().GetSequence())
	if e := wire.Write(c.writer, f); e != nil {
		diag.Event("verbose_uplink_frame_send", "stream", true, "error", e.Error())
		return nil, stage("stream_write_failed")
	}
	reply, _, e := wire.Read(&progressBody{reader: c.body, cancel: c.cancel}, wire.MaxControl, nil)
	if e != nil {
		diag.Event("verbose_uplink_frame_recv", "stream", true, "error", e.Error())
		return nil, stage("stream_read_failed")
	}
	diag.Event("verbose_uplink_frame_recv", "stream", true, "frame", frameName(reply), "items", frameItems(reply),
		"sequence", reply.GetAck().GetSequence(), "terminalFrontier", reply.GetAck().GetTerminalFrontier(),
		"results", len(reply.GetAck().GetResults()), "failureCode", reply.GetFailure().GetCode(),
		"failureReason", reply.GetFailure().GetReason(), "failureRef", reply.GetFailure().GetRef())
	return checked(reply)
}

type progressBody struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (r *progressBody) Read(b []byte) (int, error) {
	timer := time.AfterFunc(10*time.Second, r.cancel)
	defer timer.Stop()
	return r.reader.Read(b)
}

// frameName names a frame for the verbose transport log.
func frameName(f *pb.Frame) string {
	switch {
	case f == nil:
		return "none"
	case f.GetHello() != nil:
		return "hello"
	case f.GetWelcome() != nil:
		return "welcome"
	case f.GetHeartbeat() != nil:
		return "heartbeat"
	case f.GetPolicy() != nil:
		return "policy"
	case f.GetOpen() != nil:
		return "open_stream"
	case f.GetCreditRequest() != nil:
		return "credit_request"
	case f.GetCredit() != nil:
		return "credit"
	case f.GetBatch() != nil:
		return "batch"
	case f.GetAck() != nil:
		return "ack"
	case f.GetFailure() != nil:
		return "failure"
	case f.GetLifecycle() != nil:
		return "lifecycle"
	case f.GetChallenge() != nil:
		return "challenge"
	case f.GetCredential() != nil:
		return "credential"
	}
	return "unknown"
}

func frameItems(f *pb.Frame) int {
	if b := f.GetBatch(); b != nil {
		return len(b.Items)
	}
	return 0
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	}
	return "unknown"
}

// peerCertAttrs names the certificate the cloud presented, which is what a pinned-roots failure is about.
func peerCertAttrs(state tls.ConnectionState) []any {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	return []any{"peerSubject", leaf.Subject.String(), "peerIssuer", leaf.Issuer.String(),
		"peerSha256", hex.EncodeToString(sum[:]), "peerNotAfter", leaf.NotAfter.UTC().Format(time.RFC3339)}
}
