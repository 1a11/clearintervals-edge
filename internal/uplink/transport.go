// Package uplink implements one physical outbound connection with multiplexed streams.
package uplink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
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

type Failure struct {
	Code  string
	Retry time.Duration
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
	if !forceTCP && proxy == "" {
		tc.NextProtos = []string{http3.NextProtoH3}
		hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, e := quic.DialAddr(hctx, addr, tc, &quic.Config{HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 180 * time.Second, MaxIncomingStreams: 0, MaxIncomingUniStreams: 8})
		cancel()
		if e == nil {
			tr := &http3.Transport{MaxResponseHeaderBytes: 8192, DisableCompression: true}
			client := tr.NewClientConn(conn)
			return &Connection{client: &http.Client{Transport: client, CheckRedirect: noRedirect}, close: func() { _ = conn.CloseWithError(0, "") }, base: base, Kind: "h3"}, nil
		}
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
	conn, e := d.DialContext(ctx, "tcp", target)
	if e != nil {
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
		if e = req.Write(conn); e != nil {
			return nil, stage("proxy_connect_failed")
		}
		br := bufio.NewReaderSize(io.LimitReader(conn, 8192), 8192)
		res, e := http.ReadResponse(br, req)
		if e != nil || br.Buffered() != 0 {
			return nil, stage("proxy_connect_failed")
		}
		if res.StatusCode != 200 {
			return nil, stage(fmt.Sprintf("proxy_connect_http_%d", res.StatusCode))
		}
	}
	tc.NextProtos = []string{"h2"}
	secure := tls.Client(conn, tc)
	if e = secure.HandshakeContext(ctx); e != nil {
		return nil, stage(tlsStage(e))
	}
	if secure.ConnectionState().NegotiatedProtocol != "h2" {
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
	res, e := c.client.Do(req)
	if e != nil {
		return nil, stage("request_failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, stage(fmt.Sprintf("http_status_%d", res.StatusCode))
	}
	f, _, e := wire.Read(res.Body, wire.MaxControl, nil)
	if e != nil {
		return nil, stage("invalid_response_frame")
	}
	var tail [1]byte
	if n, e := res.Body.Read(tail[:]); n != 0 || e != io.EOF {
		return nil, stage("trailing_response")
	}
	return checked(f)
}
func checked(f *pb.Frame) (*pb.Frame, error) {
	if f.GetFailure() != nil {
		v := f.GetFailure()
		return nil, &Failure{v.Code, time.Duration(min(v.RetryAfterSeconds, 900)) * time.Second}
	}
	return f, nil
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
	go func() {
		if e := wire.Write(w, first); e != nil {
			_ = w.CloseWithError(e)
		}
	}()
	res, e := c.client.Do(req)
	if e != nil {
		cancel()
		w.Close()
		return nil, nil, stage("request_failed")
	}
	ch := &Channel{writer: w, body: res.Body, cancel: cancel}
	if res.StatusCode != 200 {
		ch.Close()
		return nil, nil, stage(fmt.Sprintf("http_status_%d", res.StatusCode))
	}
	f, _, e := wire.Read(&progressBody{reader: ch.body, cancel: ch.cancel}, wire.MaxControl, nil)
	if e != nil {
		ch.Close()
		return nil, nil, stage("invalid_response_frame")
	}
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
	if e := wire.Write(c.writer, f); e != nil {
		return nil, stage("stream_write_failed")
	}
	reply, _, e := wire.Read(&progressBody{reader: c.body, cancel: c.cancel}, wire.MaxControl, nil)
	if e != nil {
		return nil, stage("stream_read_failed")
	}
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
