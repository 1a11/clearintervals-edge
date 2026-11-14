// Package clock compares the host clock with the cloud ingest origin.
package clock

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Thresholds are the drift limits the gateway acts on. The cloud refuses
// captures whose clock is off by more than FailThreshold.
const (
	WarnThreshold    = 2 * time.Second
	FailThreshold    = 30 * time.Second
	StartupThreshold = 60 * time.Second
)

var ErrProbe = errors.New("clock_probe_failed")

// Probe compares the Date header of the ingest origin with the local clock and
// returns local minus server in seconds. Any HTTP answer carries the header, so
// a 2xx, 3xx or 4xx response is enough. The optional roots are the licence trust
// anchors, which a pinned ingest certificate may require.
func Probe(ctx context.Context, ingestURL string, roots ...*x509.CertPool) (float64, error) {
	u, e := url.Parse(ingestURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return 0, fmt.Errorf("%w: the ingest URL must be https://host[:port]", ErrProbe)
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	if len(roots) > 0 && roots[0] != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: roots[0], MinVersion: tls.VersionTLS12}
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+u.Host+"/", nil)
	if e != nil {
		return 0, fmt.Errorf("%w: %v", ErrProbe, e)
	}
	req.Header.Set("User-Agent", "edgegateway-clock-probe")
	res, e := client.Do(req)
	if e != nil {
		return 0, fmt.Errorf("%w: %v", ErrProbe, e)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	server, e := http.ParseTime(res.Header.Get("Date"))
	if e != nil {
		return 0, fmt.Errorf("%w: the ingest origin sent no valid Date header", ErrProbe)
	}
	return time.Since(server).Seconds(), nil
}
