package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/1a11/clearintervals-edge/internal/auth"
	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/captures"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/httpauth"
	"github.com/1a11/clearintervals-edge/internal/identity"
	"github.com/1a11/clearintervals-edge/internal/remotewrite"
	"github.com/1a11/clearintervals-edge/internal/uplink"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	hash := flag.Bool("hash-password", false, "Read a generated writer password from stdin and print its Argon2id hash")
	path := flag.String("config", "/etc/edgegateway/config.yaml", "Local configuration")
	check := flag.Bool("check", false, "Validate configuration without opening listeners or sending data")
	showVersion := flag.Bool("version", false, "Print the release version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *hash {
		raw, e := io.ReadAll(io.LimitReader(os.Stdin, 258))
		if e != nil || len(raw) > 257 {
			logger.Error("invalid_password", "hint", "Pipe one password of at most 256 bytes on stdin.")
			os.Exit(1)
		}
		value, e := auth.Hash(strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r"))
		if e != nil {
			logger.Error("invalid_password", "hint", "Use a generated password of 32 to 256 bytes.")
			os.Exit(1)
		}
		fmt.Println(value)
		return
	}
	if e := run(*path, *check); e != nil {
		if *check {
			logger.Error("configuration_invalid", stopAttrs(e)...)
		} else {
			logger.Error("gateway_stopped", stopAttrs(e)...)
		}
		os.Exit(1)
	}
}
func run(path string, check bool) error {
	c, e := config.Load(path)
	if e != nil {
		return e
	}
	if check {
		logger.Info("configuration_valid", "config", path, "remoteWrite", c.Modules.RemoteWrite.Enabled, "captures", c.Modules.Captures.Enabled, "bindings", len(c.Bindings))
		return nil
	}
	logger.Info("gateway_starting", "version", version, "config", path, "stateDir", c.StateDir)
	lock, e := durable.Lock(c.StateDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	q, e := buffer.Open(filepath.Join(c.StateDir, "buffer"), c.Buffer.MaxBytes, c.MaxAge(), c.Buffer.MaxSegments)
	if e != nil {
		return e
	}
	stats, size, segments := q.Snapshot()
	if stats.Revoked {
		return errRevoked
	}
	logger.Info("buffer_opened", "bufferBytes", size, "segments", segments, "maxBytes", c.Buffer.MaxBytes, "maxAgeDays", c.Buffer.MaxAgeDays)
	manager, e := identity.Open(filepath.Join(c.StateDir, "identity"), c.DeploymentLicensePath)
	if e != nil {
		return e
	}
	state := "enrolled"
	if manager.Active == nil {
		state = "not_enrolled"
	}
	if manager.Pending != nil {
		state = "operation_pending"
	}
	logger.Info("identity_loaded", "gatewayId", manager.Trust.GatewayID, "region", manager.Trust.Region, "state", state)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	store := config.New(c)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	var wg sync.WaitGroup
	defer wg.Wait()
	servers := []*http.Server{}
	defer func() {
		cancel()
		for _, s := range servers {
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Shutdown(shutdown)
			cancel()
		}
	}()
	errc := make(chan error, 4)
	serve := func(name, addr string, h http.Handler, tlsConfig *tls.Config, connectionLimit int) error {
		listener, e := net.Listen("tcp", addr)
		if e != nil {
			return e
		}
		logger.Info("listener_started", "listener", name, "address", listener.Addr().String(), "tls", tlsConfig != nil)
		listener = &limitedListener{Listener: listener, slots: make(chan struct{}, connectionLimit)}
		s := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(noLog{}, "", 0), TLSConfig: tlsConfig}
		servers = append(servers, s)
		wg.Go(func() {
			var e error
			if tlsConfig != nil {
				e = s.ServeTLS(listener, "", "")
			} else {
				e = s.Serve(listener)
			}
			if !errors.Is(e, http.ErrServerClosed) {
				select {
				case errc <- e:
				default:
				}
			}
		})
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		stats, _, _ := q.Snapshot()
		if stats.Integrity || stats.Revoked {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		s, size, segments := q.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "edgegateway_buffer_bytes %d\nedgegateway_buffer_segments %d\nedgegateway_accepted_total %d\nedgegateway_rejected_total %d\nedgegateway_suspended %d\nedgegateway_integrity_alarm %d\n", size, segments, s.Accepted, s.Rejected, boolInt(s.Suspended), boolInt(s.Integrity))
		for _, reason := range []string{"unmapped", "suspended", "too_old", "evicted", "invalid", "too_large"} {
			fmt.Fprintf(w, "edgegateway_drops_total{reason=%q} %d\n", reason, s.Drops[reason])
		}
	})
	if e = serve("status", c.StatusListen, mux, nil, 80); e != nil {
		return e
	}
	writerAuth := httpauth.New()
	if c.Modules.Captures.Enabled {
		tlsConfig, e := httpauth.TLS(c.Modules.Captures)
		if e != nil {
			return config.Prefix("modules.captures", e)
		}
		if e = serve("captures", c.Modules.Captures.Listen, captures.New(store, q, writerAuth), tlsConfig, 128); e != nil {
			return e
		}
	}
	if c.Modules.RemoteWrite.Enabled {
		tlsConfig, e := remotewrite.TLS(c.Modules.RemoteWrite)
		if e != nil {
			return config.Prefix("modules.remoteWrite", e)
		}
		if e = serve("remoteWrite", c.Modules.RemoteWrite.Listen, remotewrite.NewWithAuth(store, q, writerAuth), tlsConfig, 80); e != nil {
			return e
		}
	}
	if !c.Modules.RemoteWrite.Enabled && !c.Modules.Captures.Enabled {
		logger.Warn("no_modules_enabled", "hint", "No writer can send data. Enable modules.remoteWrite or modules.captures.")
	}
	wg.Go(func() { errc <- forward(ctx, store, q, manager) })
	wg.Go(func() { monitor(ctx, q, time.Minute, 15*time.Minute) })
	logger.Info("gateway_ready", "bindings", len(c.Bindings))
	for {
		select {
		case <-ctx.Done():
			logger.Info("gateway_stopping", "hint", "Signal received; finishing in-flight requests.")
			return nil
		case e := <-errc:
			return e
		case <-hup:
			next, e := config.Load(path)
			if e == nil {
				e = store.Reload(next)
			}
			if e != nil {
				logger.Error("configuration_rejected", append(stopAttrs(e), "kept", "previous configuration")...)
			} else {
				logger.Info("configuration_reloaded", "bindings", len(next.Bindings))
			}
		}
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func forward(ctx context.Context, store *config.Store, q *buffer.Queue, m *identity.Manager) error {
	backoff := 5 * time.Second
	capacityBackoff := time.Duration(0)
	tcpUntil := time.Time{}
	for {
		if ctx.Err() != nil {
			return nil
		}
		c := store.Get()
		if e := m.Prepare(time.Now()); e != nil {
			return e
		}
		var e error
		if m.Pending != nil {
			kind := m.Pending.Kind
			logger.Info("credential_operation_started", "operation", kind)
			// Result retrieval always uses server-only TLS, including after old-leaf expiry.
			conn, x := uplink.Dial(ctx, m.Trust.IngestURL, c.Uplink.Proxy, &tls.Config{RootCAs: m.Roots, MinVersion: tls.VersionTLS13}, true)
			if x == nil {
				e = m.Retrieve(ctx, conn)
				conn.Close()
			} else {
				e = x
			}
			var failure *uplink.Failure
			if errors.As(e, &failure) && failure.Code == "result_unavailable" {
				conn, x = uplink.Dial(ctx, m.Trust.IngestURL, c.Uplink.Proxy, m.TLS(time.Now()), true)
				if x == nil {
					e = m.Issue(ctx, conn)
					conn.Close()
				} else {
					e = x
				}
			}
			if e == nil && m.Pending == nil {
				attrs := []any{"operation", kind}
				if cert, x := m.Certificate(); x == nil {
					attrs = append(attrs, "expiresAt", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
				}
				logger.Info("credential_activated", attrs...)
			}
		} else {
			conn, x := uplink.Dial(ctx, m.Trust.IngestURL, c.Uplink.Proxy, m.TLS(time.Now()), c.Uplink.ForceTCP || time.Now().Before(tcpUntil))
			if x == nil {
				if conn.Kind == "h2" && !c.Uplink.ForceTCP && c.Uplink.Proxy == "" && !time.Now().Before(tcpUntil) {
					tcpUntil = time.Now().Add(30 * time.Minute)
					logger.Warn("quic_unavailable", "fallback", "h2", "retryQuicAfterMinutes", 30, "hint", "HTTP/3 over UDP 443 failed, so the gateway uses HTTP/2 over TCP. Allow outbound UDP 443, or set uplink.forceTcp to skip the attempt.")
				}
				logger.Info("uplink_connected", "transport", conn.Kind)
				cert, x := m.Certificate()
				if x != nil {
					conn.Close()
					return x
				}
				keys := []string{}
				for _, b := range c.Bindings {
					keys = append(keys, b.StreamKey)
				}
				renewAt := cert.Leaf.NotBefore.Add(cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) / 2)
				if conn.Kind == "h2" && !c.Uplink.ForceTCP && c.Uplink.Proxy == "" && tcpUntil.Before(renewAt) {
					renewAt = tcpUntil
				}
				e = conn.Run(ctx, q, m.Trust.GatewayID, m.Active.Generation, keys, renewAt)
				backoff = sessionBackoff(backoff, conn.Established)
				if conn.Established {
					capacityBackoff = 0
				}
				conn.Close()
			} else {
				e = x
			}
		}
		if errors.Is(e, uplink.ErrRenew) || errors.Is(e, uplink.ErrRotate) || e == nil {
			backoff = 5 * time.Second
			continue
		}
		if errors.Is(e, buffer.ErrIntegrity) {
			return e
		}
		var failure *uplink.Failure
		if errors.As(e, &failure) {
			if failure.Code == "revoked" {
				if e = q.SetPolicy("revoked"); e != nil {
					return e
				}
				return errRevoked
			}
			if failure.Code == "organization_suspended" {
				if e = q.SetPolicy("organization_suspended"); e != nil {
					return e
				}
			}
			if failure.Code == "rate_limited" || failure.Code == "invalid_session" {
				backoff, capacityBackoff = capacityRetry(capacityBackoff, failure)
			} else {
				backoff = retryBackoff(backoff, failure)
			}
		}
		delay := backoff + time.Duration(rand.Int64N(int64(backoff/5)+1))
		uplinkRetryEvent(e, delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		backoff = min(backoff*2, 12*time.Minute)
	}
}

func retryBackoff(previous time.Duration, failure *uplink.Failure) time.Duration {
	requested := max(5*time.Second, min(failure.Retry, 15*time.Minute))
	if failure.Code == "rate_limited" || failure.Code == "invalid_session" {
		// The authenticated server supplies the next capacity retry time.
		// Carrying an earlier exponential connection backoff into each new
		// admission attempt can starve healthy sibling gateways for minutes.
		return requested
	}
	return max(previous, requested)
}

type noLog struct{}

func (noLog) Write(b []byte) (int, error) { return len(b), nil }

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { c.once.Do(c.release); return c.Conn.Close() }

// A welcomed session proves recovery from the earlier connection outage. A later
// EOF must not inherit minutes of penalty from attempts before that welcome.
func sessionBackoff(previous time.Duration, established bool) time.Duration {
	if established {
		return 5 * time.Second
	}
	return previous
}

func capacityRetry(streak time.Duration, failure *uplink.Failure) (time.Duration, time.Duration) {
	wait := max(retryBackoff(0, failure), min(streak, time.Minute))
	return wait, min(wait*2, time.Minute)
}
