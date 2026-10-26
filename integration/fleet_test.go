//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/config"
	"gopkg.in/yaml.v3"
)

// fleetProxy models distinct customer egress addresses. No cloud admission or
// enrollment limits are raised for the test; TLS remains end to end.
func fleetProxy(t *testing.T, index int, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != u.Host {
			http.Error(w, "invalid target", 403)
			return
		}
		dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("127.1.%d.%d", index/254, index%254+1))}}
		upstream, err := dialer.DialContext(r.Context(), "tcp", u.Host)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		go func() { _, _ = io.Copy(upstream, buffered); upstream.Close() }()
		_, _ = io.Copy(client, upstream)
		client.Close()
		upstream.Close()
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// TestSensorFleet drives independent sensor clients through actual edge processes,
// the actual cloud process and the real core/database. Run via fixture.py --sensors.
func TestSensorFleet(t *testing.T) {
	f := load(t)
	var manifest struct {
		Sensors           int
		Rounds            int
		AdmissionCapacity bool
		AdmissionSeconds  int
		StartGapMillis    int
		Output            string
		Stress            bool
		ObserveSeconds    int
		DrainSeconds      int
		Fleet             []struct {
			Licence  json.RawMessage
			Bindings []struct {
				ID        string `json:"id"`
				StreamKey string `json:"streamKey"`
				SourceID  string `json:"deviceId"`
				Index     int
			}
		}
	}
	raw, err := os.ReadFile(os.Getenv("CI_GATEWAY_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.AdmissionSeconds == 0 {
		manifest.AdmissionSeconds = 180
	}
	if manifest.Sensors == 0 {
		t.Skip("use fixture.py --sensors")
	}
	const token = "fleet_fixture_only_high_entropy_token_12345678901234567890"
	digest := sha256.Sum256([]byte(token))
	var sensors []fleetSensor
	var statusURLs []string
	var logPaths []string
	for n, gateway := range manifest.Fleet {
		if n > 0 && manifest.StartGapMillis > 0 {
			time.Sleep(time.Duration(manifest.StartGapMillis) * time.Millisecond)
		}
		dir := t.TempDir()
		license := filepath.Join(dir, "license.json")
		if err = os.WriteFile(license, gateway.Licence, 0600); err != nil {
			t.Fatal(err)
		}
		c := new(config.Config)
		c.StateDir = filepath.Join(dir, "state")
		c.DeploymentLicensePath = license
		c.StatusListen = address(t)
		c.Buffer.MaxBytes = 64 << 20
		c.Buffer.MaxAgeDays = 7
		c.Buffer.MaxSegments = 10000
		c.Uplink.ForceTCP = true
		c.Uplink.Proxy = fleetProxy(t, n, f.URL)
		c.Modules.RemoteWrite.Enabled = true
		c.Modules.RemoteWrite.Listen = address(t)
		c.Modules.RemoteWrite.Principals = []config.Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(digest[:])}}
		for _, b := range gateway.Bindings {
			c.Bindings = append(c.Bindings, config.Binding{ID: b.ID, StreamKey: b.StreamKey, SourceID: b.SourceID, Kind: "series", Selector: map[string]string{"sensor": fmt.Sprint(b.Index)}, Principals: []string{"writer"}, Scale: 1})
			sensors = append(sensors, fleetSensor{"http://" + c.Modules.RemoteWrite.Listen + "/api/v1/write", b.Index})
		}
		cfg, _ := yaml.Marshal(c)
		path := filepath.Join(dir, "config.yaml")
		if err = os.WriteFile(path, cfg, 0600); err != nil {
			t.Fatal(err)
		}
		logPath := filepath.Join(dir, "edge.log")
		out, e := os.Create(logPath)
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(filepath.Join("..", "bin", "edgegateway"), "-config", path)
		cmd.Env = append(os.Environ(), "EDGE_STATE_DIR=", "EDGE_LICENSE_PATH=", "HTTPS_PROXY=", "GOMAXPROCS=1")
		cmd.Stdout, cmd.Stderr = out, out
		if e = cmd.Start(); e != nil {
			out.Close()
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait(); _ = out.Close() })
		status := "http://" + c.StatusListen
		statusURLs = append(statusURLs, status)
		logPaths = append(logPaths, logPath)
		client := &http.Client{Timeout: time.Second}
		ready := false
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
			r, e := client.Get(status + "/healthz")
			if e == nil {
				r.Body.Close()
				if r.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !ready {
			logs, _ := os.ReadFile(logPath)
			t.Fatalf("edge %d not ready: %s", n, logs)
		}
	}
	if len(sensors) != manifest.Sensors {
		t.Fatal("incomplete fleet")
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		counts := map[string]int{}
		for _, path := range logPaths {
			raw, _ := os.ReadFile(path)
			for _, line := range strings.Split(string(raw), "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["event"] == "uplink_retry" {
					if reason, ok := event["reason"].(string); ok {
						counts[reason]++
					}
				}
			}
		}
		raw, _ := json.MarshalIndent(map[string]any{"retryReasons": counts, "cloud": admin(t, f, "/cloud-metrics", nil)}, "", "  ")
		_ = os.WriteFile(manifest.Output+".failure.json", raw, 0600)
	})
	// Enrollment and change-feed refresh precede load. Existing admission budgets remain unchanged.
	admissionStarted := time.Now()
	enrolled := false
	admittedBeforeLoad := 0
	for deadline := time.Now().Add(time.Duration(manifest.AdmissionSeconds) * time.Second); time.Now().Before(deadline); {
		if n := fleetSessions(t, f); n >= min(len(manifest.Fleet), 256) {
			admittedBeforeLoad = n
			enrolled = true
			break
		}
		time.Sleep(time.Second)
	}
	if !enrolled {
		t.Fatal("fleet did not finish authenticated control admission before sensor load")
	}

	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConns: manifest.Sensors, MaxIdleConnsPerHost: 100, IdleConnTimeout: 20 * time.Second}}
	defer client.CloseIdleConnections()
	var retries, failures int64
	var latencies []float64
	started := time.Now()
	report := map[string]any{"sensors": len(sensors), "edgeGateways": len(manifest.Fleet), "admissionDeadlineSeconds": manifest.AdmissionSeconds, "admissionElapsedSeconds": time.Since(admissionStarted).Seconds(), "rounds": manifest.Rounds, "burstSkipped": manifest.Rounds == 0, "transport": "HTTP/2 mTLS uplink; authenticated Prometheus remote write ingress"}
	for round := 0; round < manifest.Rounds; round++ {
		result := fleetRound(t, sensors, round, token, client)
		retries += result.Retries
		failures += result.Failures
		latencies = append(latencies, result.Latencies...)
		t.Logf("round %d ingress acknowledged; retries=%d failures=%d", round+1, retries, failures)
	}
	if failures != 0 {
		t.Errorf("%d sensor submissions failed", failures)
	}

	expected := manifest.Sensors * manifest.Rounds
	retiredIndexes := map[int]bool{}
	full, tail := manifest.Sensors/100, manifest.Sensors%100
	expectedTotal := float64(manifest.Rounds)*(20*float64(manifest.Sensors)+float64(full*4950+tail*(tail-1)/2)/10) + float64(manifest.Sensors)*float64(manifest.Rounds*(manifest.Rounds-1))/200
	if manifest.AdmissionCapacity {
		t.Log("observing configured 256-session ceiling before retiring already-drained gateways")
		peak := admittedBeforeLoad
		for until := time.Now().Add(45 * time.Second); time.Now().Before(until); {
			n := fleetSessions(t, f)
			peak = max(peak, n)
			if n > 256 {
				t.Fatalf("per-organization session cap exceeded: %d", n)
			}
			time.Sleep(time.Second)
		}
		if peak != 256 {
			t.Fatalf("did not reach configured session ceiling: %d", peak)
		}
		report["admissionCeiling"] = map[string]any{"observedSessions": peak, "attemptedGateways": len(manifest.Fleet), "beforeRetirement": admin(t, f, "/cloud-metrics", nil)}
		var eligible []int
		for index, url := range statusURLs {
			r, err := client.Get(url + "/metrics")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "edgegateway_buffer_bytes 0\n") {
				eligible = append(eligible, index)
			}
		}
		retired := admin(t, f, "/retire-drained-fleet", map[string]any{"eligibleIndexes": eligible})
		for _, raw := range retired["retiredIndexes"].([]any) {
			retiredIndexes[int(raw.(float64))] = true
		}
		if retired["retiredCount"].(float64) < 44 {
			t.Fatalf("not enough delivered gateways could retire: %v", retired)
		}
		report["capacityRecovery"] = retired
	}
	deadline := time.Now().Add(time.Duration(manifest.DrainSeconds) * time.Second)
	var stats map[string]any
	delivered := false
	for time.Now().Before(deadline) {
		stats = admin(t, f, "/stats", nil)
		fleet := stats["fleet"].(map[string]any)
		if int(fleet["points"].(float64)) == expected {
			if expected > 0 && (int(fleet["sensors"].(float64)) != manifest.Sensors || math.Abs(fleet["total"].(float64)-expectedTotal) > 0.01) {
				t.Fatal("delivered sensor identity/value mismatch")
			}
			delivered = true
			break
		}
		t.Logf("database delivery: %.0f/%d", fleet["points"], expected)
		time.Sleep(5 * time.Second)
	}
	sort.Float64s(latencies)
	report["retries"], report["failures"], report["delivered"], report["elapsedSeconds"] = retries, failures, delivered, time.Since(started).Seconds()
	report["database"], report["cloudProcess"] = stats, admin(t, f, "/process", nil)
	if len(latencies) > 0 {
		report["ingressP50Millis"], report["ingressP95Millis"], report["ingressMaxMillis"] = latencies[len(latencies)/2], latencies[len(latencies)*95/100], latencies[len(latencies)-1]
	}
	var metrics []string
	for index, url := range statusURLs {
		if retiredIndexes[index] {
			continue
		}
		r, e := client.Get(url + "/metrics")
		if e != nil {
			t.Error(e)
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		metrics = append(metrics, string(b))
	}
	// Verify real process telemetry through core, not a UI fixture.
	telemetryDeadline := time.Now().Add(20 * time.Second)
	for {
		observation := admin(t, f, "/cloud-metrics", nil)
		instances, _ := observation["instances"].([]any)
		if len(instances) > 0 && instances[0].(map[string]any)["accepted"].(float64) >= float64(expected) {
			report["cloudTelemetry"] = observation
			break
		}
		if time.Now().After(telemetryDeadline) {
			t.Error("cloud metrics did not report durable outcomes")
			report["cloudTelemetry"] = observation
			break
		}
		time.Sleep(time.Second)
	}
	report["edgeMetrics"] = metrics
	report["retiredDrainedEdges"] = len(retiredIndexes)
	b, _ := json.MarshalIndent(report, "", "  ")
	if e := os.WriteFile(manifest.Output, b, 0600); e != nil {
		t.Fatal(e)
	}
	if manifest.Stress {
		stressFleet(t, f, sensors, token, manifest.Output, client)
		// Core commit can precede the final edge receipt. Verify queue reclamation
		// after sustained load as well as after the initial simultaneous burst.
		allEmpty := false
		for until := time.Now().Add(30 * time.Second); time.Now().Before(until); {
			metrics = nil
			allEmpty = true
			for _, url := range statusURLs {
				r, err := client.Get(url + "/metrics")
				if err != nil {
					t.Fatal(err)
				}
				raw, err := io.ReadAll(r.Body)
				r.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				metrics = append(metrics, string(raw))
				allEmpty = allEmpty && strings.Contains(string(raw), "edgegateway_buffer_bytes 0\n")
			}
			if allEmpty {
				break
			}
			time.Sleep(time.Second)
		}
		if !allEmpty {
			t.Error("durable queues did not reclaim final stress receipts")
		}
		report["postStressEdgeMetrics"] = metrics
		report["postStressQueuesEmpty"] = allEmpty
		report["postStressDatabase"] = admin(t, f, "/stats", nil)
		b, _ = json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(manifest.Output, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if manifest.ObserveSeconds > 0 {
		t.Log("fleet held for live admin observation")
		time.Sleep(time.Duration(manifest.ObserveSeconds) * time.Second)
	}
	for _, path := range logPaths {
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), token) {
			t.Error("writer token leaked")
		}
	}
	if !delivered {
		t.Fatalf("fleet did not drain: %v", stats)
	}
	for _, m := range metrics {
		if !strings.Contains(m, "edgegateway_buffer_bytes 0\n") {
			t.Error("durable queue did not drain")
		}
		for _, line := range strings.Split(m, "\n") {
			if strings.HasPrefix(line, "edgegateway_drops_total{") && !strings.HasSuffix(line, " 0") {
				t.Errorf("sensor samples dropped: %s", line)
			}
		}
		if !strings.Contains(m, "edgegateway_rejected_total 0\n") {
			t.Error("core permanently rejected a valid simulated sensor sample")
		}
		if strings.Contains(m, "edgegateway_integrity_alarm 1") {
			t.Error("edge buffer integrity alarm")
		}
	}
}
