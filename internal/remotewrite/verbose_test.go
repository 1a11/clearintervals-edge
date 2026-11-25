package remotewrite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/1a11/clearintervals-edge/internal/diag"
	"github.com/golang/snappy"
)

func snappyEncode(raw []byte) []byte { return snappy.Encode(nil, raw) }

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// verboseCapture installs a verbose logger and returns the buffer its events land in.
func verboseCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.MessageKey {
			a.Key = "event"
		}
		return a
	}}))
	diag.Set(log, true)
	t.Cleanup(func() { diag.Set(nil, false) })
	return &buf
}

func verboseEvents(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if e := json.Unmarshal([]byte(line), &event); e != nil {
			t.Fatalf("verbose line is not JSON: %v (%s)", e, line)
		}
		out = append(out, event)
	}
	return out
}

func named(events []map[string]any, name string) []map[string]any {
	out := []map[string]any{}
	for _, e := range events {
		if e["event"] == name {
			out = append(out, e)
		}
	}
	return out
}

// Verbose mode exists to answer "why is this sample not reaching the cloud": it must name the labels received,
// the binding matched and, when nothing matched, the exact selector label that differed or was absent.
func TestVerboseLogsMatchedAndUnmappedSeries(t *testing.T) {
	buf := verboseCapture(t)
	m, _ := module(t)
	at := time.Now().UnixMilli()

	if w := submit(m, snappyEncode(request(1480, at)), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("matched write: %d %s", w.Code, w.Body.String())
	}

	// A required label the writer did not send makes the same series unmapped.
	m.Config.Get().Bindings[0].Selector["must_exist"] = ""
	if w := submit(m, snappyEncode(request(42, at)), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("unmapped write: %d", w.Code)
	}

	// A matched series whose principal is not allowed is refused item by item.
	delete(m.Config.Get().Bindings[0].Selector, "must_exist")
	m.Config.Get().Bindings[0].Principals = []string{"someone_else"}
	if w := submit(m, snappyEncode(request(7, at)), testToken, "snappy"); w.Code != 403 {
		t.Fatalf("forbidden principal: %d", w.Code)
	}
	m.Config.Get().Bindings[0].Principals = []string{"writer"}

	// A wrong token is refused before decoding; the log must say so and show the digest comparison.
	byToken := strings.Repeat("x", 60)
	if w := submit(m, snappyEncode(request(1, at)), byToken, "snappy"); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}

	events := verboseEvents(t, buf)

	requests := named(events, "verbose_remotewrite_request")
	if len(requests) != 4 {
		t.Fatalf("want 4 request events, got %d", len(requests))
	}
	first := requests[0]
	if first["authorization"] != "Bearer "+testToken || first["path"] != "/api/v1/write" || first["method"] != "POST" ||
		first["uri"] != "/api/v1/write" || first["proto"] != "HTTP/1.1" {
		t.Fatalf("request event lacks the request: %v", first)
	}
	headers, ok := first["headers"].(map[string]any)
	if !ok || headers["Authorization"] != "Bearer "+testToken || headers["Content-Type"] != "application/x-protobuf" {
		t.Fatalf("request headers: %v", first["headers"])
	}

	moduleAuths := named(events, "verbose_remotewrite_auth")
	if len(moduleAuths) != 4 || moduleAuths[0]["status"] != float64(0) || moduleAuths[0]["principal"] != "writer" ||
		moduleAuths[0]["bearerSha256"] != sha256Hex(testToken) || moduleAuths[0]["reason"] != "accepted" {
		t.Fatalf("auth events: %v", moduleAuths)
	}
	if moduleAuths[3]["status"] != float64(401) || !strings.Contains(moduleAuths[3]["reason"].(string), "digest matches no principal") {
		t.Fatalf("refused auth event: %v", moduleAuths[3])
	}

	payloads := named(events, "verbose_remotewrite_payload")
	if len(payloads) != 3 {
		t.Fatalf("want 3 payload events, got %d", len(payloads))
	}
	decoded := payloads[0]
	if decoded["stage"] != "decoded" || decoded["decodedSeriesCount"] != float64(1) || decoded["totalSamples"] != float64(1) ||
		decoded["encoding"] != "snappy" || decoded["compressedBytes"] == nil || decoded["decompressedBytes"] == nil {
		t.Fatalf("payload event: %v", decoded)
	}
	if first["bearerSha256"] != sha256Hex(testToken) {
		t.Fatalf("bearer digest %v", first["bearerSha256"])
	}
	principals, ok := first["principals"].([]any)
	if !ok || len(principals) != 1 || principals[0].(map[string]any)["tokenMatch"] != true {
		t.Fatalf("principal comparison missing: %v", first["principals"])
	}

	auths := named(events, "verbose_writer_auth")
	if len(auths) != 4 || auths[0]["matchedPrincipal"] != "writer" || auths[0]["method"] != "bearer" {
		t.Fatalf("auth events: %v", auths)
	}
	if auths[3]["status"] != float64(401) || auths[3]["matchedPrincipal"] != "" {
		t.Fatalf("refused auth event: %v", auths[3])
	}

	series := named(events, "verbose_remotewrite_series")
	if len(series) != 3 {
		t.Fatalf("want 3 series events, got %d", len(series))
	}
	matched, unmapped, forbidden := series[0], series[1], series[2]
	if matched["outcome"] != "matched" || matched["bindingId"] != "binding_v1" || matched["sourceId"] != "canonical" ||
		matched["streamKey"] != strings.Repeat("k", 43) || matched["scale"] != float64(1) {
		t.Fatalf("matched event: %v", matched)
	}
	labels, ok := matched["receivedLabels"].(map[string]any)
	if !ok || labels["__name__"] != "rpm" {
		t.Fatalf("received labels: %v", matched["receivedLabels"])
	}
	if plain, ok := matched["labels"].(map[string]any); !ok || plain["__name__"] != "rpm" {
		t.Fatalf("labels: %v", matched["labels"])
	}
	samples, ok := matched["samples"].([]any)
	if !ok || len(samples) != 1 || samples[0].(map[string]any)["value"] != float64(1480) {
		t.Fatalf("samples: %v", matched["samples"])
	}

	if unmapped["outcome"] != "unmapped" {
		t.Fatalf("unmapped outcome: %v", unmapped["outcome"])
	}
	diffs, ok := unmapped["bindingDiffs"].([]any)
	if !ok || len(diffs) != 1 {
		t.Fatalf("binding diffs: %v", unmapped["bindingDiffs"])
	}
	diff := diffs[0].(map[string]any)
	if diff["bindingId"] != "binding_v1" || diff["missingLabels"].([]any)[0] != "must_exist" {
		t.Fatalf("diff: %v", diff)
	}

	if forbidden["outcome"] != "rejected" || forbidden["status"] != float64(403) ||
		!strings.Contains(forbidden["reason"].(string), "not allowed") {
		t.Fatalf("forbidden series event: %v", forbidden)
	}

	rejected := named(events, "verbose_remotewrite_rejected")
	if len(rejected) != 2 {
		t.Fatalf("want 2 rejection events, got %v", rejected)
	}
	if rejected[0]["status"] != float64(403) || rejected[0]["stage"] != "principal_not_on_binding" {
		t.Fatalf("forbidden rejection: %v", rejected[0])
	}
	if rejected[1]["status"] != float64(401) || rejected[1]["stage"] != "authentication" {
		t.Fatalf("auth rejection: %v", rejected[1])
	}
}

// Verbose mode is inert unless enabled, so normal deployments keep the redacted log.
func TestVerboseOffWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	diag.Set(slog.New(slog.NewJSONHandler(&buf, nil)), false)
	t.Cleanup(func() { diag.Set(nil, false) })
	m, _ := module(t)
	if w := submit(m, snappyEncode(request(7, time.Now().UnixMilli())), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("write: %d", w.Code)
	}
	if strings.Contains(buf.String(), "verbose_") {
		t.Fatalf("verbose events written while disabled: %s", buf.String())
	}
}

// A Kubernetes block carries tens of thousands of unmapped series. Logging each one would flood stdout, so only
// the first few and any near-miss on a configured metric are logged in full and the rest are summarized.
func TestVerboseUnmappedBatchesAreSummarized(t *testing.T) {
	buf := verboseCapture(t)
	m, q := module(t)
	m.Config.Get().Bindings[0].Selector["instance"] = "target"
	at := time.Now().UnixMilli()
	batch := make([][]byte, 0, 27)
	for i := 0; i < 25; i++ {
		batch = append(batch, timeSeries(map[string]string{"__name__": "kube_pod_info", "pod": fmt.Sprintf("p-%d", i)}, 1, at))
	}
	batch = append(batch, timeSeries(map[string]string{"__name__": "rpm", "instance": "other"}, 2, at))
	batch = append(batch, timeSeries(map[string]string{"__name__": "rpm", "instance": "target"}, 3, at))
	if w := submit(m, snappyEncode(bytes.Join(batch, nil)), testToken, "snappy"); w.Code != 204 {
		t.Fatalf("batch refused: %d", w.Code)
	}

	events := verboseEvents(t, buf)
	unmapped, nearMisses, matched := 0, 0, 0
	for _, e := range named(events, "verbose_remotewrite_series") {
		switch e["outcome"] {
		case "matched":
			matched++
		case "unmapped":
			unmapped++
			if labels, ok := e["labels"].(map[string]any); ok && labels["__name__"] == "rpm" {
				nearMisses++
			}
		}
	}
	if matched != 1 || unmapped != 21 || nearMisses != 1 {
		t.Fatalf("matched %d, unmapped logs %d, near-misses %d", matched, unmapped, nearMisses)
	}
	summary := named(events, "verbose_remotewrite_unmapped_summary")
	if len(summary) != 1 || summary[0]["totalUnmappedSeries"] != float64(26) || summary[0]["totalUnmappedSamples"] != float64(26) {
		t.Fatalf("summary: %v", summary)
	}
	names, ok := summary[0]["sampleMetricNames"].([]any)
	if !ok || len(names) != 2 || names[0] != "kube_pod_info" || names[1] != "rpm" {
		t.Fatalf("summary metric names: %v", summary[0]["sampleMetricNames"])
	}
	if stats, _, _ := q.Snapshot(); stats.Drops["unmapped"] != 26 {
		t.Fatalf("unmapped accounting: %v", stats.Drops)
	}
}
