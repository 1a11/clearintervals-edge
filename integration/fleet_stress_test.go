//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fleetPoints(t *testing.T, f *fixture) float64 {
	t.Helper()
	return admin(t, f, "/stats", nil)["fleet"].(map[string]any)["points"].(float64)
}

// Open-loop plateaus measure durable core throughput separately from local queue admission.
// Rising backlog is saturation even when edge HTTP ingress keeps returning 204.
func stressFleet(t *testing.T, f *fixture, sensors []fleetSensor, token, output string, client *http.Client) {
	t.Helper()
	// Interleave gateways, so changing the offered rate does not accidentally change
	// how many edge processes carry traffic merely because bindings were seeded in groups.
	groups := map[string][]fleetSensor{}
	var urls []string
	for _, sensor := range sensors {
		if _, ok := groups[sensor.URL]; !ok {
			urls = append(urls, sensor.URL)
		}
		groups[sensor.URL] = append(groups[sensor.URL], sensor)
	}
	var spread []fleetSensor
	for index := 0; len(spread) < len(sensors); index++ {
		for _, url := range urls {
			if index < len(groups[url]) {
				spread = append(spread, groups[url][index])
			}
		}
	}
	sensors = spread
	var stages []map[string]any
	var cursor int64
	run := func(rate, seconds int) bool {
		before := fleetPoints(t, f)
		var accepted, failed, limited, inflight atomic.Int64
		var mu sync.Mutex
		var latencies []float64
		var wg sync.WaitGroup
		start := time.Now()
		type sample struct{ Seconds, Backlog float64 }
		var samples []sample
		stop := make(chan struct{})
		sampled := make(chan struct{})
		go func() {
			defer close(sampled)
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					committed := fleetPoints(t, f) - before
					samples = append(samples, sample{time.Since(start).Seconds(), float64(accepted.Load()) - committed})
				}
			}
		}()
		count := rate * seconds
		for n := 0; n < count; n++ {
			target := start.Add(time.Duration(float64(n) / float64(rate) * float64(time.Second)))
			if delay := time.Until(target); delay > 0 {
				time.Sleep(delay)
			}
			if inflight.Load() >= 2048 {
				failed.Add(1)
				continue
			}
			i := int(atomic.AddInt64(&cursor, 1)-1) % len(sensors)
			sensor := sensors[i]
			inflight.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer inflight.Add(-1)
				began := time.Now()
				body := pointBody(sensor.Index, 0, time.Now().UnixMilli())
				request, _ := http.NewRequest(http.MethodPost, sensor.URL, bytes.NewReader(body))
				request.Header.Set("Authorization", "Bearer "+token)
				request.Header.Set("Content-Type", "application/x-protobuf")
				request.Header.Set("Content-Encoding", "snappy")
				request.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
				response, err := client.Do(request)
				if err != nil {
					failed.Add(1)
					return
				}
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode == 204 {
					accepted.Add(1)
				} else {
					failed.Add(1)
					if response.StatusCode == 429 || response.StatusCode == 503 {
						limited.Add(1)
					}
				}
				mu.Lock()
				latencies = append(latencies, float64(time.Since(began).Microseconds())/1000)
				mu.Unlock()
			}()
		}
		if delay := time.Until(start.Add(time.Duration(seconds) * time.Second)); delay > 0 {
			time.Sleep(delay)
		}
		close(stop)
		<-sampled
		atEnd := fleetPoints(t, f)
		measuredSeconds := time.Since(start).Seconds()
		wg.Wait()
		sort.Float64s(latencies)
		stage := map[string]any{"targetRecordsPerSecond": rate, "durationSeconds": measuredSeconds, "offered": count,
			"ingressAccepted": accepted.Load(), "failed": failed.Load(), "backpressure": limited.Load(),
			"coreCommitted": atEnd - before, "coreRecordsPerSecond": (atEnd - before) / measuredSeconds,
			"backlogAtWindowEnd": float64(accepted.Load()) - (atEnd - before), "cloud": admin(t, f, "/cloud-metrics", nil), "process": admin(t, f, "/process", nil)}
		if len(latencies) > 0 {
			stage["ingressP50Millis"] = latencies[len(latencies)/2]
			stage["ingressP95Millis"] = latencies[len(latencies)*95/100]
			stage["ingressMaxMillis"] = latencies[len(latencies)-1]
		}
		// Compare average backlog after warm-up with the final observations. A rising
		// queue is overload even if a short plateau happens to commit 95 percent.
		var early, late, earlyT, lateT float64
		var ne, nl int
		for _, sample := range samples {
			if sample.Seconds >= float64(seconds)*.2 && sample.Seconds <= float64(seconds)*.45 {
				early += sample.Backlog
				earlyT += sample.Seconds
				ne++
			}
			if sample.Seconds >= float64(seconds)*.75 {
				late += sample.Backlog
				lateT += sample.Seconds
				nl++
			}
		}
		growth, span := 0.0, 0.0
		if ne > 0 && nl > 0 {
			span = lateT/float64(nl) - earlyT/float64(ne)
			growth = (late/float64(nl) - early/float64(ne)) / span
		}
		stage["backlogSamples"] = samples
		stage["backlogGrowthPerSecond"] = growth
		stage["comparisonSpanSeconds"] = span
		stage["backlogGrowthLimitPerSecond"] = max(float64(rate)*.01, 2/max(span, 1))
		sustainable := stressKeptUp(float64(rate), float64(count), atEnd-before, failed.Load(), growth, span)
		stage["keptUp"] = sustainable
		stages = append(stages, stage)
		raw, _ := json.MarshalIndent(map[string]any{"sensors": len(sensors), "edgeGateways": len(urls), "sourceOrder": "round-robin across gateways", "stages": stages, "criterion": "At least 95% durably committed within the plateau, no ingress failures, and post-warmup backlog growth <=1% of offered rate with a two-record counter-resolution allowance"}, "", "  ")
		if err := os.WriteFile(output+".stress.json", raw, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("stress rate=%d/s duration=%ds ingress=%d/%d core=%.0f rate=%.1f/s keptUp=%v", rate, seconds, accepted.Load(), count, atEnd-before, (atEnd-before)/measuredSeconds, sustainable)
		deadline := time.Now().Add(120 * time.Second)
		expected := before + float64(accepted.Load())
		for fleetPoints(t, f) < expected && time.Now().Before(deadline) {
			time.Sleep(time.Second)
		}
		if fleetPoints(t, f) < expected {
			t.Error("stress backlog did not recover within 120 seconds")
			return false
		}
		return sustainable
	}
	best, ceiling, misses := 0, 0, 0
	for _, rate := range []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192} {
		seconds := 30
		if rate <= 4 {
			// Give small rates enough observations that a single in-flight record
			// does not decide a five-percent throughput threshold.
			seconds = 60
		}
		keptUp := run(rate, seconds)
		if t.Failed() {
			return
		}
		if !keptUp {
			if ceiling == 0 {
				ceiling = rate
			}
			misses++
			if misses >= 2 {
				break
			}
			continue
		}
		best, ceiling, misses = rate, 0, 0
	}
	for best > 0 && ceiling-best > 4 {
		middle := ((best + ceiling) / 2) / 4 * 4
		if middle <= best {
			break
		}
		if run(middle, 60) {
			best = middle
		} else {
			ceiling = middle
		}
	}
	for best > 0 {
		if run(best, 180) {
			break
		}
		ceiling = best
		if best <= 4 {
			best /= 2
		} else {
			best -= 4
		}
	}
	raw, err := os.ReadFile(output + ".stress.json")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	result["confirmedRecordsPerSecond"] = best
	if best == 0 {
		result["confirmedRecordsPerSecond"] = nil
	}
	result["nearestHigherFailedRecordsPerSecond"] = ceiling
	raw, _ = json.MarshalIndent(result, "", "  ")
	if err = os.WriteFile(output+".stress.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if best > 0 {
		t.Logf("confirmed rate: %d records/s; nearest higher failed rate: %d records/s on this runner/workload", best, ceiling)
	} else {
		t.Log("no positive sustained rate confirmed; inspect the stage evidence")
	}

}

func fleetSessions(t *testing.T, f *fixture) int {
	t.Helper()
	observation := admin(t, f, "/cloud-metrics", nil)
	instances, _ := observation["instances"].([]any)
	total := 0
	for _, raw := range instances {
		row := raw.(map[string]any)
		if row["live"] == true {
			total += int(row["sessions"].(float64))
		}
	}
	return total
}

// Independent ingress/core counters are sampled at different instants. A change
// of one or two records is resolution noise, not evidence of a growing queue.
func stressKeptUp(rate, offered, committed float64, failures int64, growth, span float64) bool {
	return span > 0 && failures == 0 && committed >= offered*.95 && growth <= max(rate*.01, 2/span)
}

func TestStressRateCriterion(t *testing.T) {
	if !stressKeptUp(1, 60, 59, 0, 1.0/30, 30) {
		t.Fatal("one in-flight record classified as overload")
	}
	if stressKeptUp(32, 5760, 5500, 0, 1.5, 100) {
		t.Fatal("growing queue classified as sustainable despite 95% completion")
	}
	if stressKeptUp(1, 60, 56, 0, 0, 30) {
		t.Fatal("missing durable outcomes accepted")
	}
	if stressKeptUp(1, 60, 60, 1, 0, 30) {
		t.Fatal("ingress failure accepted")
	}
	if stressKeptUp(1, 60, 60, 0, 0, 0) {
		t.Fatal("missing backlog observations accepted")
	}
}
