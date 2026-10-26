//go:build integration

package integration

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"google.golang.org/protobuf/encoding/protowire"
)

type fleetSensor struct {
	URL   string
	Index int
}
type writerResult struct {
	Retries   int64
	Failures  int64
	Latencies []float64
}
type writerInput struct {
	Sensors                     []fleetSensor
	Round                       int
	At                          int64
	Token, Start, Ready, Output string
}

func pointBody(index, round int, at int64) []byte {
	field := func(n protowire.Number, b []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
	}
	label := append(field(1, []byte("sensor")), field(2, []byte(fmt.Sprint(index)))...)
	value := binary.LittleEndian.AppendUint64(protowire.AppendTag(nil, 1, protowire.Fixed64Type), math.Float64bits(20+float64(index%100)/10+float64(round)/100))
	value = protowire.AppendVarint(protowire.AppendTag(value, 2, protowire.VarintType), uint64(at))
	return snappy.Encode(nil, field(1, append(field(1, label), field(2, value)...)))
}

func sendFleetRound(input writerInput, client *http.Client) writerResult {
	var retries, failures atomic.Int64
	var mu sync.Mutex
	var result writerResult
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	for _, s := range input.Sensors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := pointBody(s.Index, input.Round, input.At)
			<-barrier
			begin := time.Now()
			for attempt := 0; time.Since(begin) < 90*time.Second; attempt++ {
				r, _ := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+input.Token)
				r.Header.Set("Content-Type", "application/x-protobuf")
				r.Header.Set("Content-Encoding", "snappy")
				r.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
				res, e := client.Do(r)
				code := 0
				if e == nil {
					code = res.StatusCode
					_, _ = io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
				if code == 204 {
					mu.Lock()
					result.Latencies = append(result.Latencies, float64(time.Since(begin).Milliseconds()))
					mu.Unlock()
					return
				}
				if code != 0 && code != 429 && code != 503 {
					failures.Add(1)
					return
				}
				retries.Add(1)
				time.Sleep(time.Duration(100+(s.Index*37+attempt*71)%900) * time.Millisecond)
			}
			failures.Add(1)
		}()
	}
	if input.Start != "" {
		_ = os.WriteFile(input.Ready, []byte("ready"), 0600)
		for deadline := time.Now().Add(30 * time.Second); ; {
			if _, err := os.Stat(input.Start); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return writerResult{Failures: int64(len(input.Sensors))}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	close(barrier)
	wg.Wait()
	result.Retries, result.Failures = retries.Load(), failures.Load()
	return result
}

// Each generator stays below the runner's 16,384 file-descriptor hard limit.
// The shared start file releases all generator processes into the same burst.
func fleetRound(t *testing.T, sensors []fleetSensor, round int, token string, client *http.Client) writerResult {
	t.Helper()
	input := writerInput{Sensors: sensors, Round: round, At: time.Now().UnixMilli(), Token: token}
	if len(sensors) <= 5000 {
		return sendFleetRound(input, client)
	}
	dir := t.TempDir()
	start := filepath.Join(dir, "start")
	var commands []*exec.Cmd
	var inputs []writerInput
	for n := 0; n < len(sensors); n += 5000 {
		last := min(n+5000, len(sensors))
		part := input
		part.Sensors = sensors[n:last]
		part.Start = start
		part.Ready = filepath.Join(dir, fmt.Sprintf("%d.ready", n))
		part.Output = filepath.Join(dir, fmt.Sprintf("%d.out", n))
		path := filepath.Join(dir, fmt.Sprintf("%d.json", n))
		raw, _ := json.Marshal(part)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestFleetWriterWorker$", "-test.timeout=150s")
		command.Env = append(os.Environ(), "CI_FLEET_WRITER="+path, "GOMAXPROCS=1")
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if command.ProcessState == nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
		})
		commands = append(commands, command)
		inputs = append(inputs, part)
	}
	for _, part := range inputs {
		for deadline := time.Now().Add(30 * time.Second); ; {
			if _, err := os.Stat(part.Ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("writer readiness timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := os.WriteFile(start, []byte("start"), 0600); err != nil {
		t.Fatal(err)
	}
	var result writerResult
	for i, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(inputs[i].Output)
		if err != nil {
			t.Fatal(err)
		}
		var part writerResult
		if err = json.Unmarshal(raw, &part); err != nil {
			t.Fatal(err)
		}
		result.Retries += part.Retries
		result.Failures += part.Failures
		result.Latencies = append(result.Latencies, part.Latencies...)
	}
	return result
}

func TestFleetWriterWorker(t *testing.T) {
	path := os.Getenv("CI_FLEET_WRITER")
	if path == "" {
		t.Skip("fleet subprocess only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input writerInput
	if err = json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConns: 5000, MaxIdleConnsPerHost: 100, IdleConnTimeout: 20 * time.Second}}
	defer client.CloseIdleConnections()
	result := sendFleetRound(input, client)
	raw, _ = json.Marshal(result)
	if err = os.WriteFile(input.Output, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
