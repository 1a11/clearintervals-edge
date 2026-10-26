//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/golang/snappy"
	"google.golang.org/protobuf/encoding/protowire"
	"gopkg.in/yaml.v3"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func address(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	v := l.Addr().String()
	l.Close()
	return v
}
func TestProductionBinaryEnrollsAndForwardsRemoteWrite(t *testing.T) {
	f := load(t)
	dir := t.TempDir()
	license := filepath.Join(dir, "license.json")
	if e := os.WriteFile(license, f.Licences["foreign"], 0600); e != nil {
		t.Fatal(e)
	}
	token := "a_fixture_only_high_entropy_token_12345678901234567890"
	digest := sha256.Sum256([]byte(token))
	c := new(config.Config)
	c.StateDir = filepath.Join(dir, "state")
	c.DeploymentLicensePath = license
	c.StatusListen = address(t)
	c.Buffer.MaxBytes = 1 << 20
	c.Buffer.MaxAgeDays = 7
	c.Buffer.MaxSegments = 100
	c.Uplink.ForceTCP = true
	c.Modules.RemoteWrite.Enabled = true
	c.Modules.RemoteWrite.Listen = address(t)
	c.Modules.RemoteWrite.Principals = []config.Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(digest[:])}}
	b := f.Bindings["foreign"]
	c.Bindings = []config.Binding{{ID: b.ID, StreamKey: b.StreamKey, SourceID: b.SourceID, Kind: "series", Selector: map[string]string{"__name__": "temperature"}, Principals: []string{"writer"}, Scale: 1}}
	raw, _ := yaml.Marshal(c)
	path := filepath.Join(dir, "config.yaml")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	binaryPath := filepath.Join("..", "bin", "edgegateway")
	cmd := exec.Command(binaryPath, "-config", path)
	cmd.Env = append(os.Environ(), "HTTPS_PROXY=", "EDGE_STATE_DIR=", "EDGE_LICENSE_PATH=")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
		if bytes.Contains(logs.Bytes(), []byte(token)) || bytes.Contains(logs.Bytes(), []byte(b.StreamKey)) {
			t.Error("sensitive log output")
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		res, e := client.Get("http://" + c.StatusListen + "/healthz")
		if e == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("binary not ready")
	}
	before := admin(t, f, "/stats", nil)["gateway_series"].(float64)
	field := func(n protowire.Number, b []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
	}
	label := append(field(1, []byte("__name__")), field(2, []byte("temperature"))...)
	value := protowire.AppendTag(nil, 1, protowire.Fixed64Type)
	value = binary.LittleEndian.AppendUint64(value, math.Float64bits(25))
	value = protowire.AppendVarint(protowire.AppendTag(value, 2, protowire.VarintType), uint64(time.Now().UnixMilli()))
	body := snappy.Encode(nil, field(1, append(field(1, label), field(2, value)...)))
	req, _ := http.NewRequest(http.MethodPost, "http://"+c.Modules.RemoteWrite.Listen+"/api/v1/write", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatal("writer not acknowledged", res.StatusCode)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if admin(t, f, "/stats", nil)["gateway_series"].(float64) == before+1 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("remote-write sample never reached real core")
}

func TestProductionBinaryDurablyForwardsNativeWaveform(t *testing.T) {
	f := load(t)
	dir := t.TempDir()
	license := filepath.Join(dir, "license.json")
	if e := os.WriteFile(license, f.Licences["native"], 0600); e != nil {
		t.Fatal(e)
	}
	token := "a_fixture_only_high_entropy_token_12345678901234567890"
	digest := sha256.Sum256([]byte(token))
	c := new(config.Config)
	c.StateDir = filepath.Join(dir, "state")
	c.DeploymentLicensePath = license
	c.StatusListen = address(t)
	c.Buffer.MaxBytes = 64 << 20
	c.Buffer.MaxAgeDays = 7
	c.Buffer.MaxSegments = 100
	c.Uplink.ForceTCP = true
	c.Modules.Captures.Enabled = true
	c.Modules.Captures.Listen = address(t)
	c.Modules.Captures.Principals = []config.Principal{{ID: "writer", TokenSHA256: hex.EncodeToString(digest[:])}}
	b := f.Bindings["native"]
	c.Bindings = []config.Binding{{ID: b.ID, StreamKey: b.StreamKey, SourceID: b.SourceID, Kind: "captures", Principals: []string{"writer"}}}
	raw, _ := yaml.Marshal(c)
	path := filepath.Join(dir, "config.yaml")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	binaryPath := filepath.Join("..", "bin", "edgegateway")
	cmd := exec.Command(binaryPath, "-config", path)
	cmd.Env = append(os.Environ(), "HTTPS_PROXY=", "EDGE_STATE_DIR=", "EDGE_LICENSE_PATH=")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
		if bytes.Contains(logs.Bytes(), []byte(token)) || bytes.Contains(logs.Bytes(), []byte(b.StreamKey)) {
			t.Error("sensitive log output")
		}
	}()
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		res, e := client.Get("http://" + c.StatusListen + "/healthz")
		if e == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("binary not ready")
	}
	const count = 256000
	metadata := map[string]any{"captureId": "native-waveform-v1", "tier": "M", "axes": []string{"x", "y", "z"}, "fsNominalHz": 25600, "startTimeUtc": time.Now().UTC().Format(time.RFC3339Nano), "mount": "stud", "rpmDeclared": 1480, "operatingStateDeclared": "running_steady"}
	header, _ := json.Marshal(map[string]any{"metadata": metadata, "count": count})
	body := make([]byte, 4+len(header)+count*12)
	binary.LittleEndian.PutUint32(body, uint32(len(header)))
	copy(body[4:], header)
	for axis := 0; axis < 3; axis++ {
		for n := 0; n < count; n++ {
			value := float32(.3 * math.Sin(2*math.Pi*1480/60*float64(n)/25600))
			binary.LittleEndian.PutUint32(body[4+len(header)+(axis*count+n)*4:], math.Float32bits(value))
		}
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+c.Modules.Captures.Listen+"/api/v1/captures/"+b.ID, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 202 {
		t.Fatal("writer not acknowledged", res.StatusCode)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status := admin(t, f, "/native-capture", nil)
		if status["stored"] == true {
			expectedHash := sha256.Sum256(body[4+len(header):])
			if status["sampleHash"] != hex.EncodeToString(expectedHash[:]) {
				t.Fatal("stored samples changed")
			}
			if status["n"] != float64(count) || status["axes"] != float64(3) || status["receipts"] != float64(1) {
				t.Fatal("stored waveform mismatch", status)
			}
			processed := admin(t, f, "/native-capture", map[string]any{"process": true})
			if processed["state"] != "done" || processed["accepted"] != true {
				t.Fatal("native waveform DSP did not complete", processed)
			}
			testNativeWindowStream(t, f, client, c, token, metadata, count, body[4+len(header):])
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("native waveform never reached real core")
}

func testNativeWindowStream(t *testing.T, f *fixture, client *http.Client, c *config.Config, token string, metadata map[string]any, count int, samples []byte) {
	t.Helper()
	source, sink := io.Pipe()
	defer source.Close()
	defer sink.Close()
	req, _ := http.NewRequest(http.MethodPost, "http://"+c.Modules.Captures.Listen+"/api/v1/streams/captures/"+c.Bindings[0].ID, source)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.clearintervals.waveforms.v1")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("stream not admitted", response.StatusCode)
	}
	decoder := json.NewDecoder(response.Body)
	for index := 2; index <= 3; index++ {
		id := fmt.Sprintf("native-waveform-v%d", index)
		metadata["captureId"] = id
		metadata["startTimeUtc"] = time.Now().UTC().Format(time.RFC3339Nano)
		header, _ := json.Marshal(map[string]any{"metadata": metadata, "count": count})
		prefix := make([]byte, 4+len(header))
		binary.LittleEndian.PutUint32(prefix, uint32(len(header)))
		copy(prefix[4:], header)
		wrote := make(chan error, 1)
		go func() {
			_, err := io.Copy(sink, io.MultiReader(bytes.NewReader(prefix), bytes.NewReader(samples)))
			wrote <- err
		}()
		var ack map[string]any
		if err = decoder.Decode(&ack); err != nil {
			t.Fatal("no streaming window ACK", err)
		}
		if ack["captureId"] != id || ack["status"] != "queued" {
			t.Fatal("wrong streaming acknowledgement", ack)
		}
		if err = <-wrote; err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.Close()
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(30 * time.Second)
	for time.Now().Before(until) {
		state := admin(t, f, "/native-capture", nil)
		if state["receipts"] == float64(3) {
			expected := sha256.Sum256(samples)
			if state["sampleHash"] != hex.EncodeToString(expected[:]) {
				t.Fatal("streaming samples changed")
			}
			processed := admin(t, f, "/native-capture", map[string]any{"process": true})
			if processed["state"] != "done" || processed["accepted"] != true {
				t.Fatal("streaming DSP incomplete", processed)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("streaming windows did not reach core")
}
