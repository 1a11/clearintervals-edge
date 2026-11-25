package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/diag"
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/uplink"
)

// descriptorCache is the local copy of the last cloud descriptor sync.
const descriptorCache = "descriptors.json"

// maxDescriptors mirrors the configuration limit; the cloud resolves at most
// this many streams from the configured promql.
const maxDescriptors = 100

// descriptorRefresh is how often an open session re-reads the cloud descriptor
// set. The product adds streams after the gateway is already running (Step 4 of
// the wizard, or later from the gateway overview), so the gateway must keep
// asking instead of trusting the first answer, including when that answer was
// empty.
const descriptorRefresh = 15 * time.Second

// descriptorSource is the part of the uplink connection a refresh needs, so a
// test can answer without a live cloud.
type descriptorSource interface {
	Descriptors(ctx context.Context, gid string, generation uint64) ([]uplink.Descriptor, error)
}

type descriptorCacheFile struct {
	Items []config.Binding `json:"items"`
}

// syncDescriptors asks the cloud for the stream descriptors behind the
// configured promql, installs them as bindings and caches them. The request is
// outbound only: nothing here answers an incoming request, and the gateway is
// the only party that talks to the cloud. Calling it again replaces the cloud
// set, so streams added in the product start flowing without a restart.
func syncDescriptors(ctx context.Context, source descriptorSource, store *config.Store, gid string, generation uint64, stateDir, ingestURL string) error {
	diag.Event("verbose_descriptor_poll", "gatewayId", gid, "generation", generation, "ingestUrl", ingestURL)
	fetched, e := source.Descriptors(ctx, gid, generation)
	if e != nil {
		diag.Event("verbose_descriptor_response", "error", e.Error())
		return e
	}
	diag.Event("verbose_descriptor_response", "count", len(fetched), "descriptors", describeDescriptors(fetched))
	if len(fetched) > maxDescriptors {
		e = fmt.Errorf("descriptors_too_many: the cloud returned %d descriptors, at most %d are supported", len(fetched), maxDescriptors)
		diag.Event("verbose_descriptor_response", "error", e.Error())
		return e
	}
	items := make([]config.Binding, 0, len(fetched))
	for _, d := range fetched {
		items = append(items, config.Binding{ID: d.ID, StreamKey: d.StreamKey, SourceID: d.SourceID, Kind: d.Kind, Selector: d.Selector, Scale: d.Scale})
	}
	if store.SyncDescriptors(items) {
		logger.Info("descriptors_synced", "bindings", len(items), "source", "cloud")
	}
	diag.Event("verbose_active_selectors", "source", "cloud", "bindings", activeBindings(store.Get()))
	if e = saveDescriptorCache(filepath.Join(stateDir, descriptorCache), items); e != nil {
		logger.Warn("descriptors_cache_failed", "problem", bounded(e.Error()), "hint", "The descriptors are active but were not cached; they will be fetched again after a restart.")
	}
	return nil
}

// startDescriptorRefresh keeps re-reading the cloud descriptor set while the
// session is open. The returned stop function cancels an in-flight fetch and
// waits for the loop, so the caller can close the connection safely.
func startDescriptorRefresh(ctx context.Context, source descriptorSource, store *config.Store, gid string, generation uint64, stateDir, ingestURL string) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(descriptorRefresh)
		defer ticker.Stop()
		// A cloud that cannot answer would otherwise repeat the same warning
		// every 15 seconds for the life of the session.
		failing := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e := syncDescriptors(ctx, source, store, gid, generation, stateDir, ingestURL); e != nil {
					if !failing {
						logger.Warn("descriptors_unavailable", "problem", bounded(e.Error()), "hint", "The cloud could not deliver stream descriptors. Remote-write answers 503 with Retry-After until they arrive, so vmagent keeps the first batch in its WAL.")
						failing = true
					}
					continue
				}
				failing = false
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// loadDescriptorCache returns the cached bindings, or nil when the cache is
// absent or unusable: a stale cache must never stop the gateway from starting.
func loadDescriptorCache(path string) []config.Binding {
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 1<<20 {
		return nil
	}
	var body descriptorCacheFile
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	return body.Items
}

func saveDescriptorCache(path string, items []config.Binding) error {
	if items == nil {
		items = []config.Binding{}
	}
	raw, e := json.Marshal(descriptorCacheFile{Items: items})
	if e != nil {
		return e
	}
	if len(raw) > 1<<20 {
		return errors.New("descriptors_too_large")
	}
	// The refresh runs every 15 seconds; rewriting an unchanged cache would
	// fsync the state volume for nothing.
	if current, e := os.ReadFile(path); e == nil && bytes.Equal(current, raw) {
		return nil
	}
	return durable.Write(path, raw)
}

// describeDescriptors renders the cloud answer for verbose logs, keys included: the point of the event is to
// show exactly which stream the gateway received.
func describeDescriptors(items []uplink.Descriptor) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, d := range items {
		out = append(out, map[string]any{
			"id": d.ID, "streamKey": d.StreamKey, "sourceId": d.SourceID, "kind": d.Kind,
			"metric": d.Metric, "selector": d.Selector, "scale": d.Scale,
		})
	}
	return out
}

// activeBindings lists what the gateway is matching against right now, with each exact label map.
func activeBindings(c *config.Config) []map[string]any {
	out := make([]map[string]any, 0, len(c.Bindings))
	for _, b := range c.Bindings {
		out = append(out, map[string]any{
			"id": b.ID, "kind": b.Kind, "sourceId": b.SourceID, "streamKey": b.StreamKey,
			"selector": b.Selector, "scale": b.Scale, "principals": b.Principals,
		})
	}
	return out
}
