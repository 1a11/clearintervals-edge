package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/uplink"
)

// fakeDescriptors answers like the cloud, with a set the test can change
// between fetches.
type fakeDescriptors struct {
	items []uplink.Descriptor
	calls int
}

func (f *fakeDescriptors) Descriptors(context.Context, string, uint64) ([]uplink.Descriptor, error) {
	f.calls++
	return f.items, nil
}

// Step 3 of the wizard starts the gateway while the cloud has no streams yet;
// Step 4 adds them afterwards. The empty first answer must not stop a later
// answer from installing the new streams.
func TestSyncDescriptorsPicksUpStreamsAddedLater(t *testing.T) {
	dir := t.TempDir()
	c := new(config.Config)
	c.StateDir = dir
	c.Modules.RemoteWrite.Principals = []config.Principal{{ID: "writer", TokenSHA256: strings.Repeat("a", 64)}}
	store := config.New(c)
	source := &fakeDescriptors{}

	if e := syncDescriptors(context.Background(), source, store, "gateway", 7, dir, "https://ingest.example"); e != nil {
		t.Fatal(e)
	}
	if !store.DescriptorsSynced() {
		t.Fatal("empty answer did not complete the initial wait")
	}
	if b := store.Get().Bindings; len(b) != 0 {
		t.Fatalf("unexpected bindings after the empty sync: %+v", b)
	}

	source.items = []uplink.Descriptor{{
		ID:        "stream-1",
		StreamKey: strings.Repeat("k", 43),
		SourceID:  "source-1",
		Kind:      "series",
		Selector:  map[string]string{"__name__": "rpm"},
	}}
	if e := syncDescriptors(context.Background(), source, store, "gateway", 7, dir, "https://ingest.example"); e != nil {
		t.Fatal(e)
	}
	b := store.Get().Bindings
	if len(b) != 1 || b[0].ID != "stream-1" || b[0].Scale != 1 || len(b[0].Principals) != 1 || b[0].Principals[0] != "writer" {
		t.Fatalf("streams added after the first sync were not installed: %+v", b)
	}
	if source.calls != 2 {
		t.Fatalf("expected two fetches, got %d", source.calls)
	}
	// The cache carries the later set into the next start.
	if cached := loadDescriptorCache(filepath.Join(dir, descriptorCache)); len(cached) != 1 || cached[0].ID != "stream-1" {
		t.Fatalf("descriptor cache not updated: %+v", cached)
	}
}
