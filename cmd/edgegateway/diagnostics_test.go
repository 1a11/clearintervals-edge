package main

import (
	"strings"
	"testing"

	"github.com/1a11/clearintervals-edge/internal/config"
	"github.com/1a11/clearintervals-edge/internal/identity"
)

func TestClockDriftSetsTheAlarmWithoutStopping(t *testing.T) {
	d := new(diagnostics)
	d.observeClock(45, "probe")
	offset, alarm, _ := d.snapshot()
	if offset != 45 || alarm != 1 {
		t.Fatalf("offset=%v alarm=%d", offset, alarm)
	}
	if d.degraded() != "clock_skew" {
		t.Fatalf("health note %q", d.degraded())
	}
	d.observeClock(1, "probe")
	if _, alarm, _ = d.snapshot(); alarm != 0 {
		t.Fatal("recovered clock keeps the alarm")
	}
}

func TestUnknownStreamKeysNameConfiguredBindings(t *testing.T) {
	d := new(diagnostics)
	key := strings.Repeat("k", 43)
	d.observeUnknownKeys([]string{key, "stale"}, []config.Binding{{ID: "b1", Kind: "series", SourceID: "s1", StreamKey: key}})
	if _, _, rejected := d.snapshot(); rejected != 1 {
		t.Fatalf("rejected=%d", rejected)
	}
	if got := d.rejectedBindings(); len(got) != 1 || got[0].ID != "b1" || got[0].Reason != reasonUnknownKey {
		t.Fatalf("findings %v", got)
	}
	d.observeUnknownKeys(nil, nil)
	if _, _, rejected := d.snapshot(); rejected != 0 {
		t.Fatal("accepted keys keep the old finding")
	}
}

func TestDigestMismatchIsCountedButNotFatal(t *testing.T) {
	d := new(diagnostics)
	d.observeDigestMismatches([]identity.RosterMismatch{{BindingID: "b1", Kind: "series", SourceID: "s1"}})
	if _, alarm, rejected := d.snapshot(); alarm != 0 || rejected != 1 {
		t.Fatalf("alarm=%d rejected=%d", alarm, rejected)
	}
	if got := d.rejectedBindings(); len(got) != 1 || got[0].Reason != reasonDigestMismatch {
		t.Fatalf("findings %v", got)
	}
	d.observeDigestMismatches(nil)
	if _, _, rejected := d.snapshot(); rejected != 0 {
		t.Fatal("resolved mismatch keeps the finding")
	}
}
