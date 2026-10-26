package buffer

import (
	"errors"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func point(id string) *pb.Item {
	i := &pb.Item{Id: id, BindingId: "binding_v1", SourceId: "canonical", StreamKey: strings.Repeat("k", 43), Body: &pb.Item_Point{Point: &pb.Point{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Value: 1480}}}
	i.Hash, _ = wire.Hash(i)
	return i
}

// Run inside the documented 1 MiB tmpfs container to exercise a real ENOSPC.
func TestRealENOSPC(t *testing.T) {
	root := os.Getenv("EDGE_TEST_ENOSPC_ROOT")
	if root == "" {
		t.Skip("requires a bounded tmpfs")
	}
	q, e := Open(root, 10<<20, 7*24*time.Hour, 1000)
	if e != nil {
		t.Fatal(e)
	}
	accepted := 0
	for j := 0; j < 1000; j++ {
		items := make([]*pb.Item, 1000)
		for k := range items {
			items[k] = point("point")
		}
		e = q.Enqueue(items, time.Now())
		if e != nil {
			if !errors.Is(e, syscall.ENOSPC) {
				t.Fatal("expected real ENOSPC", e)
			}
			break
		}
		accepted++
	}
	if e == nil {
		t.Fatal("tmpfs did not fill")
	}
	if accepted == 0 {
		t.Fatal("fixture could not enqueue before exhaustion")
	}
	if e = q.Enqueue([]*pb.Item{point("after-failure")}, time.Now()); e == nil {
		t.Fatal("false success after ENOSPC")
	}
	q, e = Open(root, 10<<20, 7*24*time.Hour, 1000)
	if e != nil {
		t.Fatal(e)
	}
	_, _, segments := q.Snapshot()
	if segments != accepted {
		t.Fatal("accepted transactions lost after ENOSPC/restart", accepted, segments)
	}
}
func queue(t *testing.T, dir string) *Queue {
	t.Helper()
	q, e := Open(dir, 1<<20, 7*24*time.Hour, 100)
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func enqueue(t *testing.T, q *Queue, items ...*pb.Item) {
	t.Helper()
	if e := q.Enqueue(items, time.Now()); e != nil {
		t.Fatal(e)
	}
}
func next(t *testing.T, q *Queue) []Entry {
	t.Helper()
	v, e := q.Next(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func ack(entries []Entry, outcomes ...pb.Outcome) *pb.Ack {
	a := &pb.Ack{SessionId: "session", Epoch: "epoch", Sequence: 1}
	for j, o := range outcomes {
		a.Results = append(a.Results, &pb.Result{Index: uint32(j), Id: entries[j].Item.Id, Hash: entries[j].Item.Hash, Outcome: o})
	}
	return a
}
func TestPartialAckLostReplyAndRestart(t *testing.T) {
	dir := t.TempDir()
	q := queue(t, dir)
	enqueue(t, q, point("one"), point("two"))
	entries := next(t, q)
	if e := q.Resolve(entries, ack(entries, pb.Outcome_ACCEPTED, pb.Outcome_RETRY_LATER), "session", "epoch", 1); e != nil {
		t.Fatal(e)
	}
	q = queue(t, dir)
	entries = next(t, q)
	if len(entries) != 1 || entries[0].Item.Id != "two" {
		t.Fatal("retryable record lost", entries)
	}
	if e := q.Resolve(entries, ack(entries, pb.Outcome_DUPLICATE), "session", "epoch", 1); e != nil {
		t.Fatal(e)
	}
	q = queue(t, dir)
	if len(next(t, q)) != 0 {
		t.Fatal("terminal item replayed")
	}
}
func TestAckMustMatchEveryIdentityAndUnknownStays(t *testing.T) {
	for _, change := range []string{"session", "epoch", "sequence", "id", "hash", "index", "duplicate"} {
		t.Run(change, func(t *testing.T) {
			q := queue(t, t.TempDir())
			enqueue(t, q, point("one"))
			v := next(t, q)
			a := ack(v, pb.Outcome_ACCEPTED)
			switch change {
			case "session":
				a.SessionId = "stale"
			case "epoch":
				a.Epoch = "stale"
			case "sequence":
				a.Sequence = 2
			case "id":
				a.Results[0].Id = "other"
			case "hash":
				a.Results[0].Hash = []byte("other")
			case "index":
				a.Results[0].Index = 1
			case "duplicate":
				a.Results = append(a.Results, a.Results[0])
			}
			if q.Resolve(v, a, "session", "epoch", 1) == nil {
				t.Fatal("unmatched acknowledgement accepted")
			}
			if len(next(t, q)) != 1 {
				t.Fatal("record reclaimed")
			}
		})
	}
	q := queue(t, t.TempDir())
	enqueue(t, q, point("unknown"))
	v := next(t, q)
	a := ack(v, pb.Outcome(99))
	a.TerminalFrontier = 1000
	if e := q.Resolve(v, a, "session", "epoch", 1); e != nil {
		t.Fatal(e)
	}
	if len(next(t, q)) != 1 {
		t.Fatal("frontier or unknown outcome reclaimed item")
	}
}
func TestCorruptionIsQuarantinedAndCountedAgainstQuota(t *testing.T) {
	dir := t.TempDir()
	q := queue(t, dir)
	enqueue(t, q, point("one"))
	file := filepath.Join(dir, q.segments[0].name)
	if e := os.WriteFile(file, []byte("torn segment"), 0600); e != nil {
		t.Fatal(e)
	}
	q = queue(t, dir)
	s, size, _ := q.Snapshot()
	if !s.Integrity || size == 0 || len(next(t, q)) != 0 {
		t.Fatal("corrupt data not quarantined")
	}
	if _, e := os.Stat(file + ".bad"); e != nil {
		t.Fatal(e)
	}
}
func TestSuspensionPersistedAndNoUnauthenticatedResume(t *testing.T) {
	dir := t.TempDir()
	q := queue(t, dir)
	enqueue(t, q, point("backlog"))
	if e := q.SetPolicy("organization_suspended"); e != nil {
		t.Fatal(e)
	}
	q = queue(t, dir)
	enqueue(t, q, point("discarded"))
	if len(next(t, q)) != 0 {
		t.Fatal("sent while suspended")
	}
	_ = q.SetPolicy("transport_success")
	s, _, _ := q.Snapshot()
	if !s.Suspended || s.Drops["suspended"] != 1 {
		t.Fatal(s)
	}
	_ = q.SetPolicy("active")
	if len(next(t, q)) != 1 {
		t.Fatal("backlog lost")
	}
}
func TestImmutableBindingExpiryAndQuota(t *testing.T) {
	q := queue(t, t.TempDir())
	i := point("old")
	i.BindingId = "original"
	enqueue(t, q, i)
	got := next(t, q)[0].Item
	if got.BindingId != "original" {
		t.Fatal("binding changed")
	}
	q.maxSegments = 1
	enqueue(t, q, point("new"))
	s, _, _ := q.Snapshot()
	if s.Drops["evicted"] != 1 {
		t.Fatal(s)
	}
	v, e := q.Next(time.Now().Add(8 * 24 * time.Hour))
	if e != nil || len(v) != 0 {
		t.Fatal(v, e)
	}
	s, _, _ = q.Snapshot()
	if s.Drops["too_old"] != 1 {
		t.Fatal(s)
	}
}
func TestDiskFailureNeverAcknowledgesAndPoisonsAdmission(t *testing.T) {
	dir := t.TempDir()
	q := queue(t, dir)
	enqueue(t, q, point("one"))
	entries := next(t, q)
	if e := os.Mkdir(filepath.Join(dir, entries[0].Segment+".done"), 0700); e != nil {
		t.Fatal(e)
	}
	if q.Resolve(entries, ack(entries, pb.Outcome_ACCEPTED), "session", "epoch", 1) == nil {
		t.Fatal("receipt failure ignored")
	}
	if q.Enqueue([]*pb.Item{point("two")}, time.Now()) == nil {
		t.Fatal("continued after failed durable receipt")
	}
	if e := os.Remove(filepath.Join(dir, entries[0].Segment+".done")); e != nil {
		t.Fatal(e)
	}
	q = queue(t, dir)
	if len(next(t, q)) != 1 {
		t.Fatal("uncommitted receipt reclaimed record")
	}
	q.dir = filepath.Join(dir, "absent")
	if e := q.Enqueue([]*pb.Item{point("two")}, time.Now()); e == nil || errors.Is(e, ErrCapacity) {
		t.Fatal("write failure ignored", e)
	}
}

func TestCoalescedSegmentsKeepDurableReceiptIdentity(t *testing.T) {
	q := queue(t, t.TempDir())
	enqueue(t, q, point("first"))
	enqueue(t, q, point("second"))
	enqueue(t, q, point("third"))
	entries, err := q.NextBatch(time.Now())
	if err != nil || len(entries) != 3 {
		t.Fatal(err, len(entries))
	}
	if entries[0].Segment == entries[1].Segment {
		t.Fatal("fixture did not span segments")
	}
	if err = q.Resolve(entries, ack(entries, pb.Outcome_ACCEPTED, pb.Outcome_RETRY_LATER, pb.Outcome_ACCEPTED), "session", "epoch", 1); err != nil {
		t.Fatal(err)
	}
	reopened := queue(t, q.dir)
	remaining := next(t, reopened)
	if len(remaining) != 1 || remaining[0].Item.Id != "second" {
		t.Fatal("coalesced receipt lost retry identity")
	}
}
func TestDecodedCacheRevalidatesDiskChecksumOnEveryHit(t *testing.T) {
	q := queue(t, t.TempDir())
	enqueue(t, q, point("first"))
	entries := next(t, q)
	if len(q.cache) != 1 {
		t.Fatal("fixture did not populate cache")
	}
	path := filepath.Join(q.dir, entries[0].Segment)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Next(time.Now()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("cached item masked corrupted disk", err)
	}
}
func TestDecodedCacheKeepsOnlyBoundedEntries(t *testing.T) {
	q := queue(t, t.TempDir())
	for n := 0; n < 12; n++ {
		enqueue(t, q, point("point"))
	}
	if _, err := q.NextBatch(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(q.cache) > 8 || q.cacheBytes > decodedCacheBytes {
		t.Fatal(len(q.cache), q.cacheBytes)
	}
}
