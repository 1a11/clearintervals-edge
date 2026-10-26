// Package buffer stores immutable, checksummed enqueue transactions and terminal receipts.
package buffer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/1a11/clearintervals-edge/internal/durable"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"google.golang.org/protobuf/proto"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrCapacity = errors.New("buffer_capacity")
var ErrIntegrity = errors.New("buffer_integrity")

type Stats struct {
	Suspended                 bool
	Revoked                   bool
	Integrity                 bool
	Drops                     map[string]uint64
	Accepted, Rejected, Bytes uint64
}
type segment struct {
	name, kind string
	size       int64
	at         time.Time
	done       map[uint32]bool
	count      int
}
type cachedSegment struct {
	batch  *pb.Batch
	header [36]byte
	weight int64
	used   uint64
}

const decodedCacheBytes int64 = 16 << 20

type Queue struct {
	mu           sync.Mutex
	dir          string
	max          int64
	maxAge       time.Duration
	maxSegments  int
	segments     []*segment
	size         int64
	stats        Stats
	turn         uint64
	fault        error
	cache        map[string]*cachedSegment
	cacheBytes   int64
	cacheTick    uint64
	verifyBuffer [32 << 10]byte
}

// Entry.Item is immutable; callers must construct separate transport headers.
type Entry struct {
	Segment string
	Index   uint32
	Item    *pb.Item
	Kind    string
}

func Open(dir string, max int64, age time.Duration, maxSegments int) (*Queue, error) {
	if e := durable.Directory(dir); e != nil {
		return nil, e
	}
	q := &Queue{dir: dir, max: max, maxAge: age, maxSegments: maxSegments, stats: Stats{Drops: map[string]uint64{}}}
	raw, e := durable.ReadChecked(filepath.Join(dir, "policy.json"))
	missingPolicy := errors.Is(e, os.ErrNotExist)
	if e == nil {
		if json.Unmarshal(raw, &q.stats) != nil || q.stats.Drops == nil {
			return nil, ErrIntegrity
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	files, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	if missingPolicy {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".seg") || strings.HasSuffix(f.Name(), ".bad") || strings.HasSuffix(f.Name(), ".done") {
				return nil, ErrIntegrity
			}
		}
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".seg.done") {
			if _, e := os.Stat(filepath.Join(dir, strings.TrimSuffix(f.Name(), ".done"))); errors.Is(e, os.ErrNotExist) {
				if e = durable.Remove(filepath.Join(dir, f.Name())); e != nil {
					return nil, e
				}
				continue
			}
		}
		if strings.HasPrefix(f.Name(), ".pending-") {
			if e = durable.Remove(filepath.Join(dir, f.Name())); e != nil {
				return nil, e
			}
			continue
		}
		if strings.HasSuffix(f.Name(), ".bad") {
			info, e := f.Info()
			if e != nil {
				return nil, e
			}
			q.size += info.Size()
			q.stats.Integrity = true
			continue
		}
		if !strings.HasSuffix(f.Name(), ".seg") {
			continue
		}
		if len(q.segments) >= maxSegments {
			return nil, ErrCapacity
		}
		path := filepath.Join(dir, f.Name())
		info, e := f.Info()
		if e != nil {
			return nil, e
		}
		q.size += info.Size() + 8192
		batch, e := read(path)
		if e != nil {
			if e = os.Rename(path, path+".bad"); e != nil {
				return nil, e
			}
			if e = durable.SyncDir(dir); e != nil {
				return nil, e
			}
			q.stats.Integrity = true
			continue
		}
		s := &segment{name: f.Name(), size: info.Size() + 8192, at: info.ModTime(), count: len(batch.Items), done: map[uint32]bool{}}
		s.kind = kind(batch.Items[0])
		for _, i := range batch.Items {
			if kind(i) != s.kind || wire.Validate(i, s.kind) != nil {
				return nil, ErrIntegrity
			}
		}
		d, e := durable.ReadChecked(path + ".done")
		if e == nil {
			var indexes []uint32
			if json.Unmarshal(d, &indexes) != nil {
				return nil, ErrIntegrity
			}
			for _, index := range indexes {
				if int(index) >= s.count {
					return nil, ErrIntegrity
				}
				s.done[index] = true
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		q.segments = append(q.segments, s)
	}
	sort.Slice(q.segments, func(i, j int) bool { return q.segments[i].at.Before(q.segments[j].at) })
	if e = q.reclaim(); e != nil {
		return nil, e
	}
	if e = q.save(); e != nil {
		return nil, e
	}
	return q, nil
}
func kind(i *pb.Item) string {
	if i.GetPoint() != nil {
		return "series"
	}
	if i.GetCapture() != nil {
		return "captures"
	}
	return "events"
}
func read(path string) (*pb.Batch, error) {
	b, _, err := readVerified(path)
	return b, err
}
func readVerified(path string) (batch *pb.Batch, h [36]byte, err error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, h, e
	}
	defer f.Close()
	if _, e = io.ReadFull(f, h[:]); e != nil {
		return nil, h, ErrIntegrity
	}
	n := binary.BigEndian.Uint32(h[:4])
	if n == 0 || n > wire.MaxFrame {
		return nil, h, ErrIntegrity
	}
	raw := make([]byte, n)
	if _, e = io.ReadFull(f, raw); e != nil {
		return nil, h, ErrIntegrity
	}
	var tail [1]byte
	if m, e := f.Read(tail[:]); m != 0 || e != io.EOF {
		return nil, h, ErrIntegrity
	}
	hash := sha256.Sum256(raw)
	if !bytes.Equal(h[4:], hash[:]) {
		return nil, h, ErrIntegrity
	}
	b := new(pb.Batch)
	if proto.Unmarshal(raw, b) != nil || len(b.Items) == 0 || len(b.Items) > wire.MaxItems {
		return nil, h, ErrIntegrity
	}
	return b, h, nil
}
func (q *Queue) forgetCached(name string) {
	if c := q.cache[name]; c != nil {
		q.cacheBytes -= c.weight
		delete(q.cache, name)
	}
}

// Keep a bounded decoded cache for credit polling. Every hit still verifies the
// on-disk checksum with a small scratch buffer, retaining corruption detection
// without repeatedly allocating/copying a multi-megabyte waveform.
func (q *Queue) readSegment(s *segment) (*pb.Batch, error) {
	path := filepath.Join(q.dir, s.name)
	q.cacheTick++
	if c := q.cache[s.name]; c != nil {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var header [36]byte
		if _, err = io.ReadFull(f, header[:]); err != nil || header != c.header {
			return nil, ErrIntegrity
		}
		n := binary.BigEndian.Uint32(header[:4])
		hash := sha256.New()
		copied, err := io.CopyBuffer(hash, io.LimitReader(f, int64(n)+1), q.verifyBuffer[:])
		if err != nil || copied != int64(n) || !bytes.Equal(hash.Sum(nil), header[4:]) {
			return nil, ErrIntegrity
		}
		c.used = q.cacheTick
		return c.batch, nil
	}
	b, header, err := readVerified(path)
	if err != nil {
		return nil, err
	}
	weight := s.size + int64(len(b.Items))*256
	if weight > decodedCacheBytes {
		return b, nil
	}
	if q.cache == nil {
		q.cache = map[string]*cachedSegment{}
	}
	for len(q.cache) >= 8 || q.cacheBytes+weight > decodedCacheBytes {
		var oldest string
		var tick uint64
		for name, c := range q.cache {
			if oldest == "" || c.used < tick {
				oldest, tick = name, c.used
			}
		}
		if oldest == "" {
			break
		}
		q.forgetCached(oldest)
	}
	q.cache[s.name] = &cachedSegment{batch: b, header: header, weight: weight, used: q.cacheTick}
	q.cacheBytes += weight
	return b, nil
}

func (q *Queue) save() error {
	raw, e := json.Marshal(q.stats)
	if e != nil {
		return e
	}
	e = durable.WriteChecked(filepath.Join(q.dir, "policy.json"), raw)
	if e != nil {
		q.fault = e
	}
	return e
}
func (q *Queue) SetPolicy(state string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	old := q.stats
	if state != "active" {
		q.cache = nil
		q.cacheBytes = 0
	}
	switch state {
	case "active":
		q.stats.Suspended = false
	case "organization_suspended":
		q.stats.Suspended = true
	case "revoked":
		q.stats.Revoked = true
	default:
		return nil
	}
	if e := q.save(); e != nil {
		q.stats = old
		return e
	}
	return nil
}
func (q *Queue) Drop(reason string, n uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch reason {
	case "unmapped", "suspended", "too_old", "invalid", "too_large", "evicted":
	default:
		return ErrIntegrity
	}
	q.stats.Drops[reason] += n
	return q.save()
}
func (q *Queue) Snapshot() (Stats, int64, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	if q.fault != nil {
		s.Integrity = true
	}
	s.Drops = map[string]uint64{}
	for k, v := range q.stats.Drops {
		s.Drops[k] = v
	}
	return s, q.size, len(q.segments)
}
func (q *Queue) reclaim() (err error) {
	defer func() {
		if err != nil {
			q.fault = err
		}
	}()
	keep := q.segments[:0]
	for _, s := range q.segments {
		if len(s.done) != s.count {
			keep = append(keep, s)
			continue
		}
		if e := durable.Remove(filepath.Join(q.dir, s.name)); e != nil {
			return e
		}
		if e := durable.Remove(filepath.Join(q.dir, s.name+".done")); e != nil {
			return e
		}
		q.forgetCached(s.name)
		q.size -= s.size
	}
	q.segments = keep
	return nil
}
func (q *Queue) Enqueue(items []*pb.Item, now time.Time) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fault != nil {
		return q.fault
	}
	if len(items) == 0 {
		return nil
	}
	if len(items) > wire.MaxItems {
		return ErrCapacity
	}
	k := kind(items[0])
	for _, i := range items {
		if kind(i) != k || wire.Validate(i, k) != nil {
			return wire.ErrFrame
		}
	}
	if q.stats.Revoked || q.stats.Suspended && k == "captures" {
		return ErrCapacity
	}
	if q.stats.Suspended {
		q.stats.Drops["suspended"] += uint64(len(items))
		return q.save()
	}
	raw, e := proto.MarshalOptions{Deterministic: true}.Marshal(&pb.Batch{Items: items})
	if e != nil {
		return e
	}
	if len(raw) > wire.MaxFrame {
		return ErrCapacity
	}
	size := int64(len(raw) + 36 + 8192)
	if size > q.max {
		return ErrCapacity
	}
	// Context eviction is an explicit, durable loss policy; captures never evict.
	quota := q.max
	if k == "series" {
		quota = q.max * 3 / 4
	}
	if k == "events" {
		quota = q.max / 100
	}
	usage := func() int64 {
		n := int64(0)
		for _, s := range q.segments {
			if s.kind == k {
				n += s.size
			}
		}
		return n
	}
	if size > quota {
		return ErrCapacity
	}
	for q.size+size > q.max || usage()+size > quota || len(q.segments) >= q.maxSegments {
		var victim *segment
		for _, s := range q.segments {
			if s.kind == "series" {
				victim = s
				break
			}
		}
		if k != "series" || victim == nil {
			return ErrCapacity
		}
		q.stats.Drops["evicted"] += uint64(victim.count - len(victim.done))
		if e = q.save(); e != nil {
			return e
		}
		for j := 0; j < victim.count; j++ {
			victim.done[uint32(j)] = true
		}
		if e = q.reclaim(); e != nil {
			return e
		}
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return e
	}
	name := hex.EncodeToString(id[:]) + ".seg"
	hash := sha256.Sum256(raw)
	data := make([]byte, 36, len(raw)+36)
	binary.BigEndian.PutUint32(data[:4], uint32(len(raw)))
	copy(data[4:], hash[:])
	data = append(data, raw...)
	if e = durable.Write(filepath.Join(q.dir, name), data); e != nil {
		q.fault = e
		return e
	}
	q.segments = append(q.segments, &segment{name: name, kind: k, size: size, at: now, count: len(items), done: map[uint32]bool{}})
	q.size += size
	return nil
}

// Next alternates old backlog and live segments; each lane preserves enqueue order.
func (q *Queue) Next(now time.Time) ([]Entry, error) { return q.next(now, 0, wire.MaxItems) }

// NextBatch amortizes a WAN round trip across independent enqueue segments.
// The first segment may be a legal 12 MB capture; additional segments fit in
// the smaller coalescing budget. Ordinary Next retains its historical contract.
func (q *Queue) NextBatch(now time.Time) ([]Entry, error) { return q.next(now, 8<<20, 128) }
func (q *Queue) next(now time.Time, maxBytes, maxItems int) ([]Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fault != nil {
		return nil, q.fault
	}
	if q.stats.Revoked || q.stats.Suspended {
		return nil, nil
	}
	var candidates [6]*segment
	for _, s := range q.segments {
		if len(s.done) == s.count {
			continue
		}
		lane := 0
		if now.Sub(s.at) < time.Minute {
			lane = 1
		}
		if s.kind == "captures" {
			lane += 2
		}
		if s.kind == "events" {
			lane += 4
		}
		if candidates[lane] == nil {
			candidates[lane] = s
		}
	}
	var s *segment
	for j := 0; j < len(candidates); j++ {
		lane := int(q.turn % uint64(len(candidates)))
		q.turn++
		if candidates[lane] != nil {
			s = candidates[lane]
			break
		}
	}
	if s == nil {
		q.cache = nil
		q.cacheBytes = 0
		return nil, nil
	}
	b, e := q.readSegment(s)
	if e != nil {
		q.stats.Integrity = true
		_ = q.save()
		return nil, ErrIntegrity
	}
	result := []Entry{}
	expired := uint64(0)
	for j, i := range b.Items {
		if s.done[uint32(j)] {
			continue
		}
		at := eventTime(i)
		if now.Sub(at) > q.maxAge {
			expired++
			s.done[uint32(j)] = true
			continue
		}
		result = append(result, Entry{s.name, uint32(j), i, s.kind})
	}
	if expired > 0 {
		q.stats.Drops["too_old"] += expired
		if e = q.save(); e != nil {
			return nil, e
		}
		if e = q.receipt(s); e != nil {
			return nil, e
		}
		if e = q.reclaim(); e != nil {
			return nil, e
		}
	}
	if maxBytes > 0 && len(result) < maxItems {
		// Reserve room for the outer frame, session, epoch and sequence headers.
		size := 512
		for _, entry := range result {
			size += proto.Size(entry.Item) + 16
		}
		selected := false
		for _, other := range q.segments {
			if other == s {
				selected = true
				continue
			}
			if !selected || other.kind != s.kind || len(other.done) == other.count {
				continue
			}
			if len(result) >= maxItems || size+int(other.size) > maxBytes {
				break
			}
			batch, err := q.readSegment(other)
			if err != nil {
				q.stats.Integrity = true
				_ = q.save()
				return nil, ErrIntegrity
			}
			for j, item := range batch.Items {
				if other.done[uint32(j)] || now.Sub(eventTime(item)) > q.maxAge {
					continue
				}
				nextSize := proto.Size(item) + 16
				if len(result) >= maxItems || size+nextSize > maxBytes {
					break
				}
				result = append(result, Entry{other.name, uint32(j), item, other.kind})
				size += nextSize
			}
		}
	}
	return result, nil
}
func eventTime(i *pb.Item) time.Time {
	v := ""
	if p := i.GetPoint(); p != nil {
		v = p.Timestamp
	}
	if c := i.GetCapture(); c != nil {
		var m struct {
			Start string `json:"startTimeUtc"`
		}
		_ = json.Unmarshal(c.MetadataJson, &m)
		v = m.Start
	}
	if e := i.GetEvent(); e != nil {
		v = e.Timestamp
	}
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}
func (q *Queue) receipt(s *segment) error {
	indexes := make([]uint32, 0, len(s.done))
	for j := range s.done {
		indexes = append(indexes, j)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	raw, _ := json.Marshal(indexes)
	e := durable.WriteChecked(filepath.Join(q.dir, s.name+".done"), raw)
	if e != nil {
		q.fault = e
	}
	return e
}

// Resolve accepts only per-item terminal results tied to this exact batch.
func (q *Queue) Resolve(entries []Entry, a *pb.Ack, sid, epoch string, sequence uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fault != nil {
		return q.fault
	}
	if a == nil || a.SessionId != sid || a.Epoch != epoch || a.Sequence != sequence || len(a.Results) > len(entries) {
		return ErrIntegrity
	}
	seen := map[uint32]bool{}
	for _, r := range a.Results {
		if int(r.Index) >= len(entries) || seen[r.Index] {
			return ErrIntegrity
		}
		seen[r.Index] = true
		i := entries[r.Index].Item
		if r.Id != i.Id || !bytes.Equal(r.Hash, i.Hash) {
			return ErrIntegrity
		}
	}
	changed := map[*segment]bool{}
	for _, r := range a.Results {
		if r.Outcome != pb.Outcome_ACCEPTED && r.Outcome != pb.Outcome_DUPLICATE && r.Outcome != pb.Outcome_REJECTED_PERMANENT {
			continue
		}
		entry := entries[r.Index]
		for _, s := range q.segments {
			if s.name == entry.Segment && !s.done[entry.Index] {
				s.done[entry.Index] = true
				changed[s] = true
				if r.Outcome == pb.Outcome_REJECTED_PERMANENT {
					q.stats.Rejected++
				} else {
					q.stats.Accepted++
				}
				q.stats.Bytes += uint64(proto.Size(entry.Item))
			}
		}
	}
	for s := range changed {
		if e := q.receipt(s); e != nil {
			return e
		}
	}
	if e := q.save(); e != nil {
		return e
	}
	return q.reclaim()
}
