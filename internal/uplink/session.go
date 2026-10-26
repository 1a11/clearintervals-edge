package uplink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/1a11/clearintervals-edge/internal/buffer"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"google.golang.org/protobuf/proto"
	"slices"
	"time"
)

var ErrRenew = errors.New("credential_renewal_due")
var ErrRotate = errors.New("uplink_epoch_rotation_due")

type Stream struct {
	channel                        *Channel
	epoch                          string
	sequence, usedBytes, usedItems uint64
	credit                         *pb.Credit
	poll                           time.Time
}

func id() string {
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		panic("random_source_unavailable")
	}
	return hex.EncodeToString(raw[:])
}
func acceptCredit(c *pb.Credit, sid, epoch, request string, previous *pb.Credit) error {
	if c == nil || c.SessionId != sid || c.Epoch != epoch || c.RequestId != request || c.Bytes > 1<<50 || c.Items > 1<<50 || c.Grant > 1<<50 {
		return wire.ErrFrame
	}
	if previous != nil && (c.Grant < previous.Grant || c.Bytes < previous.Bytes || c.Items < previous.Items || c.Grant == previous.Grant && (c.Bytes != previous.Bytes || c.Items != previous.Items)) {
		return wire.ErrFrame
	}
	return nil
}
func (c *Connection) Run(ctx context.Context, q *buffer.Queue, gid string, generation uint64, keys []string, renewAt time.Time) error {
	return c.run(ctx, q, gid, generation, keys, renewAt, time.Minute)
}

func (c *Connection) run(ctx context.Context, q *buffer.Queue, gid string, generation uint64, keys []string, renewAt time.Time, heartbeatEvery time.Duration) error {
	control, f, e := c.Open(ctx, "control", &pb.Frame{Body: &pb.Frame_Hello{Hello: &pb.Hello{GatewayId: gid, Generation: generation, Version: "edgegateway-v1", Protocols: []uint32{1}, Modules: []string{"remoteWrite", "captures", "stream-reopen-v1", "flow-control-v1"}, StreamKeys: keys, ClockUnixMillis: time.Now().UnixMilli()}}})
	if e != nil {
		return e
	}
	defer control.Close()
	welcome := f.GetWelcome()
	if welcome == nil || !wire.ValidID(welcome.SessionId) || welcome.Generation != generation || welcome.MaxStreams < 1 || welcome.MaxFrameBytes < 1 || welcome.MaxFrameBytes > wire.MaxFrame {
		return wire.ErrFrame
	}
	c.Established = true
	sid := welcome.SessionId
	streams := map[string]*Stream{}
	openAfter := map[string]time.Time{}
	opened := uint32(0)
	defer func() {
		for _, s := range streams {
			s.channel.Close()
		}
	}()
	heartbeat := time.Now()
	for {
		if !time.Now().Before(renewAt) {
			return ErrRenew
		}
		if time.Since(heartbeat) >= heartbeatEvery {
			stats, size, _ := q.Snapshot()
			drops := uint64(0)
			for _, v := range stats.Drops {
				drops += v
			}
			reply, e := control.Exchange(&pb.Frame{Body: &pb.Frame_Heartbeat{Heartbeat: &pb.Heartbeat{BufferBytes: uint64(size), Drops: drops, Records: stats.Accepted, Bytes: stats.Bytes, Rejected: stats.Rejected}}})
			if e != nil {
				var failure *Failure
				if errors.As(e, &failure) && (failure.Code == "rate_limited" || failure.Code == "core_unavailable") {
					retry := max(5*time.Second, min(failure.Retry, 15*time.Minute))
					if retry <= time.Minute {
						// The cloud retains control after a temporary heartbeat refusal.
						// Honor its retry floor without forcing a new authenticated lease.
						heartbeat = time.Now().Add(retry - heartbeatEvery)
						continue
					}
				}
				return e
			}
			policy := reply.GetPolicy()
			if policy == nil || policy.State != "active" {
				return wire.ErrFrame
			}
			if e = q.SetPolicy("active"); e != nil {
				return e
			}
			heartbeat = time.Now()
		}
		entries, e := q.NextBatch(time.Now())
		if e != nil {
			return e
		}
		if len(entries) == 0 {
			// Older servers reserve memory for idle credit. New servers charge
			// active frames only, so keep their data streams through idle periods.
			if !slices.Contains(welcome.Capabilities, "frame-budget-v1") {
				for kind, s := range streams {
					s.channel.Close()
					delete(streams, kind)
				}
			}
			if e = pause(ctx, time.Second); e != nil {
				return e
			}
			continue
		}
		entries = entries[:min(len(entries), 128)]
		kind := entries[0].Kind
		s := streams[kind]
		if s == nil {
			// Epochs cannot be reused within a session. Rotate the physical
			// connection before exhausting the server's bounded epoch history.
			if opened >= welcome.MaxStreams {
				return ErrRotate
			}
			if time.Now().Before(openAfter[kind]) {
				if e = pause(ctx, time.Second); e != nil {
					return e
				}
				continue
			}
			epoch := id()
			ch, f, e := c.Open(ctx, "streams/"+kind, &pb.Frame{Body: &pb.Frame_Open{Open: &pb.OpenStream{SessionId: sid, Generation: generation, Epoch: epoch, Kind: kind}}})
			if e != nil {
				var failure *Failure
				if errors.As(e, &failure) && failure.Code == "rate_limited" {
					// Data admission pressure does not invalidate the authenticated control.
					// Retain it, honor the server floor and keep heartbeats running.
					openAfter[kind] = time.Now().Add(max(5*time.Second, min(failure.Retry, 15*time.Minute)))
					continue
				}
				return e
			}
			delete(openAfter, kind)
			s = &Stream{channel: ch, epoch: epoch, credit: f.GetCredit(), poll: time.Now()}
			streams[kind] = s
			opened++
			if e = acceptCredit(s.credit, sid, epoch, "", nil); e != nil {
				return e
			}
		}
		items := make([]*pb.Item, len(entries))
		for j, v := range entries {
			old := v.Item
			items[j] = &pb.Item{Index: uint32(j), Id: old.Id, Hash: old.Hash, StreamKey: old.StreamKey, BindingId: old.BindingId, SourceId: old.SourceId, Body: old.Body}
		}
		frame := &pb.Frame{Version: 1, Body: &pb.Frame_Batch{Batch: &pb.Batch{SessionId: sid, Epoch: s.epoch, Sequence: s.sequence + 1, Items: items}}}
		size := uint64(proto.Size(frame))
		if size > uint64(welcome.MaxFrameBytes) {
			return wire.ErrFrame
		}
		if s.usedBytes+size > s.credit.Bytes || s.usedItems+uint64(len(items)) > s.credit.Items {
			if time.Since(s.poll) < 5*time.Second {
				if e = pause(ctx, time.Second); e != nil {
					return e
				}
				continue
			}
			request := id()
			reply, e := control.Exchange(&pb.Frame{Body: &pb.Frame_CreditRequest{CreditRequest: &pb.CreditRequest{SessionId: sid, Epoch: s.epoch, LastGrant: s.credit.Grant, RequestId: request}}})
			if e != nil {
				var failure *Failure
				if errors.As(e, &failure) && failure.Code == "stream_closed" {
					s.channel.Close()
					delete(streams, kind)
					continue
				}
				return e
			}
			credit := reply.GetCredit()
			if e = acceptCredit(credit, sid, s.epoch, request, s.credit); e != nil {
				return e
			}
			s.credit = credit
			s.poll = time.Now()
			continue
		}
		s.sequence++
		s.usedBytes += size
		s.usedItems += uint64(len(items))
		reply, e := s.channel.Exchange(frame)
		if e != nil {
			retry := time.Second
			var failure *Failure
			temporary := errors.Is(e, ErrTransport)
			if errors.As(e, &failure) && (failure.Code == "rate_limited" || failure.Code == "core_unavailable" || failure.Code == "stream_closed") {
				temporary = true
				retry = max(retry, min(failure.Retry, 15*time.Minute))
			}
			if temporary {
				s.channel.Close()
				delete(streams, kind)
				openAfter[kind] = time.Now().Add(retry)
				continue
			}
			return e
		}
		ack := reply.GetAck()
		if e = q.Resolve(entries, ack, sid, s.epoch, s.sequence); e != nil {
			return e
		}
		if ack.Credit != nil {
			if e = acceptCredit(ack.Credit, sid, s.epoch, "", s.credit); e != nil {
				return e
			}
			s.credit = ack.Credit
		}
		retry := time.Duration(0)
		for _, r := range ack.Results {
			if r.Outcome != pb.Outcome_ACCEPTED && r.Outcome != pb.Outcome_DUPLICATE && r.Outcome != pb.Outcome_REJECTED_PERMANENT {
				retry = max(retry, time.Duration(max(uint32(5), min(r.RetryAfterSeconds, 900)))*time.Second)
			}
		}
		if len(ack.Results) < len(entries) {
			retry = max(retry, 5*time.Second)
		}
		// Short delays keep heartbeat control available during long server backoffs.
		if retry > 0 {
			if e = pause(ctx, min(retry, 5*time.Second)); e != nil {
				return e
			}
		}
	}
}
func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
