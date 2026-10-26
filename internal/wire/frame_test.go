package wire

import (
	"bytes"
	"encoding/binary"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"math"
	"testing"
)

func TestBoundsBeforeBodyRead(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		wire, decoded, items uint32
		flags                byte
	}{{"wire", MaxWire + 1, 1, 0, 1}, {"decoded", 1, MaxFrame + 1, 0, 1}, {"ratio", 1, 21, 0, 1}, {"count", 1, 1, 1001, 0}, {"flags", 1, 1, 0, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			var h [13]byte
			h[0] = tc.flags
			binary.BigEndian.PutUint32(h[1:], tc.wire)
			binary.BigEndian.PutUint32(h[5:], tc.decoded)
			binary.BigEndian.PutUint32(h[9:], tc.items)
			if _, _, e := Read(bytes.NewReader(h[:]), MaxFrame, nil); e != ErrFrame {
				t.Fatalf("got %v", e)
			}
		})
	}
	var b bytes.Buffer
	_ = Write(&b, &pb.Frame{Body: &pb.Frame_Hello{Hello: &pb.Hello{Version: "v1"}}})
	header := b.Bytes()[:13]
	if _, _, e := Read(bytes.NewReader(header), MaxFrame, func(int, int) error { return ErrCredit }); e != ErrCredit {
		t.Fatalf("credit wasn't checked before body: %v", e)
	}
}

func TestForgedItemCountIsRejectedBeforeProtobufExpansion(t *testing.T) {
	batch := []byte{}
	for j := 0; j < 1001; j++ {
		batch = protowire.AppendTag(batch, 4, protowire.BytesType)
		batch = protowire.AppendBytes(batch, nil)
	}
	raw := protowire.AppendTag(nil, 1, protowire.VarintType)
	raw = protowire.AppendVarint(raw, 1)
	raw = protowire.AppendTag(raw, 17, protowire.BytesType)
	raw = protowire.AppendBytes(raw, batch)
	if preflight(raw, (&pb.Frame{}).ProtoReflect().Descriptor(), 0) {
		t.Fatal("repeated-item expansion accepted")
	}
}
func TestFramingAndBombs(t *testing.T) {
	f := &pb.Frame{Version: 1, Body: &pb.Frame_Hello{Hello: &pb.Hello{Version: "test", Protocols: []uint32{1}}}}
	var b bytes.Buffer
	if e := Write(&b, f); e != nil {
		t.Fatal(e)
	}
	out, _, e := Read(&b, MaxControl, nil)
	if e != nil || !proto.Equal(f, out) {
		t.Fatalf("roundtrip: %v", e)
	}
	enc, _ := zstd.NewWriter(nil)
	defer enc.Close()
	bomb := enc.EncodeAll(make([]byte, 1<<20), nil)
	var h [13]byte
	h[0] = 1
	binary.BigEndian.PutUint32(h[1:], uint32(len(bomb)))
	binary.BigEndian.PutUint32(h[5:], uint32(len(bomb)*2))
	raw := append(h[:], bomb...)
	if _, _, e = Read(bytes.NewReader(raw), MaxFrame, nil); e != ErrFrame {
		t.Fatalf("expansion cap: %v", e)
	}
}
func point() *pb.Item {
	i := &pb.Item{Id: "item-1", StreamKey: "abcdefghijklmnopqrstuvwxyz0123456789abcdefgh", BindingId: "binding", SourceId: "channel", Body: &pb.Item_Point{Point: &pb.Point{Timestamp: "2026-10-21T10:00:00Z", Value: 1480}}}
	i.Hash, _ = Hash(i)
	return i
}
func TestHashExcludesGatewayKeyAndChecksContent(t *testing.T) {
	i := point()
	h := append([]byte(nil), i.Hash...)
	i.StreamKey = "another-gateway-key"
	i.BindingId = "another-version"
	got, _ := Hash(i)
	if !bytes.Equal(got, h) {
		t.Fatal("transport identity leaked into semantic hash")
	}
	i = point()
	if Validate(i, "series") != nil {
		t.Fatal("valid point")
	}
	i.GetPoint().Value++
	if Validate(i, "series") == nil {
		t.Fatal("substitution accepted")
	}
	i.GetPoint().Value = math.NaN()
	i.Hash, _ = Hash(i)
	if Validate(i, "series") == nil {
		t.Fatal("nan accepted")
	}
}
func FuzzRead(f *testing.F) {
	var b bytes.Buffer
	_ = Write(&b, &pb.Frame{Body: &pb.Frame_Hello{Hello: &pb.Hello{Version: "1"}}})
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, raw []byte) { _, _, _ = Read(bytes.NewReader(raw), MaxControl, nil) })
}
