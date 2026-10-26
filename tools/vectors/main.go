// Command vectors emits the normative, reviewable cross-language record vectors.
package main

import (
	"encoding/hex"
	"encoding/json"
	"github.com/1a11/clearintervals-edge/internal/wire"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"google.golang.org/protobuf/proto"
	"os"
)

func main() {
	items := []*pb.Item{
		{Id: "capture-1", SourceId: "channel", Body: &pb.Item_Capture{Capture: &pb.Capture{MetadataJson: []byte(`{"axes":["z"],"captureId":"capture-1","fsNominalHz":1000,"startTimeUtc":"2026-10-21T10:00:00Z","tier":"M"}`), Count: 2, SamplesLeF32: []byte{0, 0, 128, 63, 0, 0, 0, 192}}}},
		{Id: "point-1", SourceId: "channel", Body: &pb.Item_Point{Point: &pb.Point{Timestamp: "2026-10-21T10:00:00Z", Value: 1480}}},
		{Id: "event-1", SourceId: "gateway", Body: &pb.Item_Event{Event: &pb.Event{Timestamp: "2026-10-21T10:00:00Z", Kind: "buffer_full", Count: 3}}},
	}
	rows := []map[string]string{}
	for j, i := range items {
		if j < 2 {
			i.StreamKey = "abcdefghijklmnopqrstuvwxyz0123456789abcdefgh"
			i.BindingId = "binding"
		}
		canonical, e := wire.Canonical(i)
		if e != nil {
			panic(e)
		}
		hash, e := wire.Hash(i)
		if e != nil {
			panic(e)
		}
		i.Hash = hash
		encoded, e := proto.MarshalOptions{Deterministic: true}.Marshal(i)
		if e != nil {
			panic(e)
		}
		rows = append(rows, map[string]string{"name": i.Id, "itemHex": hex.EncodeToString(encoded), "canonicalHex": hex.EncodeToString(canonical), "sha256": hex.EncodeToString(hash)})
	}
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	if e := out.Encode(rows); e != nil {
		panic(e)
	}
}
