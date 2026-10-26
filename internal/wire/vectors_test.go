package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"google.golang.org/protobuf/proto"
	"os"
	"testing"
)

func TestCanonicalVectors(t *testing.T) {
	raw, e := os.ReadFile("../../protocol/v1/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []map[string]string
	if e = json.Unmarshal(raw, &rows); e != nil {
		t.Fatal(e)
	}
	for _, r := range rows {
		t.Run(r["name"], func(t *testing.T) {
			b, e := hex.DecodeString(r["itemHex"])
			if e != nil {
				t.Fatal(e)
			}
			i := new(pb.Item)
			if e = proto.Unmarshal(b, i); e != nil {
				t.Fatal(e)
			}
			canonical, e := Canonical(i)
			if e != nil || hex.EncodeToString(canonical) != r["canonicalHex"] {
				t.Fatal("canonical bytes changed")
			}
			hash, e := Hash(i)
			if e != nil || hex.EncodeToString(hash) != r["sha256"] || !bytes.Equal(hash, i.Hash) {
				t.Fatal("hash changed")
			}
		})
	}
}
