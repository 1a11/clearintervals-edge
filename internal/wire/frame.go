// Package wire implements the v1 framing, canonical hashing and bounded validation.
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	pb "github.com/1a11/clearintervals-edge/protocol/v1"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"io"
	"math"
	"time"
)

const MaxWire = 4 << 20
const MaxFrame = 16 << 20
const MaxControl = 32 << 10
const MaxItems = 1000

var ErrFrame = errors.New("invalid_frame")
var ErrCredit = errors.New("credit_exceeded")

// Header: flags:u8 (0 raw/1 zstd), wire-length:u32be, decoded-length:u32be, items:u32be.
// approve reserves resources and debits credit BEFORE reading or allocating the body.
func Read(r io.Reader, limit int, approve func(int, int) error) (*pb.Frame, int, error) {
	var sized func(int, int, int) error
	if approve != nil {
		sized = func(decoded, wireBytes, items int) error { return approve(decoded, items) }
	}
	return ReadSized(r, limit, sized)
}

// ReadSized exposes both validated lengths before body allocation. Memory
// accounting must include oversized/non-beneficial compressed inputs as well.
func ReadSized(r io.Reader, limit int, approve func(decoded, wireBytes, items int) error) (*pb.Frame, int, error) {
	var h [13]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return nil, 0, e
	}
	w, n, k := int(binary.BigEndian.Uint32(h[1:5])), int(binary.BigEndian.Uint32(h[5:9])), int(binary.BigEndian.Uint32(h[9:13]))
	if h[0] > 1 || w < 1 || h[0] == 1 && w > MaxWire || w > MaxFrame || n < 1 || n > limit || k > MaxItems || n > w*20 || h[0] == 0 && w != n {
		return nil, 0, ErrFrame
	}
	if approve != nil {
		if e := approve(n, w, k); e != nil {
			return nil, 0, e
		}
	}
	raw := make([]byte, w)
	if _, e := io.ReadFull(r, raw); e != nil {
		return nil, 0, e
	}
	if h[0] == 1 {
		dec, e := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxFrame), zstd.WithDecoderMaxWindow(MaxFrame), zstd.WithDecodeAllCapLimit(true))
		if e != nil {
			return nil, 0, ErrFrame
		}
		defer dec.Close()
		raw, e = dec.DecodeAll(raw, make([]byte, 0, n))
		if e != nil || len(raw) != n {
			return nil, 0, ErrFrame
		}
	}
	f := new(pb.Frame)
	if !preflight(raw, f.ProtoReflect().Descriptor(), 0) {
		return nil, 0, ErrFrame
	}
	if (proto.UnmarshalOptions{RecursionLimit: 16, DiscardUnknown: false}).Unmarshal(raw, f) != nil || f.Version != 1 || unknown(f.ProtoReflect()) || f.Body == nil {
		return nil, 0, ErrFrame
	}
	count := 0
	if f.GetBatch() != nil {
		count = len(f.GetBatch().Items)
	}
	if count != k {
		return nil, 0, ErrFrame
	}
	return f, n, nil
}

// Inspect counts and nested lengths before protobuf allocates repeated messages.
// A forged header cannot expand millions of tiny item fields into heap objects.
func preflight(raw []byte, desc protoreflect.MessageDescriptor, depth int) bool {
	if depth > 16 {
		return false
	}
	counts := map[protoreflect.FieldNumber]int{}
	oneofs := map[protoreflect.Name]bool{}
	for len(raw) > 0 {
		number, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return false
		}
		raw = raw[n:]
		fd := desc.Fields().ByNumber(protoreflect.FieldNumber(number))
		if fd == nil {
			return false
		}
		counts[fd.Number()]++
		maximum := 1
		if fd.IsList() {
			maximum = MaxItems
			switch fd.FullName() {
			case "clearintervals.uplink.v1.Hello.protocols":
				maximum = 8
			case "clearintervals.uplink.v1.Hello.modules":
				maximum = 32
			case "clearintervals.uplink.v1.Hello.stream_keys":
				maximum = 100
			}
		}
		if counts[fd.Number()] > maximum {
			return false
		}
		if o := fd.ContainingOneof(); o != nil {
			if oneofs[o.Name()] {
				return false
			}
			oneofs[o.Name()] = true
		}
		if typ == protowire.BytesType {
			payload, size := protowire.ConsumeBytes(raw)
			if size < 0 {
				return false
			}
			raw = raw[size:]
			if fd.Kind() == protoreflect.MessageKind {
				if !preflight(payload, fd.Message(), depth+1) {
					return false
				}
			} else if fd.IsPacked() {
				for len(payload) > 0 {
					_, m := protowire.ConsumeVarint(payload)
					if m < 0 {
						return false
					}
					payload = payload[m:]
					counts[fd.Number()]++
					if counts[fd.Number()] > maximum+1 {
						return false
					}
				}
			} else if fd.Kind() == protoreflect.StringKind {
				maximumBytes := 100
				switch fd.Name() {
				case "csr_pem":
					maximumBytes = 8192
				case "old_certificate_pem", "certificate_pem", "issuer_pem":
					maximumBytes = 16384
				case "source_id", "id", "binding_id", "epoch", "session_id", "gateway_id", "operation_id", "request_id":
					maximumBytes = 100
				case "timestamp":
					maximumBytes = 50
				}
				if len(payload) > maximumBytes {
					return false
				}
			} else if fd.Kind() == protoreflect.BytesKind {
				max := MaxFrame
				switch fd.Name() {
				case "hash", "csr_hash":
					max = 32
				case "metadata_json":
					max = 16384
				case "signature_der":
					max = 128
				case "signing_payload":
					max = 4096
				}
				if len(payload) > max {
					return false
				}
			} else {
				return false
			}
		} else {
			size := protowire.ConsumeFieldValue(number, typ, raw)
			if size < 0 || typ == protowire.StartGroupType || typ == protowire.EndGroupType {
				return false
			}
			raw = raw[size:]
		}
	}
	return true
}

func unknown(m protoreflect.Message) bool {
	if len(m.GetUnknown()) != 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		if fd.IsList() {
			l := v.List()
			for j := 0; j < l.Len(); j++ {
				found = found || unknown(l.Get(j).Message())
			}
		} else {
			found = unknown(v.Message())
		}
		return !found
	})
	return found
}
func Write(w io.Writer, f *pb.Frame) error {
	f.Version = 1
	b, e := proto.MarshalOptions{Deterministic: true}.Marshal(f)
	if e != nil {
		return e
	}
	if len(b) > MaxFrame {
		return ErrFrame
	}
	flags := byte(0)
	wire := b
	if len(b) > MaxWire {
		enc, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		if e != nil {
			return e
		}
		wire = enc.EncodeAll(b, nil)
		enc.Close()
		flags = 1
		if len(wire) > MaxWire || len(b) > 20*len(wire) {
			wire = b
			flags = 0
		}
	}
	var h [13]byte
	h[0] = flags
	binary.BigEndian.PutUint32(h[1:5], uint32(len(wire)))
	binary.BigEndian.PutUint32(h[5:9], uint32(len(b)))
	if f.GetBatch() != nil {
		binary.BigEndian.PutUint32(h[9:13], uint32(len(f.GetBatch().Items)))
	}
	if _, e = w.Write(h[:]); e != nil {
		return e
	}
	_, e = w.Write(wire)
	return e
}
func Canonical(i *pb.Item) ([]byte, error) {
	r := &pb.Record{Domain: "clearintervals-uplink-record-v1", SourceId: i.SourceId, AcquisitionId: i.Id}
	switch b := i.Body.(type) {
	case *pb.Item_Capture:
		r.Body = &pb.Record_Capture{Capture: b.Capture}
	case *pb.Item_Point:
		r.Body = &pb.Record_Point{Point: b.Point}
	case *pb.Item_Event:
		r.Body = &pb.Record_Event{Event: b.Event}
	default:
		return nil, ErrFrame
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(r)
}
func Hash(i *pb.Item) ([]byte, error) {
	b, e := Canonical(i)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	return h[:], nil
}
func ValidID(s string) bool {
	if len(s) < 1 || len(s) > 100 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func Timestamp(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e == nil && s == t.UTC().Format(time.RFC3339Nano)
}
func Validate(i *pb.Item, kind string) error {
	if i == nil || !ValidID(i.Id) || len(i.Hash) != 32 || len(i.ProtoReflect().GetUnknown()) > 0 {
		return ErrFrame
	}
	if kind != "events" && (!ValidID(i.BindingId) || !ValidID(i.SourceId) || len(i.StreamKey) < 40 || len(i.StreamKey) > 100) {
		return ErrFrame
	}
	switch kind {
	case "captures":
		c := i.GetCapture()
		if c == nil || c.Count < 2 || c.Count > 1000000 || len(c.MetadataJson) > 16384 || len(c.SamplesLeF32) > 12000000 {
			return ErrFrame
		}
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(c.MetadataJson))
		if d.Decode(&m) != nil || m == nil {
			return ErrFrame
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return ErrFrame
		}
		canonical, e := json.Marshal(m)
		if e != nil || !bytes.Equal(canonical, c.MetadataJson) {
			return ErrFrame
		}
		axes, ok := m["axes"].([]any)
		if !ok || len(axes) < 1 || len(axes) > 3 || len(c.SamplesLeF32) != int(c.Count)*len(axes)*4 {
			return ErrFrame
		}
		seen := map[string]bool{}
		for _, a := range axes {
			s, ok := a.(string)
			if !ok || s != "x" && s != "y" && s != "z" || seen[s] {
				return ErrFrame
			}
			seen[s] = true
		}
		fs, ok := m["fsNominalHz"].(float64)
		if !ok || fs <= 0 || float64(c.Count-1)/fs > 120 {
			return ErrFrame
		}
		if m["captureId"] != i.Id || m["tier"] != "M" && m["tier"] != "I" {
			return ErrFrame
		}
		start, ok := m["startTimeUtc"].(string)
		if !ok || !Timestamp(start) {
			return ErrFrame
		}
		for j := 0; j < len(c.SamplesLeF32); j += 4 {
			v := math.Float32frombits(binary.LittleEndian.Uint32(c.SamplesLeF32[j:]))
			if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
				return ErrFrame
			}
		}
	case "series":
		p := i.GetPoint()
		if p == nil || !Timestamp(p.Timestamp) || math.IsNaN(p.Value) || math.IsInf(p.Value, 0) || math.Signbit(p.Value) && p.Value == 0 {
			return ErrFrame
		}
	case "events":
		e := i.GetEvent()
		if e == nil || !Timestamp(e.Timestamp) || e.Count > 1<<50 || i.StreamKey != "" || i.BindingId != "" {
			return ErrFrame
		}
		switch e.Kind {
		case "source_unreachable", "buffer_full", "module_error", "clock_skew", "update_required":
		default:
			return ErrFrame
		}
	default:
		return ErrFrame
	}
	hash, e := Hash(i)
	if e != nil || !bytes.Equal(hash, i.Hash) {
		return ErrFrame
	}
	return nil
}
