"""Independent Python verification; generate uplink_pb2.py from the normative schema first."""
import hashlib
import json
from pathlib import Path
from protocol.v1 import uplink_pb2 as pb

for row in json.loads(Path('protocol/v1/vectors.json').read_text()):
    item = pb.Item.FromString(bytes.fromhex(row['itemHex']))
    record = pb.Record(domain='clearintervals-uplink-record-v1', source_id=item.source_id,
                       acquisition_id=item.id)
    kind = item.WhichOneof('body')
    getattr(record, kind).CopyFrom(getattr(item, kind))
    canonical = record.SerializeToString(deterministic=True)
    assert canonical.hex() == row['canonicalHex'], row['name']
    assert hashlib.sha256(canonical).hexdigest() == row['sha256'], row['name']
    assert hashlib.sha256(canonical).digest() == item.hash, row['name']
print('3 cross-language canonical vectors verified')
