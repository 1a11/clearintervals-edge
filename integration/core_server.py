"""Real core entry point plus a single bounded pre-commit crash fault for acceptance.

No production package imports this module. It runs only in the disposable fixture.
"""
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(os.environ['CORE_SOURCE']).resolve() / 'infra/core'))
from core.gateways import ingest
from core.errors import fail
from core.gateway_ingest import main

original = ingest.submit_capture
fault_dir = Path(os.environ['CI_ACCEPTANCE_FAULT_DIR'])


def fault(*args, **kwargs):
    metadata = args[6] if len(args) > 6 else kwargs['metadata']
    if metadata.get('captureId') == 'crash-second' and not (fault_dir / 'fault.release').exists():
        (fault_dir / 'fault.ready').touch()
        until = time.monotonic() + 20
        while time.monotonic() < until and not (fault_dir / 'fault.release').exists():
            time.sleep(0.01)
        fail(503, 'core_unavailable')
    return original(*args, **kwargs)


ingest.submit_capture = fault
main()
