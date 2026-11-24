from __future__ import annotations

import sys
from pathlib import Path

# The repository-level verification runs from the host root rather than from
# vendor/systutor-core. Include the vendored kernel source and plugin namespace
# without requiring an editable reinstall of the virtual environment.
CORE_ROOT = Path(__file__).resolve().parents[4]
for entry in (str(CORE_ROOT), str(CORE_ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)
