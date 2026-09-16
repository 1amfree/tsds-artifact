#!/usr/bin/env python3
"""Version-neutral entry point for contract-gated TSDS paper tables."""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.export_v10_paper_tables import main


if __name__ == "__main__":
    raise SystemExit(main())
