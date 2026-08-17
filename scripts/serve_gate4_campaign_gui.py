#!/usr/bin/env python3
"""Serve the read-only Gate 4 dashboard for a shared campaign output directory."""

from __future__ import annotations

import argparse
import signal
import time
from pathlib import Path

from gate4_campaign_gui import CampaignGui


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    stopped = False
    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    gui = CampaignGui(args.output_dir, args.port); gui.start()
    print(f"Gate 4 dashboard: http://127.0.0.1:{gui.port}", flush=True)
    try:
        while not stopped: time.sleep(.5)
    finally:
        gui.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
