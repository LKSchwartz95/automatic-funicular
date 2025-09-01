#!/usr/bin/env python3
"""Quick status helper for Clearwatch watch mode."""
from pathlib import Path

def show_log_event_status() -> None:
    """Print presence of log and event files."""
    logs_dir = Path("clearwatch/logs")
    events_dir = Path("clearwatch/events")

    log_file = logs_dir / "clearwatch.log"
    event_files = list(events_dir.glob("*.jsonl")) if events_dir.exists() else []

    print("\n\U0001F4CA Quick capture status:")
    print(f"   Log file present: {'\u2705' if log_file.exists() else '\u274C'} ({log_file})")
    print(f"   Event files present: {'\u2705' if event_files else '\u274C'} ({events_dir})")

