#!/usr/bin/env python3
"""
Real-time Clearwatch Monitor

This script provides real-time monitoring of Clearwatch's operation.
It shows live updates of events, file changes, and system status.
"""

import time
import json
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict

class ClearwatchMonitor:
    def __init__(self):
        self.events_dir = Path("clearwatch/events")
        self.logs_dir = Path("clearwatch/logs")
        self.reports_dir = Path("clearwatch/reports")
        self.last_event_count = 0
        self.last_file_count = 0
        self.event_stats = defaultdict(int)
        
    def get_file_count(self):
        """Get count of event files."""
        if not self.events_dir.exists():
            return 0
        return len(list(self.events_dir.glob("*.jsonl")))
    
    def get_total_events(self):
        """Get total number of events across all files."""
        if not self.events_dir.exists():
            return 0
        
        total = 0
        for file_path in self.events_dir.glob("*.jsonl"):
            try:
                with open(file_path, 'r') as f:
                    total += sum(1 for line in f if line.strip())
            except:
                pass
        return total
    
    def get_latest_events(self, count=5):
        """Get the latest events from all files."""
        if not self.events_dir.exists():
            return []
        
        all_events = []
        for file_path in sorted(self.events_dir.glob("*.jsonl"), key=os.path.getmtime, reverse=True):
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        if line.strip():
                            all_events.append(json.loads(line))
            except:
                pass
        
        # Sort by timestamp and return latest
        all_events.sort(key=lambda x: x.get('ts', ''), reverse=True)
        return all_events[:count]
    
    def get_log_tail(self, lines=5):
        """Get the last few lines from the log file."""
        log_file = self.logs_dir / "clearwatch.log"
        if not log_file.exists():
            return []
        
        try:
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return [line.strip() for line in all_lines[-lines:]]
        except:
            return []
    
    def update_stats(self, events):
        """Update event statistics."""
        for event in events:
            rule = event.get('rule', 'unknown')
            severity = event.get('severity', 'unknown')
            self.event_stats[f"{severity}:{rule}"] += 1
    
    def display_status(self):
        """Display current status."""
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear screen
        
        print("🔍 Clearwatch Real-time Monitor")
        print("=" * 50)
        print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # File statistics
        file_count = self.get_file_count()
        total_events = self.get_total_events()
        
        print("📊 Statistics:")
        print(f"   📁 Event files: {file_count}")
        print(f"   📈 Total events: {total_events}")
        print()
        
        # Event breakdown
        if self.event_stats:
            print("📋 Event Breakdown:")
            for key, count in sorted(self.event_stats.items()):
                severity, rule = key.split(':', 1)
                emoji = {'HIGH': '🔴', 'MED': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                print(f"   {emoji} {severity} {rule}: {count}")
            print()
        
        # Latest events
        latest_events = self.get_latest_events(3)
        if latest_events:
            print("🆕 Latest Events:")
            for event in latest_events:
                severity = event.get('severity', 'UNKNOWN')
                rule = event.get('rule', 'unknown')
                dst_ip = event.get('dst_ip', 'unknown')
                dst_port = event.get('dst_port', 'unknown')
                timestamp = event.get('ts', 'unknown')
                
                emoji = {'HIGH': '🔴', 'MED': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                print(f"   {emoji} {severity} {rule} on {dst_ip}:{dst_port}")
                print(f"      Time: {timestamp}")
            print()
        
        # Recent log entries
        log_lines = self.get_log_tail(3)
        if log_lines:
            print("📝 Recent Log Entries:")
            for line in log_lines:
                if line:
                    print(f"   {line}")
            print()
        
        # Status indicators
        print("🟢 Status: Monitoring Active")
        print("💡 Press Ctrl+C to stop monitoring")
        print("-" * 50)
    
    def run(self):
        """Run the real-time monitor."""
        print("🚀 Starting Clearwatch Real-time Monitor...")
        print("Press Ctrl+C to stop")
        time.sleep(2)
        
        try:
            while True:
                # Get current events
                current_events = self.get_latest_events(10)
                new_events = current_events[:len(current_events) - self.last_event_count]
                
                # Update statistics
                if new_events:
                    self.update_stats(new_events)
                    self.last_event_count = len(current_events)
                
                # Display status
                self.display_status()
                
                # Wait before next update
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\n\n👋 Monitor stopped by user")
            print("📊 Final Statistics:")
            for key, count in sorted(self.event_stats.items()):
                severity, rule = key.split(':', 1)
                emoji = {'HIGH': '🔴', 'MED': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                print(f"   {emoji} {severity} {rule}: {count}")

def main():
    monitor = ClearwatchMonitor()
    monitor.run()

if __name__ == "__main__":
    main()
