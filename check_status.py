#!/usr/bin/env python3
"""
Quick Clearwatch Status Checker

This script quickly checks if Clearwatch is working properly.
"""

import json
import os
from pathlib import Path
from datetime import datetime

def check_clearwatch_status():
    """Check Clearwatch status and display results."""
    print("🔍 Clearwatch Status Check")
    print("=" * 30)
    
    # Check directories
    events_dir = Path("clearwatch/events")
    logs_dir = Path("clearwatch/logs")
    reports_dir = Path("clearwatch/reports")
    
    print("📁 Directory Status:")
    print(f"   Events: {'✅' if events_dir.exists() else '❌'} {events_dir}")
    print(f"   Logs:   {'✅' if logs_dir.exists() else '❌'} {logs_dir}")
    print(f"   Reports: {'✅' if reports_dir.exists() else '❌'} {reports_dir}")
    print()
    
    # Check log file
    log_file = logs_dir / "clearwatch.log"
    if log_file.exists():
        print("📝 Log File Status:")
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                print(f"   ✅ Log file exists ({len(lines)} lines)")
                
                # Show last few lines
                if lines:
                    print("   📋 Recent entries:")
                    for line in lines[-3:]:
                        if line.strip():
                            print(f"      {line.strip()}")
        except Exception as e:
            print(f"   ❌ Error reading log: {e}")
    else:
        print("📝 Log File Status: ❌ No log file found")
    print()
    
    # Check event files
    if events_dir.exists():
        event_files = list(events_dir.glob("*.jsonl"))
        print("📊 Event Files Status:")
        if event_files:
            print(f"   ✅ {len(event_files)} event files found")
            
            # Analyze latest file
            latest_file = max(event_files, key=os.path.getmtime)
            print(f"   📄 Latest file: {latest_file.name}")
            
            try:
                with open(latest_file, 'r') as f:
                    events = []
                    for line in f:
                        if line.strip():
                            events.append(json.loads(line))
                    
                    if events:
                        print(f"   📈 {len(events)} events in latest file")
                        
                        # Show event breakdown
                        severity_count = {}
                        rule_count = {}
                        for event in events:
                            severity = event.get('severity', 'UNKNOWN')
                            rule = event.get('rule', 'unknown')
                            severity_count[severity] = severity_count.get(severity, 0) + 1
                            rule_count[rule] = rule_count.get(rule, 0) + 1
                        
                        print("   📋 Event breakdown:")
                        for severity, count in severity_count.items():
                            emoji = {'HIGH': '🔴', 'MED': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                            print(f"      {emoji} {severity}: {count}")
                        
                        print("   📋 Rules detected:")
                        for rule, count in rule_count.items():
                            print(f"      • {rule}: {count}")
                    else:
                        print("   📭 No events in latest file")
            except Exception as e:
                print(f"   ❌ Error reading events: {e}")
        else:
            print("   📭 No event files found")
    else:
        print("📊 Event Files Status: ❌ Events directory not found")
    print()
    
    # Overall status
    print("🎯 Overall Status:")
    if log_file.exists() and events_dir.exists():
        print("   ✅ Clearwatch appears to be working")
        print("   💡 Run 'python main.py --mode watch' to start monitoring")
        print("   🧪 Run 'python test_clearwatch.py' to test functionality")
    else:
        print("   ❌ Clearwatch may not be running or configured properly")
        print("   💡 Run 'python main.py' to start Clearwatch")
        print("   🔧 Check configuration and dependencies")

if __name__ == "__main__":
    check_clearwatch_status()
