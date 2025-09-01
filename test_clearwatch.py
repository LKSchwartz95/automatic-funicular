#!/usr/bin/env python3
"""
Clearwatch Testing and Monitoring Script

This script helps you test and monitor Clearwatch's operation.
It provides real-time feedback and generates test traffic.
"""

import time
import requests
import subprocess
import threading
import json
from pathlib import Path
from datetime import datetime
import argparse

class ClearwatchTester:
    def __init__(self):
        self.events_dir = Path("clearwatch/events")
        self.logs_dir = Path("clearwatch/logs")
        self.test_server_process = None
        self.clearwatch_process = None
        
    def start_test_server(self):
        """Start a simple HTTP server for testing."""
        print("🌐 Starting test HTTP server on port 8080...")
        try:
            self.test_server_process = subprocess.Popen([
                "python", "-m", "http.server", "8080"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)  # Give server time to start
            print("✅ Test server started successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to start test server: {e}")
            return False
    
    def stop_test_server(self):
        """Stop the test HTTP server."""
        if self.test_server_process:
            self.test_server_process.terminate()
            print("🛑 Test server stopped")
    
    def generate_test_traffic(self):
        """Generate test traffic to trigger detections."""
        print("\n🧪 Generating test traffic...")
        
        # Test 1: HTTP Basic Auth (should trigger HIGH alert)
        print("1. Testing HTTP Basic Auth...")
        try:
            response = requests.get("http://127.0.0.1:8080/", 
                                  auth=("alice", "secret"), 
                                  timeout=5)
            print(f"   ✅ HTTP Basic Auth request sent (Status: {response.status_code})")
        except Exception as e:
            print(f"   ❌ HTTP Basic Auth test failed: {e}")
        
        time.sleep(1)
        
        # Test 2: HTTP Form with credentials (should trigger MED alert)
        print("2. Testing HTTP Form with credentials...")
        try:
            response = requests.post("http://127.0.0.1:8080/login",
                                   data={"user": "alice", "password": "hunter2"},
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   timeout=5)
            print(f"   ✅ HTTP Form request sent (Status: {response.status_code})")
        except Exception as e:
            print(f"   ❌ HTTP Form test failed: {e}")
        
        time.sleep(1)
        
        # Test 3: Regular HTTP request (should not trigger alerts)
        print("3. Testing regular HTTP request...")
        try:
            response = requests.get("http://127.0.0.1:8080/", timeout=5)
            print(f"   ✅ Regular HTTP request sent (Status: {response.status_code})")
        except Exception as e:
            print(f"   ❌ Regular HTTP test failed: {e}")
    
    def monitor_events(self, duration=30):
        """Monitor events directory for new files and events."""
        print(f"\n👀 Monitoring events for {duration} seconds...")
        
        initial_files = set(self.events_dir.glob("*.jsonl")) if self.events_dir.exists() else set()
        start_time = time.time()
        
        while time.time() - start_time < duration:
            current_files = set(self.events_dir.glob("*.jsonl")) if self.events_dir.exists() else set()
            new_files = current_files - initial_files
            
            if new_files:
                print(f"📁 New event file detected: {new_files}")
                for file_path in new_files:
                    self.analyze_event_file(file_path)
                initial_files = current_files
            
            time.sleep(1)
        
        print("⏰ Monitoring period completed")
    
    def analyze_event_file(self, file_path):
        """Analyze an event file and display its contents."""
        print(f"\n📊 Analyzing event file: {file_path.name}")
        try:
            with open(file_path, 'r') as f:
                events = []
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
                
                if events:
                    print(f"   📈 Found {len(events)} events:")
                    for i, event in enumerate(events, 1):
                        severity = event.get('severity', 'UNKNOWN')
                        rule = event.get('rule', 'unknown')
                        dst_ip = event.get('dst_ip', 'unknown')
                        dst_port = event.get('dst_port', 'unknown')
                        timestamp = event.get('ts', 'unknown')
                        
                        severity_emoji = {
                            'HIGH': '🔴',
                            'MED': '🟡', 
                            'LOW': '🔵'
                        }.get(severity, '⚪')
                        
                        print(f"   {severity_emoji} Event {i}: {severity} {rule} on {dst_ip}:{dst_port} at {timestamp}")
                else:
                    print("   📭 No events found in file")
        except Exception as e:
            print(f"   ❌ Error analyzing file: {e}")
    
    def check_clearwatch_status(self):
        """Check if Clearwatch is running and capturing traffic."""
        print("\n🔍 Checking Clearwatch status...")
        
        # Check if log file exists and is being updated
        log_file = self.logs_dir / "clearwatch.log"
        if log_file.exists():
            print("✅ Log file exists")
            
            # Check last few lines of log
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        print("📋 Recent log entries:")
                        for line in lines[-5:]:  # Last 5 lines
                            print(f"   {line.strip()}")
                    else:
                        print("📭 Log file is empty")
            except Exception as e:
                print(f"❌ Error reading log file: {e}")
        else:
            print("❌ Log file not found")
        
        # Check events directory
        if self.events_dir.exists():
            event_files = list(self.events_dir.glob("*.jsonl"))
            print(f"📁 Event files: {len(event_files)}")
            if event_files:
                for file_path in event_files:
                    size = file_path.stat().st_size
                    mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    print(f"   📄 {file_path.name} ({size} bytes, modified: {mtime})")
        else:
            print("❌ Events directory not found")
    
    def run_comprehensive_test(self):
        """Run a comprehensive test of Clearwatch."""
        print("🚀 Starting Comprehensive Clearwatch Test")
        print("=" * 50)

        # Step 1: Check initial status
        self.check_clearwatch_status()

        # Step 2: Start test server
        if not self.start_test_server():
            print("❌ Cannot proceed without test server")
            return False

        try:
            # Step 3: Generate test traffic
            self.generate_test_traffic()

            # Step 4: Monitor for events
            self.monitor_events(15)  # Monitor for 15 seconds

            # Step 5: Final status check
            print("\n" + "=" * 50)
            print("📊 Final Status Check")
            self.check_clearwatch_status()
        except Exception as e:
            print(f"❌ Error during comprehensive test: {e}")
            return False
        finally:
            # Cleanup
            self.stop_test_server()

        print("\n✅ Test completed!")
        return True

def main():
    parser = argparse.ArgumentParser(
        description="Clearwatch Testing and Monitoring Tool"
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run comprehensive test without prompts",
    )
    args = parser.parse_args()

    tester = ClearwatchTester()

    if args.auto:
        success = tester.run_comprehensive_test()
        raise SystemExit(0 if success else 1)

    print("Clearwatch Testing and Monitoring Tool")
    print("=====================================")
    print()
    print("This tool will help you:")
    print("1. ✅ Verify Clearwatch is running")
    print("2. 🌐 Start a test HTTP server")
    print("3. 🧪 Generate test traffic")
    print("4. 👀 Monitor for security events")
    print("5. 📊 Analyze detected events")
    print()

    while True:
        print("\nChoose an option:")
        print("1. Run comprehensive test")
        print("2. Check Clearwatch status")
        print("3. Start test server only")
        print("4. Generate test traffic only")
        print("5. Monitor events only")
        print("6. Exit")

        choice = input("\nEnter your choice (1-6): ").strip()

        if choice == "1":
            tester.run_comprehensive_test()
        elif choice == "2":
            tester.check_clearwatch_status()
        elif choice == "3":
            tester.start_test_server()
            input("Press Enter to stop the test server...")
            tester.stop_test_server()
        elif choice == "4":
            if tester.start_test_server():
                tester.generate_test_traffic()
                tester.stop_test_server()
        elif choice == "5":
            duration = input(
                "Enter monitoring duration in seconds (default 30): "
            ).strip()
            try:
                duration = int(duration) if duration else 30
                tester.monitor_events(duration)
            except ValueError:
                print("Invalid duration, using default 30 seconds")
                tester.monitor_events(30)
        elif choice == "6":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1-6.")

if __name__ == "__main__":
    main()
