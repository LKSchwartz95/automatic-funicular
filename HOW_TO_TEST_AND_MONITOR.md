# 🧪 How to Test and Monitor Clearwatch

This guide shows you exactly what happens when you run Clearwatch in Watch Mode and how to verify it's working properly.

## 🎯 What Happens When You Press "1" (Watch Mode)

When you select Watch Mode, Clearwatch:

1. **🔍 Starts Network Monitoring**
   - Launches tshark to capture network traffic
   - Monitors the "Ethernet" interface (configurable)
   - Filters for HTTP, SMTP, POP3/IMAP, FTP, TELNET, and TLS traffic

2. **⚡ Real-time Detection**
   - Analyzes each packet for security violations
   - Checks for plaintext credentials, weak transports, etc.
   - Applies allowlist filtering (ignores internal networks)

3. **📺 Console Output**
   - Shows startup information
   - Displays real-time security alerts with color coding:
     - 🔴 **HIGH** alerts (red) - Critical security issues
     - 🟡 **MED** alerts (yellow) - Medium risk issues  
     - 🔵 **LOW** alerts (blue) - Low risk issues
   - Shows file rotation information

4. **💾 File Output**
   - Saves events to `clearwatch/events/YYYY-MM-DD_HH-MM.jsonl`
   - Rotates files every 5 minutes or 10MB (whichever comes first)
   - Logs all activity to `clearwatch/logs/clearwatch.log`

5. **🔄 Continuous Operation**
   - Runs until you press Ctrl+C
   - Gracefully handles shutdown and cleanup

## 🧪 How to Test Clearwatch

### Method 1: Use the Test Script (Recommended)

I've created a comprehensive testing tool for you:

```bash
python test_clearwatch.py
```

This script will:
- ✅ Check if Clearwatch is running properly
- 🌐 Start a test HTTP server
- 🧪 Generate test traffic (HTTP Basic Auth, forms with credentials)
- 👀 Monitor for security events
- 📊 Analyze and display detected events

### Method 2: Manual Testing

1. **Start Clearwatch in Watch Mode:**
   ```bash
   python main.py --mode watch
   ```

2. **In another terminal, start a test server:**
   ```bash
   python -m http.server 8080
   ```

3. **Generate test traffic:**
   ```bash
   # Test HTTP Basic Auth (should trigger HIGH alert)
   python -c "import requests; requests.get('http://127.0.0.1:8080/', auth=('alice', 'secret'))"
   
   # Test HTTP Form with credentials (should trigger MED alert)
   python -c "import requests; requests.post('http://127.0.0.1:8080/login', data={'user': 'alice', 'password': 'hunter2'})"
   ```

4. **Check for events:**
   ```bash
   # View latest events
   python -c "import json; [print(json.dumps(json.loads(line), indent=2)) for line in open('clearwatch/events/' + max([f for f in os.listdir('clearwatch/events/') if f.endswith('.jsonl')], key=lambda x: os.path.getmtime('clearwatch/events/' + x)))]"
   ```

### Method 3: Use the Batch File (Windows)

Double-click `start_clearwatch.bat` to start monitoring with a user-friendly interface.

## 👀 How to Monitor Clearwatch in Real-Time

### Method 1: Real-time Monitor Script

I've created a real-time monitoring tool:

```bash
python monitor_clearwatch.py
```

This shows:
- 📊 Live statistics (file count, event count)
- 📋 Event breakdown by severity and type
- 🆕 Latest events with details
- 📝 Recent log entries
- 🟢 Status indicators

### Method 2: Manual Monitoring

1. **Watch the console output** - Clearwatch shows real-time alerts
2. **Check log files:**
   ```bash
   # View latest log entries
   Get-Content clearwatch\logs\clearwatch.log -Tail 10
   ```
3. **Monitor event files:**
   ```bash
   # List event files
   ls clearwatch\events\
   
   # View latest events
   Get-Content clearwatch\events\*.jsonl -Tail 5
   ```

## 🔍 How to Know It's Working

### ✅ Positive Indicators:

1. **Console Shows Activity:**
   ```
   [2025-01-01 10:30:15] INFO: Clearwatch started - monitoring interface: Ethernet
   [2025-01-01 10:30:16] INFO: Using tshark: C:\Program Files\Wireshark\tshark.exe
   [2025-01-01 10:30:17] HIGH ALERT: http.basic_auth detected on 127.0.0.1:8080
   ```

2. **Event Files Are Created:**
   ```
   clearwatch/events/2025-01-01_10-30.jsonl
   clearwatch/events/2025-01-01_10-35.jsonl
   ```

3. **Log File Shows Activity:**
   ```
   [2025-01-01 10:30:15] INFO: Tshark process started with PID: 12345
   [2025-01-01 10:30:16] INFO: Created new file: clearwatch/events/2025-01-01_10-30.jsonl
   ```

4. **Test Traffic Triggers Alerts:**
   - HTTP Basic Auth → HIGH alert
   - HTTP forms with credentials → MED alert
   - Regular HTTP traffic → No alerts (filtered out)

### ❌ Troubleshooting:

1. **No Events Detected:**
   - Check if tshark is installed: `tshark --version`
   - Verify network interface name in config
   - Ensure running as Administrator
   - Check if traffic is being allowlisted

2. **Permission Errors:**
   - Run as Administrator on Windows
   - Check tshark installation path

3. **No Network Traffic:**
   - Generate test traffic using the test script
   - Check if network interface is active
   - Verify firewall settings

## 📊 Expected Output Examples

### Console Output:
```
============================================================
                    CLEARWATCH
        Clear-Text & Weak-Transport Detector
              with Local LLM Guidance
============================================================

[2025-01-01 10:30:15] INFO: Clearwatch started - monitoring interface: Ethernet
[2025-01-01 10:30:16] INFO: Using tshark: C:\Program Files\Wireshark\tshark.exe
[2025-01-01 10:30:17] HIGH ALERT: http.basic_auth detected on 127.0.0.1:8080
[2025-01-01 10:30:18] MED ALERT: http.credential_key detected on 127.0.0.1:8080
[2025-01-01 10:30:20] ROTATION: Current file: clearwatch/events/2025-01-01_10-30.jsonl (1024 bytes)
```

### Event File Content:
```json
{
  "ts": "2025-01-01T10:30:17.123456",
  "severity": "HIGH",
  "rule": "http.basic_auth",
  "src_ip": "127.0.0.1",
  "src_port": 54321,
  "dst_ip": "127.0.0.1",
  "dst_port": 8080,
  "host": "127.0.0.1",
  "context": {
    "protocol": "HTTP"
  }
}
```

## 🚀 Quick Start Commands

```bash
# Start monitoring
python main.py --mode watch

# Run comprehensive test
python test_clearwatch.py

# Monitor in real-time
python monitor_clearwatch.py

# Start with batch file (Windows)
start_clearwatch.bat
```

## 💡 Pro Tips

1. **Run as Administrator** - Required for network capture on Windows
2. **Use the test script first** - Verify everything works before monitoring real traffic
3. **Check the logs** - Always check `clearwatch/logs/clearwatch.log` for issues
4. **Monitor file rotation** - Events are saved to rotating JSONL files
5. **Test with known traffic** - Use the test script to generate predictable alerts

---

**🎯 Bottom Line:** Clearwatch is working when you see real-time console alerts, event files being created, and test traffic triggering the expected security detections.
