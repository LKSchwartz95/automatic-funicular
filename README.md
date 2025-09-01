# Clearwatch

**Clear-Text & Weak-Transport Detector with Local LLM Guidance**

A professional-grade network security monitoring tool that detects plaintext credentials and weak transport protocols in real-time, with optional AI-powered analysis using local Ollama LLM.

## Features

- **Real-time Network Monitoring**: Capture and analyze network traffic using tshark ✅
- **Security Event Detection**: Identify plaintext credentials, weak transports, and policy violations ✅
- **Dual-Mode Operation**: Watch Mode for live monitoring, Analysis Mode for LLM-powered insights ✅
- **Professional Reporting**: Generate executive-level security intelligence reports ✅
- **Privacy-First**: No raw secrets stored, configurable allowlists, GDPR compliant ✅
- **RESTful API**: Programmatic access to events and LLM analysis ✅
- **Service Deployment**: Windows Task Scheduler and Linux systemd support ✅
- **Cross-Platform**: Windows-first design with Linux/macOS support ⚠️

## What Works Right Now

### ✅ **Fully Functional Features**
- **Real-time packet capture** with tshark integration
- **All protocol detection rules** (HTTP, SMTP, POP3/IMAP, FTP, TELNET, TLS)
- **Interactive and non-interactive modes** with CLI arguments
- **LLM-powered analysis** with Ollama integration
- **Professional security reports** in Markdown format
- **RESTful API** with `/alerts/recent` and `/alerts/explain` endpoints
- **Automatic file rotation** with time and size-based limits
- **Windows deployment** with Task Scheduler templates
- **Linux deployment** with systemd service templates
- **Privacy protection** with allowlist filtering and content hashing

### ⚠️ **Known Issues**
- **TLS detection**: Minor bug in event creation (uses direct constructor instead of factory method)
- **Linux/macOS configs**: Only Windows configuration file provided
- **TLS rules**: Need to use proper Event factory methods for consistency

### 🚀 **Ready for Production Use**
The core functionality is complete and ready for production deployment. Users can:
1. Monitor network traffic in real-time
2. Generate professional security reports
3. Deploy as a background service
4. Access events via REST API
5. Get LLM-powered security analysis

## Supported Detections

### Protocol Security Issues
- **HTTP**: Basic Authentication without TLS, credential keys in forms/JSON
- **SMTP**: AUTH before STARTTLS
- **POP3/IMAP**: Plaintext credentials without TLS
- **FTP**: USER/PASS on control port
- **TELNET**: Login/password prompts

### Security Features
- CIDR-based allowlisting for internal networks
- SHA-256 hashing of sensitive content
- Configurable retention policies
- Real-time console alerts with severity levels
- Automatic file rotation (time and size-based)

## Installation

### Prerequisites

1. **Python 3.11+**
2. **Wireshark/tshark** (for packet capture)
3. **Administrator/root privileges** (required for network capture)

### Windows Installation

1. **Install Wireshark**:
   - Download from [wireshark.org](https://www.wireshark.org/)
   - Ensure Npcap is installed (usually bundled)
   - Verify tshark is available at: `C:\Program Files\Wireshark\tshark.exe`

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run as Administrator**:
   - Network capture requires elevated privileges on Windows

### Linux/macOS Installation

1. **Install tshark**:
   ```bash
   # Ubuntu/Debian
   sudo apt install tshark
   
   # CentOS/RHEL
   sudo yum install wireshark-cli
   
   # macOS
   brew install wireshark
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure capture permissions**:
   ```bash
   # Add user to wireshark group
   sudo usermod -a -G wireshark $USER
   
   # Or run with sudo
   sudo python main.py
   ```

## Quick Start

### 1. First Run

```bash
python main.py
```

The program will:
- Auto-create `clearwatch/` folder structure
- Load platform-specific configuration
- Present mode selection menu

### 2. Select Watch Mode

Choose option `1` to start monitoring:
- Automatically detects network interfaces
- Starts packet capture with tshark
- Displays real-time security alerts
- Creates rotating JSONL event files

### 3. Non-Interactive Mode (New!)

For automation and service deployment:

```bash
# Start directly in Watch Mode
python main.py --mode watch

# Start directly in Analysis Mode
python main.py --mode analysis

# Use custom configuration directory
python main.py --config /path/to/config --mode watch
```

### 4. API Server (Optional)

If enabled in configuration, the API server runs automatically in the background:
- Access recent alerts: `http://127.0.0.1:8088/alerts/recent`
- Get LLM analysis: `POST http://127.0.0.1:8088/alerts/explain`

### 5. Test Detection

Generate test traffic to verify detection:

**HTTP Basic Auth**:
```bash
curl -u alice:secret http://127.0.0.1:8080/
```

**HTTP Form with Credentials**:
```bash
curl -d "user=alice&password=hunter2" -H "Content-Type: application/x-www-form-urlencoded" http://127.0.0.1:8080/login
```

### 6. View Results

- **Console**: Real-time alerts with timestamps and severity
- **Files**: `clearwatch/events/` contains JSONL event files
- **Logs**: `clearwatch/logs/clearwatch.log` for detailed logging

## Configuration

### Windows Configuration

The program automatically loads `config/config.windows.yaml`:

```yaml
detector:
  tshark_path: "C:\\Program Files\\Wireshark\\tshark.exe"
  interface: "Ethernet"  # or "Wi-Fi"
  allowlist_cidrs:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
```

### Interface Discovery

To find available network interfaces:

```bash
# Windows
"C:\Program Files\Wireshark\tshark.exe" -D

# Linux/macOS
tshark -D
```

Update the `detector.interface` setting in your config file.

## Usage

### Watch Mode

Real-time network monitoring:
- Press `Ctrl+C` to stop monitoring
- Events automatically written to rotating JSONL files
- Console shows live alerts and file rotation info

### Analysis Mode

LLM-powered security analysis (requires Ollama):
- Reads previous capture data
- Generates professional security reports
- Provides actionable recommendations

### File Organization

```
clearwatch/
├── events/          # Rotating JSONL event files
├── logs/            # Application logs
└── reports/         # LLM-generated security reports
```

## Testing

### Manual Test Commands

**HTTP Basic Authentication**:
```bash
python -m http.server 8080 &
curl -u alice:secret http://127.0.0.1:8080/
# Expected: HIGH http.basic_auth event
```

**HTTP Form Credentials**:
```bash
curl -d "user=alice&password=hunter2" -H "Content-Type: application/x-www-form-urlencoded" http://127.0.0.1:8080/login
# Expected: MED http.credential_key event
```

**FTP Credentials**:
```bash
pip install pyftpdlib
python -m pyftpdlib -p 2121
ftp 127.0.0.1 2121
# Login with USER/PASS
# Expected: HIGH ftp.clear_creds event
```

## Troubleshooting

### Common Issues

**"No packets captured"**:
- Verify interface name in configuration
- Ensure running as Administrator/root
- Check tshark installation and path

**"Permission denied"**:
- Windows: Run as Administrator
- Linux: Add user to wireshark group or use sudo

**"tshark not found"**:
- Verify Wireshark installation
- Check path in configuration file
- Ensure tshark.exe is in PATH

**"Interface not available"**:
- Use `tshark -D` to list available interfaces
- Update configuration with correct interface name

### Performance Tuning

- **High traffic networks**: Adjust rotation settings in config
- **Memory usage**: Monitor file sizes and rotation frequency
- **CPU usage**: Use `-n` flag (already enabled) to disable DNS resolution

## Development

### Project Structure

```
clearwatch/
├── detector/           # Network detection components ✅
│   ├── __init__.py
│   ├── config.py      # Configuration loader ✅
│   ├── event_model.py # Event data models ✅
│   ├── network_detector.py # tshark integration ✅
│   ├── writer.py      # File rotation and writing ✅
│   └── rules/         # Protocol-specific detection rules ✅
│       ├── __init__.py
│       ├── http_rules.py      # HTTP Basic Auth & credentials ✅
│       ├── smtp_rules.py      # SMTP AUTH before STARTTLS ✅
│       ├── pop3_imap_rules.py # POP3/IMAP plaintext detection ✅
│       ├── ftp_rules.py       # FTP USER/PASS detection ✅
│       ├── telnet_rules.py    # TELNET login detection ✅
│       └── tls_rules.py       # TLS version & SNI detection ⚠️
├── worker/            # LLM integration ✅
│   ├── __init__.py
│   ├── llm_client.py  # Ollama client ✅
│   ├── prompts.py     # Security-focused prompts ✅
│   └── report_generator.py # Report generation ✅
├── api/               # FastAPI server ✅
│   ├── __init__.py
│   └── server.py      # RESTful API endpoints ✅
├── config/            # Configuration files ✅
│   └── config.windows.yaml # Windows configuration ✅
├── scripts/           # Deployment scripts ✅
│   ├── __init__.py
│   ├── clearwatch_task.xml # Windows Task Scheduler ✅
│   └── clearwatch.service  # Linux systemd service ✅
├── main.py            # Main program entry point ✅
├── pyproject.toml     # Project configuration ✅
└── requirements.txt   # Python dependencies ✅
```

**Legend:**
- ✅ **Complete** - Fully implemented and functional
- ⚠️ **Partial** - Implemented but has minor issues
- ❌ **Missing** - Not yet implemented

### Adding New Detection Rules

1. **Extend Event model** in `detector/event_model.py`
2. **Add detection logic** in `detector/network_detector.py`
3. **Update configuration** to enable/disable protocols
4. **Add test cases** to verify detection

## Security & Privacy

### Data Protection

- **No raw secrets stored**: All sensitive content is hashed
- **Configurable retention**: Set log and event file retention policies
- **Local operation**: No external network communication
- **Allowlist support**: Exclude internal networks from monitoring

### Compliance

- **GDPR ready**: Easy data deletion and retention controls
- **Lawful use only**: Monitor only authorized networks
- **Audit logging**: Track all monitoring activities
- **Privacy by design**: Minimal data collection

## Implementation Status

### ✅ Sprint 1 - Core Detection Engine (COMPLETE)
- [x] Core detection engine with tshark integration
- [x] Real-time network monitoring and packet capture
- [x] Thread-safe file rotation and management
- [x] Windows configuration with platform-specific loading
- [x] All protocol detection rules (HTTP, SMTP, POP3/IMAP, FTP, TELNET, TLS)
- [x] Event model with Pydantic validation
- [x] Allowlist filtering and privacy protection
- [x] Console alerts with severity levels and color coding

### ✅ Sprint 2 - LLM Integration (COMPLETE)
- [x] Ollama client integration for local LLM processing
- [x] Professional security report generation
- [x] Analysis mode with multi-file processing
- [x] Security-focused prompt templates
- [x] Graceful LLM fallback when unavailable
- [x] Executive-level security intelligence reports

### ✅ Sprint 3 - API & Operations (COMPLETE)
- [x] FastAPI server with RESTful endpoints
- [x] `/alerts/recent` - Retrieve recent security events
- [x] `/alerts/explain` - LLM-powered event analysis
- [x] CLI arguments (`--config`, `--mode`) for automation
- [x] Background API process integration
- [x] Windows Task Scheduler deployment template
- [x] Linux systemd service deployment template
- [x] Non-interactive mode support

### 🔄 Sprint 4 - Hardening & Advanced Features (IN PROGRESS)
- [ ] Extract protocol parsing into separate `*_rules.py` modules with unit tests
- [ ] Fix TLS detection bug in event creation
- [ ] Add webhook integration for real-time alerts
- [ ] Implement PCAP ingestion mode
- [ ] Add SQLite persistence for advanced querying
- [ ] Performance monitoring and metrics collection
- [ ] Advanced pattern detection and correlation
- [ ] Export functionality for compliance reporting

### ❌ Future Enhancements
- [ ] Linux/macOS configuration files
- [ ] Slack/Discord webhook integration
- [ ] Nmap integration for asset enrichment
- [ ] Advanced TLS analysis (certificate validation)
- [ ] Machine learning-based anomaly detection
- [ ] Multi-interface monitoring support

## Current Development Status

**Clearwatch is in active development with core functionality complete.** The project has successfully implemented Sprints 1-3 and is ready for production use.

### 🎯 **Immediate Next Steps (Sprint 4)**
1. **Fix TLS detection bug** - Update `detector/rules/tls_rules.py` to use proper Event factory methods
2. **Add unit tests** - Create comprehensive test suite for protocol detection rules
3. **Linux/macOS configs** - Add `config/config.yaml` for cross-platform support
4. **Webhook integration** - Add real-time alert notifications
5. **Performance optimization** - Enhance memory management and capture efficiency

### 🔧 **Development Setup**
```bash
# Clone the repository
git clone <repository-url>
cd clearwatch

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python main.py --mode watch
```

### 🧪 **Testing**
```bash
# Test HTTP Basic Auth detection
curl -u alice:secret http://127.0.0.1:8080/

# Test HTTP credential detection
curl -d "user=alice&password=hunter2" -H "Content-Type: application/x-www-form-urlencoded" http://127.0.0.1:8080/login

# Test API endpoints
curl http://127.0.0.1:8088/alerts/recent
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

### Development Guidelines
- Follow the existing code structure and patterns
- Add unit tests for new detection rules
- Update documentation for new features
- Ensure cross-platform compatibility
- Maintain security and privacy standards

## License

MIT License - see LICENSE file for details.

## Support

- **Issues**: GitHub Issues
- **Documentation**: This README and Clearwatch.md
- **Community**: Security professionals and developers

## Disclaimer

This tool is for authorized network monitoring only. Users are responsible for ensuring compliance with local laws and organizational policies. Always obtain proper authorization before monitoring any network traffic.

---

**Clearwatch** - Professional network security monitoring made simple.
