# Project Scope — Clearwatch

## Purpose
Detect plaintext/weak transport events from live traffic using tshark (Wireshark CLI), emit structured JSONL alerts with rotation, and enrich with local Ollama LLM (on-demand + periodic summaries). Windows-first, cross-platform later.

## Program Architecture & User Experience

### Dual-Mode Operation
The program operates in two distinct modes to ensure reliability and user control:

1. **Watch Mode** (Primary Operation):
   - Network monitoring and packet capture via tshark
   - Real-time terminal output with timestamps, connections, and alerts
   - Automatic file creation and rotation in the `clearwatch/` folder
   - **Zero LLM dependency** - operates completely independently
   - User can monitor network activity in real-time without interruption
   - Creates structured data files for later analysis

2. **Analysis Mode** (Secondary Operation):
   - Reads existing JSONL files from previous watch sessions
   - Uses local Ollama LLM to generate professional security reports
   - **Graceful fallback** if LLM is unavailable or slow
   - Analyzes historical data without real-time capture overhead
   - Generates actionable security intelligence for professionals

### User Workflow
```
Program Start
    ↓
Choose Mode:
├── Watch Mode
│   ├── Start monitoring network interface
│   ├── Real-time terminal output (connections, events, alerts)
│   ├── Create/rotate JSONL files automatically
│   ├── Press key to switch to Analysis Mode during runtime
│   └── Or close and restart for Analysis Mode
│
└── Analysis Mode
    ├── Check if Ollama LLM is available
    ├── Read previous watch session files (multiple JSONL files)
    ├── Generate comprehensive security reports
    └── Fallback to file listing if LLM unavailable
```

### Robustness & Reliability
- **Watch Mode**: Never fails due to LLM issues, network problems, or user input
- **Analysis Mode**: Gracefully handles LLM unavailability with informative fallbacks
- **File Persistence**: All captured data survives program restarts and crashes
- **Mode Switching**: Can switch between modes during runtime without data loss
- **Performance**: Watch mode optimized for real-time capture, no LLM overhead
- **Error Handling**: Graceful degradation if components fail

## Primary Detections (MVP)
- `http.basic_auth` - HTTP Basic Authentication without TLS
- `http.credential_key` - Credential keys in form/JSON bodies
- `smtp.no_starttls` - SMTP AUTH before STARTTLS
- `pop3.clear_creds` - POP3 USER/PASS without TLS
- `imap.clear_login` - IMAP LOGIN without STARTTLS
- `ftp.clear_creds` - FTP USER/PASS on control port
- `telnet.clear_login` - TELNET login/password prompts

## Outputs
- Console alerts
- Rotated JSONL files
- Optional FastAPI to list alerts and "Explain" via LLM
- Privacy by default (no raw secrets stored)

## Windows Paths (Locked)
- **Wireshark GUI**: `C:\Program Files\Wireshark\Wireshark.exe`
- **tshark CLI**: `C:\Program Files\Wireshark\tshark.exe`

## File Organization & Data Flow

### Automatic Folder Structure
The program automatically creates and manages a `clearwatch/` folder in the same directory as `main.py`:

```
your_project_directory/
├── main.py                    # Main program entry point
└── clearwatch/               # Auto-created folder for all data
    ├── events/               # JSONL files for LLM consumption (rotated)
    │   ├── 2024-01-15_14-30.jsonl
    │   ├── 2024-01-15_14-35.jsonl
    │   └── 2024-01-15_14-40.jsonl
    ├── logs/                 # Human-readable logs and console output
    │   └── clearwatch.log
    └── reports/              # LLM-generated security reports
        └── 2024-01-15_14-45.md
```

### Smart File Rotation Strategy
- **Time-based rotation**: Every 5 minutes (configurable)
- **Size-based rotation**: 10MB limit (configurable)
- **Smart naming convention**: `YYYY-MM-DD_HH-MM.jsonl`
- **LLM-friendly format**: Each file contains structured events for easy parsing
- **Multiple file analysis**: LLM can read all files for comprehensive time-window analysis

### Data Flow Architecture
1. **Watch Mode**: Network capture → Real-time console output → JSONL files + log files
2. **Analysis Mode**: Read multiple JSONL files → LLM processing → Professional security reports
3. **File Persistence**: All data survives program restarts, crashes, and mode switches

## Repository Structure (Target)

```
clearwatch/
  detector/
    runner.py
    event_model.py
    writer.py
    config.py               # (optional helper)
    http_rules.py           # (v1 split; MVP rules live in runner.py)
    smtp_rules.py           # (v1 split)
    pop3_imap_rules.py      # (v1 split)
    ftp_telnet_rules.py     # (v1 split)
  worker/
    batch_worker.py
    prompts.py
    llm_client.py
  api/
    server.py
  config/
    config.yaml             # default (Linux/mac)
    config.windows.yaml     # uses full tshark path + Windows iface
  events/                   # rotated JSONL output
  reports/                  # LLM markdown summaries (worker)
  logs/
  scripts/
    install_tshark.md
    windows_quickstart.md
  pyproject.toml
  README.md
```

## Epic A — Detector (Hot Path)

### A1. Config: Windows-first YAML
**Task**: Add `config.windows.yaml` with keys specified earlier (including `detector.tshark_path` and `detector.interface`).

**Acceptance**: `config.windows.yaml` loads; values appear in logs on startup.

### A2. TShark streaming runner
**Task**: Implement `detector/runner.py` using full tshark path from config, JSON streaming, `-n`, TCP reassembly options enabled.

**Acceptance**: Running `python -m detector.runner` emits no errors, writes to `events/<timestamp>.jsonl`, rotates per policy, prints console lines on matches.

### A3. Event model + validation
**Task**: Implement `Event` (pydantic) exactly as spec; include `to_jsonable()` to normalize timestamps.

**Acceptance**: Invalid events (e.g., bad IP formats) raise errors before write; valid events write clean JSON lines.

### A4. Rotating JSONL writer
**Task**: Implement `writer.py` with time+size rotation, atomic open/close, flush on write.

**Acceptance**: Files rotate by minutes or size; no truncated JSON lines; safe on abrupt stop (Ctrl+C).

### A5. Protocol detections (MVP)
**Task**: In `runner.py`, implement rules:
- **HTTP**: Authorization: Basic (HIGH), credential keys in small POST bodies (MED).
- **SMTP**: AUTH seen before STARTTLS (HIGH).
- **POP3/IMAP**: plaintext creds or LOGIN without TLS (HIGH).
- **FTP**: USER/PASS on port 21 (HIGH).
- **TELNET**: login/password prompts (HIGH).

**Acceptance**: Each rule can be triggered with the test commands in the README and produces one or more Event JSON lines.

### A6. Allowlist + privacy
**Task**: Implement CIDR allowlist for destinations and hashing/redaction for sensitive snippets.

**Acceptance**: Traffic to allowlisted IPs produces no events; logs contain only hashes for sensitive content.

## Epic B — LLM Integration (Cold Path)

### B1. Ollama client
**Task**: `worker/llm_client.py` with `ask_single_event(event: dict) -> str` (using `http://127.0.0.1:11434/api/generate`).

**Acceptance**: Given a real Event dict, returns a textual analysis without exceptions.

### B2. Batch worker
**Task**: `worker/batch_worker.py` that:
- Reads recent events for `worker.window_minutes`.
- Sorts by severity + time.
- Generates Markdown summary via Ollama.
- Writes `reports/<stamp>.md` (and optional actions JSON).

**Acceptance**: After events exist, running the worker creates a Markdown report with the required sections.

### B3. Prompts (Critical Component)
**Task**: `worker/prompts.py` with carefully crafted, hardcoded prompt templates:

**Single-Event Analysis Prompt**:
- Impact assessment (High/Medium/Low risk)
- Immediate triage steps (1-3 actionable items)
- Durable fix recommendations (long-term solutions)
- Validation steps (how to verify the fix worked)

**Periodic Summary Prompt**:
- Executive summary (key findings and risks)
- Findings by category (grouped by protocol/severity)
- Immediate actions required (urgent items)
- Risk assessment (business impact analysis)
- Compliance implications (policy violations)
- Appendix (detailed event listings)

**Prompt Design Philosophy**:
- **Hardcoded**: Stored in code to ensure consistency and quality
- **Security-Focused**: Specifically crafted for security professionals
- **Actionable**: Every output should provide clear next steps
- **Professional**: Language and format suitable for executive reports
- **Comprehensive**: Cover threat detection, compliance, and remediation

**Acceptance**: Prompts are used by B1/B2 and produce structured, professional-grade security intelligence outputs.

## Epic C — Optional API/UI

### C1. FastAPI server
**Task**: `api/server.py` with:
- `GET /alerts/recent?limit=N` → returns most recent N events from rotated files.
- `POST /alerts/explain` → body: Event JSON; returns LLM analysis string.

**Acceptance**: `uvicorn api.server:app` runs; endpoints respond with valid JSON; errors return 4xx.

## Epic D — Platform & Ops

### D1. Windows interface discovery & quickstart
**Task**: `scripts/windows_quickstart.md` with:
- `tshark -D` usage.
- Admin requirements (Npcap).
- Setting `detector.interface` to Ethernet or `\\Device\\NPF_{GUID}`.

**Acceptance**: Following the doc, a new Windows machine can produce events end-to-end.

### D2. Service/supervision
**Task**: Provide Task Scheduler XML (Windows) and systemd unit (Linux) for detector + worker.

**Acceptance**: On reboot, detector and worker start automatically and write logs.

### D3. README
**Task**: Project overview, install steps (Windows & Linux), test commands, troubleshooting, privacy note.

**Acceptance**: A fresh user can follow README to first events and first report.

## Epic E — Tests & Verification

### E1. Manual test scripts (lab)
**Task**: Add commands in README to trigger each rule:
- **HTTP Basic**: `curl -u alice:secret http://127.0.0.1:8080/`
- **HTTP POST creds**: `curl -d "user=alice&password=hunter2" ...`
- **SMTP AUTH pre-STARTTLS** (document simple procedure).
- **POP3/IMAP plaintext login** (test servers or netcat dialogue).
- **FTP USER/PASS** with pyftpdlib.
- **TELNET login prompts**.

**Acceptance**: Each command reliably generates the intended event(s).

### E2. Real-time Console Output Testing
**Task**: Verify that Watch Mode provides comprehensive real-time visibility:

**Expected Console Output**:
```
[2024-01-15 14:30:15] Clearwatch started - monitoring interface: Ethernet
[2024-01-15 14:30:16] New connection: 192.168.1.100:54321 → 8.8.8.8:80
[2024-01-15 14:30:17] HIGH ALERT: http.basic_auth detected on 8.8.8.8:80
[2024-01-15 14:30:18] Connection closed: 192.168.1.100:54321 → 8.8.8.8:80
[2024-01-15 14:30:20] File rotated: events/2024-01-15_14-30.jsonl (5 min rotation)
[2024-01-15 14:30:25] MED ALERT: http.credential_key detected on 8.8.8.8:80
```

**Acceptance**: Console shows real-time connections, events, alerts, and file operations with clear timestamps and severity levels.

### E3. Mode Switching Testing
**Task**: Verify seamless transition between Watch and Analysis modes:

**Watch → Analysis Transition**:
- Press key to switch modes during runtime
- Verify no data loss during transition
- Confirm Analysis mode can read files created in Watch mode

**Analysis → Watch Transition**:
- Return to monitoring without losing analysis context
- Verify new data continues to be captured
- Confirm file rotation continues normally

**Acceptance**: Mode switching works smoothly without data loss or program crashes.

### E4. JSON schema check
**Task**: Add a tiny script or test that loads each line from `events/*.jsonl` and validates with Event.

**Acceptance**: CI (or local) run passes with real captures.

### E5. LLM Fallback Testing
**Task**: Verify Analysis Mode gracefully handles LLM unavailability:

**LLM Available**:
- Generates comprehensive security reports
- Processes multiple JSONL files for time-window analysis
- Creates professional-grade outputs

**LLM Unavailable**:
- Provides informative error messages
- Falls back to file listing and basic statistics
- Suggests troubleshooting steps
- **Never crashes or fails completely**

**Acceptance**: Analysis Mode works reliably regardless of LLM availability, providing value even when AI analysis is not possible.

## Epic F — Quality & Next (v1 after MVP)

- Split rules into protocol modules (`http_rules.py`, etc.) and unit-test small parsers.
- Add TLS ClientHello checks (min version, SNI required).
- Optional SQLite store + query API.
- Slack/Discord webhooks for HIGH events.
- PCAP ingestion mode (`--pcap`).
- Nmap integration for assets (enrichment post-alert).

## Backlog — Task List (Copy into Tracker)

### Sprint 1 — MVP hot path
- [ ] Create repo structure & `pyproject.toml`.
- [ ] Add `config.windows.yaml` (with full tshark.exe path).
- [ ] Implement Event model (`detector/event_model.py`).
- [ ] Implement RotatingJsonlWriter (`detector/writer.py`).
- [ ] Implement `main.py` with dual-mode operation (Watch/Analysis).
- [ ] Implement Watch Mode with tshark JSON streaming and rules (HTTP/SMTP/POP3/IMAP/FTP/TELNET).
- [ ] Add real-time console output with timestamps, connections, and alerts.
- [ ] Implement automatic `clearwatch/` folder creation and management.
- [ ] Add console alert formatting (severity, rule, 5-tuple, host).
- [ ] README: Windows quickstart; interface selection.
- [ ] Manual tests: HTTP Basic + POST; verify events written/rotated.
- [ ] Test mode switching and data persistence.

### Sprint 2 — LLM cold path
- [ ] Implement `worker/llm_client.py` (Ollama, non-stream).
- [ ] Implement `worker/prompts.py` with hardcoded, security-focused prompt templates.
- [ ] Implement Analysis Mode in `main.py` with LLM integration.
- [ ] Implement multi-file JSONL reading for comprehensive time-window analysis.
- [ ] Implement graceful LLM fallback when Ollama is unavailable.
- [ ] Generate professional security reports with executive summary, findings, and actions.
- [ ] README: how to use Analysis Mode; show example report.
- [ ] Manual tests: generate events → confirm report file created with professional output.

### Sprint 3 — Optional API & polish
- [ ] Implement `api/server.py` with `/alerts/recent` and `/alerts/explain`.
- [ ] Add `--config` CLI flag to `main.py` to pick YAML file.
- [ ] Add Task Scheduler XML (Windows) and systemd service file (Linux).
- [ ] Troubleshooting section (no packets, interface name, Admin rights, `-n` flag).
- [ ] Implement runtime mode switching with hotkey support.
- [ ] Add configuration validation and error handling.
- [ ] Optimize file rotation and memory management.

### Sprint 4 — Hardening & v1 items
- [ ] Extract protocol parsing into `*_rules.py` modules with focused tests.
- [ ] Implement TLS ClientHello checks (min version/SNI).
- [ ] Add webhook sender (`detector/webhook.py`) and config switches.
- [ ] Optional: SQLite persistence + migration script.
- [ ] Optional: PCAP ingestion mode (`--pcap path`).
- [ ] Add performance monitoring and metrics collection.
- [ ] Implement advanced pattern detection and correlation.
- [ ] Add export functionality for compliance reporting.

## Acceptance Criteria (MVP)

### Watch Mode Requirements
Running `python main.py` and selecting Watch Mode on Windows (Admin):
- **Startup**: Program creates `clearwatch/` folder and subdirectories automatically
- **Interface Detection**: Automatically detects and displays available network interfaces
- **Real-time Output**: Produces comprehensive console output with timestamps, connections, and alerts
- **Event Detection**: Produces at least one HIGH `http.basic_auth` event and one MED `http.credential_key` event using the README test commands
- **File Management**: Rotates JSONL files by 5 minutes or 10 MB (whichever first)
- **Console Alerts**: Prints real-time alerts with rule, severity, and endpoint information
- **Performance**: Maintains real-time capture without LLM performance impact

### Analysis Mode Requirements
Running `python main.py` and selecting Analysis Mode:
- **LLM Integration**: Generates comprehensive Markdown report in `reports/` with:
  - Executive summary of findings
  - Findings grouped by category and severity
  - Immediate actions required
  - Risk assessment and business impact
  - Compliance implications
  - Detailed event appendix
- **Multi-file Analysis**: Processes multiple JSONL files for comprehensive time-window analysis
- **Professional Output**: Creates security intelligence suitable for executive review

### Mode Switching Requirements
- **Runtime Switching**: Can switch between Watch and Analysis modes during execution
- **Data Persistence**: All captured data survives mode switches and program restarts
- **Graceful Fallback**: Analysis Mode works reliably even when LLM is unavailable

### File Organization Requirements
- **Auto-creation**: `clearwatch/` folder and subdirectories created automatically
- **Smart Rotation**: JSONL files rotated by time and size with intelligent naming
- **LLM Compatibility**: Files formatted for easy LLM consumption and analysis
- **Human Readability**: Log files provide clear, timestamped information for operators

(If API enabled) `GET /alerts/recent` returns latest events; `POST /alerts/explain` returns an LLM remediation text for a supplied event.

## Constraints & Guardrails

### Security & Privacy
- **Do not store raw secrets**. Hash snippets; redact values.
- **Only monitor with authorization**. Document privacy and retention.
- **GDPR compliance**: Configurable log retention and easy data deletion.
- **Lawful use only**: Banner and documentation must state authorized monitoring only.

### Reliability & Performance
- **If Ollama is down/slow, detector must remain unaffected**; worker retries later.
- **Watch Mode performance**: Optimized for real-time capture, no LLM overhead.
- **File rotation**: Atomic operations to prevent data loss on crashes.
- **Memory management**: Efficient handling of large capture volumes.

### User Experience
- **Minimal user input**: Program should "just work" with minimal configuration.
- **Clear feedback**: Real-time visibility into what the program is doing.
- **Graceful degradation**: Always provide value even when components fail.
- **Professional output**: Reports suitable for security teams and executives.

### Technical Robustness
- **Cross-platform compatibility**: Windows-first, then Linux/macOS.
- **Error handling**: Comprehensive error handling with informative messages.
- **Resource management**: Proper cleanup of file handles and network connections.
- **Configuration validation**: Validate all settings before starting capture.

## Implementation Details & Technical Considerations

### Main Program Structure (`main.py`)
The main program serves as the entry point and orchestrates both modes:

```python
# High-level structure
def main():
    # 1. Auto-create clearwatch/ folder structure
    # 2. Load configuration (Windows vs. Linux)
    # 3. Present mode selection to user
    # 4. Execute selected mode with proper error handling

def watch_mode():
    # Network capture, real-time output, file creation
    # Never depends on LLM availability

def analysis_mode():
    # Read existing files, LLM processing, report generation
    # Graceful fallback if LLM unavailable
```

### Real-time Console Output Design
Console output provides immediate visibility into program operation:

**Output Categories**:
- **INFO**: Program startup, interface detection, file operations
- **CONNECTION**: New connections, connection closures, traffic patterns
- **ALERT**: Security events with severity levels (HIGH/MED/LOW)
- **ROTATION**: File rotation events with timestamps and sizes

**Format Example**:
```
[2024-01-15 14:30:15] INFO: Clearwatch started - monitoring interface: Ethernet
[2024-01-15 14:30:16] CONNECTION: 192.168.1.100:54321 → 8.8.8.8:80
[2024-01-15 14:30:17] HIGH ALERT: http.basic_auth detected on 8.8.8.8:80
[2024-01-15 14:30:20] ROTATION: events/2024-01-15_14-30.jsonl created (5 min rotation)
```

### File Management Strategy
**Automatic Folder Creation**:
- Check for `clearwatch/` folder on startup
- Create if not exists: `events/`, `logs/`, `reports/`
- Handle permission errors gracefully
- Provide clear feedback about folder operations

**Smart File Rotation**:
- Time-based: Every 5 minutes (configurable)
- Size-based: 10MB limit (configurable)
- Atomic operations: Prevent data loss on crashes
- Naming convention: `YYYY-MM-DD_HH-MM.jsonl`

### LLM Integration Architecture
**Prompt Design Philosophy**:
- **Hardcoded prompts**: Ensure consistency and quality
- **Security-focused**: Specifically crafted for security professionals
- **Actionable output**: Every analysis provides clear next steps
- **Professional format**: Suitable for executive review and compliance

**Fallback Strategy**:
- Check Ollama availability before starting analysis
- Provide informative error messages if LLM unavailable
- Fall back to basic file listing and statistics
- Never crash or fail completely

### Performance Considerations
**Watch Mode Optimization**:
- Real-time packet capture without LLM overhead
- Efficient file I/O with proper buffering
- Memory management for large capture volumes
- Minimal CPU impact during monitoring

**Analysis Mode Efficiency**:
- Process multiple files efficiently
- LLM request optimization and caching
- Report generation without blocking
- Resource cleanup after analysis

### Error Handling & Resilience
**Network Capture Errors**:
- Interface not available
- Permission denied (Admin rights required)
- tshark process failures
- Network adapter issues

**File System Errors**:
- Disk space issues
- Permission problems
- File corruption handling
- Recovery mechanisms

**LLM Integration Errors**:
- Ollama not running
- Network connectivity issues
- Model loading failures
- Response timeouts

### Security & Privacy Implementation
**Data Protection**:
- Hash sensitive content (SHA-256)
- Redact credential values
- Configurable retention policies
- Easy data deletion for compliance

**Access Control**:
- Local-only operation by default
- No external network communication
- Configurable allowlists for monitoring
- Audit logging of all operations

This comprehensive design ensures Clearwatch provides professional-grade network security monitoring with robust error handling, clear user feedback, and reliable operation regardless of external dependencies.
