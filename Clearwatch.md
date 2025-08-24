# Project Scope — Clearwatch

## Purpose
Detect plaintext/weak transport events from live traffic using tshark (Wireshark CLI), emit structured JSONL alerts with rotation, and enrich with local Ollama LLM (on-demand + periodic summaries). Windows-first, cross-platform later.

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

### B3. Prompts
**Task**: `worker/prompts.py` with two templates:
- Single-event remediation (Impact, Immediate triage, Durable fix, Validation).
- Periodic summary (Exec summary, Findings by category, Immediate actions, Risks, Appendix).

**Acceptance**: Prompts are used by B1/B2 and produce structured outputs.

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

### E2. JSON schema check
**Task**: Add a tiny script or test that loads each line from `events/*.jsonl` and validates with Event.

**Acceptance**: CI (or local) run passes with real captures.

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
- [ ] Implement `detector/runner.py` with tshark JSON streaming and rules (HTTP/SMTP/POP3/IMAP/FTP/TELNET).
- [ ] Add console alert formatting (severity, rule, 5-tuple, host).
- [ ] README: Windows quickstart; interface selection.
- [ ] Manual tests: HTTP Basic + POST; verify events written/rotated.

### Sprint 2 — LLM cold path
- [ ] Implement `worker/llm_client.py` (Ollama, non-stream).
- [ ] Implement `worker/prompts.py` (single event + periodic).
- [ ] Implement `worker/batch_worker.py` (window read → Markdown report).
- [ ] README: how to run worker; show example report.
- [ ] Manual tests: generate events → confirm report file created.

### Sprint 3 — Optional API & polish
- [ ] Implement `api/server.py` with `/alerts/recent` and `/alerts/explain`.
- [ ] Add `--config` CLI flag to `runner.py` and `batch_worker.py` to pick YAML file.
- [ ] Add Task Scheduler XML (Windows) and systemd service file (Linux).
- [ ] Troubleshooting section (no packets, interface name, Admin rights, `-n` flag).

### Sprint 4 — Hardening & v1 items
- [ ] Extract protocol parsing into `*_rules.py` modules with focused tests.
- [ ] Implement TLS ClientHello checks (min version/SNI).
- [ ] Add webhook sender (`detector/webhook.py`) and config switches.
- [ ] Optional: SQLite persistence + migration script.
- [ ] Optional: PCAP ingestion mode (`--pcap path`).

## Acceptance Criteria (MVP)

Running `python -m detector.runner` on Windows (Admin) with your config:
- Produces at least one HIGH `http.basic_auth` event and one MED `http.credential_key` event using the README test commands.
- Rotates JSONL files by 5 minutes or 10 MB (whichever first).
- Prints console alerts with rule and endpoint info.

Running `python -m worker.batch_worker`:
- Generates a Markdown report in `reports/` with Executive summary, Findings by category, Immediate actions, Risks, Appendix.

(If API enabled) `GET /alerts/recent` returns latest events; `POST /alerts/explain` returns an LLM remediation text for a supplied event.

## Constraints & Guardrails

- **Do not store raw secrets**. Hash snippets; redact values.
- **Only monitor with authorization**. Document privacy and retention.
- **If Ollama is down/slow, detector must remain unaffected**; worker retries later.
