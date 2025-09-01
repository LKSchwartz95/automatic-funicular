import orjson
import logging
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

from .llm_client import OllamaClient
from .prompts import PERIODIC_SUMMARY_PROMPT
from detector.config import ConfigLoader

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates security reports by analyzing event files with an LLM.
    """
    def __init__(self, config: ConfigLoader, llm_client: OllamaClient):
        self.config = config
        self.llm_client = llm_client
        self.worker_config = config.get_worker_config()
        self.events_dir = Path("clearwatch") / config.get("events.dir", "events")
        self.reports_dir = Path("clearwatch") / self.worker_config.get("reports_dir", "reports")
        self.reports_dir.mkdir(exist_ok=True)

    def _read_recent_events(self) -> List[Dict[str, Any]]:
        """
        Reads events from .jsonl files created within the configured time window.
        """
        events = []
        window_minutes = self.worker_config.get("window_minutes", 10)
        max_lines = self.worker_config.get("max_lines_per_window", 500)
        time_window = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        if not self.events_dir.exists():
            logger.warning(f"Events directory not found: {self.events_dir}")
            return []

        event_files = sorted(self.events_dir.glob("*.jsonl"), reverse=True)
        
        logger.info(f"Scanning for events in the last {window_minutes} minutes...")

        for file_path in event_files:
            try:
                # Check if file is within the time window
                file_mod_time = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
                if file_mod_time < time_window:
                    break  # Files are sorted, so we can stop here

                with open(file_path, "rb") as f:
                    for line in f:
                        if len(events) >= max_lines:
                            logger.warning(f"Reached max lines ({max_lines}), stopping event collection.")
                            return events
                        try:
                            events.append(orjson.loads(line))
                        except orjson.JSONDecodeError:
                            logger.warning(f"Skipping malformed JSON line in {file_path.name}")
            except Exception as e:
                logger.error(f"Error reading event file {file_path.name}: {e}")
        
        logger.info(f"Found {len(events)} events in the time window.")
        return events

    def generate_summary_report(self) -> Optional[Path]:
        """
        Generates a summary report from recent events and saves it to a file.

        Returns:
            The path to the generated report, or None if no report was created.
        """
        # 1. Check LLM availability
        if not self.llm_client.is_available():
            logger.error("Ollama service is not available. Cannot generate report.")
            print("Error: Ollama service is not available. Please ensure it is running.")
            return None

        # 2. Read recent events
        events = self._read_recent_events()
        if not events:
            logger.info("No recent events found to analyze.")
            print("No recent events found. Nothing to analyze.")
            return None
            
        # Sort events by severity (HIGH > MED > LOW) and then by timestamp
        severity_map = {"HIGH": 0, "MED": 1, "LOW": 2}
        events.sort(key=lambda e: (severity_map.get(e.get("severity"), 3), e.get("ts")), reverse=False)

        # 3. Generate report content with the LLM
        print(f"Generating report from {len(events)} events...")
        report_content = self.llm_client.generate_summary_report(
            events=events,
            prompt_template=PERIODIC_SUMMARY_PROMPT
        )

        if not report_content:
            logger.error("Failed to generate report content from LLM.")
            print("Error: Failed to get a response from the LLM.")
            return None

        # 4. Save the report to a file
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_path = self.reports_dir / f"security_report_{timestamp}.md"
            
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            
            logger.info(f"Security report saved to: {report_path}")
            print(f"\nSuccessfully generated security report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Failed to save report file: {e}")
            print(f"Error: Could not save the report file: {e}")
            return None
