#!/usr/bin/env python3
"""
Clearwatch - Clear-Text & Weak-Transport Detector with Local LLM Guidance

A dual-mode network security monitoring tool that detects plaintext credentials
and weak transport protocols, with optional AI-powered analysis.
"""

import os
import sys
import signal
import logging
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector.config import ConfigLoader
from detector.network_detector import NetworkDetector
from detector.writer import RotatingJsonlWriter
from worker.llm_client import OllamaClient
from worker.report_generator import ReportGenerator
from quick_status import show_log_event_status

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class Clearwatch:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config: Optional[ConfigLoader] = None
        self.detector: Optional[NetworkDetector] = None
        self.writer: Optional[RotatingJsonlWriter] = None
        self.llm_client: Optional[OllamaClient] = None
        self.report_generator: Optional[ReportGenerator] = None
        self.api_process: Optional[subprocess.Popen] = None
        self.running = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.api_process:
            self.api_process.terminate()
        
    def _create_folders(self):
        """Create the clearwatch folder structure."""
        base_dir = Path("clearwatch")
        base_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (base_dir / "events").mkdir(exist_ok=True)
        (base_dir / "logs").mkdir(exist_ok=True)
        (base_dir / "reports").mkdir(exist_ok=True)
        
        logger.info("Created clearwatch folder structure")
        
    def _setup_logging(self):
        """Setup file logging."""
        log_file = Path("clearwatch/logs/clearwatch.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Add file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Add to root logger
        logging.getLogger().addHandler(file_handler)
        logger.info(f"Logging to file: {log_file}")
        
    def _load_configuration(self):
        """Load and validate configuration."""
        try:
            config_dir = self.config_path if self.config_path else "config"
            self.config = ConfigLoader(config_dir=config_dir)
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
            
    def _initialize_components(self, interface_override: Optional[str] = None):
        """Initialize detector and writer components."""
        try:
            # Core components for Watch Mode
            self.detector = NetworkDetector(self.config, interface_override)
            logger.info("Network detector initialized")
            
            events_config = self.config.get_events_config()
            self.writer = RotatingJsonlWriter(
                dir_path=f"clearwatch/{events_config['dir']}",
                rotate_minutes=events_config['rotate_every_minutes'],
                rotate_max_mb=events_config['rotate_max_mb'],
                fmt=events_config['filename_format']
            )
            logger.info("Event writer initialized")

            # Optional components for Analysis Mode
            if self.config.get("worker.enabled", False):
                worker_config = self.config.get_worker_config()
                self.llm_client = OllamaClient(model=worker_config.get("model"))
                self.report_generator = ReportGenerator(self.config, self.llm_client)
                logger.info("LLM worker components initialized")
            else:
                logger.info("LLM worker is disabled in configuration.")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            sys.exit(1)

    def _start_api_server(self):
        """Start the FastAPI server as a background process if enabled."""
        api_config = self.config.get_api_config()
        if api_config.get("enabled", False):
            try:
                # Use sys.executable to ensure we're using the same python interpreter
                cmd = [sys.executable, "-m", "uvicorn", "api.server:app", 
                       "--host", api_config.get("host", "127.0.0.1"),
                       "--port", str(api_config.get("port", 8088))]
                
                self.api_process = subprocess.Popen(cmd)
                logger.info(f"API server started in background (PID: {self.api_process.pid})")
                print(f"INFO: API server running at http://{api_config.get('host', '127.0.0.1')}:{api_config.get('port', 8088)}")
            except Exception as e:
                logger.error(f"Failed to start API server: {e}")
                print(f"ERROR: Could not start the API server: {e}")

    def _print_banner(self):
        """Print program banner."""
        print("\n" + "="*60)
        print("                    CLEARWATCH")
        print("        Clear-Text & Weak-Transport Detector")
        print("              with Local LLM Guidance")
        print("="*60)
        print()
        
    def _print_mode_selection(self):
        """Print mode selection menu."""
        print("Select operation mode:")
        print("1. Watch Mode - Monitor network traffic and detect security events")
        analysis_mode_status = "enabled" if self.config.get("worker.enabled") else "disabled"
        print(f"2. Analysis Mode - Analyze previous captures with LLM (status: {analysis_mode_status})")
        print("3. Exit")
        print()
        
    def _get_mode_selection(self) -> str:
        """Get user mode selection."""
        while True:
            try:
                choice = input("Enter your choice (1-3): ").strip()
                if choice in ['1', '2', '3']:
                    return choice
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
            except KeyboardInterrupt:
                print("\nExiting...")
                sys.exit(0)

    def _select_network_interface(self) -> Optional[str]:
        """Allow user to select network interface for monitoring."""
        print("\n" + "="*50)
        print("NETWORK INTERFACE SELECTION")
        print("="*50)
        
        # Get available interfaces
        available_interfaces = self.detector.get_available_interfaces()
        active_interfaces = self.detector.get_active_interfaces()
        active_names = {iface['name'] for iface in active_interfaces}
        
        if not available_interfaces:
            print("❌ No network interfaces available!")
            return None
            
        print("Available network interfaces:")
        print()
        
        # Display interfaces with status
        for i, iface in enumerate(available_interfaces, 1):
            status = "🟢 ACTIVE" if iface['name'] in active_names else "🔴 INACTIVE"
            print(f"{i:2d}. {iface['name']:<25} {status}")
            
        print()
        print("Options:")
        print("  A. Auto-detect best interface")
        print("  Q. Use configured interface")
        print()
        
        while True:
            try:
                choice = input("Select interface (1-{}, A, Q): ").strip().upper()
                
                if choice == 'A':
                    # Auto-detect best interface
                    best_interface = self.detector.interface_detector.find_best_interface()
                    if best_interface:
                        print(f"✅ Auto-selected: {best_interface}")
                        return best_interface
                    else:
                        print("❌ Could not auto-detect interface")
                        continue
                        
                elif choice == 'Q':
                    # Use configured interface
                    configured = self.config.get('detector.interface')
                    print(f"✅ Using configured interface: {configured}")
                    return configured
                    
                elif choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(available_interfaces):
                        selected = available_interfaces[idx]['name']
                        if selected in active_names:
                            print(f"✅ Selected: {selected}")
                            return selected
                        else:
                            print(f"⚠️  Warning: {selected} is not active. Continue anyway? (y/n): ", end="")
                            confirm = input().strip().lower()
                            if confirm in ['y', 'yes']:
                                print(f"✅ Selected: {selected}")
                                return selected
                            else:
                                continue
                    else:
                        print("Invalid selection. Please try again.")
                        continue
                else:
                    print("Invalid choice. Please try again.")
                    continue
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                sys.exit(0)
            except Exception as e:
                print(f"Error: {e}")
                continue
                
    def _watch_mode(self, interface_override: Optional[str] = None):
        """Execute Watch Mode - monitor network traffic."""
        print("\n" + "="*50)
        print("WATCH MODE - Network Traffic Monitoring")
        print("="*50)
        
        # Select interface if not provided
        if not interface_override:
            interface_override = self._select_network_interface()
            if not interface_override:
                print("❌ No interface selected. Returning to main menu.")
                return
                
        # Reinitialize detector with selected interface
        try:
            self.detector = NetworkDetector(self.config, interface_override)
            logger.info(f"Network detector reinitialized with interface: {interface_override}")
        except Exception as e:
            logger.error(f"Failed to reinitialize detector: {e}")
            print(f"❌ Error: {e}")
            return
        
        print("Press Ctrl+C to stop monitoring")
        print()
        
        # Print startup information
        tshark_path = self.config.get("detector.tshark_path")
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Clearwatch started - monitoring interface: {interface_override}")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Using tshark: {tshark_path}")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Events directory: clearwatch/events/")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: Log file: clearwatch/logs/clearwatch.log")
        print()
        
        # Start monitoring
        self.running = True
        event_count = 0
        status_interval = 30  # seconds
        start_time = time.time()
        last_status_time = start_time
        
        try:
            for event in self.detector.start_capture():
                if not self.running:
                    break

                current_time = time.time()
                elapsed = current_time - start_time
                if event_count == 0 and current_time - last_status_time >= status_interval:
                    print(
                        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: No detections yet; capture is active ({int(elapsed)}s elapsed)."
                    )
                    last_status_time = current_time

                # Write event to file
                self.writer.write_line(event.to_jsonable())
                event_count += 1
                
                # Print console alert
                severity_color = {
                    "HIGH": "\033[91m",  # Red
                    "MED": "\033[93m",   # Yellow
                    "LOW": "\033[94m"    # Blue
                }.get(event.severity, "")
                reset_color = "\033[0m"
                
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {severity_color}{event.severity} ALERT{reset_color}: {event.rule} detected on {event.dst_ip}:{event.dst_port}")
                
                # Print file rotation info
                file_info = self.writer.get_current_file_info()
                if file_info:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ROTATION: Current file: {file_info['path']} ({file_info['size_bytes']} bytes)")
                    
        except KeyboardInterrupt:
            print("\nStopping network monitoring...")
        except Exception as e:
            logger.error(f"Error in watch mode: {e}")
            print(f"Error: {e}")
        finally:
            if self.writer:
                self.writer.close()
            print(f"\nWatch mode completed. Total events captured: {event_count}")
            show_log_event_status()
            
    def _analysis_mode(self):
        """Execute Analysis Mode - analyze previous captures."""
        print("\n" + "="*50)
        print("ANALYSIS MODE - LLM-Powered Security Analysis")
        print("="*50)

        if not self.report_generator:
            print("Analysis mode is disabled in the configuration.")
            print("Please enable 'worker.enabled' in your config file and restart.")
            return

        print("This mode requires Ollama to be running locally.")
        print()
        
        self.report_generator.generate_summary_report()
        
    def run(self, direct_mode: Optional[str] = None, interface: Optional[str] = None):
        """Main program execution."""
        try:
            # Setup
            self._create_folders()
            self._setup_logging()
            self._load_configuration()
            self._initialize_components(interface)
            self._start_api_server()

            if direct_mode:
                if direct_mode == "watch":
                    self._watch_mode(interface)
                elif direct_mode == "analysis":
                    self._analysis_mode()
                return # Exit after running in direct mode

            # Main interactive loop
            while True:
                self._print_banner()
                self._print_mode_selection()
                choice = self._get_mode_selection()
                
                if choice == '1':
                    self._watch_mode()
                elif choice == '2':
                    self._analysis_mode()
                elif choice == '3':
                    print("Exiting Clearwatch...")
                    break
                    
                # Ask if user wants to continue
                if choice in ['1', '2']:
                    print("\n" + "-"*50)
                    continue_choice = input("Return to main menu? (y/n): ").strip().lower()
                    if continue_choice not in ['y', 'yes']:
                        print("Exiting Clearwatch...")
                        break
                        
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            print(f"Fatal error: {e}")
            sys.exit(1)
        finally:
            if self.writer:
                self.writer.close()
            if self.api_process:
                self.api_process.terminate()
                logger.info("API server terminated.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Clearwatch - Network Security Monitor")
    parser.add_argument(
        "--config",
        type=str,
        help="Path to the configuration directory (e.g., 'config/'). Defaults to 'config'."
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["watch", "analysis"],
        help="Run Clearwatch in a specific non-interactive mode."
    )
    parser.add_argument(
        "--interface",
        type=str,
        help="Network interface to monitor (e.g., 'Wi-Fi', 'Ethernet')."
    )
    args = parser.parse_args()

    app = Clearwatch(config_path=args.config)
    app.run(direct_mode=args.mode, interface=args.interface)


if __name__ == "__main__":
    main()
