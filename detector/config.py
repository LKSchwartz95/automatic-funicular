import os
import platform
from pathlib import Path
from typing import Dict, Any
import yaml
import logging

logger = logging.getLogger(__name__)


class ConfigLoader:
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self):
        """Load configuration based on platform."""
        system = platform.system().lower()
        
        # Try platform-specific config first
        platform_config = self.config_dir / f"config.{system}.yaml"
        default_config = self.config_dir / "config.yaml"
        
        if platform_config.exists():
            config_file = platform_config
            logger.info(f"Loading platform-specific config: {platform_config}")
        elif default_config.exists():
            config_file = default_config
            logger.info(f"Loading default config: {default_config}")
        else:
            raise FileNotFoundError(
                f"No configuration file found. Expected one of: {platform_config}, {default_config}"
            )

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f)
            logger.info(f"Configuration loaded successfully from {config_file}")
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration from {config_file}: {e}")

        self._validate_config()

    def _validate_config(self):
        """Validate essential configuration values."""
        required_sections = ["detector", "events", "worker"]
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")

        # Validate detector section
        detector = self.config["detector"]
        if "tshark_path" not in detector:
            raise ValueError("Missing detector.tshark_path in configuration")
        
        if "interface" not in detector:
            raise ValueError("Missing detector.interface in configuration")

        # Validate tshark path exists
        tshark_path = Path(detector["tshark_path"])
        if not tshark_path.exists():
            raise FileNotFoundError(f"tshark not found at: {tshark_path}")

        # Validate events section
        events = self.config["events"]
        if "dir" not in events:
            raise ValueError("Missing events.dir in configuration")

        logger.info("Configuration validation passed")

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'detector.interface')."""
        keys = key.split(".")
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def get_detector_config(self) -> Dict[str, Any]:
        """Get detector configuration section."""
        return self.config.get("detector", {})

    def get_events_config(self) -> Dict[str, Any]:
        """Get events configuration section."""
        return self.config.get("events", {})

    def get_worker_config(self) -> Dict[str, Any]:
        """Get worker configuration section."""
        return self.config.get("worker", {})

    def get_api_config(self) -> Dict[str, Any]:
        """Get API configuration section."""
        return self.config.get("api", {})

    def get_alerting_config(self) -> Dict[str, Any]:
        """Get alerting configuration section."""
        return self.config.get("alerting", {})

    def get_allowlist_cidrs(self) -> list:
        """Get allowlist CIDR ranges."""
        return self.config.get("detector", {}).get("allowlist_cidrs", [])

    def get_credential_keys(self) -> list:
        """Get HTTP credential keys to monitor."""
        return (
            self.config.get("detector", {})
            .get("protocols", {})
            .get("http", {})
            .get("credential_keys", [])
        )

    def get_max_body_size(self) -> int:
        """Get maximum body size in bytes."""
        max_kb = self.config.get("detector", {}).get("max_body_kb", 64)
        return max_kb * 1024

    def is_protocol_enabled(self, protocol: str) -> bool:
        """Check if a protocol is enabled for monitoring."""
        return (
            self.config.get("detector", {})
            .get("protocols", {})
            .get(protocol, {})
            .get("enabled", False)
        )
