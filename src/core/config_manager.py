"""
Scanwell Configuration Manager

Persistent configuration for scanning thresholds, resource limits,
and file type filters. Uses JSON stored in ~/.scanwell/config.json.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manage persistent Scanwell configuration."""

    def __init__(self, config_path: str = None):
        if config_path:
            self.config_file = Path(config_path)
        else:
            self.config_file = Path.home() / ".scanwell" / "config.json"
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config: dict[str, Any] = {}
        self.load_config()

    def load_config(self):
        """Load config from disk, or create with defaults."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                # Merge in any missing defaults
                defaults = self.get_default_config()
                for key, val in defaults.items():
                    if key not in self.config:
                        self.config[key] = val
                    elif isinstance(val, dict):
                        for subkey, subval in val.items():
                            if subkey not in self.config[key]:
                                self.config[key][subkey] = subval
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Config load error: {e}. Using defaults.")
                self.config = self.get_default_config()
                self.save_config()
        else:
            self.config = self.get_default_config()
            self.save_config()

    def save_config(self):
        """Persist config to disk."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except IOError as e:
            logger.error(f"Failed to save config: {e}")

    def get_default_config(self) -> dict:
        """Return default configuration."""
        return {
            "resource_limits": {
                "cpu_percent": 50,
                "memory_percent": 50,
                "storage_limit_mb": 1000,
                "max_file_size_mb": 50,
            },
            "risk_thresholds": {
                "high": 10,
                "medium": 5,
                "low": 1,
            },
            "file_types": [
                ".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml",
                ".doc", ".docx", ".pdf", ".xls", ".xlsx",
                ".py", ".java", ".c", ".cpp", ".go", ".rs",
                ".sh", ".sql", ".conf", ".ini",
            ],
            "scan_settings": {
                "use_yara": True,
                "enable_similarity": False,
                "skip_hidden": True,
                "skip_pycache": True,
            },
        }

    def get(self, key: str, default=None):
        """Get a config value by key."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any):
        """Set a config value and save."""
        self.config[key] = value
        self.save_config()

    def get_risk_level(self, finding_count: int) -> str:
        """Determine risk level based on finding count and thresholds."""
        thresholds = self.config.get("risk_thresholds", {})
        if finding_count >= thresholds.get("high", 10):
            return "High"
        elif finding_count >= thresholds.get("medium", 5):
            return "Medium"
        elif finding_count >= thresholds.get("low", 1):
            return "Low"
        return "None"


# Backward-compatible alias
Config = ConfigManager
