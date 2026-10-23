"""Default configuration values for GhydraMCP CLI."""

from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from ..utils.validators import truthy


@dataclass
class GhidraConfig:
    """Configuration for GhydraMCP CLI.

    Attributes:
        default_host: Default Ghidra host
        default_port: Default Ghidra port
        timeout: HTTP request timeout in seconds
        use_colors: Enable colored output
        page_output: Enable paging for long output
        max_pagination: Maximum items per page
        kuna_enabled: Enable the Kuna decompiler integration; None means the
            environment decides
        kuna_path: Path to the kuna executable
    """

    default_host: str = "localhost"
    default_port: int = 8192
    timeout: int = 900
    use_colors: bool = True
    page_output: bool = True
    max_pagination: int = 100
    kuna_enabled: Optional[bool] = None
    kuna_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary.

        The Kuna settings live under a "kuna" section, so the file reads
        {"kuna": {"enabled": true, "path": "..."}} rather than two flat keys.
        """
        data = asdict(self)
        enabled = data.pop("kuna_enabled")
        path = data.pop("kuna_path")
        data["kuna"] = {"enabled": enabled, "path": path}
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GhidraConfig":
        """Create config from dictionary."""
        values = dict(data)
        section = values.pop("kuna", None)
        if not isinstance(section, dict):
            section = {}

        known = {f for f in cls.__dataclass_fields__}
        config = cls(**{k: v for k, v in values.items() if k in known})

        if section.get("enabled") is not None:
            config.kuna_enabled = truthy(section["enabled"])
        if section.get("path"):
            config.kuna_path = str(section["path"])

        return config
