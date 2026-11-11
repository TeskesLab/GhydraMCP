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
        ghidra_home: Path of the Ghidra installation; empty means it is
            looked for
        java_home: Path of the JDK Ghidra runs on; empty means it is looked
            for
        x64dbg_host: Where the x64dbg MCP server is; empty means the default
        x64dbg_port: The port of the x64dbg MCP server; 0 means the default
        x64dbg_token: The bearer token the x64dbg plugin wants
        x64dbg_path: The x64dbg installation, where the plugin's own
            mcp_config.json - and with it the token - is found
    """

    default_host: str = "localhost"
    default_port: int = 8192
    timeout: int = 900
    use_colors: bool = True
    page_output: bool = True
    max_pagination: int = 100
    kuna_enabled: Optional[bool] = None
    kuna_path: str = ""
    ghidra_home: str = ""
    java_home: str = ""
    x64dbg_host: str = ""
    x64dbg_port: int = 0
    x64dbg_token: str = ""
    x64dbg_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary.

        The Kuna and the x64dbg settings live under their own sections, so the
        file reads {"kuna": {...}, "x64dbg": {...}} rather than flat keys.
        """
        data = asdict(self)
        enabled = data.pop("kuna_enabled")
        path = data.pop("kuna_path")
        data["kuna"] = {"enabled": enabled, "path": path}
        data["x64dbg"] = {
            "host": data.pop("x64dbg_host"),
            "port": data.pop("x64dbg_port"),
            "token": data.pop("x64dbg_token"),
            "path": data.pop("x64dbg_path"),
        }
        return data

    def x64dbg_section(self) -> Dict[str, Any]:
        """The x64dbg settings as the section `ghydra.x64dbg.resolve_config` takes.

        The file nests them under "x64dbg" and the object keeps them flat; a caller
        that read an attribute named `x64dbg` got None and silently ignored the
        configuration. This is the one place that knows the four keys.
        """
        section: Dict[str, Any] = {}
        if self.x64dbg_host:
            section["host"] = self.x64dbg_host
        if self.x64dbg_port:
            section["port"] = self.x64dbg_port
        if self.x64dbg_token:
            section["token"] = self.x64dbg_token
        if self.x64dbg_path:
            section["path"] = self.x64dbg_path
        return section

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GhidraConfig":
        """Create config from dictionary."""
        values = dict(data)
        section = values.pop("kuna", None)
        if not isinstance(section, dict):
            section = {}
        x64dbg = values.pop("x64dbg", None)
        if not isinstance(x64dbg, dict):
            x64dbg = {}

        known = {f for f in cls.__dataclass_fields__}
        config = cls(**{k: v for k, v in values.items() if k in known})

        if section.get("enabled") is not None:
            config.kuna_enabled = truthy(section["enabled"])
        if section.get("path"):
            config.kuna_path = str(section["path"])

        if x64dbg.get("host"):
            config.x64dbg_host = str(x64dbg["host"])
        if x64dbg.get("port"):
            try:
                config.x64dbg_port = int(x64dbg["port"])
            except (TypeError, ValueError):
                config.x64dbg_port = 0
        if x64dbg.get("token"):
            config.x64dbg_token = str(x64dbg["token"])
        if x64dbg.get("path"):
            config.x64dbg_path = str(x64dbg["path"])

        return config
