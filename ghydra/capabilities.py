"""Capability triage: rank ATT&CK/MBC-style technique leads from imports and strings.

This module is deliberately pure: it takes HATEOAS envelopes and returns a
report dict. No Ghidra, no network, no imports from the bridge (the CLI must
stay standalone). The bridge carries its own copy because it ships as one file;
``test_capabilities_summary.py`` asserts the two copies stay identical.

The result is a ranked list of *leads*, not a verdict. Nothing is inferred from
a rule that has no matching evidence, and addresses are copied verbatim from
the server's answer so the analyst can verify every claim.
"""

from __future__ import annotations

# (id, name, tactic, import patterns, string patterns)
CAPABILITY_RULES = (
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "imports": ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                    "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext",
                    "NtMapViewOfSection"),
        "strings": (),
    },
    {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "imports": ("CreateToolhelp32Snapshot", "Process32First", "Process32Next",
                    "EnumProcesses", "NtQuerySystemInformation"),
        "strings": (),
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "imports": ("GetSystemInfo", "GetVersionEx", "GetComputerName",
                    "GetUserName", "GetDiskFreeSpace", "RegQueryValueEx"),
        "strings": (),
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "imports": ("URLDownloadToFile", "WinHttpOpen", "InternetOpenUrl",
                    "HttpSendRequest", "curl_easy_perform", "recv", "WSARecv"),
        "strings": ("http://", "https://", "Mozilla/", "User-Agent", "download"),
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "imports": ("WSAConnect", "InternetConnect", "HttpOpenRequest",
                    "WSAStartup", "connect", "send"),
        "strings": (),
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "imports": ("CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "CryptDeriveKey"),
        "strings": ("YOUR FILES", "ransom", "decrypt", ".locked", "bitcoin",
                    "restore your", "encrypted"),
    },
    {
        "id": "T1497",
        "name": "Virtualization / Sandbox Evasion",
        "tactic": "Defense Evasion / Discovery",
        "imports": ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "GetTickCount", "Sleep", "NtQueryInformationProcess"),
        "strings": ("VMware", "VirtualBox", "QEMU", "Sandbox", "VBox", "ollydbg"),
    },
    {
        "id": "T1113",
        "name": "Screen Capture",
        "tactic": "Collection",
        "imports": ("BitBlt", "GetDC", "CreateCompatibleBitmap", "PrintWindow",
                    "GetWindowDC"),
        "strings": (),
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "imports": ("CreateService", "OpenSCManager", "RegSetValueEx", "ShellExecute"),
        "strings": ("\\CurrentVersion\\Run", "\\RunOnce", "schtasks", "startup"),
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "imports": ("VirtualProtect", "GetProcAddress", "LoadLibraryA",
                    "LoadLibraryW", "LdrLoadDll"),
        "strings": ("base64", "obfuscat"),
    },
)

_IMPORT_KEYS = ("name", "label", "symbol", "value")
_STRING_KEYS = ("value", "name", "string", "text")
_ADDRESS_KEYS = ("address", "addr", "offset")


def _items(response: object) -> list[dict]:
    if not isinstance(response, dict) or not response.get("success", False):
        return []
    payload = response.get("result")
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _text(item: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _address(item: dict) -> str:
    for key in _ADDRESS_KEYS:
        value = item.get(key)
        if isinstance(value, (str, int)) and value != "":
            return str(value)
    return ""


def _evidence(items: list[dict], keys: tuple[str, ...],
              patterns: tuple[str, ...], kind: str) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        text = _text(item, keys)
        if not text:
            continue
        lowered = text.lower()
        for pattern in patterns:
            if pattern.lower() in lowered:
                marker = (kind, text)
                if marker not in seen:
                    seen.add(marker)
                    found.append({
                        "kind": kind,
                        "name": text[:120],
                        "address": _address(item),
                        "matched": pattern,
                    })
                break
    return found


def build_capability_report(program: object, imports: object, strings: object,
                            include_strings: bool = True) -> dict:
    """Compose the three envelopes into a ranked capability triage report."""
    import_items = _items(imports)
    string_items = _items(strings) if include_strings else []

    failures = []
    for label, response in (("imports", imports), ("strings", strings)):
        if label == "strings" and not include_strings:
            continue
        if isinstance(response, dict) and response.get("success") is False:
            failures.append(label)

    findings = []
    for rule in CAPABILITY_RULES:
        import_hits = _evidence(import_items, _IMPORT_KEYS, rule["imports"], "import")
        string_hits = _evidence(string_items, _STRING_KEYS, rule["strings"], "string")
        score = 2 * len(import_hits) + len(string_hits)
        if score < 2:
            continue
        confidence = "high" if score >= 6 else ("medium" if score >= 3 else "low")
        findings.append({
            "id": rule["id"],
            "name": rule["name"],
            "tactic": rule["tactic"],
            "confidence": confidence,
            "score": score,
            "import_matches": len(import_hits),
            "string_matches": len(string_hits),
            "evidence": (import_hits + string_hits)[:6],
        })
    findings.sort(key=lambda finding: (-finding["score"], finding["id"]))

    name = ""
    if isinstance(program, dict) and isinstance(program.get("result"), dict):
        name = program["result"].get("name") or ""

    return {
        "success": True,
        "result": {
            "program": name,
            "summary": {
                "imports_scanned": len(import_items),
                "strings_scanned": len(string_items),
                "rules": len(CAPABILITY_RULES),
                "techniques_matched": len(findings),
            },
            "failures": failures,
            "findings": findings,
            "method": "Heuristic import/string matching; a lead for an analyst, "
                      "not a verdict.",
        },
    }
