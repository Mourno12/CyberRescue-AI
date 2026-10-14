"""Pure, deterministic predicates over structured evidence values.

Every function takes plain values (paths, command lines, addresses) - never a
raw log line - and returns a fact. No I/O, no clock, no state.
"""

from __future__ import annotations

import ipaddress
import re

# Windows locations any user (or a dropper) can write to.
_USER_WRITABLE_RE = re.compile(
    r"^[a-z]:\\(?:programdata|users\\public|windows\\temp|"
    r"users\\[^\\]+\\(?:downloads|appdata|desktop|documents))\\|\\temp\\",
    re.IGNORECASE)
_RUN_KEY_RE = re.compile(
    r"\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\run(?:once)?(?:\\|$)",
    re.IGNORECASE)

INTERPRETERS = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                          "cscript.exe", "mshta.exe", "python.exe", "pythonw.exe",
                          "node.exe"})
_SUSPICIOUS_ARGS = (
    ("encoded_command", re.compile(r"(?:^|\s)[-/](?:e|ec|enc|encodedcommand)\s", re.I)),
    ("invoke_expression", re.compile(r"\biex\b|invoke-expression", re.I)),
    ("download_cradle", re.compile(r"downloadstring|downloadfile|invoke-webrequest|"
                                   r"frombase64string|\bcurl\b|\bwget\b", re.I)),
    ("remote_url", re.compile(r"https?://", re.I)),
    ("hidden_window", re.compile(r"-w(?:indowstyle)?\s+hidden", re.I)),
    ("policy_bypass", re.compile(r"-(?:nop|noprofile)\b|executionpolicy\s+bypass", re.I)),
)
OFFICE_AND_BROWSERS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                                 "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"})
_RECOVERY_INHIBITION = (
    ("vssadmin_delete_shadows", re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.I)),
    ("wmic_shadowcopy_delete", re.compile(r"wmic(?:\.exe)?\s+shadowcopy\s+delete", re.I)),
    ("bcdedit_recovery_disabled", re.compile(r"bcdedit(?:\.exe)?.*recoveryenabled\s+no", re.I)),
    ("wbadmin_delete", re.compile(r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|"
                                  r"backup)", re.I)),
)
PRIVILEGED_GROUPS = frozenset({"domain admins", "enterprise admins", "schema admins",
                               "administrators", "backup operators", "account operators",
                               "server operators"})
DB_DUMP_TOOLS = frozenset({"pg_dump.exe", "pg_dumpall.exe", "mysqldump.exe", "sqlcmd.exe",
                           "bcp.exe", "expdp.exe", "mongodump.exe"})
ADMIN_PORTS = frozenset({135, 139, 445, 3389, 5985, 5986})
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "iso", "img", "cab"})
SENSITIVE_DATA_CLASSES = frozenset({"customer_pii", "financial", "credentials"})
# Threat-intel confidence vocabulary (ioc_db.json) -> detection confidence.
CONFIDENCES_FROM_INTEL = {"high": "high", "medium": "medium", "low": "low"}

# Not "is_global": synthetic data uses documentation ranges (RFC 5737) for the
# internet, so "internal" means RFC 1918 / loopback / link-local / CGNAT / ULA.
_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"))


def basename(path: str) -> str:
    return re.split(r"[\\/]", path or "")[-1]


def dirname(path: str) -> str:
    parts = re.split(r"[\\/]", path or "")
    return "\\".join(parts[:-1]).lower()


def is_user_writable(path: str | None) -> bool:
    return bool(path) and bool(_USER_WRITABLE_RE.search(path))


def is_run_key(path: str | None) -> bool:
    return bool(path) and bool(_RUN_KEY_RE.search(path))


def suspicious_arguments(cmdline: str | None) -> list[str]:
    return [name for name, rx in _SUSPICIOUS_ARGS if cmdline and rx.search(cmdline)]


def recovery_inhibition(cmdline: str | None) -> str | None:
    for name, rx in _RECOVERY_INHIBITION:
        if cmdline and rx.search(cmdline):
            return name
    return None


def appended_extension(original: str | None, new: str | None) -> str | None:
    """``x.db`` -> ``x.db.locked`` gives ``locked``; anything else gives None."""
    if not original or not new or not new.startswith(original + "."):
        return None
    ext = new[len(original) + 1:]
    return ext.lower() if ext and not re.search(r"[\\/.\s]", ext) else None


def normalize_ip(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def is_internal(ip: str | None) -> bool:
    addr = normalize_ip(ip)
    if addr is None:
        return False
    a = ipaddress.ip_address(addr)
    return any(a in net for net in _INTERNAL_NETS)


def is_external(ip: str | None) -> bool:
    return normalize_ip(ip) is not None and not is_internal(ip)


def normalize_domain(value: object) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    return d if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", d) else None


def url_host(url: object) -> str | None:
    """Host of ``https://h/p``, ``h:443`` or ``h/p``."""
    s = str(url or "").strip()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s, flags=re.I)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("["):
        return None
    return normalize_domain(s.split(":", 1)[0])


def normalize_sha256(value: object) -> str | None:
    s = str(value or "").strip().lower()
    return s if re.fullmatch(r"[0-9a-f]{64}", s) else None


_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def safe_token(value: object) -> str:
    """For human-readable summaries only: attacker-influenced values that are
    not plain identifiers are never interpolated."""
    s = str(value) if value is not None else ""
    return s if _SAFE_TOKEN_RE.match(s) else "<unprintable>"
