"""Target validation for proposed actions.

Every target the planner proposes comes from the inventory or from evidence -
and evidence is attacker-influenceable. A planted log line must not be able to
make the planner propose isolating the wrong host, blocking an internal or
allowlisted address, or disabling a defender's account. Checks:

* host    - a plain identifier AND an asset in the Core inventory (the policy
            engine's P3 would deny anything else anyway);
* ip      - a valid, globally routable, external address that the evidence does
            not map to one of our hosts and threat intel does not allowlist;
* account - a plain account name (no domain prefix, no machine account) that is
            not on the protected-accounts list (decision Q5). A protected
            account is not dropped: the planner turns it into a human decision.

Refusal reasons are fixed templates; a refused value is never echoed unless it
is a safe token.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from cyberrescue.core.audit import canonical_json
from cyberrescue.detection.context import AssetContext, EvidenceView
from cyberrescue.detection.matchers import is_external, normalize_ip, safe_token
from cyberrescue.response.model import Target

PROTECTED_ACCOUNTS_FILE = Path(__file__).with_name("protected_accounts.json")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class ProtectedAccounts:
    names: frozenset[str]
    sha256: str


def load_protected_accounts(path: str | Path | None = None) -> ProtectedAccounts:
    raw = Path(path or PROTECTED_ACCOUNTS_FILE).read_bytes()
    doc = json.loads(raw)
    if doc.get("schema") != "cyberrescue.protected-accounts/1":
        raise ValueError("not a cyberrescue.protected-accounts/1 document")
    names = frozenset(str(a).strip().lower() for a in doc.get("accounts", []) if str(a).strip())
    # Fingerprint the normalised list, not the bytes (line endings must not matter).
    return ProtectedAccounts(names=names, sha256=hashlib.sha256(
        canonical_json(sorted(names)).encode()).hexdigest())


@dataclass(frozen=True)
class TargetCheck:
    ok: bool
    target: Target | None = None
    reason: str = ""
    protected: bool = False
    checks: tuple[str, ...] = field(default=())


def _refuse(reason: str, *, protected: bool = False, target: Target | None = None) -> TargetCheck:
    return TargetCheck(False, target=target, reason=reason, protected=protected)


def check_host(value: object, assets: AssetContext) -> TargetCheck:
    s = str(value or "")
    if not _HOST_RE.match(s):
        return _refuse("host name is not a plain identifier")
    if not assets.is_asset(s):
        return _refuse(f"host {safe_token(s)} is not in the asset inventory")
    checks = ("plain_identifier", "in_inventory")
    return TargetCheck(True, Target(kind="host", value=s, source="inventory", checks=checks),
                       checks=checks)


def check_ip(value: object, view: EvidenceView) -> TargetCheck:
    ip = normalize_ip(value)
    if ip is None:
        return _refuse("not a valid IP address")
    addr = ipaddress.ip_address(ip)
    if not (is_external(ip) and addr.is_global) or addr.is_multicast or addr.is_reserved \
            or addr.is_unspecified:
        return _refuse(f"{ip} is internal or not globally routable; blocking it could cut "
                       "off our own systems")
    if view.addresses.resolve(ip) is not None or ip in view.addresses.ambiguous():
        return _refuse(f"{ip} is used by one of our hosts in the evidence")
    if view.intel.allowlisted(view.intel.lookup_ip(ip)):
        return _refuse(f"{ip} is allowlisted by threat intel")
    checks = ("valid_ip", "external_global", "not_our_host", "not_allowlisted")
    return TargetCheck(True, Target(kind="ip", value=ip, source="evidence", checks=checks),
                       checks=checks)


def check_account(value: object, protected: ProtectedAccounts) -> TargetCheck:
    s = str(value or "").strip().lower()
    if s.endswith("$"):
        return _refuse("machine accounts are never proposed for disabling")
    if not _ACCOUNT_RE.match(s):
        return _refuse("account is not a plain account name")
    if s in protected.names:
        return _refuse(f"{s} is a protected account; disabling it is a human decision",
                       protected=True,
                       target=Target(kind="account", value=s, source="evidence",
                                     checks=("plain_account_name", "protected")))
    checks = ("plain_account_name", "not_protected")
    return TargetCheck(True, Target(kind="account", value=s, source="evidence", checks=checks),
                       checks=checks)
