"""Loading: the asset inventory (inventory.csv), the Intune managed devices (intune.csv), the Defender for Endpoint device inventory
(defender.csv), the BitLocker recovery keys in Entra ID (recovery-keys.csv) and, when present, the local administrators reported
by an Intune remediation script (local-admins.csv), the Endpoint Privilege Management elevation report (epm-elevations.csv), the
exceptions (exceptions.csv) and last month's coverage (previous-coverage.csv). Forgiving column names, into plain dataclasses."""
from __future__ import annotations

import csv
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

INVENTORY_ALIASES = {
    "device": ["Device", "Device name", "DeviceName", "Hostname", "Computer", "ComputerName", "Name", "ci name"],
    "serial": ["Serial", "Serial number", "SerialNumber", "Service tag", "Asset serial"],
    "asset_tag": ["AssetTag", "Asset tag", "Asset", "Asset id", "Asset number"],
    "platform": ["Platform", "OS", "Operating system", "OS family", "Type"],
    "model": ["Model", "Device model", "Hardware model", "Product"],
    "site": ["Site", "Location", "Office", "Building"],
    "department": ["Department", "Dept", "Cost centre", "Cost center", "Business unit", "Team"],
    "user": ["User", "Assigned to", "Owner", "Primary user", "UserPrincipalName", "Email"],
    "status": ["Status", "State", "Lifecycle", "Install status", "Asset state"],
}
INTUNE_ALIASES = {
    "device": ["deviceName", "Device name", "Device", "Name", "Hostname"],
    "serial": ["serialNumber", "Serial number", "Serial"],
    "entra_id": ["azureADDeviceId", "Azure AD device ID", "Entra device ID", "Microsoft Entra Device ID", "EntraDeviceId", "aadDeviceId"],
    "os": ["operatingSystem", "OS", "Operating system", "Platform"],
    "os_version": ["osVersion", "OS version", "Version", "Build"],
    "compliance": ["complianceState", "Compliance", "Compliance state", "Compliant"],
    "encrypted": ["isEncrypted", "Encrypted", "Encryption", "Storage encrypted"],
    "last_sync": ["lastSyncDateTime", "Last check-in", "Last sync", "Last check in", "LastSync"],
    "user": ["userPrincipalName", "Primary user UPN", "User", "Primary user"],
    "ownership": ["managedDeviceOwnerType", "Ownership", "Owner type", "Owned by"],
    "realtime": ["realTimeProtectionEnabled", "Real-time protection", "RealTimeProtection", "RTP"],
    "signature_overdue": ["signatureUpdateOverdue", "Signature update overdue", "Signatures overdue", "Definitions overdue"],
    "tamper": ["tamperProtectionEnabled", "Tamper protection", "TamperProtection"],
}
DEFENDER_ALIASES = {
    "device": ["computerDnsName", "Device Name", "Device", "Name", "Hostname"],
    "entra_id": ["aadDeviceId", "Entra device ID", "Azure AD device ID", "Microsoft Entra Device ID", "Aad Device Id"],
    "onboarding": ["onboardingStatus", "Onboarding Status", "Onboarding"],
    "health": ["healthStatus", "Health Status", "Sensor health state", "Health", "Sensor health"],
    "last_seen": ["lastSeen", "Last Seen", "Last device update", "Last seen date"],
    "platform": ["osPlatform", "OS Platform", "Platform", "OS"],
    "exposure": ["exposureLevel", "Exposure Level", "Exposure"],
}
KEY_ALIASES = {
    "entra_id": ["deviceId", "Device ID", "Entra device ID", "azureADDeviceId", "aadDeviceId"],
    "volume": ["volumeType", "Volume type", "Volume", "Drive type"],
    "created": ["createdDateTime", "Created", "Backed up", "Backup date", "Date"],
}
ADMIN_ALIASES = {
    "device": ["Device", "Device name", "DeviceName", "Computer", "ComputerName", "Hostname"],
    "account": ["Account", "Member", "Name", "Principal", "User", "Identity"],
    "kind": ["Type", "Kind", "Object class", "ObjectClass", "Principal source", "Member type"],
}
EPM_ALIASES = {
    "device": ["Device", "Device name", "DeviceName", "Computer"],
    "user": ["User", "UPN", "User principal name", "Elevated by", "Upn"],
    "file": ["File", "File name", "FileName", "Application", "Executable", "Process"],
    "publisher": ["Publisher", "Signer", "Certificate", "Company"],
    "kind": ["Elevation type", "Type", "ElevationType", "Rule type", "Kind"],
    "result": ["Result", "Outcome", "Status"],
    "when": ["Date", "Time", "Elevation time", "Timestamp", "When", "Date time"],
}
EXCEPTION_ALIASES = {
    "device": ["Device", "Device name", "Computer", "Hostname", "Scope", "Name"],
    "control": ["Control", "Control id", "Check", "Requirement", "Setting"],
    "reason": ["Reason", "Justification", "Business reason", "Rationale", "Description"],
    "approver": ["Approver", "Approved by", "Risk owner", "Accepted by"],
    "ticket": ["Ticket", "Change", "Reference", "Risk id", "Request"],
    "expires": ["Expires", "Expiry", "Expiry date", "Expiration", "Valid until", "End date"],
}
PREVIOUS_ALIASES = {
    "control": ["control", "Control", "Control id"],
    "pct": ["coverage_pct", "Coverage", "Coverage %", "Pct", "Percent"],
    "devices": ["devices", "Devices", "In scope"],
}
YES = {"yes", "y", "true", "1", "x", "si", "enabled", "on", "encrypted"}
NO = {"no", "n", "false", "0", "disabled", "off", "not encrypted", "notencrypted"}
DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M", "%d/%m/%Y", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%d %b %Y", "%d-%b-%Y")

# The controls, in the order they are shown. Platform "all" or a platform name.
CONTROLS = {
    "MDM": ("Managed in Intune", "all"),
    "COMPLIANT": ("Compliant in Intune", "all"),
    "CHECKIN": ("Checked in recently", "all"),
    "ENCRYPTED": ("Disk encrypted (BitLocker / FileVault)", "all"),
    "KEY": ("BitLocker recovery key in Entra ID", "windows"),
    "EDR": ("Onboarded and active in Defender for Endpoint", "all"),
    "AV": ("Antivirus healthy (real-time, signatures, tamper)", "windows"),
    "ADMIN": ("No standing local administrators", "windows"),
    "OS": ("Supported operating system", "all"),
}
DEFAULT_OWNERS = {"MDM": "Endpoint team", "COMPLIANT": "Endpoint team", "CHECKIN": "Service desk", "ENCRYPTED": "Endpoint team",
                  "KEY": "Endpoint team", "EDR": "Security operations", "AV": "Security operations", "ADMIN": "Endpoint team",
                  "OS": "Endpoint team", "EPM": "Endpoint team", "INVENTORY": "IT asset manager", "EXCEPTIONS": "Security risk manager",
                  "COVERAGE": "Head of IT"}


def _norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", "".join(ch for ch in s if not unicodedata.combining(ch))).strip()


def parse_dt(v) -> datetime | None:
    s = str(v or "").strip()
    if not s or _norm(s) in {"n a", "na", "none", "null", "never", "tbd"}:
        return None
    s = re.sub(r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})$", "", s)
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def parse_d(v) -> date | None:
    x = parse_dt(v)
    return x.date() if x else None


def num(v) -> float | None:
    s = str(v or "").strip()
    if not re.fullmatch(r"-?\d+([.,]\d+)?", s):
        return None
    return float(s.replace(",", "."))


def yes_no(v) -> bool | None:
    n = _norm(v)
    if n in YES:
        return True
    if n in NO:
        return False
    return None


def host(v) -> str:
    """Short upper-case device name: 'tsa-mad-l0142.tailspin.local' -> 'TSA-MAD-L0142'."""
    return str(v or "").strip().split(".")[0].upper()


def guid(v) -> str:
    return str(v or "").strip().strip("{}").lower()


def platform(v) -> str:
    """windows, macos, or what it was ('ios', 'android', 'linux')."""
    n = _norm(v)
    if not n:
        return ""
    if "windows" in n or n in {"win", "win10", "win11", "pc"}:
        return "windows"
    if "mac" in n or "os x" in n or n == "darwin":
        return "macos"
    return n.split()[0]


def compliance(v) -> str:
    """compliant, noncompliant, grace, unknown."""
    n = _norm(v).replace(" ", "")
    if n in {"compliant", "yes", "true"}:
        return "compliant"
    if n in {"ingraceperiod", "grace", "graceperiod"}:
        return "grace"
    if n in {"noncompliant", "notcompliant", "no", "false", "error", "conflict"}:
        return "noncompliant"
    return "unknown"


def health(v) -> str:
    """active, inactive, impaired, nosensor, unknown."""
    n = _norm(v).replace(" ", "")
    if n == "active":
        return "active"
    if n == "inactive":
        return "inactive"
    if "nosensor" in n:
        return "nosensor"
    if "impaired" in n or "misconfigured" in n:
        return "impaired"
    return "unknown"


def onboarded(v) -> bool:
    return _norm(v).replace(" ", "") == "onboarded"


def in_use(status: str) -> bool:
    n = _norm(status)
    return not n or n in {"in use", "inuse", "deployed", "active", "assigned", "live", "operational", "production"}


def retired(status: str) -> bool:
    return _norm(status) in {"retired", "disposed", "decommissioned", "lost", "stolen", "scrapped", "returned"}


def os_build(version: str) -> tuple[int, ...]:
    """'10.0.22631.4460' -> (10, 0, 22631, 4460); '14.6.1' -> (14, 6, 1)."""
    return tuple(int(x) for x in re.findall(r"\d+", str(version or ""))[:4])


def _read(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = fh.readline()
        fh.seek(0)
        delim = max(",;\t", key=header.count)
        reader = csv.DictReader(fh, delimiter=delim)
        return list(reader.fieldnames or []), list(reader)


def _map(fields: list[str], aliases: dict[str, list[str]]) -> dict[str, str]:
    heads = {_norm(h): h for h in fields}
    cols = {}
    for k, names in aliases.items():
        for n in names + [k.replace("_", " ")]:
            if _norm(n) in heads and heads[_norm(n)] not in cols.values():
                cols[k] = heads[_norm(n)]
                break
    return cols


def _rows(path: Path, aliases: dict[str, list[str]]) -> list[dict]:
    fields, raw = _read(path)
    cols = _map(fields, aliases)
    return [{k: (r.get(c) or "").strip() for k, c in cols.items()} for r in raw]


# ---------------------------------------------------------------- records

@dataclass
class Asset:
    device: str
    serial: str = ""
    asset_tag: str = ""
    platform: str = ""
    model: str = ""
    site: str = ""
    department: str = ""
    user: str = ""
    status: str = ""


@dataclass
class Managed:
    device: str
    serial: str = ""
    entra_id: str = ""
    platform: str = ""
    os_version: str = ""
    compliance: str = "unknown"
    encrypted: bool | None = None
    last_sync: datetime | None = None
    user: str = ""
    ownership: str = ""
    realtime: bool | None = None
    signature_overdue: bool | None = None
    tamper: bool | None = None


@dataclass
class Sensor:
    device: str
    entra_id: str = ""
    onboarded: bool = False
    health: str = "unknown"
    last_seen: datetime | None = None
    platform: str = ""
    exposure: str = ""


@dataclass
class Elevation:
    device: str
    user: str
    file: str
    publisher: str
    kind: str
    result: str
    when: datetime | None = None


@dataclass
class Exception_:
    device: str
    control: str
    reason: str = ""
    approver: str = ""
    ticket: str = ""
    expires: date | None = None


@dataclass
class Settings:
    organisation: str = "Endpoint estate"
    review_date: datetime | None = None
    previous_review: date | None = None
    target_pct: float = 98.0
    red_pct: float = 90.0
    targets: dict = field(default_factory=dict)          # per control: {"EDR": 100}
    checkin_days: int = 14
    sensor_days: int = 7
    exception_warning_days: int = 30
    min_os: dict = field(default_factory=lambda: {"windows": "10.0.22631", "macos": "14.0"})
    allowed_admins: list = field(default_factory=lambda: ["Administrator", "Domain Admins", "Device administrators"])
    epm_rule_users: int = 5                              # same file elevated by this many users -> candidate rule
    action_days: dict = field(default_factory=lambda: {"red": 7, "amber": 30})
    owners: dict = field(default_factory=lambda: dict(DEFAULT_OWNERS))

    def owner(self, key: str) -> str:
        return self.owners.get(key) or DEFAULT_OWNERS.get(key) or "Endpoint team"

    def target(self, control: str) -> float:
        return float(num(self.targets.get(control)) or self.target_pct)


def settings_from_dict(raw: dict) -> Settings:
    s = Settings()
    for k, v in raw.items():
        if not hasattr(s, k) or v is None:
            continue
        cur = getattr(s, k)
        if k == "review_date":
            s.review_date = parse_dt(v)
        elif k == "previous_review":
            s.previous_review = parse_d(v)
        elif isinstance(cur, dict):
            cur.update({str(a): b for a, b in v.items()})
        elif isinstance(cur, list):
            setattr(s, k, [str(x) for x in v])
        elif isinstance(cur, int) and not isinstance(cur, bool):
            setattr(s, k, int(float(v)))
        elif isinstance(cur, float):
            setattr(s, k, float(v))
        else:
            setattr(s, k, str(v))
    return s


@dataclass
class Data:
    settings: Settings
    as_of: datetime
    assets: list = field(default_factory=list)
    managed: list = field(default_factory=list)
    sensors: list = field(default_factory=list)
    keys: set | None = None                      # Entra device ids with an OS-volume recovery key
    admins: dict | None = None                   # device -> [(account, kind)]
    elevations: list | None = None
    exceptions: list | None = None
    previous: dict | None = None                 # control -> coverage %
    sources: dict = field(default_factory=dict)

    @property
    def today(self) -> date:
        return self.as_of.date()


# ---------------------------------------------------------------- loaders

def load_inventory(path: Path) -> list[Asset]:
    out, seen = [], set()
    for r in _rows(path, INVENTORY_ALIASES):
        name = host(r.get("device"))
        if not name and not r.get("serial"):
            continue
        key = name or r["serial"].upper()
        if key in seen:
            continue
        seen.add(key)
        out.append(Asset(name, r.get("serial", "").upper(), r.get("asset_tag", ""), platform(r.get("platform")), r.get("model", ""),
                         r.get("site", ""), r.get("department", ""), r.get("user", "").lower(), r.get("status", "")))
    return out


def load_intune(path: Path) -> list[Managed]:
    out = []
    for r in _rows(path, INTUNE_ALIASES):
        if not r.get("device") and not r.get("serial"):
            continue
        out.append(Managed(host(r.get("device")), r.get("serial", "").upper(), guid(r.get("entra_id")), platform(r.get("os")),
                           r.get("os_version", ""), compliance(r.get("compliance")), yes_no(r.get("encrypted")),
                           parse_dt(r.get("last_sync")), r.get("user", "").lower(), _norm(r.get("ownership")),
                           yes_no(r.get("realtime")), yes_no(r.get("signature_overdue")), yes_no(r.get("tamper"))))
    return out


def load_defender(path: Path) -> list[Sensor]:
    out = []
    for r in _rows(path, DEFENDER_ALIASES):
        if not r.get("device") and not r.get("entra_id"):
            continue
        out.append(Sensor(host(r.get("device")), guid(r.get("entra_id")), onboarded(r.get("onboarding")), health(r.get("health")),
                          parse_dt(r.get("last_seen")), platform(r.get("platform")), r.get("exposure", "")))
    return out


def load_keys(path: Path) -> set:
    out = set()
    for r in _rows(path, KEY_ALIASES):
        v = _norm(r.get("volume"))
        if r.get("entra_id") and v in {"", "1", "operatingsystemvolume", "operating system volume", "os", "os volume", "system"}:
            out.add(guid(r["entra_id"]))
    return out


def load_admins(path: Path) -> dict:
    out: dict = {}
    for r in _rows(path, ADMIN_ALIASES):
        if r.get("device") and r.get("account"):
            out.setdefault(host(r["device"]), []).append((r["account"], _norm(r.get("kind")) or "user"))
    return out


def load_elevations(path: Path) -> list[Elevation]:
    out = []
    for r in _rows(path, EPM_ALIASES):
        if not r.get("file"):
            continue
        out.append(Elevation(host(r.get("device")), r.get("user", "").lower(), r["file"], r.get("publisher", ""),
                             _norm(r.get("kind")), _norm(r.get("result")) or "success", parse_dt(r.get("when"))))
    return out


def load_exceptions(path: Path) -> list[Exception_]:
    out = []
    for r in _rows(path, EXCEPTION_ALIASES):
        if not r.get("device") or not r.get("control"):
            continue
        out.append(Exception_(host(r["device"]), r["control"].strip().upper(), r.get("reason", ""), r.get("approver", ""),
                              r.get("ticket", ""), parse_d(r.get("expires"))))
    return sorted(out, key=lambda x: (x.device, x.control))


def load_previous(path: Path) -> dict:
    out = {}
    for r in _rows(path, PREVIOUS_ALIASES):
        p = num(str(r.get("pct", "")).replace("%", "").strip())
        if r.get("control") and p is not None:
            out[r["control"].strip().upper()] = p
    return out


FILES = {
    "inventory.csv": "Asset inventory (CMDB or asset register)",
    "intune.csv": "Intune managed devices (Collect-EndpointCoverage.ps1)",
    "defender.csv": "Defender for Endpoint device inventory",
    "recovery-keys.csv": "BitLocker recovery keys in Entra ID (no key values)",
    "local-admins.csv": "Local administrators (Intune remediation script)",
    "epm-elevations.csv": "Endpoint Privilege Management elevation report",
    "exceptions.csv": "Approved exceptions",
    "previous-coverage.csv": "Last review's coverage per control",
}


def load(folder: Path, as_of: datetime | None = None) -> Data:
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"no folder {folder}")
    sp = folder / "settings.json"
    s = settings_from_dict(json.loads(sp.read_text(encoding="utf-8"))) if sp.exists() else Settings()
    when = as_of or s.review_date or datetime.now().replace(second=0, microsecond=0)
    for f in ("inventory.csv", "intune.csv", "defender.csv"):
        if not (folder / f).exists():
            raise FileNotFoundError(f"{folder}: need {f} ({FILES[f]})")
    d = Data(s, when)
    d.assets = load_inventory(folder / "inventory.csv")
    if not d.assets:
        raise ValueError(f"{folder / 'inventory.csv'}: no devices (check the Device or Serial column)")
    d.managed = load_intune(folder / "intune.csv")
    d.sensors = load_defender(folder / "defender.csv")
    d.sources = {"inventory.csv": len(d.assets), "intune.csv": len(d.managed), "defender.csv": len(d.sensors)}
    optional = (("recovery-keys.csv", load_keys, "keys"), ("local-admins.csv", load_admins, "admins"),
                ("epm-elevations.csv", load_elevations, "elevations"), ("exceptions.csv", load_exceptions, "exceptions"),
                ("previous-coverage.csv", load_previous, "previous"))
    for f, fn, attr in optional:
        if (folder / f).exists():
            val = fn(folder / f)
            setattr(d, attr, val)
            d.sources[f] = sum(len(v) for v in val.values()) if attr == "admins" else len(val)
    return d


__all__ = ["Data", "Settings", "Asset", "Managed", "Sensor", "Elevation", "Exception_", "CONTROLS", "FILES", "load",
           "load_inventory", "load_intune", "load_defender", "load_keys", "load_admins", "load_elevations", "load_exceptions",
           "load_previous", "settings_from_dict", "host", "guid", "platform", "compliance", "health", "yes_no", "num", "parse_d",
           "parse_dt", "os_build", "in_use", "retired"]
