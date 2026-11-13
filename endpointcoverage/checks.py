"""The review: reconcile the inventory, Intune and Defender into one list of devices, check every control on every device in scope,
apply the exceptions, and turn the gaps into findings with an owner, a due date and, where needed, a decision."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from .model import CONTROLS, Data, Exception_, in_use, os_build, retired

RED, AMBER, GREEN = "RED", "AMBER", "GREEN"
GROUPS = {"inventory": "Inventory and sources", "edr": "Defender for Endpoint", "encryption": "Encryption", "av": "Antivirus",
          "mdm": "Intune", "privilege": "Local admin and EPM", "os": "Operating system", "exceptions": "Exceptions",
          "coverage": "Coverage"}
WEIGHTS = {"MDM": 5, "EDR": 5, "ENCRYPTED": 5, "OS": 4, "ADMIN": 4, "AV": 3, "KEY": 3, "COMPLIANT": 2, "CHECKIN": 1}
PLATFORM = {"windows": "Windows", "macos": "macOS"}
HIGH = {"MDM", "EDR", "ENCRYPTED", "OS", "ADMIN"}          # an expired exception on these is RED


@dataclass
class Device:
    name: str
    asset: object = None
    managed: object = None
    sensor: object = None
    platform: str = ""
    scope: str = ""                         # in scope, retired, stock, other platform
    results: dict = field(default_factory=dict)        # control -> (status, cause)

    @property
    def site(self) -> str:
        return self.asset.site if self.asset else ""

    @property
    def department(self) -> str:
        return self.asset.department if self.asset else ""

    @property
    def user(self) -> str:
        return (self.asset.user if self.asset and self.asset.user else "") or (self.managed.user if self.managed else "")

    def failed(self) -> list[str]:
        return [c for c, (st, _) in self.results.items() if st == "fail"]

    @property
    def protected(self) -> bool:
        return self.scope == "in scope" and not self.failed()

    @property
    def risk(self) -> int:
        return sum(WEIGHTS.get(c, 1) for c in self.failed())


@dataclass
class Finding:
    severity: str
    code: str
    group: str
    title: str
    subject: str
    detail: str
    action: str
    devices: list
    owner: str
    due: date | None = None

    @property
    def count(self) -> int:
        return len(self.devices)


@dataclass
class Decision:
    id: str
    decision: str
    why: str
    options: str
    proposed: str
    owner: str
    needed_by: date | None


# ---------------------------------------------------------------- reconcile

def reconcile(d: Data) -> list[Device]:
    """One record per physical device: the inventory first, then Intune by name or serial, then Defender by Entra device id or name."""
    devices: list[Device] = []
    by_name: dict[str, Device] = {}
    by_serial: dict[str, Device] = {}
    for a in d.assets:
        dv = Device(a.device or a.serial, asset=a)
        devices.append(dv)
        if a.device:
            by_name[a.device] = dv
        if a.serial:
            by_serial[a.serial] = dv
    by_entra: dict[str, Device] = {}
    for m in sorted(d.managed, key=lambda m: m.last_sync or datetime.min, reverse=True):
        dv = (by_serial.get(m.serial) if m.serial else None) or by_name.get(m.device)
        if dv is None:
            dv = Device(m.device or m.serial)
            devices.append(dv)
            by_name.setdefault(dv.name, dv)
        if dv.managed is None:          # keep the most recent record when a device was enrolled twice
            dv.managed = m
        if m.entra_id:
            by_entra.setdefault(m.entra_id, dv)
    for s in sorted(d.sensors, key=lambda s: s.last_seen or datetime.min, reverse=True):
        dv = (by_entra.get(s.entra_id) if s.entra_id else None) or by_name.get(s.device)
        if dv is None:
            dv = Device(s.device or s.entra_id)
            devices.append(dv)
            by_name.setdefault(dv.name, dv)
        if dv.sensor is None:
            dv.sensor = s
    for dv in devices:
        dv.platform = (dv.asset.platform if dv.asset and dv.asset.platform else "") or \
            (dv.managed.platform if dv.managed else "") or (dv.sensor.platform if dv.sensor else "")
        if dv.platform not in ("windows", "macos"):
            dv.scope = "other platform"
        elif dv.asset and retired(dv.asset.status):
            dv.scope = "retired"
        elif dv.asset and not in_use(dv.asset.status):
            dv.scope = "stock"
        else:
            dv.scope = "in scope"
    return devices


def _recent(when, today: date, days: int) -> bool:
    return when is not None and (today - when.date()).days <= days


def active_somewhere(dv: Device, d: Data) -> bool:
    s = d.settings
    return bool((dv.managed and _recent(dv.managed.last_sync, d.today, s.checkin_days)) or
                (dv.sensor and _recent(dv.sensor.last_seen, d.today, s.sensor_days)))


# ---------------------------------------------------------------- controls

def exception_state(x: Exception_, today: date, warn: int) -> str:
    if not x.approver or not x.ticket or not x.expires:
        return "incomplete"
    if x.expires < today:
        return "expired"
    if (x.expires - today).days <= warn:
        return "expiring"
    return "valid"


def _admins_outside(accounts: list, allowed: list) -> list[str]:
    ok = {a.lower() for a in allowed}
    out = []
    for acc, _kind in accounts:
        short = acc.split("\\")[-1].lower()
        if acc.lower() in ok or short in ok or short.endswith("-500"):
            continue
        out.append(acc)
    return out


def evaluate(dv: Device, d: Data, has_av: bool) -> None:
    s, m, sn = d.settings, dv.managed, dv.sensor
    win = dv.platform == "windows"
    r = {}
    r["MDM"] = ("pass", "") if m else ("fail", "not enrolled in Intune")
    if not m:
        r["COMPLIANT"] = ("fail", "not managed")
        r["CHECKIN"] = ("fail", "not managed")
        r["ENCRYPTED"] = ("fail", "not managed: unknown")
    else:
        r["COMPLIANT"] = ("pass", "") if m.compliance == "compliant" else ("fail", {"grace": "in grace period", "noncompliant":
                                                                                   "noncompliant"}.get(m.compliance, "state unknown"))
        if _recent(m.last_sync, d.today, s.checkin_days):
            r["CHECKIN"] = ("pass", "")
        else:
            age = (d.today - m.last_sync.date()).days if m.last_sync else None
            r["CHECKIN"] = ("fail", f"last check-in {age} days ago" if age is not None else "never checked in")
        r["ENCRYPTED"] = ("pass", "") if m.encrypted else ("fail", "not encrypted" if m.encrypted is False else "encryption unknown")
    if win:
        if d.keys is None:
            r["KEY"] = ("unknown", "no recovery key export")
        elif not m or not m.encrypted:
            r["KEY"] = ("unknown", "not encrypted")
        else:
            r["KEY"] = ("pass", "") if m.entra_id in d.keys else ("fail", "no OS volume key in Entra ID")
    if not sn or not sn.onboarded:
        r["EDR"] = ("fail", "not onboarded" if sn else "not in Defender")
    elif sn.health != "active":
        r["EDR"] = ("fail", {"inactive": "sensor inactive", "impaired": "impaired communication", "nosensor": "no sensor data"}
                    .get(sn.health, "sensor health unknown"))
    elif not _recent(sn.last_seen, d.today, s.sensor_days):
        r["EDR"] = ("fail", "no report for more than " f"{s.sensor_days} days")
    else:
        r["EDR"] = ("pass", "")
    if win and has_av:
        if not m:
            r["AV"] = ("unknown", "not managed")
        else:
            bad = [t for t, ok in (("real-time off", m.realtime is not False), ("signatures overdue", m.signature_overdue is not True),
                                   ("tamper protection off", m.tamper is not False)) if not ok]
            r["AV"] = ("fail", ", ".join(bad)) if bad else ("pass", "")
    if win and d.admins is not None:
        if dv.name not in d.admins:
            r["ADMIN"] = ("unknown", "not reported")
        else:
            extra = _admins_outside(d.admins[dv.name], s.allowed_admins)
            r["ADMIN"] = ("fail", "local admin: " + ", ".join(extra)) if extra else ("pass", "")
    ver = m.os_version if m else ""
    if not ver:
        r["OS"] = ("unknown", "no OS version")
    else:
        need = os_build(s.min_os.get(dv.platform, ""))
        have = os_build(ver)
        if need and have < need:
            label = "Windows 10" if win and len(have) >= 3 and have[2] < 22000 else f"version {ver}"
            r["OS"] = ("fail", f"{label}, out of support" if win and "Windows 10" in label else f"{label} below {s.min_os.get(dv.platform)}")
        else:
            r["OS"] = ("pass", "")
    # exceptions
    for x in d.exceptions or []:
        if x.device == dv.name and x.control in r and r[x.control][0] == "fail":
            st = exception_state(x, d.today, s.exception_warning_days)
            if st in ("valid", "expiring"):
                r[x.control] = ("exception", f"exception {x.ticket} until {x.expires:%d %b %Y}: {r[x.control][1]}")
    dv.results = {c: r[c] for c in CONTROLS if c in r}


def coverage(devs: list[Device], control: str) -> tuple[int, int, float | None]:
    """covered, counted, % (exceptions count as covered; unknown is not counted)."""
    rows = [dv.results[control][0] for dv in devs if control in dv.results and dv.results[control][0] != "unknown"]
    ok = sum(1 for st in rows if st in ("pass", "exception"))
    return ok, len(rows), (100.0 * ok / len(rows) if rows else None)


def full(devs: list[Device]) -> tuple[int, int, float | None]:
    ok = sum(1 for dv in devs if dv.protected)
    return ok, len(devs), (100.0 * ok / len(devs) if devs else None)


def _by(devs: list[Device], attr: str) -> list:
    groups = defaultdict(list)
    for dv in devs:
        groups[getattr(dv, attr) or "(not in inventory)"].append(dv)
    return sorted(((k, full(v)) for k, v in groups.items()), key=lambda x: (x[1][2] if x[1][2] is not None else 101, x[0]))


# ---------------------------------------------------------------- findings

def _names(devs) -> list[str]:
    return sorted(dv.name for dv in devs)


def _top(counter: Counter, n: int = 3) -> str:
    return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n) if k)


def review(d: Data) -> dict:
    s = d.settings
    devices = reconcile(d)
    has_av = any(m.realtime is not None or m.tamper is not None for m in d.managed)
    scope = [dv for dv in devices if dv.scope == "in scope"]
    for dv in scope:
        evaluate(dv, d, has_av)
    due = {RED: d.today + timedelta(days=int(s.action_days.get("red", 7))),
           AMBER: d.today + timedelta(days=int(s.action_days.get("amber", 30)))}
    F: list[Finding] = []

    def add(sev, code, group, title, subject, detail, action, devs, owner):
        F.append(Finding(sev, code, group, title, subject, detail, action, devs, owner, due[sev]))

    def failing(control, cause_has=None):
        return [dv for dv in scope if dv.results.get(control, ("", ""))[0] == "fail" and
                (cause_has is None or cause_has in dv.results[control][1])]

    # inventory and sources
    x = failing("MDM")
    if x:
        add(RED, "INV-UNMANAGED", "inventory", "In use but not managed", f"{len(x)} devices in the inventory not enrolled in Intune",
            f"By site and department: {_top(Counter(f'{dv.site} {dv.department}'.strip() or 'not in the inventory' for dv in x))}. Not in Defender either: "
            f"{sum(1 for dv in x if dv.results['EDR'][0] == 'fail')}.",
            "Enrol them (Autopilot reset or manual enrolment) or block them from the network until they are.", _names(x),
            s.owner("MDM"))
    x = [dv for dv in scope if not dv.asset]
    if x:
        add(AMBER, "INV-UNKNOWN", "inventory", "Not in the inventory",
            f"{len(x)} devices in Intune or Defender that the inventory does not have",
            f"Seen in: {_top(Counter('Intune and Defender' if dv.managed and dv.sensor else 'Intune' if dv.managed else 'Defender' for dv in x))}.",
            "Add them to the inventory with owner and site, or retire them in Intune and Defender.", _names(x), s.owner("INVENTORY"))
    x = [dv for dv in devices if dv.scope == "retired" and active_somewhere(dv, d)]
    if x:
        add(AMBER, "INV-RETIRED", "inventory", "Retired but still active", f"{len(x)} retired devices still checking in",
            "Retired in the inventory, but checked in to Intune or reported to Defender in the review window.",
            "Find the device; wipe and retire it in Intune, offboard it in Defender, or correct the inventory.", _names(x),
            s.owner("INVENTORY"))
    # Defender
    x = [dv for dv in failing("EDR") if dv.results["EDR"][1] in ("not onboarded", "not in Defender") and dv.managed]
    if x:
        add(RED, "EDR-MISSING", "edr", "Managed but not onboarded", f"{len(x)} Intune devices not onboarded to Defender for Endpoint",
            f"Department: {_top(Counter(dv.department for dv in x))}. Check the onboarding policy assignment for these devices' groups.",
            "Assign the EDR onboarding policy to their group and confirm the sensor reports within 24 hours.", _names(x), s.owner("EDR"))
    x = [dv for dv in failing("EDR") if dv.results["EDR"][1] not in ("not onboarded", "not in Defender")]
    if x:
        add(AMBER, "EDR-UNHEALTHY", "edr", "Sensor not healthy", f"{len(x)} devices onboarded but not reporting properly",
            f"State: {_top(Counter(dv.results['EDR'][1] for dv in x))}.",
            "Contact the users; if the device is in use, fix the sensor (proxy, service, onboarding); if not, update the inventory.",
            _names(x), s.owner("EDR"))
    # encryption
    x = failing("ENCRYPTED", "not encrypted")
    if x:
        add(RED, "ENC-OFF", "encryption", "Not encrypted", f"{len(x)} devices without disk encryption",
            f"Platform: {_top(Counter(PLATFORM.get(dv.platform, dv.platform) for dv in x))}. Models: {_top(Counter(dv.asset.model if dv.asset else '' for dv in x))}.",
            "Resume or enable BitLocker / FileVault and confirm the key is escrowed; check why the encryption policy did not apply.",
            _names(x), s.owner("ENCRYPTED"))
    x = failing("KEY")
    if x:
        add(AMBER, "ENC-NOKEY", "encryption", "Recovery key not escrowed", f"{len(x)} encrypted Windows devices with no key in Entra ID",
            f"Department: {_top(Counter(dv.department for dv in x))}. Without the key, a locked device cannot be recovered by the "
            "service desk.", "Back up the key to Entra ID (BackupToAAD-BitLockerKeyProtector, or a remediation script) and re-check.",
            _names(x), s.owner("KEY"))
    # antivirus
    for code, cause, sev, title, act in (
            ("AV-REALTIME", "real-time off", RED, "Real-time protection off",
             "Turn real-time protection back on and replace the change with a scoped exclusion if an application needs one."),
            ("AV-SIGNATURES", "signatures overdue", AMBER, "Signatures out of date",
             "Check the update source and the device's connectivity; update the signatures."),
            ("AV-TAMPER", "tamper protection off", AMBER, "Tamper protection off",
             "Turn tamper protection on from Intune or the Defender portal for these devices.")):
        x = failing("AV", cause)
        if x:
            add(sev, code, "av", title, f"{len(x)} devices: {title.lower()}",
                f"Department: {_top(Counter(dv.department for dv in x))}.", act, _names(x), s.owner("AV"))
    # Intune
    x = failing("COMPLIANT")
    x = [dv for dv in x if dv.managed]
    if x:
        add(AMBER, "MDM-NONCOMPLIANT", "mdm", "Noncompliant", f"{len(x)} devices not compliant in Intune",
            f"State: {_top(Counter(dv.results['COMPLIANT'][1] for dv in x))}. Conditional Access blocks them from company data.",
            "Work the compliance reasons per device; most follow from the other findings.", _names(x), s.owner("COMPLIANT"))
    x = [dv for dv in failing("CHECKIN") if dv.managed]
    if x:
        add(AMBER, "MDM-CHECKIN", "mdm", "Not checking in", f"{len(x)} devices with no Intune check-in for more than {s.checkin_days} days",
            "Their compliance and settings are out of date.", "Contact the users; sync, or retire the device if it is no longer used.",
            _names(x), s.owner("CHECKIN"))
    # local admin and EPM
    x = failing("ADMIN")
    if x:
        accts = Counter(a for dv in x for a in dv.results["ADMIN"][1].replace("local admin: ", "").split(", "))
        add(RED, "PRIV-ADMIN", "privilege", "Standing local administrators", f"{len(x)} devices with local admins outside the approved list",
            f"Department: {_top(Counter(dv.department for dv in x))}. {len(accts)} accounts outside the approved list, for example "
            f"{', '.join(sorted(accts)[:2])}.",
            "Remove the accounts from the local Administrators group (account protection policy) and cover the need with EPM rules.",
            _names(x), s.owner("ADMIN"))
    rules, unsigned = epm(d)
    for f in rules:
        add(AMBER, "EPM-RULE", "privilege", "Candidate elevation rule",
            f"{f['file']}: elevated {f['count']} times by {f['users']} users",
            f"Publisher {f['publisher'] or 'none'}; {f['kind']}. Each elevation waits for the user or the service desk.",
            "Decide: an automatic rule for this file and publisher, or keep approval per request.", f["devices"], s.owner("EPM"))
    for f in unsigned:
        add(AMBER, "EPM-UNSIGNED", "privilege", "Unsigned file elevated", f"{f['file']}: unsigned, elevated {f['count']} times",
            f"By {f['users']} users on {len(f['devices'])} devices; no publisher, so a rule can only match the file hash.",
            "Confirm what the tool is and who needs it; sign it or allow it by hash with an owner, or block it.", f["devices"],
            s.owner("EPM"))
    # OS
    x = failing("OS")
    if x:
        add(RED, "OS-UNSUPPORTED", "os", "Unsupported operating system", f"{len(x)} devices on an unsupported OS version",
            f"{_top(Counter(dv.results['OS'][1] for dv in x))}. Department: {_top(Counter(dv.department for dv in x))}.",
            "Upgrade or replace them; for a device that cannot move yet, an exception with an approver, a ticket and an end date.",
            _names(x), s.owner("OS"))
    # exceptions
    exc = []
    for xx in d.exceptions or []:
        st = exception_state(xx, d.today, s.exception_warning_days)
        dv = next((v for v in scope if v.name == xx.device), None)
        still = bool(dv and dv.results.get(xx.control, ("", ""))[0] in ("fail", "exception"))
        exc.append({"exception": xx, "state": st if (still or st in ("valid", "expiring")) else "not needed",
                    "days": (xx.expires - d.today).days if xx.expires else None, "gap": still,
                    "action": {"expired": "Renew with approval or fix the device", "incomplete": "Add approver, ticket and expiry",
                               "expiring": "Plan the fix or the renewal before expiry", "valid": "", "not needed":
                               "Close the exception"}[st if (still or st in ("valid", "expiring")) else "not needed"]})
    for st, code, title in (("expired", "EXC-EXPIRED", "Exception expired"), ("incomplete", "EXC-INCOMPLETE", "Exception incomplete"),
                            ("expiring", "EXC-EXPIRING", "Exception expiring")):
        for e in [e for e in exc if e["state"] == st]:
            xx = e["exception"]
            sev = RED if st == "expired" and xx.control in HIGH else AMBER
            add(sev, code, "exceptions", title, f"{xx.device} · {CONTROLS.get(xx.control, (xx.control,))[0]}",
                f"{xx.reason or 'No reason'}; ticket {xx.ticket or 'none'}, approver {xx.approver or 'none'}, expiry "
                f"{xx.expires:%d %b %Y}." if xx.expires else f"{xx.reason or 'No reason'}; ticket {xx.ticket or 'none'}, approver "
                f"{xx.approver or 'none'}, no expiry.", e["action"] + ".", [xx.device], s.owner("EXCEPTIONS"))
    # coverage against target
    for c in CONTROLS:
        ok, n, pct = coverage(scope, c)
        if pct is None:
            continue
        t = s.target(c)
        if pct < t:
            sev = RED if pct < s.red_pct else AMBER
            add(sev, "CTL-TARGET", "coverage", "Below target", f"{CONTROLS[c][0]}: {pct:.1f} % (target {t:.0f} %)",
                f"{n - ok} of {n} devices not covered.", "Close the gaps listed under this control.",
                _names(dv for dv in scope if dv.results.get(c, ("", ""))[0] == "fail"), s.owner(c))
    order = {RED: 0, AMBER: 1}
    gorder = list(GROUPS)
    F.sort(key=lambda f: (order[f.severity], gorder.index(f.group), -f.count, f.subject))
    rv = {"devices": devices, "scope": scope, "findings": F, "exceptions": exc, "elevations": (rules, unsigned),
          "controls": {c: coverage(scope, c) for c in CONTROLS}, "full": full(scope), "sites": _by(scope, "site"),
          "departments": _by(scope, "department"), "platforms": _by(scope, "platform")}
    rv["decisions"] = decisions(d, rv, due)
    return rv


def epm(d: Data) -> tuple[list[dict], list[dict]]:
    """Files elevated with approval by many users (candidates for an automatic rule) and unsigned files elevated at all."""
    if not d.elevations:
        return [], []
    by = defaultdict(list)
    for e in d.elevations:
        by[e.file.lower()].append(e)
    rules, unsigned = [], []
    for _, es in by.items():
        ok = [e for e in es if "fail" not in e.result and "denied" not in e.result]
        if not ok:
            continue
        users = {e.user for e in ok}
        info = {"file": es[0].file, "publisher": es[0].publisher, "count": len(ok), "users": len(users),
                "devices": sorted({e.device for e in ok}), "kind": _top(Counter(e.kind for e in ok), 2)}
        if not es[0].publisher.strip():
            unsigned.append(info)
        elif len(users) >= d.settings.epm_rule_users and all("automatic" not in e.kind for e in ok):
            rules.append(info)
    rules.sort(key=lambda x: -x["count"])
    unsigned.sort(key=lambda x: -x["count"])
    return rules, unsigned


def decisions(d: Data, rv: dict, due: dict) -> list[Decision]:
    s, out = d.settings, []
    F = rv["findings"]

    def nd(sev):
        return due[sev]

    for f in [f for f in F if f.code == "OS-UNSUPPORTED"]:
        out.append(Decision("", f"{f.count} devices on an unsupported OS", f.detail,
                            "Upgrade in place · replace (hardware) · time-limited exception with paid extended updates",
                            "Upgrade what the hardware supports this month; exception only for devices tied to equipment, with an end date",
                            s.owner("OS"), nd(RED)))
    for f in [f for f in F if f.code == "PRIV-ADMIN"]:
        out.append(Decision("", f"Standing admin rights on {f.count} devices", f.detail,
                            "Remove now · remove after EPM rules are in place · accept with an exception",
                            "Create the EPM rules for the tools these users elevate, then remove the rights in one change",
                            s.owner("ADMIN"), nd(RED)))
    for f in [f for f in F if f.code == "EPM-RULE"]:
        out.append(Decision("", f"Automatic elevation for {f.subject.split(':')[0]}", f.subject + ". " + f.detail,
                            "Automatic rule (file and publisher) · keep user confirmation · keep support approval",
                            "Automatic rule scoped to the group that uses it, file name and publisher, reviewed in six months",
                            s.owner("EPM"), nd(AMBER)))
    for f in [f for f in F if f.code == "INV-UNMANAGED"]:
        out.append(Decision("", f"{f.count} unmanaged devices in use", f.detail,
                            "Enrol this week · block from the network until enrolled · exception for a stated reason",
                            "Enrol this week; block any device not enrolled by the due date", s.owner("MDM"), nd(RED)))
    for f in [f for f in F if f.code == "EXC-EXPIRED"]:
        out.append(Decision("", f"Expired exception: {f.subject}", f.detail, "Fix the device · renew with approval",
                            "Renew only with a new end date and an approver; otherwise fix", s.owner("EXCEPTIONS"),
                            nd(RED if f.severity == RED else AMBER)))
    for i, x in enumerate(out, 1):
        x.id = f"D{i}"
    return out


def summary(d: Data, rv: dict) -> dict:
    F = rv["findings"]
    ok, n, pct = rv["full"]
    red = sum(1 for f in F if f.severity == RED)
    amber = sum(1 for f in F if f.severity == AMBER)
    devs = rv["devices"]
    return {"status": RED if red else AMBER if amber else GREEN, "devices": len(devs), "scope": n, "protected": ok, "pct": pct,
            "prev_pct": (d.previous or {}).get("FULL"), "red": red, "amber": amber, "decisions": len(rv["decisions"]),
            "controls": {c: v[2] for c, v in rv["controls"].items()},
            "unmanaged": len([dv for dv in rv["scope"] if dv.results.get("MDM", ("",))[0] == "fail"]),
            "no_edr": len([dv for dv in rv["scope"] if dv.results.get("EDR", ("",))[0] == "fail"]),
            "unencrypted": len([dv for dv in rv["scope"] if dv.results.get("ENCRYPTED", ("",))[0] == "fail"]),
            "admins": len([dv for dv in rv["scope"] if dv.results.get("ADMIN", ("",))[0] == "fail"]),
            "unsupported": len([dv for dv in rv["scope"] if dv.results.get("OS", ("",))[0] == "fail"]),
            "unknown": len([dv for dv in rv["scope"] if not dv.asset]),
            "retired": len([dv for dv in devs if dv.scope == "retired"]), "other": len([dv for dv in devs if dv.scope == "other platform"]),
            "stock": len([dv for dv in devs if dv.scope == "stock"]),
            "exceptions": len(d.exceptions or []), "elevations": len(d.elevations or [])}


__all__ = ["review", "summary", "reconcile", "evaluate", "coverage", "full", "epm", "exception_state", "Device", "Finding",
           "Decision", "GROUPS", "RED", "AMBER", "GREEN"]
