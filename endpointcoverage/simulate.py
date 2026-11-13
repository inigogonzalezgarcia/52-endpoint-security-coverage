"""Deterministic demo data: Tailspin Aerospace, a made-up maker of drone and avionics parts with two sites (Madrid and Bilbao), about
400 laptops, workstations and Macs in the asset inventory, managed with Intune and protected with Defender for Endpoint. The review runs
on Friday 13 November 2026; the previous one was on 13 October. The problems are placed on purpose among devices that are fine:

- 9 flight test laptops in Bilbao built locally by the field team and never enrolled in Intune (or onboarded to Defender);
- 6 new engineering workstations in Intune but not onboarded to Defender (their group is not in the onboarding policy);
- 4 Defender sensors not healthy (inactive, impaired communication, no sensor data);
- 3 devices not encrypted (BitLocker suspended after a firmware update and never resumed; a Mac with FileVault off);
- 11 production laptops encrypted by the old imaging process, with no recovery key in Entra ID;
- real-time protection turned off on 2 CAD workstations, signatures overdue on 7 test bench laptops, tamper protection off on 5;
- 14 engineering users left in the local Administrators group after a CAD tool rollout;
- the CAD installer elevated 37 times by 12 users with service desk approval, and an unsigned avionics flashing tool elevated;
- 12 Windows 10 devices on the production floor and in the lab (3 under a valid exception, 1 whose exception expired), and 2 Macs
  below the minimum macOS version;
- 5 devices that the inventory does not have, and 2 retired laptops still checking in;
- 6 laptops with no Intune check-in for more than two weeks, and an exception with no approver.
"""
from __future__ import annotations

import csv
import json
import random
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path

ORG = "Tailspin Aerospace"
AS_OF = datetime(2026, 11, 13, 9, 0)
PREVIOUS = date(2026, 10, 13)
SEED = 52
DOMAIN = "tailspin-aero.example"
FIRST = ["Lucía", "Javier", "Marta", "Carlos", "Elena", "Pablo", "Ane", "Iker", "Sara", "Daniel", "Laura", "Mikel", "Paula", "Jorge",
         "Nerea", "Álvaro", "Irene", "Unai", "Clara", "Sergio", "Leire", "Hugo", "Andrea", "Rubén", "Maite", "Óscar", "Julia", "Asier",
         "Carmen", "Diego", "Alba", "Adrián", "Eider", "Raúl", "Noelia", "Gorka"]
LAST = ["Moreno", "Ruiz", "Etxeberria", "Navarro", "Iglesias", "Ortega", "Aguirre", "Castro", "Romero", "Zubiri", "Delgado", "Vidal",
        "Garmendia", "Herrera", "Molina", "Arana", "Serrano", "Ibarra", "Prieto", "Lozano", "Urrutia", "Cabrera", "Campos", "Larrea"]
# (department, site, kind, count): kind L laptop, W workstation, M Mac
FLEET = [("Engineering", "Madrid", "L", 70), ("Engineering", "Madrid", "W", 24), ("Flight test", "Bilbao", "L", 34),
         ("Production", "Bilbao", "L", 46), ("Production", "Bilbao", "W", 20), ("Quality", "Bilbao", "L", 26),
         ("Programmes", "Madrid", "L", 38), ("Finance", "Madrid", "L", 22), ("People", "Madrid", "L", 14),
         ("Sales", "Madrid", "L", 24), ("IT", "Madrid", "L", 12), ("Design", "Madrid", "M", 30), ("Marketing", "Madrid", "M", 8)]
MODELS = {"L": ["Latitude 7450", "Latitude 5550", "EliteBook 840 G11"], "W": ["Precision 3680", "Precision 5860"],
          "M": ["MacBook Pro 14", "MacBook Air 13"]}
ALLOWED = ["{dev}\\Administrator", "TAILSPIN\\Domain Admins", "TAILSPIN\\Device administrators"]


def _dt(x: datetime) -> str:
    return x.strftime("%Y-%m-%dT%H:%M:%SZ")


def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def build() -> dict:
    rng = random.Random(SEED)
    ids = random.Random(SEED + 1)

    def gid() -> str:
        return str(uuid.UUID(int=ids.getrandbits(128), version=4))

    used = set()

    def person() -> tuple[str, str]:
        while True:
            f, l1, l2 = rng.choice(FIRST), rng.choice(LAST), rng.choice(LAST)
            upn = (f"{f}.{l1}".lower().translate(str.maketrans("áéíóúñ", "aeioun")) + f"@{DOMAIN}")
            if upn not in used:
                used.add(upn)
                return f"{f} {l1} {l2}", upn

    devs = []
    n = {"Madrid": {"L": 0, "W": 0, "M": 0}, "Bilbao": {"L": 0, "W": 0, "M": 0}}
    for dept, site, kind, count in FLEET:
        for _ in range(count):
            n[site][kind] += 1
            code = "MAD" if site == "Madrid" else "BIO"
            name = f"TSA-{code}-{kind}{n[site][kind]:04d}"
            _, upn = person()
            mac = kind == "M"
            devs.append({"device": name, "serial": ("C02" if mac else "TS") + f"{ids.getrandbits(32):08X}"[:8], "kind": kind,
                         "platform": "macOS" if mac else "Windows", "model": rng.choice(MODELS[kind]), "site": site, "dept": dept,
                         "user": upn, "status": "In use", "entra": gid(), "os": rng.choice(["15.1", "15.0.1", "14.7.1"]) if mac else
                         rng.choice(["10.0.26100.7171", "10.0.26100.7019", "10.0.22631.6199"]), "compliance": "compliant",
                         "encrypted": True, "sync": AS_OF - timedelta(hours=rng.randint(1, 70)), "realtime": True, "sig_overdue": False,
                         "tamper": True, "intune": True, "defender": True, "health": "Active", "seen": AS_OF - timedelta(hours=rng.randint(1, 30)),
                         "key": not mac, "admins": [], "reported": not mac, "asset": True})
    by = {d["device"]: d for d in devs}

    def pick(dept: str, kind: str, k: int, site: str | None = None, skip: set | None = None) -> list[dict]:
        pool = [d for d in devs if d["dept"] == dept and d["kind"] == kind and (site is None or d["site"] == site)
                and d["device"] not in (skip or set()) and d["intune"] and d["status"] == "In use"]
        return pool[-k:] if k else []

    taken: set = set()

    def take(lst):
        for d in lst:
            taken.add(d["device"])
        return lst

    # 1 · flight test laptops built locally: not in Intune, not in Defender
    for d in take(pick("Flight test", "L", 9)):
        d.update(intune=False, defender=False, key=False, reported=False)
    # 2 · new engineering workstations not onboarded to Defender
    for d in take(pick("Engineering", "W", 6, skip=taken)):
        d.update(defender=False)
    # 3 · sensors not healthy
    for d, (h, days) in zip(take(pick("Sales", "L", 4, skip=taken)), [("Inactive", 12), ("Inactive", 20),
                                                                     ("ImpairedCommunication", 2), ("NoSensorData", 1)]):
        d.update(health=h, seen=AS_OF - timedelta(days=days))
    # 4 · not encrypted
    for d in take(pick("Programmes", "L", 2, skip=taken)) + take(pick("Design", "M", 1, skip=taken)):
        d.update(encrypted=False, key=False, compliance="noncompliant")
    # 5 · encrypted, no key in Entra ID
    for d in take(pick("Production", "L", 11, skip=taken)):
        d.update(key=False)
    # 6 · antivirus
    for d in take(pick("Engineering", "W", 2, skip=taken)):
        d.update(realtime=False, compliance="noncompliant")
    for d in take(pick("Flight test", "L", 7, skip=taken)):
        d.update(sig_overdue=True, compliance="noncompliant")
    for d in take(pick("Quality", "L", 5, skip=taken)):
        d.update(tamper=False)
    # 7 · standing local admins after the CAD tool rollout
    eng = [d for d in devs if d["dept"] == "Engineering" and d["kind"] == "L" and d["device"] not in taken][:14]
    for d in take(eng):
        d["admins"] = ["TAILSPIN\\" + d["user"].split("@")[0]]
    # 8 · Windows 10 on the production floor and in the lab
    w10 = take(pick("Production", "W", 8, skip=taken)) + take(pick("Quality", "L", 4, skip=taken))
    for d in w10:
        d.update(os="10.0.19045.6456", compliance="noncompliant")
    for d in take(pick("Design", "M", 2, skip=taken)):
        d.update(os="13.7.1", compliance="noncompliant")
    bench = by["TSA-BIO-W0012"]          # isolated test bench: no Defender, under an exception
    taken.add(bench["device"])
    bench.update(defender=False)
    # 9 · not checking in
    for d, days in zip(take(pick("Finance", "L", 6, skip=taken)), [18, 22, 25, 31, 36, 44]):
        d.update(sync=AS_OF - timedelta(days=days), seen=AS_OF - timedelta(days=days - 1), health="Inactive",
                 compliance="noncompliant" if days > 30 else "compliant")
    for d in take(pick("People", "L", 2, skip=taken)):
        d.update(compliance="inGracePeriod")
    # 10 · not in the inventory; retired but active; stock; phones
    extra = []
    for i, (code, kind, intune, defender) in enumerate([("MAD", "L", True, True), ("MAD", "L", True, True), ("BIO", "W", True, True),
                                                       ("BIO", "W", False, True), ("MAD", "L", False, True)]):
        _, upn = person()
        nm = f"TSA-{code}-{kind}{9001 + i:04d}" if intune else f"DESKTOP-{ids.getrandbits(28):07X}"
        extra.append({"device": nm, "serial": f"TS{ids.getrandbits(32):08X}", "kind": kind, "platform": "Windows",
                      "model": "Latitude 5550" if kind == "L" else "Precision 3680", "site": "", "dept": "", "user": upn if intune else "",
                      "status": "", "entra": gid(), "os": "10.0.26100.7171", "compliance": "compliant" if intune else "unknown",
                      "encrypted": True, "sync": AS_OF - timedelta(hours=rng.randint(2, 60)), "realtime": True, "sig_overdue": False,
                      "tamper": True, "intune": intune, "defender": defender, "health": "Active",
                      "seen": AS_OF - timedelta(hours=rng.randint(2, 40)), "key": intune, "admins": [], "reported": intune,
                      "asset": False})
    for d in pick("Sales", "L", 2, skip=taken):
        taken.add(d["device"])
        d.update(status="Retired", sync=AS_OF - timedelta(days=3), seen=AS_OF - timedelta(days=2))
    for d in pick("IT", "L", 3, skip=taken):
        taken.add(d["device"])
        d.update(status="In stock", intune=False, defender=False, key=False, reported=False)
    phones = []
    for i in range(14):
        _, upn = person()
        phones.append([f"iPhone-{i + 1:02d}", f"F{ids.getrandbits(40):010X}", gid(), "iOS", "18.1", "compliant", "true",
                       _dt(AS_OF - timedelta(hours=rng.randint(1, 48))), upn, "company", "", "", ""])
    # a few Windows devices whose local admin report never arrived
    for d in [x for x in devs if x["kind"] == "L" and x["dept"] == "Programmes" and x["device"] not in taken][:5]:
        d["reported"] = False
    exceptions = [
        [w10[0]["device"], "OS", "CNC cell controller software certified on Windows 10 only; paid extended updates", "M. Arana (COO)",
         "RSK-2026-031", "2027-10-13"],
        [w10[1]["device"], "OS", "CNC cell controller software certified on Windows 10 only; paid extended updates", "M. Arana (COO)",
         "RSK-2026-031", "2027-10-13"],
        [w10[2]["device"], "OS", "Coordinate measuring machine PC, vendor upgrade in Q1 2027", "M. Arana (COO)", "RSK-2026-034", "2027-03-31"],
        [w10[8]["device"], "OS", "Lab spectrometer PC, replacement ordered", "P. Herrera (Quality)", "RSK-2026-012", "2026-10-31"],
        [eng[0]["device"], "ADMIN", "Needs admin to install CAD plug-ins", "", "REQ-48121", "2027-01-31"],
        ["TSA-BIO-W0012", "EDR", "Isolated test bench, no internet by design; monitored by the bench owner", "I. Zubiri (CISO)",
         "RSK-2026-027", "2026-12-04"],
    ]
    return {"devs": devs, "extra": extra, "phones": phones, "exceptions": exceptions, "by": by}


def write(folder: Path) -> None:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    b = build()
    devs, extra = b["devs"], b["extra"]
    rng = random.Random(SEED + 2)
    _w(folder / "inventory.csv", ["AssetTag", "DeviceName", "SerialNumber", "Platform", "Model", "Site", "Department", "AssignedTo", "Status"],
       [[f"TSA-{i:05d}", d["device"], d["serial"], d["platform"], d["model"], d["site"], d["dept"], d["user"], d["status"]]
        for i, d in enumerate(devs, 10001)] +
       [[f"TSA-{20001 + i:05d}", f"iPhone-{i + 1:02d}", p[1], "iOS", "iPhone 15", "Madrid", "Sales", p[8], "In use"]
        for i, p in enumerate(b["phones"][:10])])
    _w(folder / "intune.csv", ["deviceName", "serialNumber", "azureADDeviceId", "operatingSystem", "osVersion", "complianceState",
                               "isEncrypted", "lastSyncDateTime", "userPrincipalName", "managedDeviceOwnerType",
                               "realTimeProtectionEnabled", "signatureUpdateOverdue", "tamperProtectionEnabled"],
       [[d["device"], d["serial"], d["entra"], d["platform"], d["os"], d["compliance"], str(d["encrypted"]).lower(), _dt(d["sync"]),
         d["user"], "company", *([str(d["realtime"]).lower(), str(d["sig_overdue"]).lower(), str(d["tamper"]).lower()]
                                 if d["platform"] == "Windows" else ["", "", ""])]
        for d in devs + extra if d["intune"]] + b["phones"])
    plat = {"Windows": lambda d: "Windows10" if d["os"].startswith("10.0.19") else "Windows11", "macOS": lambda d: "macOS"}
    _w(folder / "defender.csv", ["computerDnsName", "aadDeviceId", "osPlatform", "onboardingStatus", "healthStatus", "lastSeen",
                                 "exposureLevel"],
       [[f"{d['device'].lower()}.{DOMAIN}", d["entra"] if d["intune"] else "", plat[d["platform"]](d), "Onboarded", d["health"],
         _dt(d["seen"]), rng.choice(["Low", "Low", "Medium"])] for d in devs + extra if d["defender"]] +
       [[f"{d['device'].lower()}.{DOMAIN}", d["entra"], plat[d["platform"]](d), "CanBeOnboarded", "Inactive", "", ""]
        for d in devs if d["intune"] and not d["defender"]][:4])
    keys = []
    for d in devs + extra:
        if d["platform"] == "Windows" and d["intune"] and d["encrypted"] and d["key"]:
            created = d["sync"] - timedelta(days=rng.randint(30, 600))
            keys.append([str(uuid.UUID(int=rng.getrandbits(128), version=4)), d["entra"], "1", _dt(created)])
            if d["kind"] == "W" and rng.random() < 0.4:
                keys.append([str(uuid.UUID(int=rng.getrandbits(128), version=4)), d["entra"], "2", _dt(created)])
    _w(folder / "recovery-keys.csv", ["id", "deviceId", "volumeType", "createdDateTime"], keys)
    admins = []
    for d in devs + extra:
        if d["platform"] != "Windows" or not d["reported"]:
            continue
        for a in ALLOWED + d["admins"]:
            acc = a.format(dev=d["device"])
            admins.append([d["device"], acc, "Group" if a.endswith(("Admins", "administrators")) else "User",
                           _dt(AS_OF - timedelta(hours=rng.randint(2, 40)))])
    _w(folder / "local-admins.csv", ["Device", "Account", "Type", "Reported"], admins)
    # EPM elevation report, last 30 days
    eng = [d for d in devs if d["dept"] == "Engineering"]
    elev = []

    def ev(d, file, pub, kind, n=1):
        for _ in range(n):
            when = AS_OF - timedelta(days=rng.randint(0, 29), hours=rng.randint(0, 9), minutes=rng.randint(0, 59))
            elev.append([d["device"], d["user"], file, pub, kind, "Success", when.strftime("%Y-%m-%d %H:%M")])

    cad_users = [d for d in eng if not d["admins"]][:12]
    counts = [5, 5, 4, 4, 3, 3, 3, 3, 2, 2, 2, 1]
    for d, k in zip(cad_users, counts):
        ev(d, "AeroCAD_Setup.exe", "AeroCAD Systems Ltd", "Support approved", k)
    ft = [d for d in devs if d["dept"] == "Flight test" and d["intune"]][:3]
    for d, k in zip(ft, [2, 1, 1]):
        ev(d, "avionics-flasher.exe", "", "User confirmed", k)
    for d in rng.sample([x for x in devs if x["platform"] == "Windows" and x["intune"]], 40):
        ev(d, "PrinterDriverInstaller.exe", "Tailspin Aerospace IT", "Automatic")
    for d in rng.sample(eng, 4):
        ev(d, "DataLoggerTool.exe", "Sensotec Instruments", "User confirmed")
    elev.sort(key=lambda r: r[6])
    _w(folder / "epm-elevations.csv", ["Device", "User", "File name", "Publisher", "Elevation type", "Result", "Date"], elev)
    _w(folder / "exceptions.csv", ["Device", "Control", "Reason", "Approver", "Ticket", "Expires"], b["exceptions"])
    _w(folder / "previous-coverage.csv", ["control", "name", "covered", "devices", "coverage_pct"],
       [["FULL", "Fully protected", 341, 366, "93.2"], ["MDM", "Managed in Intune", 365, 366, "99.7"],
        ["COMPLIANT", "Compliant in Intune", 352, 366, "96.2"], ["CHECKIN", "Checked in recently", 362, 366, "98.9"],
        ["ENCRYPTED", "Disk encrypted (BitLocker / FileVault)", 364, 366, "99.5"],
        ["KEY", "BitLocker recovery key in Entra ID", 309, 313, "98.7"],
        ["EDR", "Onboarded and active in Defender for Endpoint", 363, 366, "99.2"],
        ["AV", "Antivirus healthy (real-time, signatures, tamper)", 312, 317, "98.4"],
        ["ADMIN", "No standing local administrators", 311, 313, "99.4"], ["OS", "Supported operating system", 354, 360, "98.3"]])
    (folder / "settings.json").write_text(json.dumps({
        "organisation": ORG, "review_date": AS_OF.strftime("%Y-%m-%d %H:%M"), "previous_review": PREVIOUS.isoformat(),
        "target_pct": 98, "red_pct": 90, "targets": {"EDR": 99, "ENCRYPTED": 99, "MDM": 99},
        "checkin_days": 14, "sensor_days": 7, "exception_warning_days": 30,
        "min_os": {"windows": "10.0.22631", "macos": "14.0"},
        "allowed_admins": ["Administrator", "Domain Admins", "Device administrators"], "epm_rule_users": 5,
        "action_days": {"red": 7, "amber": 30},
        "owners": {"MDM": "Endpoint team (M. Castro)", "EDR": "Security operations (A. Larrea)", "AV": "Security operations (A. Larrea)",
                   "ADMIN": "Endpoint team (M. Castro)", "EPM": "Endpoint team (M. Castro)", "OS": "Endpoint team (M. Castro)",
                   "ENCRYPTED": "Endpoint team (M. Castro)", "KEY": "Endpoint team (M. Castro)", "CHECKIN": "Service desk",
                   "COMPLIANT": "Endpoint team (M. Castro)", "INVENTORY": "IT asset manager (R. Vidal)",
                   "EXCEPTIONS": "Security risk manager (I. Zubiri)", "COVERAGE": "Head of IT (S. Prieto)"}},
        indent=2) + "\n", encoding="utf-8")


__all__ = ["write", "build", "ORG", "AS_OF"]
