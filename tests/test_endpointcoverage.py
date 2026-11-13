import csv
import json
from datetime import datetime
from pathlib import Path

import pytest

from endpointcoverage import report, simulate
from endpointcoverage.checks import RED, coverage, epm, exception_state, reconcile, review, summary
from endpointcoverage.cli import OUTPUTS, main, run
from endpointcoverage.model import (Settings, compliance, health, host, load, load_intune, load_inventory, os_build, parse_dt,
                                    platform, settings_from_dict)

AS_OF = datetime(2026, 11, 13, 9, 0)


def _csv(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _mini(tmp_path: Path, **extra) -> Path:
    """Three devices: one fine, one not in Intune, one with every gap; plus one only in Defender."""
    _csv(tmp_path / "inventory.csv", ["Device name", "Serial number", "OS", "Site", "Department", "Assigned to", "Status"],
         [["PC-OK", "S1", "Windows", "Madrid", "IT", "a@x.example", "In use"],
          ["PC-NOMDM", "S2", "Windows", "Madrid", "IT", "b@x.example", "In use"],
          ["PC-BAD", "S3", "Windows 11", "Bilbao", "Lab", "c@x.example", "Deployed"],
          ["PC-OLD", "S4", "Windows", "Bilbao", "Lab", "", "Retired"]])
    _csv(tmp_path / "intune.csv", ["Device name", "Serial number", "Entra device ID", "OS", "OS version", "Compliance", "Encrypted",
                                   "Last check-in", "realTimeProtectionEnabled", "signatureUpdateOverdue", "tamperProtectionEnabled"],
         [["PC-OK", "S1", "{AAAA-1}", "Windows", "10.0.26100.7171", "Compliant", "True", "2026-11-12T08:00:00Z", "true", "false", "true"],
          ["PC-BAD", "S3", "bbbb-3", "Windows", "10.0.19045.6456", "noncompliant", "False", "2026-10-01 10:00", "false", "true", "false"],
          ["PC-OLD", "S4", "dddd-4", "Windows", "10.0.26100.7171", "Compliant", "True", "2026-11-10", "true", "false", "true"]])
    _csv(tmp_path / "defender.csv", ["Device Name", "Aad Device Id", "Onboarding Status", "Health Status", "Last Seen", "OS Platform"],
         [["pc-ok.x.example", "aaaa-1", "Onboarded", "Active", "2026-11-13T01:00:00Z", "Windows11"],
          ["pc-bad.x.example", "bbbb-3", "Onboarded", "Inactive", "2026-10-20T01:00:00Z", "Windows10"],
          ["ghost-01.x.example", "", "Onboarded", "Active", "2026-11-12T01:00:00Z", "Windows11"]])
    _csv(tmp_path / "recovery-keys.csv", ["id", "deviceId", "volumeType", "createdDateTime"], [["k1", "aaaa-1", "1", "2025-01-01"]])
    _csv(tmp_path / "local-admins.csv", ["Device", "Account", "Type"],
         [["PC-OK", "PC-OK\\Administrator", "User"], ["PC-BAD", "X\\Domain Admins", "Group"], ["PC-BAD", "X\\c.user", "User"]])
    (tmp_path / "settings.json").write_text(json.dumps({"organisation": "Test", "review_date": "2026-11-13 09:00", **extra}))
    return tmp_path


def _dev(rv, name):
    return next(dv for dv in rv["devices"] if dv.name == name)


def test_parsers():
    assert host("tsa-mad-l0001.tailspin.example") == "TSA-MAD-L0001"
    assert platform("Windows 11 Enterprise") == "windows" and platform("macOS") == "macos" and platform("iOS") == "ios"
    assert compliance("inGracePeriod") == "grace" and compliance("Compliant") == "compliant" and compliance("") == "unknown"
    assert health("NoSensorDataImpairedCommunication") == "nosensor" and health("ImpairedCommunication") == "impaired"
    assert os_build("10.0.19045.6456") < os_build("10.0.22631") <= os_build("10.0.26100.1")
    assert parse_dt("2026-11-12T08:00:00.123Z") == datetime(2026, 11, 12, 8, 0)


def test_loaders_accept_other_column_names(tmp_path):
    d = load(_mini(tmp_path))
    assert [a.device for a in d.assets] == ["PC-OK", "PC-NOMDM", "PC-BAD", "PC-OLD"]
    m = {x.device: x for x in d.managed}
    assert m["PC-OK"].entra_id == "aaaa-1" and m["PC-OK"].encrypted is True and m["PC-BAD"].realtime is False
    assert d.keys == {"aaaa-1"} and len(d.admins["PC-BAD"]) == 2
    assert d.as_of == AS_OF


def test_reconcile_by_serial_name_and_entra_id(tmp_path):
    d = load(_mini(tmp_path))
    devs = {dv.name: dv for dv in reconcile(d)}
    assert devs["PC-OK"].managed and devs["PC-OK"].sensor          # Defender matched by Entra device id
    assert devs["PC-NOMDM"].managed is None and devs["PC-NOMDM"].sensor is None
    assert devs["GHOST-01"].asset is None and devs["GHOST-01"].scope == "in scope"
    assert devs["PC-OLD"].scope == "retired"


def test_controls_on_each_device(tmp_path):
    rv = review(load(_mini(tmp_path)))
    ok = _dev(rv, "PC-OK")
    assert ok.protected and set(ok.results) == {"MDM", "COMPLIANT", "CHECKIN", "ENCRYPTED", "KEY", "EDR", "AV", "ADMIN", "OS"}
    bad = _dev(rv, "PC-BAD").results
    assert bad["ENCRYPTED"] == ("fail", "not encrypted")
    assert bad["KEY"][0] == "unknown"                                # not encrypted: no key to look for
    assert bad["EDR"] == ("fail", "sensor inactive")
    assert bad["AV"] == ("fail", "real-time off, signatures overdue, tamper protection off")
    assert bad["ADMIN"] == ("fail", "local admin: X\\c.user")
    assert bad["OS"][0] == "fail" and "Windows 10" in bad["OS"][1]
    assert bad["CHECKIN"][0] == "fail"
    nomdm = _dev(rv, "PC-NOMDM").results
    assert nomdm["MDM"][0] == "fail" and nomdm["EDR"] == ("fail", "not in Defender") and nomdm["ADMIN"][0] == "unknown"


def test_coverage_ignores_unknown_and_counts_exceptions(tmp_path):
    folder = _mini(tmp_path)
    _csv(folder / "exceptions.csv", ["Device", "Control", "Reason", "Approver", "Ticket", "Expires"],
         [["PC-BAD", "OS", "Lab equipment", "CISO", "RSK-1", "2027-06-30"]])
    rv = review(load(folder))
    assert _dev(rv, "PC-BAD").results["OS"][0] == "exception"
    ok, n, pct = coverage(rv["scope"], "OS")
    assert (ok, n) == (2, 2)                                         # PC-NOMDM has no OS version: not counted
    ok, n, _ = coverage(rv["scope"], "ADMIN")
    assert (ok, n) == (1, 2)


def test_exception_states():
    from endpointcoverage.model import Exception_
    today = AS_OF.date()
    assert exception_state(Exception_("A", "OS", "r", "x", "t", today.replace(year=2027)), today, 30) == "valid"
    assert exception_state(Exception_("A", "OS", "r", "x", "t", today.replace(day=30)), today, 30) == "expiring"
    assert exception_state(Exception_("A", "OS", "r", "x", "t", today.replace(day=1)), today, 30) == "expired"
    assert exception_state(Exception_("A", "OS", "r", "", "t", today.replace(year=2027)), today, 30) == "incomplete"


def test_expired_exception_does_not_count_and_is_red(tmp_path):
    folder = _mini(tmp_path)
    _csv(folder / "exceptions.csv", ["Device", "Control", "Reason", "Approver", "Ticket", "Expires"],
         [["PC-BAD", "OS", "Lab equipment", "CISO", "RSK-1", "2026-10-31"]])
    rv = review(load(folder))
    assert _dev(rv, "PC-BAD").results["OS"][0] == "fail"
    f = next(f for f in rv["findings"] if f.code == "EXC-EXPIRED")
    assert f.severity == RED and f.devices == ["PC-BAD"]


def test_findings_for_the_mini_estate(tmp_path):
    rv = review(load(_mini(tmp_path)))
    codes = {f.code for f in rv["findings"]}
    assert {"INV-UNMANAGED", "INV-UNKNOWN", "INV-RETIRED", "ENC-OFF", "AV-REALTIME", "PRIV-ADMIN", "OS-UNSUPPORTED",
            "EDR-UNHEALTHY", "MDM-CHECKIN"} <= codes
    assert "EDR-MISSING" not in codes                                  # PC-NOMDM is unmanaged, reported there
    assert summary(load(_mini(tmp_path)), rv)["status"] == RED


def test_epm_candidate_rules_and_unsigned(tmp_path):
    folder = _mini(tmp_path, epm_rule_users=3)
    rows = [[f"PC-{i}", f"u{i}@x", "Tool.exe", "Vendor Ltd", "Support approved", "Success", "2026-11-01 10:00"] for i in range(4)]
    rows += [["PC-9", "u9@x", "flash.exe", "", "User confirmed", "Success", "2026-11-02 10:00"],
             ["PC-8", "u8@x", "Printer.exe", "IT", "Automatic", "Success", "2026-11-02 10:00"]]
    rows += [[f"PC-{i}", f"u{i}@x", "Printer.exe", "IT", "Automatic", "Success", "2026-11-02 10:00"] for i in range(5)]
    _csv(folder / "epm-elevations.csv", ["Device", "User", "File name", "Publisher", "Elevation type", "Result", "Date"], rows)
    d = load(folder)
    rules, unsigned = epm(d)
    assert [r["file"] for r in rules] == ["Tool.exe"] and rules[0]["users"] == 4
    assert [u["file"] for u in unsigned] == ["flash.exe"]


def test_settings_from_dict():
    s = settings_from_dict({"target_pct": "97", "targets": {"EDR": 100}, "checkin_days": "21", "min_os": {"windows": "10.0.26100"},
                            "allowed_admins": ["Administrator"], "unknown_key": 1})
    assert s.target("EDR") == 100 and s.target("OS") == 97 and s.checkin_days == 21 and s.min_os["macos"] == "14.0"
    assert s.allowed_admins == ["Administrator"] and isinstance(Settings().owner("EDR"), str)


def test_missing_required_file(tmp_path):
    _mini(tmp_path)
    (tmp_path / "defender.csv").unlink()
    with pytest.raises(FileNotFoundError, match="defender.csv"):
        load(tmp_path)
    assert main(["review", str(tmp_path), "--out", str(tmp_path / "o")]) == 2


def test_demo_numbers(tmp_path):
    simulate.write(tmp_path / "data")
    sm = run(tmp_path / "data", tmp_path / "out")
    assert sm["status"] == RED and sm["scope"] == 368
    assert round(sm["pct"], 1) == 76.9 and sm["prev_pct"] == 93.2
    assert (sm["unmanaged"], sm["unsupported"], sm["admins"], sm["unknown"]) == (11, 11, 14, 5)
    rv = review(load(tmp_path / "data"))
    f = {x.code: x for x in rv["findings"]}
    assert f["EDR-MISSING"].count == 6 and f["ENC-OFF"].count == 3 and f["ENC-NOKEY"].count == 11
    assert f["EPM-RULE"].subject.startswith("AeroCAD_Setup.exe: elevated 37 times by 12 users")
    assert f["EXC-EXPIRED"].devices == ["TSA-BIO-L0098"] and f["EXC-INCOMPLETE"].count == 1
    assert [x.id for x in rv["decisions"]] == ["D1", "D2", "D3", "D4", "D5"]


def test_demo_is_deterministic(tmp_path):
    simulate.write(tmp_path / "a")
    simulate.write(tmp_path / "b")
    for f in ("inventory.csv", "intune.csv", "defender.csv", "epm-elevations.csv"):
        assert (tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()


def test_outputs_and_next_months_previous(tmp_path):
    simulate.write(tmp_path / "data")
    run(tmp_path / "data", tmp_path / "out")
    for f in OUTPUTS:
        assert (tmp_path / "out" / f).stat().st_size > 0
    html = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert "<script" not in html and "Fully protected" in html and "AeroCAD_Setup.exe" in html
    pack = (tmp_path / "out" / "review-pack.md").read_text(encoding="utf-8")
    assert "## Decisions needed" in pack and "[TO COMPLETE]" in pack
    # this month's coverage-summary.csv is next month's previous-coverage.csv
    (tmp_path / "out" / "coverage-summary.csv").replace(tmp_path / "data" / "previous-coverage.csv")
    sm = run(tmp_path / "data", tmp_path / "out2")
    assert round(sm["prev_pct"], 1) == round(sm["pct"], 1)
    gaps = list(csv.DictReader(open(tmp_path / "out" / "gaps.csv", encoding="utf-8")))
    assert any(g["control"] == "OS" and g["status"] == "exception" for g in gaps)
    assert report.coverage_rows(review(load(tmp_path / "data")))[0][0] == "FULL"


def test_intune_export_with_portal_columns(tmp_path):
    _csv(tmp_path / "i.csv", ["Device name", "Serial number", "Microsoft Entra Device ID", "OS", "OS version", "Compliance",
                              "Encrypted", "Last check-in", "Primary user UPN"],
         [["LAP-1", "x1", "ID-1", "Windows", "10.0.26100.1", "Compliant", "Yes", "13/11/2026 08:00", "a@b"]])
    m = load_intune(tmp_path / "i.csv")[0]
    assert (m.device, m.serial, m.entra_id, m.encrypted, m.user) == ("LAP-1", "X1", "id-1", True, "a@b")
    assert m.last_sync == datetime(2026, 11, 13, 8, 0) and m.realtime is None
    _csv(tmp_path / "inv.csv", ["Hostname", "Serial", "Platform"], [["LAP-1", "x1", "Windows"], ["LAP-1", "x1", "Windows"]])
    assert len(load_inventory(tmp_path / "inv.csv")) == 1
