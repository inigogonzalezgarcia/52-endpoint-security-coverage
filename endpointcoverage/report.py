"""Outputs: report.html (tiles, decisions, coverage per control against target and last month, coverage by site, department and
platform, a heat map of departments by control, the reconciliation of the three sources, EPM elevations, exceptions and every finding),
review-pack.md (one page for the monthly endpoint security review), and the CSVs: device-coverage, gaps, reconciliation,
coverage-summary (next month's previous-coverage.csv), elevations-review, exceptions-review, findings and actions."""
from __future__ import annotations

import csv
import html
from collections import defaultdict
from pathlib import Path

from .checks import GROUPS, RED, coverage, full, summary
from .model import CONTROLS, FILES, Data

e = html.escape
TODO = "**[TO COMPLETE]**"


def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _d(x) -> str:
    return "" if x is None else x.isoformat()


def _day(x) -> str:
    return "–" if x is None else f"{x:%d %b %Y}"


def _p(x) -> str:
    return "–" if x is None else f"{x:.1f} %"


def _f(x) -> str:
    return "" if x is None else f"{x:.1f}"


def _ts(x) -> str:
    return "" if x is None else x.strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------- csv

def write_devices(rv: dict, path: Path) -> None:
    head = ["device", "site", "department", "user", "platform", "model", "os_version", "in_inventory", "in_intune", "in_defender",
            "fully_protected", "gaps", "risk_score"] + [c.lower() for c in CONTROLS]
    rows = []
    for dv in sorted(rv["scope"], key=lambda v: (-v.risk, v.name)):
        rows.append([dv.name, dv.site, dv.department, dv.user, dv.platform, dv.asset.model if dv.asset else "",
                     dv.managed.os_version if dv.managed else "", "yes" if dv.asset else "no", "yes" if dv.managed else "no",
                     "yes" if dv.sensor and dv.sensor.onboarded else "no", "yes" if dv.protected else "no", len(dv.failed()), dv.risk]
                    + [dv.results.get(c, ("n/a", ""))[0] for c in CONTROLS])
    _w(path, head, rows)


def write_gaps(rv: dict, path: Path) -> None:
    rows = []
    for dv in rv["scope"]:
        for c, (st, cause) in dv.results.items():
            if st in ("fail", "exception"):
                rows.append([dv.name, dv.site, dv.department, dv.user, dv.platform, c, CONTROLS[c][0], st, cause])
    rows.sort(key=lambda r: (r[7] != "fail", list(CONTROLS).index(r[5]), r[0]))
    _w(path, ["device", "site", "department", "user", "platform", "control", "name", "status", "cause"], rows)


def write_reconciliation(d: Data, rv: dict, path: Path) -> None:
    s = d.settings
    rows = []
    for dv in rv["devices"]:
        a, m, sn = dv.asset, dv.managed, dv.sensor
        if dv.scope == "other platform":
            continue
        if not a:
            note = "not in the inventory"
        elif dv.scope == "retired":
            note = "retired" + (", still active" if (m and m.last_sync and (d.today - m.last_sync.date()).days <= s.checkin_days) or
                                (sn and sn.last_seen and (d.today - sn.last_seen.date()).days <= s.sensor_days) else "")
        elif dv.scope == "stock":
            note = "in stock"
        elif not m and not (sn and sn.onboarded):
            note = "in use, in no tool"
        elif not m:
            note = "not in Intune"
        elif not (sn and sn.onboarded):
            note = "not in Defender"
        else:
            note = "in all three"
        rows.append([dv.name, a.serial if a else (m.serial if m else ""), dv.platform, a.status if a else "", "yes" if a else "no",
                     "yes" if m else "no", _ts(m.last_sync) if m else "", "yes" if sn and sn.onboarded else "no",
                     sn.health if sn else "", _ts(sn.last_seen) if sn else "", dv.scope, note])
    order = {"in use, in no tool": 0, "not in Intune": 1, "not in Defender": 2, "not in the inventory": 3}
    rows.sort(key=lambda r: (order.get(r[11], 4 if "still active" in r[11] else 5), r[0]))
    _w(path, ["device", "serial", "platform", "inventory_status", "in_inventory", "in_intune", "intune_last_checkin", "in_defender",
              "sensor_health", "defender_last_seen", "scope", "note"], rows)


def coverage_rows(rv: dict) -> list[list]:
    ok, n, pct = rv["full"]
    rows = [["FULL", "Fully protected", ok, n, _f(pct)]]
    for c, (name, _) in CONTROLS.items():
        ok, n, pct = rv["controls"][c]
        if pct is not None:
            rows.append([c, name, ok, n, _f(pct)])
    return rows


def write_coverage(rv: dict, path: Path) -> None:
    _w(path, ["control", "name", "covered", "devices", "coverage_pct"], coverage_rows(rv))


def write_elevations(d: Data, rv: dict, path: Path) -> None:
    rules, unsigned = rv["elevations"]
    flagged = {f["file"].lower(): ("candidate rule", "Decide: automatic rule or keep approval") for f in rules}
    flagged.update({f["file"].lower(): ("unsigned", "Confirm the tool; sign it, allow by hash with an owner, or block it")
                    for f in unsigned})
    by = defaultdict(list)
    for x in d.elevations or []:
        by[x.file.lower()].append(x)
    rows = []
    for k, xs in by.items():
        users = {x.user for x in xs}
        kinds = sorted({x.kind for x in xs})
        st, act = flagged.get(k, ("ok", ""))
        rows.append([xs[0].file, xs[0].publisher, len(xs), len(users), len({x.device for x in xs}), "; ".join(kinds),
                     _ts(max((x.when for x in xs if x.when), default=None)), st, act])
    rows.sort(key=lambda r: (r[7] == "ok", -r[2]))
    _w(path, ["file", "publisher", "elevations", "users", "devices", "elevation_types", "last", "review", "action"], rows)


def write_exceptions(rv: dict, path: Path) -> None:
    _w(path, ["device", "control", "name", "reason", "approver", "ticket", "expires", "days_to_expiry", "gap_still_there", "state",
              "action"],
       [[x.device, x.control, CONTROLS.get(x.control, (x.control,))[0], x.reason, x.approver, x.ticket, _d(x.expires),
         "" if ex["days"] is None else ex["days"], "yes" if ex["gap"] else "no", ex["state"], ex["action"]]
        for ex in rv["exceptions"] for x in [ex["exception"]]])


def write_findings(rv: dict, path: Path) -> None:
    _w(path, ["severity", "code", "group", "title", "subject", "detail", "action", "devices", "count", "owner", "due"],
       [[f.severity, f.code, GROUPS[f.group], f.title, f.subject, f.detail, f.action, "; ".join(f.devices), f.count, f.owner, _d(f.due)]
        for f in rv["findings"]])


def actions(rv: dict) -> list:
    return [(f"A-{i:03d}", f) for i, f in enumerate(rv["findings"], 1)]


def write_actions(rv: dict, path: Path) -> None:
    _w(path, ["ref", "severity", "code", "subject", "action", "devices", "owner", "due", "done"],
       [[ref, f.severity, f.code, f.subject, f.action, f.count, f.owner, _d(f.due), ""] for ref, f in actions(rv)])


# ---------------------------------------------------------------- the review pack

def _md(x) -> str:
    return str(x).replace("|", "/").replace("\n", " ")


def pack_md(d: Data, rv: dict, title: str) -> str:
    s = d.settings
    sm = summary(d, rv)
    prev = f" ({_p(sm['prev_pct'])} at the last review)" if sm["prev_pct"] is not None else ""
    out = [f"# {title}", "",
           f"> Prepared on {d.as_of:%a %d %b %Y} from the exports listed at the end, for the monthly endpoint security review. "
           "Read-only: no device, policy or group was changed. Approved, valid exceptions count as covered. Thresholds are in "
           f"settings.json. Sections marked {TODO} are for the meeting.", "",
           f"**{sm['status']}. {_p(sm['pct'])} of {sm['scope']} devices in use fully protected{prev}; {sm['red']} red and "
           f"{sm['amber']} amber findings.**", "", "## Headlines", ""]
    for f in [f for f in rv["findings"] if f.severity == RED and f.code != "CTL-TARGET"][:6]:
        out.append(f"- **{_md(f.subject)}.** {_md(f.detail)}")
    am = [f for f in rv["findings"] if f.severity != RED and f.code not in ("CTL-TARGET",)]
    if am:
        out.append("- Also: " + "; ".join(_md(f.subject) for f in am[:6]) + ("; …" if len(am) > 6 else "") + ".")
    out += ["", "## Coverage by control", "", "| Control | Covered | Coverage | Last review | Target |", "|---|---|---|---|---|"]
    ok, n, pct = rv["full"]
    out.append(f"| **Fully protected** | {ok} / {n} | **{_p(pct)}** | {_p((d.previous or {}).get('FULL'))} | |")
    for c, (name, _) in CONTROLS.items():
        ok, n, pct = rv["controls"][c]
        if pct is None:
            continue
        flag = " ⚠" if pct < s.target(c) else ""
        out.append(f"| {name} | {ok} / {n} | {_p(pct)}{flag} | {_p((d.previous or {}).get(c))} | {s.target(c):.0f} % |")
    out += ["", "## Decisions needed", "", "| # | Decision | Options | Proposed | Owner | Needed by | Outcome |", "|---|---|---|---|---|---|---|"]
    out += [f"| {x.id} | **{_md(x.decision)}**<br>{_md(x.why)} | {_md(x.options)} | {_md(x.proposed)} | {_md(x.owner)} | "
            f"{_day(x.needed_by)} | |" for x in rv["decisions"]] or ["| – | No decisions needed | | | | | |"]
    out += ["", "## Actions", "", "Every finding is an action in `actions.csv`; every gap per device and control is in `gaps.csv`.", "",
            "| Ref | Severity | Action | Devices | Owner | Due | Done |", "|---|---|---|---|---|---|---|"]
    for ref, f in actions(rv):
        if f.code == "CTL-TARGET":
            continue
        out.append(f"| {ref} | {f.severity} | **{_md(f.subject)}**: {_md(f.action)} | {f.count} | {_md(f.owner)} | {_day(f.due)} | |")
    out += ["", "## By site and department", "", "| Scope | Devices | Fully protected |", "|---|---|---|"]
    for label, rows in (("Site ", rv["sites"]), ("", rv["departments"])):
        for k, (ok, n, pct) in rows:
            out.append(f"| {label}{_md(k)} | {n} | {_p(pct)} |")
    out += ["", "## Audit evidence (ISO 27001 / NIS2)", "",
            f"- Asset inventory reconciled with Intune and Defender for Endpoint: `reconciliation.csv` ({sm['devices']} records, "
            f"{sm['unknown']} devices not in the inventory, {sm['retired']} retired).",
            "- Coverage per device and control in `device-coverage.csv`; every gap with its cause in `gaps.csv`.",
            f"- Exceptions register with approver, ticket and expiry: `exceptions-review.csv` ({sm['exceptions']} exceptions).",
            f"- Privileged access on endpoints: local administrators and the EPM elevations ({sm['elevations']} in the period) in "
            "`elevations-review.csv`.",
            "- Treatment: actions with owner and due date in `actions.csv`; decisions and outcome in this pack.",
            "- Trend: `coverage-summary.csv` is next month's `previous-coverage.csv`.", "",
            "## Scope and sources", "", f"- Organisation: {s.organisation}", f"- Review date: {d.as_of:%a %d %b %Y %H:%M}" +
            (f"; previous review {s.previous_review:%d %b %Y}" if s.previous_review else ""),
            f"- In scope: Windows and macOS devices in use in the inventory, plus devices active in Intune or Defender that the "
            f"inventory does not have. Out of scope: {sm['other']} phones and tablets, {sm['stock']} in stock, {sm['retired']} retired.",
            f"- Check-in within {s.checkin_days} days; Defender sensor report within {s.sensor_days} days; minimum OS "
            + ", ".join(f"{k} {v}" for k, v in s.min_os.items()) + ".", "", "| Source | File | Records |", "|---|---|---|"]
    out += [f"| {FILES.get(k, k)} | `{k}` | {v:,} |" for k, v in d.sources.items()]
    out += ["", "## Notes", "", f"- Decisions taken: {TODO}", f"- Exceptions approved or closed: {TODO}", f"- Next review: {TODO}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb;
--g:#cfeedd;--a:#fbe6bd;--r:#f8d2cd;--n:#eef0f2}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;
--bad:#f2685c;--info:#5aa9f0;--g:#173527;--a:#3d2f12;--r:#45201d;--n:#232a31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:24px}
.overall{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:99px;font-weight:700;border:2px solid currentColor}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.red{color:var(--bad)}.amber{color:var(--warn)}.green{color:var(--ok)}
.bar{height:12px;background:var(--n);border-radius:3px;position:relative;min-width:120px}.bar i{display:block;height:12px;border-radius:3px;background:var(--ok)}
.bar i.a{background:var(--warn)}.bar i.r{background:var(--bad)}.bar s{position:absolute;top:-3px;width:2px;height:18px;background:var(--ink)}
table.heat td,table.heat th{padding:4px 5px;text-align:center;font-size:12px;border-bottom:1px solid var(--card)}table.heat td.srv{text-align:left;white-space:nowrap}
table.heat td.c{min-width:44px;font-variant-numeric:tabular-nums}.cg{background:var(--g)}.ca{background:var(--a)}.cr{background:var(--r)}.cn{background:var(--n);color:var(--muted)}
td.subj{min-width:150px}td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);min-width:200px;max-width:340px}td.sm{font-size:13px}
.brk{overflow-wrap:anywhere;word-break:break-word}footer{margin-top:40px;font-size:13px}
"""


def _pill(x: str) -> str:
    return f"<span class='pill {x.lower()}'>{e(x)}</span>"


def _table(head: list[str], rows: list[str], cls: str = "") -> str:
    return (f"<div class='wrap'><table class='{cls}'><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + "".join(rows)
            + "</table></div>")


def _cell(p, target: float, red: float) -> str:
    if p is None:
        return "<td class='c cn'>–</td>"
    cls = "cg" if p >= target else "ca" if p >= red else "cr"
    return f"<td class='c {cls}'>{p:.0f}</td>"


def _bar(p, target: float, red: float) -> str:
    if p is None:
        return ""
    cls = "" if p >= target else " a" if p >= red else " r"
    lo = 80.0
    w = max(0.0, (p - lo) / (100 - lo) * 100)
    t = (target - lo) / (100 - lo) * 100
    return f"<div class='bar' title='scale {lo:.0f}–100 %'><i class='{cls.strip()}' style='width:{w:.1f}%'></i><s style='left:{t:.1f}%'></s></div>"


def render_html(d: Data, rv: dict, title: str) -> str:
    s = d.settings
    sm = summary(d, rv)
    prev = d.previous or {}
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>{e(s.organisation)} · {sm['scope']} Windows and macOS devices in use · inventory, Intune, "
         f"Defender for Endpoint, Entra ID recovery keys, local admins and EPM · run on {d.as_of:%a %d %b %Y %H:%M}"
         + (f" · previous review {s.previous_review:%d %b %Y}" if s.previous_review else "") + "</p>",
         f"<span class='overall {sm['status'].lower()}'>{e(sm['status'])} · {sm['red']} red and {sm['amber']} amber findings</span>",
         "<div class='tiles'>"]
    delta = "" if sm["prev_pct"] is None or sm["pct"] is None else f"{sm['pct'] - sm['prev_pct']:+.1f} pts vs {sm['prev_pct']:.1f} %"
    tiles = [("Fully protected", _p(sm["pct"]), delta or "no previous review"),
             ("Not managed", str(sm["unmanaged"]), "in use, not in Intune"),
             ("No working EDR", str(sm["no_edr"]), "missing or unhealthy sensor"),
             ("Not encrypted", str(sm["unencrypted"]), "or unknown"),
             ("Standing admins", str(sm["admins"]), "devices"),
             ("Unsupported OS", str(sm["unsupported"]), "devices, after exceptions")]
    h += [f"<div class='tile'><span class='muted'>{e(a)}</span><b>{e(b)}</b><span class='muted'>{e(c)}</span></div>" for a, b, c in tiles]
    h.append("</div><h2>Decisions needed</h2>")
    h.append(_table(["#", "Decision", "Options", "Proposed", "Owner", "By"],
                    [f"<tr><td class='nw'>{e(x.id)}</td><td class='subj'><b>{e(x.decision)}</b><br><span class='sm muted'>{e(x.why)}</span></td>"
                     f"<td class='sm'>{e(x.options)}</td><td class='fix'>{e(x.proposed)}</td><td class='sm'>{e(x.owner)}</td>"
                     f"<td class='nw'>{e(_day(x.needed_by))}</td></tr>" for x in rv["decisions"]]
                    or ["<tr><td colspan='6'>No decisions needed.</td></tr>"]))
    h.append("<h2>Coverage by control</h2><p class='muted'>Exceptions count as covered. Bars on a 80–100 % scale; the line is the "
             "target.</p>")
    rows = []
    ok, n, pct = rv["full"]
    pf = prev.get("FULL")
    rows.append(f"<tr><td><b>Fully protected</b></td><td class='num'>{ok} / {n}</td><td class='num'><b>{_p(pct)}</b></td>"
                f"<td>{_bar(pct, s.target_pct, s.red_pct)}</td><td class='num'>{_p(pf)}</td><td class='num'>"
                f"{'' if pct is None or pf is None else f'{pct - pf:+.1f}'}</td></tr>")
    for c, (name, plat) in CONTROLS.items():
        ok, n, pct = rv["controls"][c]
        if pct is None:
            continue
        pv = prev.get(c)
        rows.append(f"<tr><td>{e(name)}{' <span class=muted>(Windows)</span>' if plat == 'windows' else ''}</td><td class='num'>{ok} / {n}"
                    f"</td><td class='num'>{_p(pct)}</td><td>{_bar(pct, s.target(c), s.red_pct)}</td><td class='num'>{_p(pv)}</td>"
                    f"<td class='num'>{'' if pv is None else f'{pct - pv:+.1f}'}</td></tr>")
    h.append(_table(["Control", "Covered", "Coverage", "", "Last review", "Change"], rows))
    h.append("<h2>Heat map: departments by control</h2><p class='muted'>Coverage % per department and control. Green: at target; "
             f"amber: from {s.red_pct:.0f} %; red: below.</p>")
    groups = defaultdict(list)
    for dv in rv["scope"]:
        groups[(dv.site or "–", dv.department or "(not in inventory)")].append(dv)
    hrows = []
    for (site, dept), devs in sorted(groups.items()):
        cells = "".join(_cell(coverage(devs, c)[2], s.target(c), s.red_pct) for c in CONTROLS)
        hrows.append(f"<tr><td class='srv'>{e(dept)} <span class='muted'>· {e(site)} · {len(devs)}</span></td>"
                     f"{_cell(full(devs)[2], s.target_pct, s.red_pct)}{cells}</tr>")
    h.append("<div class='wrap'><table class='heat'><tr><th>Department</th><th>All</th>" +
             "".join(f"<th title='{e(CONTROLS[c][0])}'>{e(c)}</th>" for c in CONTROLS) + "</tr>" + "".join(hrows) + "</table></div>")
    recon = defaultdict(int)
    for dv in rv["devices"]:
        if dv.scope == "other platform":
            continue
        key = ("inventory" if dv.asset else "–", "Intune" if dv.managed else "–", "Defender" if dv.sensor and dv.sensor.onboarded else "–")
        recon[(dv.scope, key)] += 1
    h.append("<h2>Three sources, one list</h2><p class='muted'>Every Windows and macOS device in the inventory, Intune or Defender, "
             "matched by serial number, name and Entra device ID.</p>")
    h.append(_table(["Scope", "Inventory", "Intune", "Defender", "Devices"],
                    [f"<tr><td>{e(sc)}</td><td>{e(k[0])}</td><td>{e(k[1])}</td><td>{e(k[2])}</td><td class='num'>{v}</td></tr>"
                     for (sc, k), v in sorted(recon.items(), key=lambda x: (x[0][0] != 'in scope', -x[1]))]))
    rules, unsigned = rv["elevations"]
    if d.elevations is not None:
        h.append("<h2>Endpoint Privilege Management</h2><p class='muted'>Elevations in the period. Files approved for many users are "
                 "candidates for an automatic rule; unsigned files need an owner.</p>")
        h.append(_table(["File", "Publisher", "Elevations", "Users", "Type", "Review"],
                        [f"<tr><td class='nw'><b>{e(f['file'])}</b></td><td class='sm'>{e(f['publisher'] or 'unsigned')}</td><td class='num'>"
                         f"{f['count']}</td><td class='num'>{f['users']}</td><td class='sm'>{e(f['kind'])}</td><td class='sm "
                         f"{'amber'}'>{e(t)}</td></tr>" for t, xs in (("candidate rule", rules), ("unsigned", unsigned)) for f in xs]
                        or ["<tr><td colspan='6'>Nothing to review.</td></tr>"]))
    if rv["exceptions"]:
        h.append("<h2>Exceptions</h2>")
        h.append(_table(["Device", "Control", "Reason", "Approver / ticket", "Expires", "State", "Action"],
                        [f"<tr><td class='nw'>{e(x.device)}</td><td class='sm'>{e(CONTROLS.get(x.control, (x.control,))[0])}</td>"
                         f"<td class='sm'>{e(x.reason)}</td><td class='sm'>{e(x.approver or 'none')} / {e(x.ticket or 'none')}</td>"
                         f"<td class='nw'>{e(_day(x.expires))}</td><td class='sm {'red' if ex['state'] == 'expired' else 'amber' if ex['state'] in ('incomplete', 'expiring') else ''}'>"
                         f"{e(ex['state'])}</td><td class='fix'>{e(ex['action'])}</td></tr>" for ex in rv["exceptions"]
                         for x in [ex["exception"]]]))
    h.append("<h2>All findings</h2>")
    h.append(_table(["Severity", "Group", "Subject", "Detail", "Owner", "Due"],
                    [f"<tr><td>{_pill(f.severity)}</td><td class='sm'>{e(GROUPS[f.group])}</td><td class='subj'><b>{e(f.subject)}</b><br>"
                     f"<span class='sm muted'>{e(f.title)}</span></td><td class='sm brk'>{e(f.detail)}<br><span class='muted'>→ "
                     f"{e(f.action)}</span></td><td class='sm'>{e(f.owner)}</td><td class='nw'>{e(_day(f.due))}</td></tr>"
                     for f in rv["findings"]] or ["<tr><td colspan='6'>No findings.</td></tr>"]))
    h.append("<footer class='muted'>Generated by endpointcoverage. Fictional demo data unless you ran it on your own exports. The one-page "
             "pack for the monthly review is review-pack.md; every gap per device is in gaps.csv.</footer></main></body></html>")
    return "".join(h)


__all__ = ["render_html", "pack_md", "write_devices", "write_gaps", "write_reconciliation", "write_coverage", "write_elevations",
           "write_exceptions", "write_findings", "write_actions", "actions", "coverage_rows"]
