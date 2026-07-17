#!/usr/bin/env python3
"""Build and triage a process tree from Sysmon Event ID 1 records.

Uses EvtxECmd to turn an EVTX into JSON when an .evtx input is supplied.
JSON/JSONL inputs are also accepted, making the tool easy to use in pipelines.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

def norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("/", "\\")


def basename(value: str) -> str:
    return norm(value).rsplit("\\", 1)[-1]


def event_data(record: dict[str, Any]) -> dict[str, str]:
    """Find Sysmon fields across EvtxECmd JSON, JSONL, and nested Event XML JSON."""
    candidates: list[Any] = [record, record.get("EventData"), record.get("event_data")]
    event = record.get("Event")
    if isinstance(event, dict):
        candidates += [event.get("EventData"), event.get("UserData")]
    for data in candidates:
        if isinstance(data, dict):
            # EvtxECmd can put the useful values under PayloadData or as direct keys.
            for nested in (data.get("PayloadData"), data.get("Data")):
                if isinstance(nested, dict):
                    data = {**data, **nested}
                elif isinstance(nested, list):
                    # EvtxECmd --fj XML-shaped JSON: [{"@Name": "Image", "#text": "..."}].
                    named_values = {
                        str(item.get("@Name")): str(item.get("#text", ""))
                        for item in nested
                        if isinstance(item, dict) and item.get("@Name")
                    }
                    data = {**data, **named_values}
            result = {str(k): str(v) for k, v in data.items() if not isinstance(v, (dict, list))}
            if any(k.lower() in {"image", "processguid", "parentimage"} for k in result):
                return result
    return {}


def get_field(data: dict[str, str], *names: str) -> str:
    lower = {k.lower(): v for k, v in data.items()}
    for name in names:
        if name.lower() in lower:
            return str(lower[name.lower()])
    return ""


def time_value(record: dict[str, Any], data: dict[str, str]) -> str:
    return get_field(data, "UtcTime") or get_field(record, "UtcTime", "TimeCreated", "Timestamp", "TimeCreated_SystemTime")


@dataclass
class Process:
    guid: str
    parent_guid: str
    image: str
    command_line: str
    parent_image: str
    parent_command_line: str
    pid: str
    parent_pid: str
    user: str
    integrity: str
    hashes: str
    company: str
    original_file_name: str
    description: str
    time: str
    record_id: str
    score: int = 0
    findings: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return basename(self.image) or "<unknown>"


def load_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not raw:
        return []
    if raw.startswith("["):
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def convert_evtx(evtx: Path, ecmd: str) -> Path:
    executable = Path(ecmd)
    if not executable.exists():
        found = shutil.which(ecmd)
        if not found:
            raise RuntimeError(f"EvtxECmd not found: {ecmd}. Use --evtxecmd or provide exported JSON.")
        executable = Path(found)
    temp = Path(tempfile.mkdtemp(prefix="sysmon_tree_"))
    command = [str(executable), "-f", str(evtx), "--json", str(temp), "--jsonf", "events.json", "--fj", "--inc", "1"]
    run = subprocess.run(command, capture_output=True, text=True)
    if run.returncode != 0:
        raise RuntimeError("EvtxECmd failed:\n" + (run.stderr or run.stdout)[-2000:])
    files = list(temp.rglob("*.json"))
    if not files:
        raise RuntimeError("EvtxECmd finished without writing JSON output.")
    return files[0]


def parse_processes(records: Iterable[dict[str, Any]]) -> list[Process]:
    processes = []
    for record in records:
        data = event_data(record)
        image = get_field(data, "Image")
        guid = get_field(data, "ProcessGuid")
        # Ignore non-Sysmon records, but permit simple analyst-created JSONL records.
        event_id = get_field(record, "EventId", "EventID", "Id")
        if not event_id and isinstance(record.get("Event"), dict):
            system = record["Event"].get("System")
            if isinstance(system, dict):
                event_id = get_field(system, "EventId", "EventID", "Id")
        if not image or not guid or (event_id and event_id != "1"):
            continue
        processes.append(Process(
            guid=guid, parent_guid=get_field(data, "ParentProcessGuid"), image=image,
            command_line=get_field(data, "CommandLine"), parent_image=get_field(data, "ParentImage"),
            parent_command_line=get_field(data, "ParentCommandLine"), pid=get_field(data, "ProcessId"),
            parent_pid=get_field(data, "ParentProcessId"), user=get_field(data, "User"),
            integrity=get_field(data, "IntegrityLevel"), hashes=get_field(data, "Hashes"),
            company=get_field(data, "Company"), original_file_name=get_field(data, "OriginalFileName"),
            description=get_field(data, "Description"), time=time_value(record, data),
            record_id=get_field(record, "RecordId", "EventRecordID", "RecordNumber"),
        ))
    return sorted(processes, key=lambda p: p.time or "")


def load_rules(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        rules = json.load(fh)
    if not isinstance(rules.get("relationships"), list):
        raise ValueError("Intelligence file must contain a 'relationships' list.")
    return rules


def matches(value: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, value, re.I) for pattern in patterns)


def score_processes(processes: list[Process], intel: dict[str, Any]) -> None:
    for proc in processes:
        parent, child, cmd = norm(proc.parent_image), norm(proc.image), norm(proc.command_line)
        for rule in intel["relationships"]:
            if (matches(parent, rule.get("parent", [".*"])) and
                matches(child, rule.get("child", [".*"])) and
                matches(cmd, rule.get("command_line", [".*"]))):
                proc.score += int(rule.get("score", 0))
                proc.findings.append(rule.get("name", "custom relationship"))
        # Independent context checks complement parent/child relationships.
        for rule in intel.get("process_indicators", []):
            target = " ".join([child, cmd, norm(proc.image)])
            if matches(target, rule.get("pattern", [])):
                proc.score += int(rule.get("score", 0))
                proc.findings.append(rule.get("name", "process indicator"))
        proc.findings = list(dict.fromkeys(proc.findings))


def severity(score: int) -> str:
    return "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW" if score else "INFO"


def build_tree(processes: list[Process]) -> tuple[dict[str, Process], dict[str, list[str]], list[str]]:
    by_guid = {norm(p.guid): p for p in processes}
    children: dict[str, list[str]] = defaultdict(list)
    roots = []
    for proc in processes:
        key, parent_key = norm(proc.guid), norm(proc.parent_guid)
        if parent_key and parent_key in by_guid and parent_key != key:
            children[parent_key].append(key)
        else:
            roots.append(key)
    for value in children.values():
        value.sort(key=lambda x: by_guid[x].time or "")
    return by_guid, children, roots


def label(p: Process) -> str:
    flag = f" [{severity(p.score)}:{p.score} - {'; '.join(p.findings)}]" if p.score else ""
    return f"{p.name} (PID {p.pid or '?'}, {p.time or 'time unknown'}){flag}"


def render_tree(by_guid: dict[str, Process], children: dict[str, list[str]], roots: list[str]) -> str:
    lines: list[str] = []
    def walk(key: str, prefix: str, last: bool, stack: set[str], is_root: bool = False) -> None:
        p = by_guid[key]
        lines.append(("" if is_root else prefix + ("└── " if last else "├── ")) + label(p))
        if key in stack:
            lines.append(prefix + "    └── <cycle suppressed>")
            return
        next_prefix = prefix + ("    " if last else "│   ")
        kids = children.get(key, [])
        for i, child in enumerate(kids):
            walk(child, next_prefix, i == len(kids)-1, stack | {key})
    for i, root in enumerate(roots):
        if i: lines.append("")
        walk(root, "", True, set(), is_root=True)
    return "\n".join(lines) + "\n"


def write_reports(output: Path, processes: list[Process], source: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    by_guid, children, roots = build_tree(processes)
    tree = render_tree(by_guid, children, roots)
    (output / "process_tree.txt").write_text(tree, encoding="utf-8")
    with (output / "relationships.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["utc_time", "parent_image", "parent_pid", "child_image", "child_pid", "severity", "score", "findings", "command_line", "user", "process_guid", "parent_process_guid"])
        for p in processes:
            writer.writerow([p.time, p.parent_image, p.parent_pid, p.image, p.pid, severity(p.score), p.score, "; ".join(p.findings), p.command_line, p.user, p.guid, p.parent_guid])
    report = {"source": source, "process_count": len(processes), "flagged_count": sum(bool(p.score) for p in processes), "roots": roots, "processes": [asdict(p) | {"severity": severity(p.score)} for p in processes]}
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    # Legacy Windows consoles may use a code page without box-drawing glyphs.
    console_encoding = sys.stdout.encoding or "utf-8"
    print(tree.encode(console_encoding, errors="replace").decode(console_encoding), end="")
    print(f"\nProcessed {len(processes)} Sysmon Event ID 1 records; flagged {report['flagged_count']}.")
    print(f"Reports: {output.resolve()}")


def main() -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Create and triage a process tree from Sysmon EVTX Event ID 1 data.")
    ap.add_argument("input", type=Path, help="Sysmon .evtx, EvtxECmd JSON, or JSONL file")
    ap.add_argument("-o", "--output", type=Path, default=Path("sysmon_tree_output"), help="Report directory")
    ap.add_argument("--intel", type=Path, default=here / "behavior_intelligence.json", help="Editable relationship intelligence JSON")
    ap.add_argument("--evtxecmd", help="Path to EvtxECmd executable (required for .evtx input)")
    args = ap.parse_args()
    if not args.input.exists(): ap.error(f"Input does not exist: {args.input}")
    try:
        source = args.input
        converted = None
        if source.suffix.lower() == ".evtx":
            if not args.evtxecmd:
                ap.error("--evtxecmd is required when the input is an .evtx file")
            converted = convert_evtx(source, args.evtxecmd)
            source = converted
        processes = parse_processes(load_records(source))
        if not processes:
            raise RuntimeError("No Sysmon Event ID 1 process-create records were found.")
        score_processes(processes, load_rules(args.intel))
        write_reports(args.output, processes, str(args.input.resolve()))
        if converted:
            shutil.rmtree(converted.parent, ignore_errors=True)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
