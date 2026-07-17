# Sysmon Process Tree

`sysmon_tree.py` is a dependency-free Python command-line tool for investigating Sysmon process creation activity. It reads Sysmon Event ID 1 records, joins a child to its parent using `ProcessGuid` and `ParentProcessGuid`, renders a process tree, and assigns investigation scores to abnormal parent-child combinations and suspicious command-line behavior.

It invokes Eric Zimmerman's EvtxECmd for `.evtx` input. It can also consume EvtxECmd JSON or line-delimited JSON (`.jsonl`) if event conversion is performed separately.

## Requirements

- Python **3.10 or later**. On the tested workstation use `python3`, not `python`, because `python` may point to Python 2.7.
- An EVTX containing Sysmon Event ID 1 (Process Create) events.
- EvtxECmd only when reading an `.evtx` directly. Supply its executable path with `--evtxecmd`.

## Supported Sysmon data and versions

The tool analyzes **Sysmon Event ID 1 only**. It requires at least `Image` and `ProcessGuid`; it uses `ParentProcessGuid`, image paths, command lines, PIDs, user, integrity level, hashes, and file metadata when present. Other Sysmon event IDs are intentionally ignored in this version.

The parser is schema-based rather than hard-coded to a Sysmon release number. It was validated against the supplied log produced by **Sysmon 15.21**. It should work with Sysmon releases that emit the usual Event ID 1 fields above. If a custom/old Sysmon configuration omits process-create events or `ProcessGuid`, a tree cannot be built reliably.

## Basic usage

Run from the tool folder, or use full paths:

```powershell
python3 .\sysmon_tree.py "<sysmon-evtx-file>" `
  --evtxecmd "<path-to-EvtxECmd.exe>" `
  -o .\case_output
```

Use an exported EvtxECmd JSON/JSONL file without running EvtxECmd again:

```powershell
python3 .\sysmon_tree.py .\events.json -o .\case_output
```

Use a case-specific intelligence file:

```powershell
python3 .\sysmon_tree.py "<sysmon-evtx-file>" `
  --evtxecmd "<path-to-EvtxECmd.exe>" `
  --intel .\case_intelligence.json `
  -o .\case_output
```

Run `python3 .\sysmon_tree.py --help` for all command options.

## Output

The selected output directory contains:

| File | Purpose |
| --- | --- |
| `process_tree.txt` | Readable hierarchy. Findings appear beside the child process as `[SEVERITY:score - finding]`. |
| `relationships.csv` | One row per process-create event, including parent/child paths, PIDs, command line, user, score, GUIDs, and findings. Best for filtering in a spreadsheet or SIEM. |
| `report.json` | Complete structured result for scripting, enrichment, or dashboards. |

Severity thresholds are additive: `INFO` 0, `LOW` 1–24, `MEDIUM` 25–49, `HIGH` 50–79, and `CRITICAL` 80 or greater. A score is a triage signal, not proof of malicious activity.

Parents whose process-create event occurred before the log began appear as separate roots. This is expected: the child still retains its parent image, PID, and GUID in the CSV/JSON output.

## Managing behavior intelligence

All detection content is stored in `behavior_intelligence.json`; the Python code does not need to change when tuning rules. Copy the file per customer/case and supply it with `--intel` to keep local decisions separate from the defaults.

The file must be valid JSON and have two optional lists: `relationships` and `process_indicators`. Regular expressions are evaluated case-insensitively using Python's `re` engine. Windows backslashes must be escaped in JSON (`\\`).

### Relationship rules

A relationship rule compares the full parent image path, child image path, and optionally the child command line. All specified conditions must match; multiple patterns within a condition are alternatives.

```json
{
  "name": "Line-of-business app launched PowerShell",
  "parent": ["\\\\myapp\\.exe$"],
  "child": ["\\\\(powershell|pwsh)\\.exe$"],
  "command_line": ["-enc", "-encodedcommand"],
  "score": 65
}
```

- `name`: human-readable finding included in reports.
- `parent`: regex array for the parent image. Omit it to match any parent.
- `child`: regex array for the child image. Omit it to match any child.
- `command_line`: optional regex array for the child command line.
- `score`: non-negative integer added to every matching event.

Use `\\\\powershell\\.exe$` to match `powershell.exe` at the end of a Windows path. Avoid broad rules such as `"child": [".*"]` at high scores, because benign activity can create excessive alerts.

### Process-indicator rules

These detect context in the combined child image and command line; they do not require a specific parent. Use them for encoded commands, remote-content usage, execution from user-writable folders, or organization-specific paths.

```json
{
  "name": "Unsigned tool staged in Downloads",
  "pattern": ["\\\\users\\\\[^\\\\]+\\\\downloads\\\\"],
  "score": 20
}
```

## Tuning workflow

1. Run the tool with the baseline intelligence file.
2. Filter `relationships.csv` by `severity`, `score`, parent/child image, or command line.
3. Validate whether each relationship is expected for the host, user, and time period.
4. Add a narrowly-scoped rule for useful detections; use a small score for weak context and a larger score for a high-confidence relationship.
5. Re-run against known-good data to measure false positives before making the rule a baseline.

For known-good activity, prefer reducing/removing the specific rule or making it more precise instead of broadly suppressing PowerShell, Office, browsers, or system binaries. Keep a separate case intelligence file when an exception is temporary.

## Current baseline detections

The provided intelligence highlights Office or browser applications launching scripting hosts/LOLBins, `svchost.exe` launching scripting hosts, scripting hosts launching proxy-execution tools, encoded PowerShell, remote-content use by common LOLBins, execution from user-writable paths, PowerShell launching the C# compiler, and PowerShell launching WMIC.

These relationships can be legitimate administration, development, EDR collection, or software installation activity. Investigate the command line, user, file hash, source host, and surrounding parent/child processes before escalating.
