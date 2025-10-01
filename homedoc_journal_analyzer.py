#!/usr/bin/env python3
"""
 homedoc_journal_analyzer v0.1.1

 Single-file, stdlib-only journalctl/dmesg analyzer with optional local LLM summary.

 Defaults:
  - Source: journal
  - Mode: error (PRIORITY<=3)
  - Window: --last 24h
  - Output: **flat single-file** Markdown in CWD (e.g., homedoc_journal_analyzer_<ts>_report.md)
  - Model: qwen3:14b @ http://localhost:11434 (Ollama-compatible)
  - Max preflight entries: 10000 (interactive guard)

 Helpers:
  - Run with no flags (or --interactive) for a guided setup starting from the 1h quick scan (gemma3:12b by default).
  - Use --quick for a non-interactive 1h journal error sweep (gemma3:4b) that streams the answer to the terminal.

 Folder mode is auto-enabled when you request extra artifacts (--json/--log/--debug/--all) or pass --outdir or --no-flat.
 In folder mode, files include the timestamp by default (e.g., report_<ts>.md). You can disable that with --no-stamp-names.
 Optionally include the model tag in outdir/filenames with --tag-model (e.g., ..._qwen3_14b...).

 Artifacts (folder mode):
  - report_<ts>[_<model>].md
  - events_<ts>[_<model>].jsonl (when --json or --all)
  - insights_<ts>[_<model>].json (when --json or --all)
  - raw.journal_<ts>[_<model>].jsonl OR raw.dmesg_<ts>[_<model>].log (when --log or --all)
  - debug_<ts>[_<model>].log (when --debug or --all)
  - thinking_<ts>[_<model>].txt (when LLM outputs <think>/<thinking> and folder mode)

 Exit codes:
  0 OK
  1 Generic error
  2 Too many entries; user declined
  3 No entries matched filters
  4 Missing dependency (journalctl/dmesg)
  5 Permission denied / not enough privileges

 Security note: --debug will capture LLM request payloads and cluster previews. Only use on trusted hosts.

 SPDX-License-Identifier: GPL-3.0-or-later
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# -------------------------------
# Utilities & config
# -------------------------------
APP_NAME = "homedoc_journal_analyzer"
VERSION = "0.1.1"
# Align with homedoc flags/env: prefer HOMEDOC_SERVER; keep HOMEDOC_MODEL_URL for compatibility
DEFAULT_MODEL_URL = (
    os.environ.get("HOMEDOC_SERVER")
    or os.environ.get("HOMEDOC_MODEL_URL")
    or "http://localhost:11434/api/generate"
)
DEFAULT_MODEL_NAME = os.environ.get("HOMEDOC_MODEL", "qwen3:14b")
DEFAULT_LAST = os.environ.get("HOMEDOC_LAST", "24h")
DEFAULT_MAX_ENTRIES = int(os.environ.get("HOMEDOC_MAX_ENTRIES", "10000"))

VERBOSE = True

LEVEL_NAMES = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warn",
    5: "notice",
    6: "info",
    7: "debug",
}

RE_IP4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b")
RE_HEX = re.compile(r"0x[0-9A-Fa-f]+|\b[0-9A-Fa-f]{8,}\b")
RE_NUM = re.compile(r"\b\d+\b")
RE_TS_BRACKET = re.compile(r"^\[[^\]]+\]\s+")  # dmesg prefix
RE_THINK = re.compile(r"<(think|thinking)>(.*?)</(think|thinking)>", re.DOTALL | re.IGNORECASE)
RE_PATH = re.compile(r"/[^\s]+")

# -------------------------------
# CLI parsing
# -------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Analyze Linux logs from journalctl and/or dmesg, cluster problems, and (optionally)\n"
            "summarize with a local LLM. Default is error triage over last 24h from journald.\n\n"
            "Notes:\n"
            "  - Align flags with homedoc tooling: --server (alias of --model-url) and HOMEDOC_SERVER env\n"
            "  - Flat by default; folder mode when extra artifacts or --outdir/--no-flat\n"
            "  - In folder mode, timestamp in filenames by default; disable via --no-stamp-names\n"
            "  - Optional --tag-model to include model tag in outdir/filenames\n"
            "  - --debug captures payloads, cluster preview, and stream summaries (10s cadence + final)\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")

    # Sources & modes
    p.add_argument("--source", choices=["journal", "dmesg", "both"], default="journal",
                   help="Which source to read (default: journal)")
    p.add_argument("--mode", default="error",
                   choices=["error", "warn", "all", "security", "boot", "kernel"],
                   help="Filter preset (default: error)")
    p.add_argument("--grep", metavar="REGEX", default=None,
                   help="Additional message filter (regex).")

    # Time scoping
    p.add_argument("--last", default=DEFAULT_LAST,
                   help="journalctl time window, e.g., '2h' '3d' '1w'. Ignored if --since/--until present.")
    p.add_argument("--since", default=None, help="journalctl --since ISO or 'YYYY-MM-DD HH:MM:SS'")
    p.add_argument("--until", default=None, help="journalctl --until ISO or 'YYYY-MM-DD HH:MM:SS'")

    # Volume guard
    p.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES,
                   help="Preflight threshold for total entries before prompting (default: 10000)")
    p.add_argument("--limit", type=int, default=None, help="Hard cap on entries to process (non-interactive)")
    p.add_argument("--yes", action="store_true", help="Proceed without interactive confirmation")
    p.add_argument("--no", action="store_true", help="Abort if over threshold without prompt")

    # Outputs / layout
    p.add_argument("--outdir", default=None, help="Output directory (forces folder mode)")
    p.add_argument("--outfile", default=None, help="(flat) Explicit Markdown output path; supports {ts} and {model}")
    p.add_argument("--flat", action="store_true", help="Force flat single-file Markdown in CWD or --outfile path")
    p.add_argument("--no-flat", action="store_true", help="Disable flat mode; always write into a folder")
    p.add_argument("--stamp-names", action="store_true", help="(folder) Include timestamp in filenames (default)")
    p.add_argument("--no-stamp-names", action="store_true", help="(folder) Do not include timestamp in filenames")
    p.add_argument("--tag-model", action="store_true", help="Include model tag in outdir and filenames")

    p.add_argument("--md", action="store_true", help="Write Markdown report (default if no outputs chosen)")
    p.add_argument("--json", action="store_true", help="Write events.jsonl and insights.json (folder mode)")
    p.add_argument("--log", action="store_true", help="Write raw logs (folder mode)")
    p.add_argument("--debug", action="store_true", help="Write debug log, including payloads and stream summaries")
    p.add_argument("--all", action="store_true", help="Write all artifacts (md, json, log, debug) (folder mode)")

    # LLM
    p.add_argument("--server", dest="model_url", help="LLM server URL (alias of --model-url)")
    p.add_argument("--model-url", dest="model_url", default=DEFAULT_MODEL_URL,
                   help="LLM server URL (Ollama /api/generate assumed)")
    p.add_argument("--model", default=DEFAULT_MODEL_NAME, help="LLM model name (default: qwen3:14b)")
    p.add_argument("--no-llm", action="store_true", help="Disable LLM summary entirely")

    p.add_argument("--quick", action="store_true",
                   help="Shortcut: last 1h journal errors, gemma3:4b, stream answer to terminal")
    p.add_argument("--interactive", action="store_true",
                   help="Launch interactive helper (default when no flags)")

    # Redaction
    p.add_argument("--redact", default=None,
                   help="Comma-separated: ips,macs,nums,hex (applies to outputs, not internal clustering)")

    args = p.parse_args(argv)

    setattr(args, "stream_only", False)

    # Output defaults
    if not (args.md or args.json or args.log or args.debug or args.all):
        args.md = True
    if args.all:
        args.md = args.json = args.log = args.debug = True

    # Name stamping default behaviour in folder mode
    args.stamp_names = not args.no_stamp_names

    return args


def normalize_model_url(raw: Optional[str]) -> str:
    s = (raw or "").strip()
    if not s:
        return DEFAULT_MODEL_URL

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        candidate = f"http://{s}"
    else:
        candidate = s

    parsed = urllib.parse.urlparse(candidate)
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""

    if not netloc:
        return DEFAULT_MODEL_URL

    if parsed.port is None:
        if netloc.startswith("[") and netloc.endswith("]"):
            netloc = f"{netloc}:11434"
        elif ":" not in netloc:
            netloc = f"{netloc}:11434"

    if not path or path == "/":
        path = "/api/generate"
    elif not path.endswith("/api/generate"):
        path = path.rstrip("/") or "/api/generate"

    return urllib.parse.urlunparse(
        (
            parsed.scheme or "http",
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def apply_quick_defaults(args: argparse.Namespace, provided_options: Optional[set[str]] = None) -> None:
    provided_options = provided_options or set()
    args.source = "journal"
    args.mode = "error"
    if "--last" not in provided_options and "--since" not in provided_options and "--until" not in provided_options:
        args.last = "1h"
        args.since = None
        args.until = None
    if "--model" not in provided_options:
        args.model = "gemma3:4b"
    if "--no-llm" not in provided_options:
        args.no_llm = False
    args.stream_only = True
    args.md = False
    args.json = False
    args.log = False
    args.debug = False
    args.all = False
    args.outdir = None
    args.outfile = None
    args.flat = False
    args.no_flat = False
    args.tag_model = False


def run_interactive_wizard(args: argparse.Namespace, provided_options: Optional[set[str]] = None) -> None:
    provided_options = provided_options or set()
    print(f"{APP_NAME} v{VERSION} — interactive helper")
    print("Repository: https://github.com/tmw-homedoc/homedoc-journal-analyzer")
    print("This assistant prepares a fast journalctl triage (defaults: last 1h of error-level entries).")
    print("")

    default_model_choice = "gemma3:12b"
    quick_model_choice = "gemma3:4b"
    thinking_model_choice = "qwen3:14b"
    existing_model = args.model if "--model" in provided_options else default_model_choice
    prompt = (
        f"Model? [Enter={existing_model} | q={quick_model_choice} | t={thinking_model_choice} | custom name] "
    )
    choice = ""
    try:
        choice = input(prompt).strip()
    except EOFError:
        choice = ""

    if not choice:
        args.model = existing_model
    elif choice.lower() == "q":
        args.model = quick_model_choice
    elif choice.lower() == "t":
        args.model = thinking_model_choice
    elif choice.lower() == "c":
        custom = input("Enter model tag: ").strip()
        if custom:
            args.model = custom
    else:
        args.model = choice

    default_server = args.model_url or DEFAULT_MODEL_URL
    server_prompt = (
        "LLM server? Enter host/url (defaults to {}): ".format(default_server)
    )
    try:
        server_choice = input(server_prompt).strip()
    except EOFError:
        server_choice = ""
    if server_choice:
        args.model_url = server_choice
    else:
        args.model_url = default_server

    output_prompt = "Output target? [Enter=terminal stream | f=file report] "
    try:
        output_choice = input(output_prompt).strip().lower()
    except EOFError:
        output_choice = ""

    if output_choice == "f":
        args.stream_only = False
        args.md = True
    else:
        args.stream_only = True
        args.md = False

    try:
        adv = input("More options (advanced)? [y/N] ").strip().lower()
    except EOFError:
        adv = ""

    if adv in ("y", "yes"):
        try:
            last_choice = input("Look-back window (--last), e.g. 30m or 2h (default 1h): ").strip()
        except EOFError:
            last_choice = ""
        if last_choice:
            args.last = last_choice
            args.since = None
            args.until = None

        try:
            mode_choice = input("Severity preset [error/warn/all/security/boot/kernel] (default error): ").strip()
        except EOFError:
            mode_choice = ""
        if mode_choice:
            args.mode = mode_choice

        try:
            source_choice = input("Log source [journal/dmesg/both] (default journal): ").strip()
        except EOFError:
            source_choice = ""
        if source_choice:
            args.source = source_choice

        try:
            grep_choice = input("Optional regex filter (blank to skip): ").strip()
        except EOFError:
            grep_choice = ""
        if grep_choice:
            args.grep = grep_choice

        if not args.stream_only:
            try:
                extras = input("Extra artifacts? [j]son, [l]og, [d]ebug (combine, blank=none): ").strip().lower()
            except EOFError:
                extras = ""
            if "a" in extras:
                args.all = True
                args.json = True
                args.log = True
                args.debug = True
            else:
                args.json = "j" in extras
                args.log = "l" in extras
                args.debug = "d" in extras
                args.all = bool(args.json and args.log and args.debug)
    print("")

# -------------------------------
# Logging helpers
# -------------------------------

def ts() -> str:
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")


def info(msg: str):
    if VERBOSE:
        print(f"[{ts()}] {msg}")


class DebugLog:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.buf: List[str] = []
    def log(self, msg: str):
        line = f"[{ts()}] {msg}"
        self.buf.append(line)
        if self.enabled:
            print(line, file=sys.stderr)
    def log_block(self, title: str, payload: str):
        if not self.enabled:
            return
        header = f"[{ts()}] -- {title} --\n"
        block = header + payload + "\n-- END --"
        self.buf.append(block)
        print(header + "(captured)", file=sys.stderr)
    def flush_to(self, path: Path):
        if not self.enabled:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(self.buf) + "\n", encoding="utf-8")

# -------------------------------
# Shell exec helpers
# -------------------------------

def have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def run_process(cmd: List[str]) -> subprocess.Popen:
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# -------------------------------
# Source command builders
# -------------------------------

def build_journalctl_cmd(args: argparse.Namespace, for_count: bool = False) -> List[str]:
    cmd = ["journalctl", "--no-pager"]

    # Mode mapping
    if args.mode == "boot":
        cmd.append("-b")
    if args.mode == "kernel":
        cmd.append("-k")

    # Priority filters
    if args.mode == "error":
        cmd.extend(["-p", "0..3"])  # emerg..err
    elif args.mode == "warn":
        cmd.extend(["-p", "0..4"])  # emerg..warn
    elif args.mode == "security":
        cmd.append("_TRANSPORT=audit")

    # Time window
    if args.since:
        cmd.extend(["--since", args.since])
    if args.until:
        cmd.extend(["--until", args.until])
    if not (args.since or args.until):
        if args.last:
            cmd.extend(["--since", f"-{args.last}"])

    # Output
    cmd.append("--output=short" if for_count else "--output=json")

    # Grep filter (journal-side)
    if args.grep:
        cmd.extend(["--grep", args.grep])

    return cmd


def build_dmesg_cmd(args: argparse.Namespace, for_count: bool = False) -> List[str]:
    cmd = ["dmesg", "--color=never", "--decode"]
    # Level mapping
    if args.mode == "error":
        cmd.extend(["--level", "emerg,alert,crit,err"])  # 0-3
    elif args.mode == "warn":
        cmd.extend(["--level", "emerg,alert,crit,err,warn"])  # 0-4
    elif args.mode == "security":
        cmd.extend(["--level", "emerg,alert,crit,err"])  # pragmatic
    return cmd

# -------------------------------
# Preflight counting & interactive gate
# -------------------------------

def count_lines(cmd: List[str], dbg: DebugLog, label: str) -> int:
    dbg.log(f"Preflight count ({label}): {' '.join(shlex.quote(c) for c in cmd)}")
    p = run_process(cmd)
    n = 0
    if p.stdout is None:
        return 0
    for _ in p.stdout:
        n += 1
        if n > DEFAULT_MAX_ENTRIES * 5:
            break
    if p.stdout:
        p.stdout.close()
    p.wait(timeout=15)
    dbg.log(f"{label} preflight count ≈ {n}")
    return n


def interactive_gate(total: int, args: argparse.Namespace) -> Tuple[bool, Optional[int]]:
    """Return (proceed, cap_limit)."""
    if args.limit is not None:
        return (total > 0 and args.limit > 0), args.limit

    if total <= args.max_entries:
        return True, None

    if args.no:
        return False, None

    if args.yes or not sys.stdin.isatty():
        return True, args.max_entries

    print(f"Found {total} entries (> {args.max_entries}). Proceed? [y]es/[n]o/[s]uggested/[k] number:", file=sys.stderr)
    try:
        choice = input().strip().lower()
    except EOFError:
        return False, None
    if choice in ("y", "yes"):
        return True, None
    if choice in ("n", "no"):
        return False, None
    if choice in ("s", "suggested"):
        return True, args.max_entries
    if choice.startswith("k"):
        parts = choice.split()
        try:
            k = int(parts[1]) if len(parts) > 1 else int(input("Enter number: "))
            return (k > 0), k
        except Exception:
            return False, None
    return False, None

# -------------------------------
# Readers & parsers
# -------------------------------

Event = Dict[str, object]


def iter_journal_events(args: argparse.Namespace, dbg: DebugLog, raw_sink: Optional[io.TextIOBase]=None) -> Iterator[Event]:
    if not have_cmd("journalctl"):
        return
    cmd = build_journalctl_cmd(args, for_count=False)
    dbg.log(f"Run journalctl: {' '.join(shlex.quote(c) for c in cmd)}")
    p = run_process(cmd)
    if p.stdout is None:
        return
    for line in p.stdout:
        line = line.strip()
        if not line:
            continue
        if raw_sink is not None:
            print(line, file=raw_sink)
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = str(obj.get("MESSAGE", "")).rstrip()
        if args.grep and not re.search(args.grep, msg, re.IGNORECASE):
            continue
        level = obj.get("PRIORITY")
        try:
            level = int(level) if level is not None else None
        except Exception:
            level = None
        unit = obj.get("_SYSTEMD_UNIT") or obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM")
        pid = obj.get("_PID") or obj.get("SYSLOG_PID")
        host = obj.get("_HOSTNAME")
        boot_id = obj.get("_BOOT_ID")
        ts_val = obj.get("__REALTIME_TIMESTAMP")
        if ts_val:
            try:
                ts_dt = dt.datetime.fromtimestamp(int(ts_val)/1_000_000, tz=dt.timezone.utc).astimezone()
                ts_iso = ts_dt.isoformat()
            except Exception:
                ts_iso = None
        else:
            ts_iso = None
        yield {
            "ts": ts_iso,
            "level": level,
            "level_name": LEVEL_NAMES.get(level, str(level) if level is not None else None),
            "source": "journal",
            "unit": unit,
            "pid": pid,
            "host": host,
            "boot_id": boot_id,
            "msg": msg,
            "cursor": obj.get("__CURSOR"),
        }
    if p.stdout:
        p.stdout.close()
    _, err = p.communicate()
    if err:
        dbg.log(f"journalctl stderr: {err.strip()}")


def iter_dmesg_events(args: argparse.Namespace, dbg: DebugLog, raw_sink: Optional[io.TextIOBase]=None) -> Iterator[Event]:
    if not have_cmd("dmesg"):
        return
    cmd = build_dmesg_cmd(args, for_count=False)
    dbg.log(f"Run dmesg: {' '.join(shlex.quote(c) for c in cmd)}")
    p = run_process(cmd)
    if p.stdout is None:
        return
    run_time = dt.datetime.now().astimezone().isoformat()
    for line in p.stdout:
        if raw_sink is not None:
            raw_sink.write(line)
        s = line.strip()
        if not s:
            continue
        s2 = RE_TS_BRACKET.sub("", s)
        if args.grep and not re.search(args.grep, s2, re.IGNORECASE):
            continue
        m = re.match(r"^<([0-7])>\s*(.*)$", s2)
        if m:
            lvl = int(m.group(1)); msg = m.group(2)
        else:
            lvl = None; msg = s2
        yield {
            "ts": run_time,
            "level": lvl,
            "level_name": LEVEL_NAMES.get(lvl, str(lvl) if lvl is not None else None),
            "source": "dmesg",
            "unit": "kernel",
            "pid": None,
            "host": None,
            "boot_id": None,
            "msg": msg,
            "cursor": None,
        }
    if p.stdout:
        p.stdout.close()
    _, err = p.communicate()
    if err:
        dbg.log(f"dmesg stderr: {err.strip()}")

# -------------------------------
# Clustering & LLM
# -------------------------------

class Cluster:
    __slots__ = ("signature", "sample", "count", "first_ts", "last_ts", "units", "levels")
    def __init__(self, signature: str, sample: str, ts: Optional[str], unit: Optional[str], level: Optional[int]):
        self.signature = signature
        self.sample = sample
        self.count = 1
        self.first_ts = ts
        self.last_ts = ts
        self.units = collections.Counter([unit] if unit else [])
        self.levels = collections.Counter([level] if level is not None else [])
    def add(self, ts: Optional[str], unit: Optional[str], level: Optional[int]):
        self.count += 1
        self.last_ts = ts or self.last_ts
        if unit:
            self.units[unit] += 1
        if level is not None:
            self.levels[level] += 1


def signature_of(message: str, unit: Optional[str]) -> str:
    x = RE_IP4.sub('<IP>', message)
    x = RE_MAC.sub('<MAC>', x)
    x = RE_HEX.sub('<HEX>', x)
    x = RE_PATH.sub('/<PATH>', x)
    x = RE_NUM.sub('<N>', x)
    x = re.sub(r"\s+", " ", x).strip()
    return f"{unit} :: {x}" if unit else x


def build_clusters(events: Iterable[Event]) -> Tuple[List[Cluster], int]:
    clusters: Dict[str, Cluster] = {}
    total = 0
    for ev in events:
        total += 1
        unit = (str(ev.get("unit")) or None)
        msg = str(ev.get("msg") or "")
        sig = signature_of(msg, unit)
        cl = clusters.get(sig)
        if cl is None:
            cl = Cluster(sig, sample=msg, ts=ev.get("ts") if isinstance(ev.get("ts"), str) else None,
                         unit=unit, level=ev.get("level") if isinstance(ev.get("level"), int) else None)
            clusters[sig] = cl
        else:
            cl.add(ev.get("ts") if isinstance(ev.get("ts"), str) else None,
                   unit, ev.get("level") if isinstance(ev.get("level"), int) else None)
    ordered = sorted(clusters.values(), key=lambda c: (-c.count, c.signature))
    return ordered, total


def sanitize_model_tag(model: str) -> str:
    tag = re.sub(r"[^A-Za-z0-9]+", "_", model).strip("_").lower()
    return tag


def llm_summarize(
    clusters: List[Cluster],
    args: argparse.Namespace,
    dbg: DebugLog,
    stream_stdout: bool = False,
) -> Tuple[str, Optional[str]]:
    if args.no_llm:
        return "(LLM disabled)", None
    top = clusters[: min(50, len(clusters))]
    bullet_lines = []
    for c in top:
        units = ", ".join(u for u, _ in c.units.most_common(3)) if c.units else "-"
        lvls = ",".join(LEVEL_NAMES.get(k, str(k)) for k, _ in c.levels.most_common(3)) if c.levels else "-"
        bullet_lines.append(f"- cnt={c.count} unit={units} level={lvls} :: {c.sample}")
    prompt = (
        "You are a Linux log forensic assistant. Given clustered log events, produce a short,\n"
        "practical triage: top probable causes, likely impact, and suggested next checks.\n"
        "Return a concise Markdown section with headings 'Findings', 'Likely causes', 'Next steps'.\n"
        "Avoid reprinting all messages; focus on patterns.\n\n"
        "Clusters:\n" + "\n".join(bullet_lines)
    )
    data_obj = {"model": args.model, "prompt": prompt, "stream": True, "options": {"temperature": 0.2}}
    data = json.dumps(data_obj).encode("utf-8")
    req = urllib.request.Request(args.model_url, data=data, headers={"Content-Type": "application/json"})

    # Log full payload once, with caution
    dbg.log(f"LLM request → {args.model_url} model={args.model}")
    dbg.log_block("LLM JSON payload", json.dumps(data_obj, ensure_ascii=False, indent=2))

    # Stream with 10s cadence summaries
    t0 = time.time()
    next_tick = t0 + 10.0
    chunks = 0
    chars = 0

    thinking_buf: List[str] = []
    final_buf: List[str] = []
    streamed_any = False
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            for raw in r:
                try:
                    obj = json.loads(raw.decode("utf-8"))
                except Exception:
                    continue
                piece = obj.get("response") or obj.get("message") or ""
                if not piece:
                    continue
                chunks += 1
                chars += len(piece)
                m = RE_THINK.search(piece)
                if m:
                    thinking_buf.append(m.group(2))
                    piece = RE_THINK.sub("", piece)
                final_buf.append(piece)
                if stream_stdout and piece:
                    print(piece, end="", flush=True)
                    streamed_any = True
                now = time.time()
                if now >= next_tick:
                    elapsed = now - t0
                    approx_tokens = int(chars / 4)  # very rough heuristic
                    rate = approx_tokens / elapsed if elapsed > 0 else 0.0
                    dbg.log(f"LLM stream: t={elapsed:.1f}s chunks={chunks} chars={chars} ~tokens={approx_tokens} rate={rate:.1f} tok/s")
                    next_tick += 10.0
    except Exception as e:
        dbg.log(f"LLM call failed: {e}")
        return "(LLM unavailable)", None

    elapsed = time.time() - t0
    approx_tokens = int(chars / 4)
    rate = approx_tokens / elapsed if elapsed > 0 else 0.0
    dbg.log(f"LLM done: t={elapsed:.1f}s chunks={chunks} chars={chars} ~tokens={approx_tokens} rate={rate:.1f} tok/s")

    final_text = "".join(final_buf).strip()
    if stream_stdout and streamed_any and (not final_text.endswith("\n")):
        print()
    thinking_text = "\n\n".join(thinking_buf).strip() if thinking_buf else None
    return (final_text or "(no summary)", thinking_text)

# -------------------------------
# Rendering
# -------------------------------

def make_report_md(run_meta: Dict[str, str], clusters: List[Cluster], llm_md: Optional[str], transparency: Optional[str]) -> str:
    lines: List[str] = []
    lines.append(f"# {APP_NAME} report — {run_meta['timestamp']}")
    lines.append("")
    lines.append("## Run parameters")
    for k, v in run_meta.items():
        if k == "timestamp":
            continue
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    lines.append("## Top clusters")
    if not clusters:
        lines.append("No events matched the filters.")
    else:
        lines.append("Count | Levels | Units | Signature / Sample")
        lines.append(":--: | :-- | :-- | :--")
        for c in clusters[:50]:
            lvls = ",".join(LEVEL_NAMES.get(k, str(k)) for k, _ in c.levels.most_common(3)) if c.levels else "-"
            units = ", ".join(u for u, _ in c.units.most_common(3)) if c.units else "-"
            sig = c.signature if len(c.signature) < 200 else c.signature[:197] + "…"
            lines.append(f"{c.count} | {lvls or '-'} | {units or '-'} | `{sig}`")
    lines.append("")

    if llm_md:
        lines.append("## Preliminary analysis (LLM)")
        lines.append(llm_md)
        lines.append("")

    if transparency:
        lines.append("## Transparency")
        lines.append("The model's <thinking> content (verbatim):\n")
        lines.append("```\n" + transparency.strip() + "\n```")
        lines.append("")

    lines.append("---\nGenerated by " + APP_NAME + " v" + VERSION)
    return "\n".join(lines)

# -------------------------------
# Main
# -------------------------------

def subst_placeholders(path: Path, run_id: str, model_tag: Optional[str]) -> Path:
    s = str(path)
    s = s.replace("{ts}", run_id)
    if model_tag:
        s = s.replace("{model}", model_tag)
    else:
        s = s.replace("{model}", "model")
    return Path(s)


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv: List[str]
    if argv is None:
        raw_argv = sys.argv[1:]
    else:
        raw_argv = list(argv)

    args = parse_args(raw_argv)

    provided_options = {arg.split("=", 1)[0] for arg in raw_argv if arg.startswith("--")}
    invoked_without_flags = len(raw_argv) == 0

    if args.quick:
        apply_quick_defaults(args, provided_options)

    run_interactive = args.interactive or (invoked_without_flags and not args.quick)
    if run_interactive:
        if sys.stdin.isatty():
            if not args.quick:
                apply_quick_defaults(args, provided_options)
            run_interactive_wizard(args, provided_options)
        else:
            if not args.quick:
                apply_quick_defaults(args, provided_options)

    args.model_url = normalize_model_url(args.model_url)

    global VERBOSE
    VERBOSE = not getattr(args, "stream_only", False)

    # Decide flat vs folder
    extra_artifacts = bool(args.json or args.log or args.debug or args.all)
    folder_mode = bool(args.outdir) or extra_artifacts or bool(args.no_flat)
    if args.stream_only:
        folder_mode = False

    # Run id and model tag
    run_dt = dt.datetime.now().astimezone()
    run_id = run_dt.strftime("%Y%m%d_%H%M%S")
    model_tag = sanitize_model_tag(args.model) if args.tag_model else None
    model_suffix = ("_" + model_tag) if model_tag else ""

    # Paths
    if folder_mode:
        outdir = Path(args.outdir or f"{APP_NAME}_{run_id}{model_suffix}")
        outdir.mkdir(parents=True, exist_ok=True)
        def fname(base: str, ext: str) -> Path:
            if args.stamp_names:
                return outdir / f"{base}_{run_id}{model_suffix}.{ext}"
            else:
                return outdir / f"{base}{model_suffix}.{ext}"
        md_path = fname("report", "md")
        debug_path = fname("debug", "log") if args.debug else None
        events_path = fname("events", "jsonl") if args.json else None
        insights_path = fname("insights", "json") if args.json else None
        raw_path = fname(
            "raw.journal" if args.source=="journal" else ("raw.dmesg" if args.source=="dmesg" else "raw.mixed"),
            "jsonl" if args.source=="journal" else "log"
        ) if args.log else None
        thinking_path = fname("thinking", "txt")
    else:
        outdir = None
        if args.stream_only:
            md_path = None
            debug_path = None
            events_path = insights_path = raw_path = thinking_path = None
        else:
            if args.outfile:
                md_path = subst_placeholders(Path(args.outfile), run_id, model_tag)
                md_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                md_path = Path.cwd() / f"{APP_NAME}_{run_id}{model_suffix}_report.md"
            debug_path = (md_path.with_name(md_path.stem + "_debug.log")) if args.debug else None
            events_path = insights_path = raw_path = thinking_path = None

    # Debug logger
    dbg = DebugLog(enabled=bool(args.debug))

    # Dependency checks
    if args.source in ("journal", "both") and not have_cmd("journalctl"):
        print("journalctl not found (systemd-journald required)", file=sys.stderr)
        return 4 if args.source == "journal" else 0
    if args.source in ("dmesg", "both") and not have_cmd("dmesg"):
        print("dmesg not found", file=sys.stderr)
        return 4 if args.source == "dmesg" else 0

    # Preflight counts
    total = 0
    if args.source in ("journal", "both"):
        cmd = build_journalctl_cmd(args, for_count=True)
        dbg.log("Preflight count (journalctl): " + " ".join(shlex.quote(c) for c in cmd))
        n1 = count_lines(cmd, dbg, "journalctl")
        info(f"Preflight count (journalctl): {n1}")
        total += n1
    if args.source in ("dmesg", "both"):
        cmd = build_dmesg_cmd(args, for_count=True)
        dbg.log("Preflight count (dmesg): " + " ".join(shlex.quote(c) for c in cmd))
        n2 = count_lines(cmd, dbg, "dmesg")
        info(f"Preflight count (dmesg): {n2}")
        total += n2

    proceed, cap = interactive_gate(total, args)
    info(f"Preflight decision: total={total}, proceed={proceed}, cap={cap}")
    if not proceed:
        return 2

    # Raw log sink only in folder mode
    raw_f: Optional[io.TextIOBase] = None
    if raw_path is not None:
        raw_f = raw_path.open("w", encoding="utf-8")

    # Build iterators & apply cap
    def limited(iterable: Iterator[Event], limit: Optional[int]) -> Iterator[Event]:
        if limit is None:
            yield from iterable
        else:
            n = 0
            for ev in iterable:
                n += 1
                if n > limit:
                    break
                yield ev

    iters: List[Iterator[Event]] = []
    if args.source in ("journal", "both"):
        iters.append(iter_journal_events(args, dbg, raw_sink=raw_f))
    if args.source in ("dmesg", "both"):
        iters.append(iter_dmesg_events(args, dbg, raw_sink=raw_f))

    def chain(iters: List[Iterator[Event]]) -> Iterator[Event]:
        for it in iters:
            for ev in it:
                yield ev

    events_iter = limited(chain(iters), cap)

    # Collect
    collected: List[Event] = []
    for ev in events_iter:
        collected.append(ev)
    if raw_f:
        raw_f.close()

    if not collected:
        print("No events matched the filters.", file=sys.stderr)
        return 3

    # Cluster
    clusters, processed_total = build_clusters(collected)
    dbg.log(f"Built {len(clusters)} clusters from {processed_total} events")
    # Log a compact preview
    preview = "\n".join(
        f"{i+1:02d}. {c.count}× {c.signature[:160]}" for i, c in enumerate(clusters[:20])
    )
    dbg.log_block("Cluster preview (top 20)", preview)

    # JSON outputs (folder mode)
    if events_path is not None and insights_path is not None:
        with events_path.open("w", encoding="utf-8") as f:
            for ev in collected:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        with insights_path.open("w", encoding="utf-8") as f:
            payload = []
            for c in clusters:
                payload.append({
                    "signature": c.signature,
                    "sample": c.sample,
                    "count": c.count,
                    "first_ts": c.first_ts,
                    "last_ts": c.last_ts,
                    "units": dict(c.units),
                    "levels": {str(k): v for k, v in c.levels.items()},
                })
            json.dump(payload, f, ensure_ascii=False, indent=2)

    # LLM
    llm_md = None
    thinking_text = None
    if not args.no_llm:
        llm_md, thinking_text = llm_summarize(clusters, args, dbg, stream_stdout=getattr(args, "stream_only", False))
        if folder_mode and thinking_text and thinking_path is not None:
            thinking_path.write_text(thinking_text, encoding="utf-8")

    # Report
    if not args.stream_only:
        meta = {
            "timestamp": run_dt.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "source": args.source,
            "mode": args.mode,
            "grep": args.grep or "-",
            "since": args.since or (f"-{args.last}" if args.last else "-"),
            "until": args.until or "now",
            "processed entries": str(processed_total),
            "limit": str(cap) if cap else "-",
            "model": "disabled" if args.no_llm else args.model,
            "server": args.model_url,
        }
        transparency = None if folder_mode else thinking_text
        md = make_report_md(meta, clusters, llm_md, transparency)
        if md_path is not None:
            md_path.write_text(md, encoding="utf-8")

    # Debug log
    if debug_path is not None:
        dbg.flush_to(debug_path)

    # Final status
    if not args.stream_only:
        if folder_mode:
            info(f"Wrote outputs to: {outdir}")
        else:
            info(f"Wrote outputs to: {md_path}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
