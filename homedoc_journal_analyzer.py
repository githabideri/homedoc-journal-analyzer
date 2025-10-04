#!/usr/bin/env python3
"""
 homedoc_journal_analyzer v0.1.2

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
import getpass
import io
import json
import os
import random
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# -------------------------------
# Utilities & config
# -------------------------------
_RAW_PROG = Path(sys.argv[0]).stem if sys.argv else "homedoc-journal-analyzer"
APP_NAME = _RAW_PROG.replace("_", "-")
if APP_NAME not in {"homedoc-journal-analyzer", "lyseur"}:
    APP_NAME = "homedoc-journal-analyzer"
VERSION = "0.1.2"
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

    # Handoff / integrations
    p.add_argument("--handoff", choices=["w"], default=None,
                   help="Post-run handoff target (w = OpenWebUI chat)")
    p.add_argument("--openwebui", dest="openwebui_base",
                   help="OpenWebUI base URL for --handoff w (e.g. http://openwebui)")
    p.add_argument("--token", dest="openwebui_token",
                   help="OpenWebUI Bearer token (or set OPENWEBUI_TOKEN env)")
    p.add_argument("--open-browser", action="store_true",
                   help="Open OpenWebUI home/chat links after successful handoff")
    p.add_argument("--allow-unstable-openwebui", action="store_true",
                   help="Skip the OpenWebUI >= 0.6.15 requirement (use with caution)")

    p.add_argument("--quick", action="store_true",
                   help="Shortcut: last 1h journal errors, gemma3:4b, stream answer to terminal")
    p.add_argument("--interactive", action="store_true",
                   help="Launch interactive helper (default when no flags)")
    p.add_argument("--show-thinking", action="store_true",
                   help="Include the model's <thinking> block in terminal/file outputs")

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
    if "--show-thinking" not in provided_options:
        args.show_thinking = False


def ensure_openwebui_artifacts(args: argparse.Namespace, announce: bool = False) -> None:
    if getattr(args, "handoff", None) != "w":
        return
    messages: List[str] = []
    if getattr(args, "stream_only", False):
        args.stream_only = False
        messages.append("disabling streaming output")
    if not getattr(args, "md", False):
        args.md = True
    if not getattr(args, "outdir", None) and not getattr(args, "outfile", None):
        args.outdir = "artifacts"
        messages.append("saving artifacts under ./artifacts")
    if getattr(args, "outdir", None):
        args.flat = False
        args.no_flat = True
    if not getattr(args, "no_stamp_names", False):
        args.stamp_names = True
    if announce and messages:
        joined = ", ".join(messages)
        print(
            "OpenWebUI handoff needs saved files; "
            f"{joined}. Markdown and JSON reports will be ready before the chat handoff.",
        )


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

    output_prompt = "Output target? [Enter=terminal | t=terminal + thinking | f=file report] "
    try:
        output_choice = input(output_prompt).strip().lower()
    except EOFError:
        output_choice = ""

    if output_choice == "t":
        args.stream_only = True
        args.md = False
        args.show_thinking = True
    elif output_choice == "f":
        args.stream_only = False
        args.md = True
        if "--show-thinking" not in provided_options:
            args.show_thinking = False
    else:
        args.stream_only = True
        args.md = False
        if "--show-thinking" not in provided_options:
            args.show_thinking = False

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
        try:
            think_prompt = f"Include model <thinking> block? [y/N] (currently {'on' if args.show_thinking else 'off'}): "
            think_choice = input(think_prompt).strip().lower()
        except EOFError:
            think_choice = ""
        if think_choice in ("y", "yes"):
            args.show_thinking = True
        elif think_choice in ("n", "no"):
            args.show_thinking = False
    want_handoff = args.handoff == "w"
    if "--handoff" not in provided_options:
        try:
            handoff_choice = input("Continue in OpenWebUI after the run? [y/N] ").strip().lower()
        except EOFError:
            handoff_choice = ""
        if handoff_choice in ("y", "yes"):
            args.handoff = "w"
            want_handoff = True
        elif handoff_choice in ("n", "no"):
            args.handoff = None
            want_handoff = False
    elif want_handoff:
        print("OpenWebUI handoff already enabled via CLI options.")
    if want_handoff:
        if "--openwebui" not in provided_options:
            try:
                base_choice = input("OpenWebUI base URL (e.g. https://openwebui): ").strip()
            except EOFError:
                base_choice = ""
            if base_choice:
                args.openwebui_base = base_choice
        normalized_base = normalize_openwebui_base(args.openwebui_base or "")
        if normalized_base:
            print(f"Bearer token page: {normalized_base}/settings/account")
        else:
            print("Bearer token page: <your OpenWebUI base>/settings/account")
        if "--token" not in provided_options and not args.openwebui_token:
            token = prompt_openwebui_token("OpenWebUI Bearer token (leave blank to provide later): ")
            if token:
                args.openwebui_token = token
        if "--open-browser" not in provided_options:
            try:
                open_choice = input("Open the OpenWebUI chat in your browser afterwards? [y/N] ").strip().lower()
            except EOFError:
                open_choice = ""
            if open_choice in ("y", "yes"):
                args.open_browser = True
            elif open_choice in ("n", "no"):
                args.open_browser = False
        ensure_openwebui_artifacts(args, announce=True)
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
    current_thinking: List[str] = []
    final_buf: List[str] = []
    streamed_any = False
    partial_tag: str = ""
    in_thinking = False
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
                if partial_tag:
                    piece = partial_tag + piece
                    partial_tag = ""

                idx = 0
                piece_len = len(piece)
                lower_piece = piece.lower()
                while idx < piece_len:
                    if in_thinking:
                        close_idx = lower_piece.find("</think", idx)
                        if close_idx == -1:
                            current_thinking.append(piece[idx:])
                            idx = piece_len
                            break
                        current_thinking.append(piece[idx:close_idx])
                        gt_idx = piece.find(">", close_idx)
                        if gt_idx == -1:
                            partial_tag = piece[close_idx:]
                            idx = piece_len
                            break
                        thinking_buf.append("".join(current_thinking).strip())
                        current_thinking.clear()
                        idx = gt_idx + 1
                        in_thinking = False
                        lower_piece = piece.lower()  # refresh in case of modifications
                        continue
                    open_idx = lower_piece.find("<think", idx)
                    if open_idx == -1:
                        segment = piece[idx:]
                        if segment:
                            final_buf.append(segment)
                            if stream_stdout:
                                print(segment, end="", flush=True)
                                streamed_any = True
                        idx = piece_len
                    else:
                        before = piece[idx:open_idx]
                        if before:
                            final_buf.append(before)
                            if stream_stdout:
                                print(before, end="", flush=True)
                                streamed_any = True
                        gt_idx = piece.find(">", open_idx)
                        if gt_idx == -1:
                            partial_tag = piece[open_idx:]
                            in_thinking = True
                            idx = piece_len
                        else:
                            idx = gt_idx + 1
                            in_thinking = True
                            current_thinking.clear()
                        lower_piece = piece.lower()
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
    if in_thinking and current_thinking:
        thinking_buf.append("".join(current_thinking).strip())
    thinking_text = "\n\n".join([t for t in thinking_buf if t]).strip() if thinking_buf else None
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


def make_report_json(
    run_meta: Dict[str, str],
    clusters: List[Cluster],
    llm_md: Optional[str],
    transparency: Optional[str],
) -> Dict[str, object]:
    cluster_payload = []
    for c in clusters:
        cluster_payload.append(
            {
                "signature": c.signature,
                "sample": c.sample,
                "count": c.count,
                "first_ts": c.first_ts,
                "last_ts": c.last_ts,
                "units": dict(c.units),
                "levels": {str(k): v for k, v in c.levels.items()},
            }
        )
    payload: Dict[str, object] = {
        "meta": run_meta,
        "clusters": cluster_payload,
        "llm": {
            "summary": llm_md,
            "thinking": transparency,
        },
    }
    return payload

# -------------------------------
# OpenWebUI handoff
# -------------------------------

def normalize_openwebui_base(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        host = s
        default_scheme = "http"
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host) or host.startswith("localhost"):
            default_scheme = "http"
        elif ":" in host:
            default_scheme = "http"
        elif "." in host:
            default_scheme = "https"
        s = f"{default_scheme}://{host}"
    parsed = urllib.parse.urlparse(s)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path
    if not netloc:
        return None
    normalized = urllib.parse.urlunparse((scheme, netloc, "", "", "", ""))
    return normalized.rstrip("/")


def openwebui_base_candidates(raw: Optional[str]) -> List[str]:
    if raw is None:
        return []
    s = (raw or "").strip()
    if not s:
        return []
    candidates: List[str] = []
    explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s))
    if explicit_scheme:
        primary = normalize_openwebui_base(s)
        if primary:
            candidates.append(primary)
        parsed = urllib.parse.urlparse(s)
        netloc = parsed.netloc or parsed.path
        if netloc:
            if parsed.scheme.lower() == "https":
                alt = normalize_openwebui_base(f"http://{netloc}")
                if alt:
                    candidates.append(alt)
            elif parsed.scheme.lower() == "http":
                alt = normalize_openwebui_base(f"https://{netloc}")
                if alt:
                    candidates.append(alt)
    else:
        host = s.rstrip("/")
        is_ip = bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))
        prefer_https = bool("." in host and not is_ip and not host.startswith("localhost") and ":" not in host)
        https_candidate = normalize_openwebui_base(f"https://{host}")
        http_candidate = normalize_openwebui_base(f"http://{host}")
        if prefer_https:
            if https_candidate:
                candidates.append(https_candidate)
            if http_candidate:
                candidates.append(http_candidate)
        else:
            if http_candidate:
                candidates.append(http_candidate)
            if https_candidate:
                candidates.append(https_candidate)
    deduped: List[str] = []
    seen = set()
    for candidate in candidates:
        if candidate and candidate not in seen:
            deduped.append(candidate)
            seen.add(candidate)
    return deduped


def prompt_openwebui_token(prompt_text: str) -> Optional[str]:
    if not sys.stdin.isatty():
        return None
    try:
        token = getpass.getpass(prompt_text)
    except Exception:
        return None
    token = (token or "").strip()
    return token or None


def parse_semver_tuple(version: str) -> Tuple[int, int, int]:
    parts = re.split(r"[.+-]", version)
    nums: List[int] = []
    for part in parts:
        if not part:
            continue
        m = re.match(r"(\d+)", part)
        if m:
            nums.append(int(m.group(1)))
        if len(nums) >= 3:
            break
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


OPENWEBUI_LAST_URL: Optional[str] = None


def openwebui_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: float = 30.0,
):
    global OPENWEBUI_LAST_URL
    headers = dict(headers or {})
    current_url = url
    current_method = method
    body = data
    for _ in range(6):
        req = urllib.request.Request(current_url, data=body, method=current_method)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                OPENWEBUI_LAST_URL = resp.geturl()
                content = resp.read()
                ctype = resp.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    if not content:
                        return {}
                    return json.loads(content.decode("utf-8"))
                if not content:
                    return {}
                try:
                    return json.loads(content.decode("utf-8"))
                except Exception:
                    return content
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location") if e.headers else None
                if location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    if e.code in (301, 302, 303) and current_method not in ("GET", "HEAD"):
                        current_method = "GET"
                        body = None
                    continue
            raise
    raise RuntimeError("Too many redirects while contacting OpenWebUI")


def openwebui_request_json(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    json_body: Optional[object] = None,
    timeout: float = 30.0,
):
    data = None
    headers = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    return openwebui_request(method, url, headers=headers, data=data, timeout=timeout)


def effective_openwebui_base(default_base: str) -> str:
    if not OPENWEBUI_LAST_URL:
        return default_base
    parsed = urllib.parse.urlparse(OPENWEBUI_LAST_URL)
    if not parsed.scheme or not parsed.netloc:
        return default_base
    normalized = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    normalized = normalized.rstrip("/")
    return normalized or default_base


def extract_first_id(payload: object) -> Optional[str]:
    if isinstance(payload, dict):
        for key in ("id", "_id"):
            if key in payload and payload[key] is not None:
                return str(payload[key])
        for value in payload.values():
            found = extract_first_id(value)
            if found:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = extract_first_id(item)
            if found:
                return found
    elif isinstance(payload, (str, int)):
        s = str(payload)
        if s:
            return s
    return None


def extract_model_names(payload: object) -> List[str]:
    models: List[str] = []
    if isinstance(payload, dict):
        for key in ("data", "models", "result", "items", "list"):
            if key in payload:
                models.extend(extract_model_names(payload[key]))
        for value in payload.values():
            if isinstance(value, (dict, list, str)):
                models.extend(extract_model_names(value))
    elif isinstance(payload, list):
        for item in payload:
            models.extend(extract_model_names(item))
    elif isinstance(payload, str):
        models.append(payload)
    return models


def wait_for_openwebui_file_processing(base: str, token: str, file_id: str, timeout: float = 180.0) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    deadline = time.time() + timeout
    status_urls = [
        f"{base}/api/v1/files/{file_id}/process/status",
        f"{base}/api/v1/files/{file_id}",
    ]
    saw_endpoint = False
    last_status: Optional[str] = None
    while time.time() < deadline:
        progressed = False
        for url in status_urls:
            try:
                payload = openwebui_request("GET", url, headers=headers, timeout=20)
            except urllib.error.HTTPError as e:
                if e.code in (404, 405, 422):
                    continue
                raise
            except urllib.error.URLError:
                continue
            if not payload:
                continue
            saw_endpoint = True
            status_value = None
            if isinstance(payload, dict):
                status_value = payload.get("status")
                if not status_value and isinstance(payload.get("data"), dict):
                    status_value = payload["data"].get("status")
                if not status_value and isinstance(payload.get("file"), dict):
                    status_value = payload["file"].get("status")
            if status_value:
                status_lower = str(status_value).lower()
                last_status = status_lower
                if status_lower in {"completed", "complete", "done", "processed", "processing_completed"}:
                    return
                if status_lower in {"processing", "queued", "pending", "in_progress"}:
                    progressed = True
            else:
                last_status = None
        if not saw_endpoint:
            return
        if not progressed and last_status is None:
            return
        time.sleep(1.0)
    if saw_endpoint:
        raise TimeoutError(
            f"Timed out waiting for OpenWebUI to process file {file_id} (last status: {last_status})"
        )


def upload_openwebui_file(base: str, token: str, path: Path) -> str:
    boundary = "----homedoc{}".format(uuid.uuid4().hex)
    content_type = "text/markdown" if path.suffix.lower() in {".md", ".markdown"} else "application/json"
    body = []
    body.append(f"--{boundary}\r\n".encode("utf-8"))
    disposition = (
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
    )
    body.append(disposition.encode("utf-8"))
    body.append(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
    body.append(path.read_bytes())
    body.append(b"\r\n")
    body.append(f"--{boundary}--\r\n".encode("utf-8"))
    data = b"".join(body)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Accept": "application/json",
    }
    upload_paths = [
        f"{base}/api/v1/files/upload?process=true&process_in_background=false",
        f"{base}/api/v1/files/upload",
        f"{base}/api/v1/files/?process=true&process_in_background=false",
        f"{base}/api/v1/files?process=true&process_in_background=false",
        f"{base}/api/v1/files/",
        f"{base}/api/v1/files",
    ]
    seen: set[str] = set()
    last_error: Optional[Exception] = None
    for url in upload_paths:
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = openwebui_request("POST", url, headers=headers, data=data, timeout=120)
        except urllib.error.HTTPError as e:
            last_error = e
            continue
        except urllib.error.URLError as e:
            last_error = e
            continue
        file_id = extract_first_id(resp)
        if file_id:
            try:
                wait_for_openwebui_file_processing(base, token, file_id)
            except TimeoutError:
                info(f"Warning: file {file_id} processing did not confirm completion in time")
            return file_id
        last_error = RuntimeError(f"OpenWebUI upload did not return an id for {path}")
    if last_error:
        raise last_error
    raise RuntimeError(f"Failed to upload {path} to OpenWebUI")


def create_openwebui_collection(base: str, token: str, name: str, description: str) -> Tuple[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"name": name, "description": description}
    endpoints = [
        ("knowledge", f"{base}/api/v1/knowledge/create"),
        ("knowledge", f"{base}/api/v1/knowledge"),
        ("collection", f"{base}/api/v1/collections"),
    ]
    last_error: Optional[Exception] = None
    for container_type, url in endpoints:
        try:
            resp = openwebui_request_json("POST", url, headers=headers, json_body=payload)
        except urllib.error.HTTPError as e:
            if e.code in (404, 405):
                last_error = e
                continue
            raise
        cid = extract_first_id(resp)
        if cid:
            return container_type, cid
        last_error = RuntimeError("OpenWebUI knowledge creation returned no id")
    if last_error:
        raise last_error
    raise RuntimeError("Failed to create OpenWebUI knowledge collection")


def attach_files_to_collection(base: str, token: str, container_type: str, container_id: str, file_ids: List[str]) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    if container_type == "knowledge":
        url = f"{base}/api/v1/knowledge/{container_id}/file/add"
    else:
        url = f"{base}/api/v1/collections/{container_id}/files"
    retries = 5
    for file_id in file_ids:
        payload_options = [
            {"file_id": file_id},
            {"file_ids": [file_id]},
        ]
        success = False
        for attempt in range(retries):
            need_retry = False
            for idx, payload in enumerate(payload_options):
                try:
                    openwebui_request_json("POST", url, headers=headers, json_body=payload)
                    success = True
                    break
                except urllib.error.HTTPError as e:
                    if e.code in (409, 422, 425, 503):
                        need_retry = True
                        break
                    if e.code in (400, 404, 405) and idx == 0 and len(payload_options) > 1:
                        continue
                    raise
            if success:
                break
            if need_retry and attempt < retries - 1:
                time.sleep(0.4 + random.random() * 0.6)
                continue
            if attempt < retries - 1 and not success:
                time.sleep(0.2 + random.random() * 0.4)
        if not success:
            raise RuntimeError(f"Failed to attach file {file_id} to OpenWebUI {container_type} {container_id}")


def fetch_openwebui_container_metadata(
    base: str, token: str, container_type: str, container_id: str
) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    endpoints: List[str] = []
    if container_type == "knowledge":
        endpoints = [
            f"{base}/api/v1/knowledge/{container_id}",
            f"{base}/api/v1/knowledge/item/{container_id}",
        ]
    else:
        endpoints = [
            f"{base}/api/v1/collections/{container_id}",
        ]
    for url in endpoints:
        try:
            payload = openwebui_request("GET", url, headers=headers, timeout=30)
        except urllib.error.HTTPError as e:
            if e.code in (404, 405):
                continue
            raise
        if isinstance(payload, dict):
            candidate = payload
            for key in ("data", "result", "item"):
                if isinstance(candidate.get(key), dict):
                    candidate = candidate[key]
            return candidate
    return {}


def upsert_entry_by_id(items: List[Any], entry: Dict[str, Any]) -> bool:
    entry_id = str(entry.get("id")) if entry.get("id") is not None else None
    if not entry_id:
        return False
    for idx, existing in enumerate(items):
        if isinstance(existing, dict) and str(existing.get("id")) == entry_id:
            updated = False
            merged = dict(existing)
            for key, value in entry.items():
                if value is None:
                    continue
                if merged.get(key) != value:
                    merged[key] = value
                    updated = True
            if updated:
                items[idx] = merged
            return updated
    items.append(entry)
    return True


def link_openwebui_collection_to_chat(
    base: str,
    token: str,
    chat_id: str,
    container_type: str,
    container_id: str,
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    chat_payload = openwebui_request("GET", f"{base}/api/v1/chats/{chat_id}", headers=headers, timeout=30)
    chat_obj = extract_chat_object(chat_payload)
    if not isinstance(chat_obj, dict):
        return
    metadata = fetch_openwebui_container_metadata(base, token, container_type, container_id)
    entry_id = str(metadata.get("id") or metadata.get("_id") or container_id)
    file_entry = {
        "id": entry_id,
        "type": "collection",
    }
    for key in ("name", "description", "status"):
        value = metadata.get(key)
        if value:
            file_entry[key] = value
    file_entry.setdefault("status", "processed")
    changed = False
    files = chat_obj.get("files")
    if not isinstance(files, list):
        files = []
        chat_obj["files"] = files
        changed = True
    file_entry_for_chat = json.loads(json.dumps(file_entry))
    if upsert_entry_by_id(files, file_entry_for_chat):
        changed = True
    linkage_key = "knowledge_ids" if container_type == "knowledge" else "collection_ids"
    linked_ids = chat_obj.get(linkage_key)
    if not isinstance(linked_ids, list):
        linked_ids = []
        chat_obj[linkage_key] = linked_ids
    if entry_id not in linked_ids:
        linked_ids.append(entry_id)
        changed = True

    def update_message_files(message: Dict[str, Any]) -> bool:
        if message.get("role") != "user":
            return False
        files_list = message.get("files")
        if not isinstance(files_list, list):
            files_list = []
            message["files"] = files_list
        entry_clone = json.loads(json.dumps(file_entry))
        return upsert_entry_by_id(files_list, entry_clone)

    for msg in chat_obj.get("messages", []):
        if isinstance(msg, dict) and update_message_files(msg):
            changed = True

    history = chat_obj.get("history")
    if isinstance(history, dict):
        history_messages = history.get("messages")
        if isinstance(history_messages, dict):
            for msg in history_messages.values():
                if isinstance(msg, dict) and update_message_files(msg):
                    changed = True

    if changed:
        openwebui_request_json(
            "POST",
            f"{base}/api/v1/chats/{chat_id}",
            headers=headers,
            json_body={"chat": chat_obj},
        )


def build_openwebui_message(
    *,
    msg_id: str,
    role: str,
    content: str,
    model: str,
    timestamp: int,
    parent_id: Optional[str],
    children_ids: Optional[List[str]] = None,
    done: bool = True,
    status_history: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    models = [model] if model else []
    message = {
        "id": msg_id,
        "role": role,
        "content": content,
        "timestamp": timestamp,
        "models": models,
        "modelName": model,
        "modelIdx": 0,
        "parentId": parent_id,
        "childrenIds": list(children_ids or []),
        "done": done,
        "statusHistory": list(status_history or []),
    }
    return message


def extract_chat_object(payload: object) -> Optional[Dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("chat"), dict):
            return payload["chat"]
        data = payload.get("data")
        if isinstance(data, dict):
            if isinstance(data.get("chat"), dict):
                return data["chat"]
            if "messages" in data:
                return data
        if "messages" in payload:
            return payload
    return None


def ensure_chat_children(chat: Dict[str, Any], parent_id: str, child_id: str) -> None:
    for msg in chat.get("messages", []):
        if msg.get("id") == parent_id:
            children = msg.setdefault("childrenIds", [])
            if child_id not in children:
                children.append(child_id)
            break
    history = chat.get("history")
    if isinstance(history, dict):
        h_messages = history.get("messages")
        if isinstance(h_messages, dict) and parent_id in h_messages:
            children = h_messages[parent_id].setdefault("childrenIds", [])
            if child_id not in children:
                children.append(child_id)


def create_openwebui_chat(
    base: str,
    token: str,
    model: str,
    old_output: str,
    when: dt.datetime,
    question: str,
) -> Tuple[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    title = f"homedoc run — {when.strftime('%Y-%m-%d %H:%M')}"
    now_ts = int(time.time())
    assistant_seed_id = uuid.uuid4().hex
    user_id = uuid.uuid4().hex
    placeholder_id = uuid.uuid4().hex
    assistant_seed = build_openwebui_message(
        msg_id=assistant_seed_id,
        role="assistant",
        content=old_output,
        model=model,
        timestamp=now_ts - 1,
        parent_id=None,
        children_ids=[user_id],
        done=True,
    )
    user_message = build_openwebui_message(
        msg_id=user_id,
        role="user",
        content=question,
        model=model,
        timestamp=now_ts,
        parent_id=assistant_seed_id,
        children_ids=[],
        done=True,
    )
    assistant_history = json.loads(json.dumps(assistant_seed))
    user_history = json.loads(json.dumps(user_message))
    chat_obj: Dict[str, Any] = {
        "title": title,
        "models": [model] if model else [],
        "model": model,
        "system": "You are the homedoc assistant. Prefer information from the attached knowledge collection.",
        "messages": [assistant_seed, user_message],
        "history": {
            "current_id": user_id,
            "currentId": user_id,
            "messages": {
                assistant_seed_id: assistant_history,
                user_id: user_history,
            },
        },
        "currentId": user_id,
        "files": [],
    }
    payload_new = {"chat": chat_obj}
    resp = openwebui_request_json(
        "POST",
        f"{base}/api/v1/chats/new",
        headers=headers,
        json_body=payload_new,
    )
    chat_id = extract_first_id(resp)
    if not chat_id:
        raise RuntimeError("OpenWebUI chat creation returned no id")
    chat_obj["id"] = chat_id
    placeholder = build_openwebui_message(
        msg_id=placeholder_id,
        role="assistant",
        content="",
        model=model,
        timestamp=now_ts,
        parent_id=user_id,
        children_ids=[],
        done=False,
        status_history=[],
    )
    placeholder_history = json.loads(json.dumps(placeholder))
    chat_obj["messages"].append(placeholder)
    history_messages = chat_obj["history"]["messages"]
    history_messages[placeholder_id] = placeholder_history
    chat_obj["history"]["current_id"] = placeholder_id
    chat_obj["history"]["currentId"] = placeholder_id
    chat_obj["currentId"] = placeholder_id
    ensure_chat_children(chat_obj, user_id, placeholder_id)
    payload_update = {"chat": chat_obj}
    openwebui_request_json(
        "POST",
        f"{base}/api/v1/chats/{chat_id}",
        headers=headers,
        json_body=payload_update,
    )
    return chat_id, placeholder_id


def trigger_openwebui_completion(
    base: str,
    token: str,
    model: str,
    chat_id: str,
    container_id: str,
    container_type: str,
    old_output: str,
    question: str,
    assistant_message_id: str,
) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    session_id = str(uuid.uuid4())
    file_type = "collection" if container_type in {"knowledge", "collection"} else container_type
    payload = {
        "model": model,
        "chat_id": chat_id,
        "id": assistant_message_id,
        "session_id": session_id,
        "messages": [
            {"role": "assistant", "content": old_output},
            {"role": "user", "content": question},
        ],
        "files": [{"type": file_type, "id": container_id}] if container_id else [],
        "stream": False,
        "background_tasks": {
            "title_generation": False,
            "tags_generation": False,
            "follow_up_generation": False,
        },
        "features": {
            "code_interpreter": False,
            "web_search": False,
            "image_generation": False,
            "memory": False,
        },
    }
    url_primary = f"{base}/api/chat/completions"
    try:
        openwebui_request_json("POST", url_primary, headers=headers, json_body=payload, timeout=120)
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        url_fallback = f"{base}/v1/chat/completions"
        openwebui_request_json(
            "POST", url_fallback, headers=headers, json_body=payload, timeout=120
        )
    return session_id


def poll_openwebui_chat(
    base: str,
    token: str,
    chat_id: str,
    assistant_message_id: str,
    timeout: float = 180.0,
) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    deadline = time.time() + timeout
    url = f"{base}/api/v1/chats/{chat_id}"
    last_payload: Optional[Dict[str, Any]] = None
    while time.time() < deadline:
        payload = openwebui_request("GET", url, headers=headers, timeout=30)
        chat_obj = extract_chat_object(payload)
        if isinstance(chat_obj, dict):
            last_payload = chat_obj
            messages = chat_obj.get("messages") if isinstance(chat_obj.get("messages"), list) else []
            history = chat_obj.get("history") if isinstance(chat_obj.get("history"), dict) else {}
            history_messages = history.get("messages") if isinstance(history.get("messages"), dict) else {}
            target_msg = None
            for msg in messages:
                if isinstance(msg, dict) and msg.get("id") == assistant_message_id:
                    target_msg = msg
                    break
            history_msg = history_messages.get(assistant_message_id)
            content = None
            done = False
            if isinstance(target_msg, dict) and target_msg.get("content"):
                content = target_msg.get("content")
                done = bool(target_msg.get("done", False))
            elif isinstance(history_msg, dict) and history_msg.get("content"):
                content = history_msg.get("content")
                done = bool(history_msg.get("done", False))
            if content:
                if isinstance(target_msg, dict):
                    target_msg["done"] = True
                    target_msg.setdefault("statusHistory", history_msg.get("statusHistory", []) if isinstance(history_msg, dict) else [])
                if isinstance(history_msg, dict):
                    history_msg["done"] = True
                if isinstance(chat_obj.get("history"), dict):
                    chat_obj["history"]["current_id"] = assistant_message_id
                    chat_obj["history"]["currentId"] = assistant_message_id
                chat_obj["currentId"] = assistant_message_id
                if isinstance(target_msg, dict) and isinstance(history_msg, dict):
                    target_msg.setdefault("childrenIds", history_msg.get("childrenIds", []))
                return chat_obj
        time.sleep(1.5)
    if last_payload is not None:
        return last_payload
    raise TimeoutError("Timed out waiting for OpenWebUI completion")


def sync_openwebui_chat(
    base: str,
    token: str,
    chat_id: str,
    chat_payload: Dict[str, Any],
    assistant_message_id: str,
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    messages = chat_payload.get("messages") if isinstance(chat_payload.get("messages"), list) else []
    history = chat_payload.get("history") if isinstance(chat_payload.get("history"), dict) else {}
    history_messages = history.get("messages") if isinstance(history.get("messages"), dict) else {}
    target_msg = None
    for msg in messages:
        if isinstance(msg, dict) and msg.get("id") == assistant_message_id:
            target_msg = msg
            break
    history_msg = history_messages.get(assistant_message_id)
    changed = False
    if isinstance(history_msg, dict):
        if target_msg is None:
            target_msg = json.loads(json.dumps(history_msg))
            messages.append(target_msg)
            changed = True
        else:
            if target_msg.get("content") != history_msg.get("content"):
                target_msg["content"] = history_msg.get("content")
                changed = True
            if bool(target_msg.get("done")) != bool(history_msg.get("done")):
                done_value = bool(history_msg.get("done"))
                target_msg["done"] = done_value
                history_msg["done"] = done_value
                changed = True
            if target_msg.get("statusHistory") != history_msg.get("statusHistory"):
                target_msg["statusHistory"] = history_msg.get("statusHistory", [])
                changed = True
    if isinstance(target_msg, dict):
        if not target_msg.get("content"):
            return
        if target_msg.get("done") is not True:
            target_msg["done"] = True
            changed = True
        if isinstance(history_msg, dict) and history_msg.get("done") is not True:
            history_msg["done"] = True
            changed = True
        if isinstance(history_msg, dict) and target_msg.get("statusHistory") != history_msg.get("statusHistory"):
            target_msg["statusHistory"] = history_msg.get("statusHistory", [])
            changed = True
    if changed:
        chat_payload.setdefault("id", chat_id)
        if isinstance(chat_payload.get("history"), dict):
            chat_payload["history"]["current_id"] = assistant_message_id
            chat_payload["history"]["currentId"] = assistant_message_id
        chat_payload["currentId"] = assistant_message_id
        openwebui_request_json(
            "POST",
            f"{base}/api/v1/chats/{chat_id}",
            headers=headers,
            json_body={"chat": chat_payload},
        )


def complete_openwebui_session(
    base: str,
    token: str,
    chat_id: str,
    assistant_message_id: str,
    model: str,
    session_id: str,
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "chat_id": chat_id,
        "id": assistant_message_id,
        "session_id": session_id,
        "model": model,
    }
    openwebui_request_json(
        "POST",
        f"{base}/api/chat/completed",
        headers=headers,
        json_body=payload,
        timeout=60,
    )


def fetch_openwebui_version(base: str, token: Optional[str]) -> Optional[str]:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{base}/api/version"
    try:
        payload = openwebui_request("GET", url, headers=headers, timeout=10)
    except urllib.error.HTTPError:
        return None
    except urllib.error.URLError:
        return None
    if isinstance(payload, dict):
        if "version" in payload and payload["version"]:
            return str(payload["version"])
        data = payload.get("data") if isinstance(payload.get("data"), dict) else None
        if data and data.get("version"):
            return str(data["version"])
    return None


def run_openwebui_handoff(
    args: argparse.Namespace,
    run_meta: Optional[Dict[str, str]],
    md_path: Optional[Path],
    report_json_path: Optional[Path],
    llm_md: Optional[str],
    run_dt: dt.datetime,
) -> None:
    if args.handoff != "w":
        return
    global OPENWEBUI_LAST_URL
    OPENWEBUI_LAST_URL = None
    if getattr(args, "stream_only", False):
        print("OpenWebUI handoff requires saved artifacts; streaming mode is not supported.", file=sys.stderr)
        return
    if md_path is None or not md_path.exists():
        print("OpenWebUI handoff requires a Markdown report artifact.", file=sys.stderr)
        return
    if report_json_path is None or not report_json_path.exists():
        print("OpenWebUI handoff requires report.json (consider enabling file outputs).", file=sys.stderr)
        return
    if run_meta is None:
        print("OpenWebUI handoff missing run metadata; cannot proceed.", file=sys.stderr)
        return

    candidates = openwebui_base_candidates(args.openwebui_base)
    if not candidates:
        print("--openwebui BASE is required for OpenWebUI handoff.", file=sys.stderr)
        return

    token = (args.openwebui_token or os.environ.get("OPENWEBUI_TOKEN") or None)
    if not token:
        token = prompt_openwebui_token("OpenWebUI Bearer token: ")
    if not token:
        print("OpenWebUI token is required (pass --token or set OPENWEBUI_TOKEN).", file=sys.stderr)
        return

    headers = {"Authorization": f"Bearer {token}"}

    models_payload = None
    base: Optional[str] = None
    last_error: Optional[Exception] = None
    for candidate in candidates:
        current_base = candidate
        for attempt in range(2):
            try:
                models_payload = openwebui_request("GET", f"{current_base}/api/models", headers=headers, timeout=20)
                current_base = effective_openwebui_base(current_base)
                base = current_base
                break
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    print("OpenWebUI token rejected; please re-enter.", file=sys.stderr)
                    token = prompt_openwebui_token("OpenWebUI Bearer token: ")
                    if not token:
                        print("No token provided; aborting OpenWebUI handoff.", file=sys.stderr)
                        return
                    args.openwebui_token = token
                    headers = {"Authorization": f"Bearer {token}"}
                    continue
                last_error = e
                break
            except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
                last_error = e
                break
        if models_payload is not None:
            break
    if models_payload is None or base is None:
        if isinstance(last_error, urllib.error.HTTPError):
            print(
                f"Failed to query OpenWebUI models: HTTP {last_error.code}",
                file=sys.stderr,
            )
        elif last_error is not None:
            print(f"Failed to reach OpenWebUI models endpoint: {last_error}", file=sys.stderr)
        else:
            print("Could not retrieve OpenWebUI models list.", file=sys.stderr)
        return

    try:
        version = fetch_openwebui_version(base, token)
    except (TimeoutError, socket.timeout):
        version = None
    if version:
        version_tuple = parse_semver_tuple(version)
        if version_tuple < (0, 6, 15) and not args.allow_unstable_openwebui:
            print(
                f"OpenWebUI server reports version {version}; require >= 0.6.15 or pass --allow-unstable-openwebui.",
                file=sys.stderr,
            )
            return
        if version_tuple < (0, 6, 15):
            print(
                f"Warning: OpenWebUI version {version} is below 0.6.15; continuing due to override.",
                file=sys.stderr,
            )
    else:
        if not args.allow_unstable_openwebui:
            print(
                "Unable to determine OpenWebUI version (need >= 0.6.15). Use --allow-unstable-openwebui to override.",
                file=sys.stderr,
            )
            return
        print(
            "Warning: OpenWebUI version check failed; proceeding due to override.",
            file=sys.stderr,
        )

    model_candidates = [m for m in extract_model_names(models_payload) if m]
    models = list(dict.fromkeys(model_candidates))
    handoff_model = args.model
    if models:
        if handoff_model not in models:
            handoff_model = models[0]
            if args.model != handoff_model:
                info(
                    f"OpenWebUI handoff: model '{args.model}' not found on server; using '{handoff_model}'."
                )

    md_abs = md_path.resolve()
    report_json_abs = report_json_path.resolve()

    try:
        info(f"Uploading {md_abs.name} to OpenWebUI…")
        file_md_id = upload_openwebui_file(base, token, md_abs)
        info(f"Uploading {report_json_abs.name} to OpenWebUI…")
        file_json_id = upload_openwebui_file(base, token, report_json_abs)
        collection_name = f"homedoc-run-{run_dt.strftime('%Y%m%d-%H%M%S')}"
        collection_desc = "Artifacts from homedoc analyzer run"
        info("Creating OpenWebUI knowledge collection…")
        container_type, container_id = create_openwebui_collection(base, token, collection_name, collection_desc)
        info("Attaching artifacts to knowledge collection…")
        attach_files_to_collection(base, token, container_type, container_id, [file_md_id, file_json_id])

        llm_seed = llm_md or md_abs.read_text(encoding="utf-8")
        first_question = "What would you like to know about the computer?"
        info("Creating OpenWebUI chat thread…")
        chat_id, assistant_message_id = create_openwebui_chat(
            base,
            token,
            handoff_model,
            llm_seed,
            run_dt,
            first_question,
        )
        info("Triggering OpenWebUI completion…")
        session_id = trigger_openwebui_completion(
            base,
            token,
            handoff_model,
            chat_id,
            container_id,
            container_type,
            llm_seed,
            first_question,
            assistant_message_id,
        )
        info("Waiting for OpenWebUI response…")
        chat_payload = poll_openwebui_chat(base, token, chat_id, assistant_message_id)
        sync_openwebui_chat(base, token, chat_id, chat_payload, assistant_message_id)
        link_openwebui_collection_to_chat(base, token, chat_id, container_type, container_id)
        try:
            complete_openwebui_session(
                base,
                token,
                chat_id,
                assistant_message_id,
                handoff_model,
                session_id,
            )
        except urllib.error.HTTPError as completion_err:
            if completion_err.code not in (404, 405):
                raise
        base = effective_openwebui_base(base)
    except urllib.error.HTTPError as e:
        print(f"OpenWebUI API error (HTTP {e.code}): {e.reason}", file=sys.stderr)
        return
    except urllib.error.URLError as e:
        print(f"OpenWebUI connection error: {e}", file=sys.stderr)
        return
    except Exception as e:
        print(f"OpenWebUI handoff failed: {e}", file=sys.stderr)
        return

    base = effective_openwebui_base(base)
    home_url = f"{base}/"
    chat_url = f"{base}/c/{chat_id}"
    print("OpenWebUI home:", home_url)
    print("OpenWebUI chat:", chat_url)

    if args.open_browser:
        try:
            webbrowser.open(home_url)
            time.sleep(0.5)
            webbrowser.open(chat_url)
        except Exception as e:
            print(f"Failed to open browser: {e}", file=sys.stderr)

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

    ensure_openwebui_artifacts(args)

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
        report_json_path = fname("report", "json") if args.handoff == "w" else None
        debug_path = fname("debug", "log") if args.debug else None
        events_path = fname("events", "jsonl") if args.json else None
        insights_path = fname("insights", "json") if args.json else None
        raw_path = fname(
            "raw.journal" if args.source=="journal" else ("raw.dmesg" if args.source=="dmesg" else "raw.mixed"),
            "jsonl" if args.source=="journal" else "log"
        ) if args.log else None
        thinking_path = fname("thinking", "txt") if args.show_thinking else None
    else:
        outdir = None
        if args.stream_only:
            md_path = None
            report_json_path = None
            debug_path = None
            events_path = insights_path = raw_path = thinking_path = None
        else:
            if args.outfile:
                md_path = subst_placeholders(Path(args.outfile), run_id, model_tag)
                md_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                md_path = Path.cwd() / f"{APP_NAME}_{run_id}{model_suffix}_report.md"
            report_json_path = md_path.with_suffix(".json") if args.handoff == "w" else None
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
        if folder_mode and args.show_thinking and thinking_text and thinking_path is not None:
            thinking_path.write_text(thinking_text, encoding="utf-8")
        if args.stream_only and args.show_thinking and thinking_text:
            print("\n\n---\nModel thinking (verbatim):\n")
            print(thinking_text.strip())
            print("\n---")

    run_meta: Optional[Dict[str, str]] = None

    # Report
    if not args.stream_only:
        run_meta = {
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
        transparency = thinking_text if (args.show_thinking and not folder_mode) else None
        md = make_report_md(run_meta, clusters, llm_md, transparency)
        if md_path is not None:
            md_path.write_text(md, encoding="utf-8")
        if report_json_path is not None:
            json_payload = make_report_json(
                run_meta,
                clusters,
                llm_md,
                thinking_text if args.show_thinking else None,
            )
            report_json_path.write_text(
                json.dumps(json_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

    # Debug log
    if debug_path is not None:
        dbg.flush_to(debug_path)

    # Final status
    if not args.stream_only:
        if folder_mode:
            info(f"Wrote outputs to: {outdir}")
        else:
            info(f"Wrote outputs to: {md_path}")

    if args.handoff == "w":
        run_openwebui_handoff(args, run_meta, md_path, report_json_path, llm_md, run_dt)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
