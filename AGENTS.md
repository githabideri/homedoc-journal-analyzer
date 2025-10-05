# AGENTS GUIDE

## Project Snapshot
- **Name**: HomeDoc — Journal Analyzer (`homedoc-journal-analyzer`, CLI alias `lyseur`).
- **Purpose**: Read `journalctl`/`dmesg`, cluster recurring issues, optionally summarize with a local LLM, and emit Markdown or artifact bundles.
- **Language**: Python 3.9+ (stdlib only).
- **Entry Point**: `homedoc_journal_analyzer.py` (also exported via `pyproject.toml` console scripts).
- **Versioning**: Bump `VERSION` in `homedoc_journal_analyzer.py` and `pyproject.toml` together.

## Layout Cheat Sheet
- `homedoc_journal_analyzer.py` — full CLI implementation, including clustering, LLM hand-off, and artifact writers.
- `README.md` — user-facing quickstart and flag reference; keep in sync with CLI defaults.
- `pyproject.toml` — packaging metadata; `setuptools` build backend.
- `Makefile` — helper targets: `install`, `run`, `build`, `clean`.
- `artifacts/` — captured reports, debug logs, and chat exports; treat as examples, do not rely on them for automated tests.
- `build/`, `CHANGELOG.md`, `LICENSE` — standard packaging/support files.

## Running the Tool
- Streaming quick scan: `python homedoc_journal_analyzer.py --quick`.
- Full CLI help: `python homedoc_journal_analyzer.py --help`.
- Installed entry points: `homedoc-journal-analyzer` and `lyseur`.
- Interactive wizard: run with no flags or `--interactive` to step through presets, choose models, toggle artifacts, etc.

## LLM & Environment Hooks
- Defaults pull from env vars: `HOMEDOC_SERVER`, `HOMEDOC_MODEL_URL`, `HOMEDOC_MODEL`, `HOMEDOC_LAST`, `HOMEDOC_MAX_ENTRIES`.
- LLM endpoint expects Ollama-compatible `/api/generate`; disable via `--no-llm` when offline.
- OpenWebUI integration requires `--openwebui` plus base/token flags or env vars (`HOMEDOC_OPENWEBUI_BASE`, `HOMEDOC_OPENWEBUI_TOKEN`).
- Redaction options (`--redact ips,macs,nums,hex`) apply to outputs only; clustering still sees raw data.

## Artifacts & Output Modes
- Flat mode (default) writes a single Markdown report; target file controlled by `--outfile` with `{ts}`/`{model}` tokens.
- Folder mode auto-enables when requesting extras or using `--outdir`/`--no-flat`; emits Markdown, clustered events, JSON exports, raw logs, debug streams, and thinking traces as requested.
- Preflight guard (`--max-entries`, `--limit`, `--yes`, `--no`) protects against huge journal reads; respect it when scripting.

## Development Workflow
- Editable install: `python -m pip install -e .` (or `make install` which upgrades `pip` and installs editable package).
- Local smoke test: `make run` (runs `--help`).
- Build sdist/wheel: `make build` (calls `python -m build`).
- Cleanup: `make clean` removes `dist/`, `build/`, and `*.egg-info`.
- No automated tests yet; consider adding regression coverage for clustering, artifact naming, and OpenWebUI hand-off stubs before major refactors.

## Git Conventions
- Primary remote is named `github` (not `origin`); e.g., `git fetch github main`.
- Keep generated reports or large artifacts out of commits unless they are deliberately curated examples.
- Repository may be in a dirty state; avoid clobbering existing local edits when scripting updates.

## Agent Field Notes
- Requires Linux journal access; `journalctl`/`dmesg` must be present and readable by the user.
- Verbose logging is on by default; watch for sensitive data in debug artifacts before sharing.
- Exit codes signal specific failure classes (see header docstring in `homedoc_journal_analyzer.py`).
- When updating CLI flags, mirror changes in README tables and docstrings to prevent drift.
- If coordinating with other HomeDoc tools, align flag naming (`--server`, `--model`, tagging/stamping options) for cross-script consistency.
