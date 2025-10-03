# Changelog

## Unreleased
- Document `lyseur` as an alias for the `homedoc-journal-analyzer` CLI and publish it as an additional console script.

## 0.1.2 — 2025-10-02
- Added: OpenWebUI handoff (`--handoff w`) to continue analysis in a dedicated chat.
- Features: uploads `report.md`/`report.json`, creates a knowledge collection, seeds a new chat with the prior output, triggers the first assistant reply, and prints the deep link.
- Security: Bearer token required; stateless, never persisted.

## 0.1.1 — 2025-10-01
- Normalize `--server` to assume `http://<host>:11434/api/generate` while still accepting full URLs.
- Add `--quick` streaming mode and an interactive wizard (default when no flags).
- Stream LLM output directly to the terminal for quick/interactive runs.
- Make thinking transcripts opt-in with `--show-thinking` and new interactive display choices.
- Refresh README with run/install/update notes and new defaults.

## 0.1.0 — 2025-09-30
- Initial release of homedoc-journal-analyzer.
- Flat single-file Markdown by default; folder mode for multi-artifact runs.
- `--server` alias kept (like tailscale script).
- Unified `--debug` with payload capture and streaming summaries.
