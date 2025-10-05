# Changelog

## Unreleased
- _Nothing yet_

## 0.1.2 — 2025-10-05
- Add OpenWebUI hand-off workflow that seeds a chat, uploads artifacts, and links a knowledge collection.
- Gracefully skip OpenWebUI integration when credentials or network access are missing instead of failing.
- Export full `journalctl` JSON dumps alongside clustered insights for better forensic follow-up.
- Document `lyseur` as an alias for the `homedoc-journal-analyzer` CLI and expose it as an additional console script.

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
