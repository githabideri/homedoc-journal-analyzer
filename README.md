# General Info
Second member of the homedoc scripts that query local computer or network feature, parses its content and produces a small (local) LLM enhanced report; HomeDoc — Journal Analyzer queries status of tailscale and writes a timestamped report.

I am experimenting to find potential use cases for local LLMs as semantic engines that convert the often too technical program outputs into more understandable reports/explanation/documentation for us half or two third literates in the world of technical jargon. Maybe this or similar scripts can be useful to somebody.

# Disclaimer
This and other scripts (as well as accompanying texts/files/documentation) are written by (mostly) GPT-5, so be aware of potential security issues or plain nonsense; never run code that you haven't inspected. I tried to minimize the potential damage by sticking to the very simple approach of single file scripts with as little dependencies as possible.

If you want to commit, feel free to fork, mess around and put "ai slop" on my "ai slop", or maybe deslop it enirely, but there is no garantuee that I will incorporate changes.

# HomeDoc — Journal Analyzer

![version](https://img.shields.io/badge/version-0.1.3-blue.svg)
![license](https://img.shields.io/badge/license-GPLv3-blue.svg)

Single-file, stdlib-only utility that:
1) reads Linux logs (`journalctl` and/or `dmesg`) with sensible presets,
2) clusters repeated problems,
3) (optionally) asks a local LLM (Ollama-compatible HTTP) to produce a concise Markdown triage,
4) writes either a **flat** single-file report (default) or a folder with artifacts.

> Designed to mirror the style/flags of the first homedoc script (tailscale status).

> The CLI installs as `homedoc-journal-analyzer` with a shorter alias `lyseur`.

## Run or Install

```bash
# Run directly without installing (quick streaming triage)
python3 homedoc_journal_analyzer.py --quick

# Or via the installed CLI entry points (alias: lyseur)
homedoc-journal-analyzer --quick
# or
lyseur --quick
```

```bash
pipx install .
# or
pip install .
```

## Quickstart

```bash
# Flat output directly into a file (placeholders: {ts}, {model})
homedoc-journal-analyzer \\
  --server http://localhost:11434/api/generate \\
  --model qwen3:14b \\
  --outfile ~/Obsidian/IT/homedoc/journal_analyzer/{ts}_{model}_journal.md

# or use the alias
lyseur \\
  --server http://localhost:11434/api/generate \\
  --model qwen3:14b \\
  --outfile ~/Obsidian/IT/homedoc/journal_analyzer/{ts}_{model}_journal.md
```

### Interactive helper

Run without flags (or pass `--interactive`) to open a guided prompt that starts from the one-hour quick scan and lets you pick the model (gemma3:12b default, `q` for gemma3:4b, `t` for qwen3:14b, or custom), server, and how to display the reply (`Enter`=terminal without thinking, `t`=terminal plus the model's `<thinking>` block, `f`=file report). Advanced prompts cover look-back window, filters, artifacts, and whether to include the thinking transcript by default.

### Folder mode (automatically when --outdir or extra artifacts)

```bash
# Folder mode works with either entry point name
homedoc-journal-analyzer --all --tag-model --outdir ~/Obsidian/IT/homedoc/runs
# or
lyseur --all --tag-model --outdir ~/Obsidian/IT/homedoc/runs
```

### Outputs and artifacts

- Markdown triage report (always when not streaming only).
- `journal.full_<ts>[_<model>].json` — complete JSON array of every journalctl event that was analyzed (written whenever the
  journal source is in scope, regardless of other artifact flags).
- Optional extras when the respective flags are enabled: clustered events (`events_*.jsonl`), insights summary (`insights_*.json`),
  raw log capture (`raw.*`), debug stream transcript, and thinking traces.

## Key flags

- `--source journal|dmesg|both` (default: journal)
- `--mode error|warn|all|security|boot|kernel` (default: error)
- `--last 24h` / `--since` / `--until`
- `--grep REGEX`
- **Output layout**
  - `--outfile PATH` (flat; supports `{ts}` and `{model}` placeholders)
  - `--outdir DIR` (forces folder mode), `--no-flat` (folder), `--tag-model`, `--no-stamp-names`
  - `--md` (default), `--json`, `--log`, `--all`
- **LLM**
  - `--server` (alias of `--model-url`), `--model` (default: qwen3:14b), `--no-llm`
- `--quick` (1h journal errors, gemma3:4b, streamed output without thinking), `--interactive`
- `--show-thinking` (include the model's `<thinking>` block in terminal/file outputs)
- **Guards**
  - `--max-entries`, `--limit`, `--yes`, `--no`
- **OpenWebUI hand-off**
  - `--openwebui` uploads the generated Markdown report (and any extra artifacts) to an OpenWebUI chat, seeds the first assistant
    reply with the local LLM summary, links a knowledge collection, and opens the chat in your browser.
  - Provide credentials via `--openwebui-base` / `--openwebui-token` or set `HOMEDOC_OPENWEBUI_BASE` / `HOMEDOC_OPENWEBUI_TOKEN`.
  - The interactive wizard prompts for the base URL and token when you enable the hand-off.

## OpenWebUI workflow

When `--openwebui` is enabled the script:

1. Creates a fresh chat seeded with the triage metadata and top cluster summary.
2. Uploads the Markdown report and any other generated artifacts, waits for OpenWebUI to process them, and stores them in a new
   knowledge collection.
3. Links the knowledge collection to the chat so the attachments show up immediately alongside the seeded user turn.
4. Prefills the assistant response with the local LLM's Markdown summary (or a fallback note when the LLM was disabled).
5. Marks the assistant turn as complete and launches your browser directly to the new chat so you can continue the
   investigation inside OpenWebUI.

> Tip: the token is a standard OpenWebUI API token (same as used by their CLI). Store it in `HOMEDOC_OPENWEBUI_TOKEN` if you
> don't want to pass it on every invocation.

## Update

If you installed with `pipx`, refresh the package:

```bash
pipx upgrade homedoc-journal-analyzer
```

For a `pip` installation:

```bash
pip install --upgrade homedoc-journal-analyzer
```

## Debugging

`--debug` logs:
- full LLM JSON payload (prompt + options) once,
- 10s streaming summaries (elapsed, chunks, chars, ~tokens, tok/s),
- final summary,
- cluster preview (top 20).

> Security note: payloads include real log text; only enable on trusted hosts.

## Preflight

- The script counts candidate lines first to avoid grinding through millions of events and to allow capping the work load. 
- If over the threshold (`--max-entries`), you'll be prompted (or auto-capped with `--yes`/CI).

## License

GPL-3.0-or-later. See `LICENSE`.
