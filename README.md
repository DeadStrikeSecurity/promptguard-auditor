# PromptGuard Auditor

An automated red-teaming framework that tests whether an LLM chatbot's
system-prompt guardrail actually holds up against prompt-injection attacks.

Built by Scott Taylor for CYB 333 Security Automation (Fall 2026).

## Objectives

Prompt injection is the top risk on the OWASP Top 10 for LLM Applications.
Testing a guardrail by hand (typing tricks into a chat box) is slow,
inconsistent and impossible to repeat. This project automates the whole
loop so a guardrail can be audited the same way every time:

1. Generate hundreds of attack prompts from a structured taxonomy.
2. Fire each one at a guarded chatbot.
3. Automatically decide whether the guardrail held or leaked.
4. Produce a ranked report showing which attack categories work best.

The chatbot under test is given a fake secret (`PINEAPPLE-7742`) and told
never to reveal it. Using an exact secret makes "did the attack work?" a
yes/no question the computer can answer without a human reading every reply.

## Features

- **Three-axis payload generator** based on the Arcanum Prompt Injection
  Taxonomy (PITAX): 2 intents x 15 techniques x 3 core evasions = 90
  payloads, expandable to 660 with `--stretch` (19 extra encodings such as
  NATO phonetic, Braille, fullwidth, zalgo and right-to-left override).
- **Multi-turn attacks**: real back-and-forth conversations and fabricated
  "planted history" conversations where the model appears to have already
  complied.
- **PITAX reference suite**: 424 published example prompts from the taxonomy
  itself (`data/pitax_reference.json`), so results are not limited to attacks
  I wrote myself.
- **Decode-aware scorer**: catches the secret even if it comes back
  reversed, spaced out, base64, hex, binary, ROT13 or any of the 19 encodings.
- **LLM-as-judge scorer** (`scoring/judge.py`) for future intents that have no
  fixed string to match, such as unauthorized professional advice.
- **Swappable backends**: Anthropic, OpenAI, a local Ollama model, or a
  built-in `mock` target that needs no key and leaks on purpose (a positive
  control that proves the scorer can detect a break).
- **Reports**: a ranked `.txt` summary plus a raw per-payload `.csv` for every
  run, timestamped in `results/`.
- **Resilient runner**: a failed API call (rate limit, timeout, refusal with
  no text) is recorded and the run continues instead of crashing.

## How the pieces fit together

```
generator/  -->  runner/   -->  target/   -->  scoring/  -->  reporting/
(builds        (sends each    (the chatbot   (checks if     (aggregates
 attack         payload to     under test)    the guardrail  results into
 prompts)       the target)                   held or        a ranked
                                              broke)         report)
```

| Path | Purpose |
|---|---|
| `cli.py` | Single entry point that runs the whole pipeline |
| `target/chatbot.py` | Guardrail system prompt and the `TargetChatbot` class |
| `target/providers.py` | Common interface over Anthropic, OpenAI, Ollama and mock |
| `generator/generate.py` | Intent x technique x evasion payload grid |
| `generator/multi_turn.py` | Real and fabricated multi-turn scripts |
| `generator/reference.py` | Loads the PITAX reference prompts |
| `evasions_lib.py` | 19 extra encoders and matching decoders |
| `runner/run.py` | Sends payloads and records responses or errors |
| `scoring/score.py` | Keyword and decode-aware leak detection |
| `scoring/judge.py` | Model-based judge for non-keyword intents |
| `reporting/report.py` | Text and CSV reports |
| `tests/` | Offline unit and end-to-end tests |
| `results/` | Saved reports from the live runs |
| `FINDINGS.md` | Write-up of the results against real models |

## Prerequisites

- Python 3.10 or newer (developed on 3.14)
- `pip` packages in `requirements.txt` (`anthropic`, `openai`, `requests`)
- For live runs, one of:
  - an Anthropic API key (`ANTHROPIC_API_KEY`)
  - an OpenAI API key (`OPENAI_API_KEY`)
  - [Ollama](https://ollama.com) running locally with a model pulled

No key is needed for the `mock` provider or the test suite.

## Setup

```bash
git clone https://github.com/DeadStrikeSecurity/promptguard-auditor.git
cd promptguard-auditor
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### API keys

Keys are read from environment variables only and are **never** stored in
the code or committed to the repository (`.env` is in `.gitignore`).

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

## Usage

Run all commands from the project root.

```bash
# Sanity check with the built-in weak target (no key, no cost)
python cli.py --provider mock

# Live run against Claude (default model: claude-sonnet-5)
python cli.py --provider anthropic

# Pick a model and slow down to respect rate limits
python cli.py --provider anthropic --model claude-haiku-4-5 --delay 1

# Full 660-payload grid with all 19 extra encodings
python cli.py --provider anthropic --stretch

# Cheaper sample: 3 random extra encodings per technique
python cli.py --provider anthropic --stretch --sample-evasions 3

# Only the 424 published PITAX example prompts
python cli.py --provider anthropic --reference-only

# Local model through Ollama
python cli.py --provider ollama --model gemma4:12b
```

Run `python cli.py --help` for every option. Reports are written to
`results/` (change with `--out-dir`).

### Example output (mock target)

```
Overall: 6/90 payloads leaked the secret (7%)

By technique (worst-held first):
  stacked_authority_end_sequence   4/6   leaked (67%)
  authority_claim          2/6   leaked (33%)
  direct                   0/6   leaked (0%)
  ...
```

## Testing

```bash
python -m unittest discover -s tests -v   # 20 offline tests
python -m scoring.judge                     # judge self-test (9 checks)
python evasions_lib.py                      # encoder/decoder round-trip self-test
```

The tests cover the scorer (plain, reformatted, partial and every encoded
leak), grid sizing, runner error handling, provider errors and report edge
cases.

## Results summary

Against Claude Sonnet 5 and Claude Haiku 4.5, the guardrail held on every
attempt: 0 leaks across roughly 2,100 live attacks (the 660-payload grid,
the multi-turn scripts and the 424 PITAX reference prompts, for each model).
The mock positive control does leak, which shows the zero is a real result
and not a blind scorer. See [FINDINGS.md](FINDINGS.md) for the full analysis,
including the different refusal behavior of the two models.

## Ethics and scope

This tool only attacks a chatbot that it creates itself, guarding a fake
secret. Do not point it at systems you do not own or have permission to test.

## Credits

Technique and evasion categories, plus the reference prompts, come from the
Arcanum Prompt Injection Taxonomy (v1.6.1) by Jason Haddix, Arcanum
Information Security, used under CC BY 4.0. AI assistance (Claude, GitHub
Copilot) was used during development, as described in the course report.
