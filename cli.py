#!/usr/bin/env python3
"""
cli.py
------
The single entry point that ties every module together:

    generate_payloads() -> run_payloads() -> score_results() -> build_report()

Run it from the project root, e.g.:

    python cli.py --provider mock                     # no key needed, sanity check
    python cli.py --provider anthropic                 # needs ANTHROPIC_API_KEY
    python cli.py --provider openai --model gpt-6-sol   # override the default model
    python cli.py --provider ollama --model gemma4:12b  # needs Ollama running locally
"""

import argparse
import sys

from generator.generate import generate_payloads
from generator.multi_turn import generate_multi_turn_payloads
from target.chatbot import TargetChatbot, SECRET_CODE
from runner.run import run_payloads, run_multi_turn_payloads
from scoring.score import score_results
from reporting.report import build_report, save_report, build_multi_turn_report, save_multi_turn_report


def main():
    parser = argparse.ArgumentParser(description="PromptGuard Auditor - automated LLM guardrail red-teaming")
    parser.add_argument("--provider", default="mock", choices=["anthropic", "openai", "ollama", "mock"],
                         help="Which backend the target chatbot runs on (default: mock, needs no API key)")
    parser.add_argument("--model", default=None,
                         help="Override the provider's default model (e.g. gpt-6-sol, claude-haiku-4-5)")
    parser.add_argument("--delay", type=float, default=0.0,
                         help="Seconds to wait between requests (useful to stay under rate limits)")
    parser.add_argument("--out-dir", default="results",
                         help="Where to save the report and CSV (default: results/)")
    parser.add_argument("--quiet", action="store_true",
                         help="Don't print per-payload progress while running")
    parser.add_argument("--multi-turn-only", action="store_true",
                         help="Skip the single-turn suite and only run the multi-turn scripts (fewer, real conversations)")
    parser.add_argument("--skip-multi-turn", action="store_true",
                         help="Only run the single-turn suite, skip the multi-turn scripts")
    parser.add_argument("--stretch", action="store_true",
                         help="Also test every technique against the Stretch evasion channels "
                              "in evasions_lib.py (many more payloads per run)")
    parser.add_argument("--sample-evasions", type=int, default=None, metavar="N",
                         help="With --stretch, add only N randomly sampled Stretch evasions per "
                              "technique instead of all of them, to keep the run (and API bill) small")
    parser.add_argument("--reference", action="store_true",
                         help="Also run the Arcanum PITAX taxonomy's own example prompts "
                              "(data/pitax_reference.json) against the guardrail")
    parser.add_argument("--reference-only", action="store_true",
                         help="Run ONLY the PITAX reference prompts, skipping the generated grid")
    parser.add_argument("--judge-provider", default=None,
                         choices=["anthropic", "openai", "ollama", "mock"],
                         help="Enable the model judge on a backend for intents the keyword "
                              "scorer can't decide. Use a different model than --provider. "
                              "Inert unless the generator has a judged intent (see scoring/judge.py).")
    parser.add_argument("--judge-model", default=None,
                         help="Override the judge provider's default model")
    args = parser.parse_args()

    # Optional model judge for non-keyword intents.
    judge = None
    judged_intents = frozenset()
    if args.judge_provider:
        from scoring.judge import JudgeScorer, INTENT_TO_RUBRIC
        judge_kwargs = {"model": args.judge_model} if args.judge_model else {}
        judge = JudgeScorer.from_provider_name(args.judge_provider, **judge_kwargs)
        judged_intents = frozenset(INTENT_TO_RUBRIC)
        print(f"Model judge enabled on provider={args.judge_provider} "
              f"for intents: {sorted(judged_intents) or '(none present yet)'}\n")

    provider_kwargs = {"model": args.model} if args.model else {}
    try:
        bot = TargetChatbot(provider_name=args.provider, **provider_kwargs)
    except RuntimeError as e:
        # get_provider() raises this with an already-helpful, specific
        # message (missing key, Ollama unreachable, etc.) - no need for a
        # full traceback on top of it.
        print(f"Couldn't start the target chatbot: {e}")
        sys.exit(1)

    if not args.multi_turn_only:
        if args.reference_only:
            from generator.reference import generate_reference_payloads
            payloads = generate_reference_payloads()
        else:
            payloads = generate_payloads(include_stretch=args.stretch,
                                         sample_evasions=args.sample_evasions)
            if args.reference:
                from generator.reference import generate_reference_payloads
                payloads = payloads + generate_reference_payloads()
        print(f"Generated {len(payloads)} single-turn payloads. Running against provider={args.provider} "
              f"model={args.model or '(default)'} ...\n")

        results = run_payloads(bot, payloads, delay_seconds=args.delay, verbose=not args.quiet)
        scored = score_results(results, SECRET_CODE, judge=judge, judged_intents=judged_intents)

        print("\n" + build_report(scored))

        txt_path, csv_path = save_report(scored, out_dir=args.out_dir)
        print(f"\nSaved report to {txt_path}")
        print(f"Saved raw results to {csv_path}")

    if not args.skip_multi_turn:
        mt_payloads = generate_multi_turn_payloads()
        print(f"\nRunning {len(mt_payloads)} multi-turn scripts against provider={args.provider} "
              f"model={args.model or '(default)'} ...\n")

        mt_results = run_multi_turn_payloads(bot, mt_payloads, delay_seconds=args.delay, verbose=not args.quiet)
        mt_scored = score_results(mt_results, SECRET_CODE, judge=judge, judged_intents=judged_intents)

        print("\n" + build_multi_turn_report(mt_scored))

        mt_txt_path, mt_csv_path = save_multi_turn_report(mt_scored, out_dir=args.out_dir)
        print(f"\nSaved multi-turn report to {mt_txt_path}")
        print(f"Saved multi-turn raw results to {mt_csv_path}")


if __name__ == "__main__":
    main()
