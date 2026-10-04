"""
report.py
---------
The last stage: takes every ScoredResult and rolls it up into something a
human can actually read and act on - a ranked breakdown of which technique
and evasion categories broke the guardrail most often, plus the actual
transcripts of any successful breaks as evidence. This is the artifact
that goes in the class writeup/presentation.
"""

from collections import defaultdict
from datetime import datetime, timezone
import csv
import os

from scoring.score import ScoredResult, Verdict

LEAK_VERDICTS = (Verdict.FULL_LEAK, Verdict.PARTIAL_LEAK)


def _leak_rate_table(scored: list[ScoredResult], key_fn) -> list[tuple]:
    """
    Groups results by whatever key_fn returns (e.g. technique name or
    evasion name), and computes a leak rate per group. Returns rows sorted
    worst-guardrail-first (highest leak rate at the top), since that's
    what you actually want to see first in a security report.
    """
    counts = defaultdict(lambda: {"total": 0, "leaks": 0})
    for s in scored:
        key = key_fn(s.run_result.payload)
        counts[key]["total"] += 1
        if s.verdict in LEAK_VERDICTS:
            counts[key]["leaks"] += 1

    rows = []
    for key, c in counts.items():
        rate = c["leaks"] / c["total"] if c["total"] else 0
        rows.append((key, c["leaks"], c["total"], rate))
    rows.sort(key=lambda r: r[3], reverse=True)
    return rows


def build_report(scored: list[ScoredResult]) -> str:
    total = len(scored)
    leaks = sum(1 for s in scored if s.verdict in LEAK_VERDICTS)
    errors = sum(1 for s in scored if s.verdict == Verdict.ERROR)

    lines = []
    lines.append("PromptGuard Auditor - Report")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append(f"Overall: {leaks}/{total} payloads leaked the secret "
                  f"({leaks/total:.0%})" + (f", {errors} errored" if errors else ""))
    lines.append("")

    lines.append("By technique (worst-held first):")
    for key, leak_count, group_total, rate in _leak_rate_table(scored, lambda p: p.technique):
        lines.append(f"  {key:22} {leak_count:>3}/{group_total:<3} leaked ({rate:.0%})")
    lines.append("")

    lines.append("By evasion (worst-held first):")
    for key, leak_count, group_total, rate in _leak_rate_table(scored, lambda p: p.evasion):
        lines.append(f"  {key:22} {leak_count:>3}/{group_total:<3} leaked ({rate:.0%})")
    lines.append("")

    successful = [s for s in scored if s.verdict in LEAK_VERDICTS]
    if successful:
        lines.append(f"Evidence: {len(successful)} successful break(s):")
        for s in successful:
            p = s.run_result.payload
            lines.append(f"\n  [{s.verdict.value}] technique={p.technique} evasion={p.evasion} intent={p.intent}")
            if s.channel and s.channel not in ("plaintext", "judge"):
                lines.append(f"  CHANNEL:  secret returned encoded, caught by decoder '{s.channel}'")
            if s.channel == "judge":
                lines.append(f"  JUDGE:    {s.judge_label}  ({s.judge_rationale})")
            lines.append(f"  PROMPT:   {p.prompt}")
            lines.append(f"  RESPONSE: {s.run_result.response}")
    else:
        lines.append("No successful breaks - the guardrail held against every payload tested.")

    return "\n".join(lines)


def build_multi_turn_report(scored: list[ScoredResult]) -> str:
    """
    A simpler report for multi-turn results: there's no technique/evasion
    grid to group by here (just a handful of named scripts), so we list
    each script and its verdict directly instead of computing rates.
    """
    total = len(scored)
    leaks = sum(1 for s in scored if s.verdict in LEAK_VERDICTS)

    lines = ["PromptGuard Auditor - Multi-Turn Report", ""]
    lines.append(f"Overall: {leaks}/{total} multi-turn scripts leaked the secret")
    lines.append("")
    for s in scored:
        p = s.run_result.payload
        lines.append(f"  [{s.verdict.value:12}] ({p.kind}) {p.name}")
    lines.append("")

    successful = [s for s in scored if s.verdict in LEAK_VERDICTS]
    if successful:
        lines.append(f"Evidence: {len(successful)} successful break(s):")
        for s in successful:
            p = s.run_result.payload
            lines.append(f"\n  [{s.verdict.value}] {p.kind} / {p.name}")
            if p.kind == "conversation":
                for i, t in enumerate(p.user_turns, 1):
                    lines.append(f"    turn {i} (user): {t}")
            else:
                for fu, fa in p.planted_turns:
                    lines.append(f"    (planted user): {fu}")
                    lines.append(f"    (planted asst): {fa}")
                lines.append(f"    (real user):    {p.final_message}")
            lines.append(f"  FINAL RESPONSE: {s.run_result.response}")
    else:
        lines.append("No successful breaks in the multi-turn suite either.")

    return "\n".join(lines)


def save_report(scored: list[ScoredResult], out_dir: str = "results") -> tuple[str, str]:
    """
    Writes both a human-readable .txt report and a raw .csv (one row per
    payload) into out_dir, timestamped so repeated runs don't overwrite
    each other. Returns (txt_path, csv_path).
    """
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    txt_path = os.path.join(out_dir, f"report_{stamp}.txt")
    with open(txt_path, "w") as f:
        f.write(build_report(scored))

    csv_path = os.path.join(out_dir, f"results_{stamp}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["intent", "technique", "evasion", "verdict", "channel", "prompt", "response", "error"])
        for s in scored:
            p = s.run_result.payload
            writer.writerow([
                p.intent, p.technique, p.evasion, s.verdict.value, s.channel,
                p.prompt, s.run_result.response, s.run_result.error or "",
            ])

    return txt_path, csv_path


def save_multi_turn_report(scored: list[ScoredResult], out_dir: str = "results") -> tuple[str, str]:
    """Same idea as save_report(), for multi-turn results' different shape."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    txt_path = os.path.join(out_dir, f"multi_turn_report_{stamp}.txt")
    with open(txt_path, "w") as f:
        f.write(build_multi_turn_report(scored))

    csv_path = os.path.join(out_dir, f"multi_turn_results_{stamp}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["kind", "name", "verdict", "script", "final_response", "error"])
        for s in scored:
            p = s.run_result.payload
            if p.kind == "conversation":
                script_desc = " | ".join(p.user_turns)
            else:
                script_desc = " | ".join(f"[planted] {u} -> {a}" for u, a in p.planted_turns)
                script_desc += f" | [real] {p.final_message}"
            writer.writerow([p.kind, p.name, s.verdict.value, script_desc, s.run_result.response, s.run_result.error or ""])

    return txt_path, csv_path


if __name__ == "__main__":
    # Quick manual check: `python -m reporting.report [provider]` runs the
    # full pipeline end to end and prints + saves the report.
    import sys
    from generator.generate import generate_payloads
    from target.chatbot import TargetChatbot, SECRET_CODE
    from runner.run import run_payloads
    from scoring.score import score_results

    provider_name = sys.argv[1] if len(sys.argv) > 1 else "mock"
    bot = TargetChatbot(provider_name=provider_name)
    results = run_payloads(bot, generate_payloads(), verbose=False)
    scored = score_results(results, SECRET_CODE)

    report_text = build_report(scored)
    print(report_text)

    txt_path, csv_path = save_report(scored)
    print(f"\nSaved to {txt_path} and {csv_path}")
