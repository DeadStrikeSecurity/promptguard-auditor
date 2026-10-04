"""
run.py
------
The test runner. Its job is narrow on purpose: take a list of Payloads
(from generator/generate.py) and a TargetChatbot (from target/chatbot.py),
send each payload, and record what came back. It does NOT decide whether
an attack "worked" - that's scoring/score.py's job. Keeping "send and
record" separate from "judge" means we can improve the judge later
(e.g. swap keyword matching for an LLM-as-judge) without touching this
file at all.
"""

from dataclasses import dataclass
from typing import Union
import time

from generator.generate import Payload
from generator.multi_turn import MultiTurnPayload
from target.chatbot import TargetChatbot


@dataclass
class RunResult:
    payload: Union[Payload, MultiTurnPayload]
    response: str
    error: str = None  # set if the call to the target failed


def run_payloads(
    chatbot: TargetChatbot,
    payloads: list[Payload],
    delay_seconds: float = 0.0,
    verbose: bool = True,
) -> list[RunResult]:
    """
    Send every payload to the chatbot in order, one at a time, and collect
    the results. A single payload erroring out (rate limit, network blip)
    is recorded and skipped rather than crashing the whole run - with 48+
    payloads going to a real API, some transient failures are normal, and
    we don't want one bad request to throw away everything before it.
    """
    results = []
    total = len(payloads)
    for i, payload in enumerate(payloads, start=1):
        if verbose:
            print(f"[{i}/{total}] {payload.intent} / {payload.technique} / {payload.evasion}", end=" ... ")
        try:
            response = chatbot.ask(payload.prompt)
            results.append(RunResult(payload=payload, response=response))
            if verbose:
                print("ok")
        except Exception as e:
            results.append(RunResult(payload=payload, response="", error=str(e)))
            if verbose:
                print(f"ERROR: {e}")
        if delay_seconds:
            time.sleep(delay_seconds)
    return results


def run_multi_turn_payloads(
    chatbot: TargetChatbot,
    payloads: list[MultiTurnPayload],
    delay_seconds: float = 0.0,
    verbose: bool = True,
) -> list[RunResult]:
    """
    Same job as run_payloads(), but for MultiTurnPayload scripts. The
    difference is just which TargetChatbot method to call: a "conversation"
    script makes several real calls (one per turn), a "planted_history"
    script makes one call with fabricated history attached. Scoring and
    reporting don't need to know the difference - both still come back as
    a single RunResult with one final response to judge.
    """
    results = []
    total = len(payloads)
    for i, payload in enumerate(payloads, start=1):
        if verbose:
            print(f"[{i}/{total}] {payload.kind} / {payload.name}", end=" ... ")
        try:
            if payload.kind == "conversation":
                response = chatbot.ask_conversation(payload.user_turns)
            elif payload.kind == "planted_history":
                response = chatbot.ask_with_planted_history(payload.planted_turns, payload.final_message)
            else:
                raise ValueError(f"Unknown multi-turn payload kind: {payload.kind}")
            results.append(RunResult(payload=payload, response=response))
            if verbose:
                print("ok")
        except Exception as e:
            results.append(RunResult(payload=payload, response="", error=str(e)))
            if verbose:
                print(f"ERROR: {e}")
        if delay_seconds:
            time.sleep(delay_seconds)
    return results


if __name__ == "__main__":
    # Quick manual check: `python -m runner.run [provider]` from project
    # root runs every generated payload against the given provider
    # (default: mock, so this works with no API key) and prints a summary.
    import sys
    from generator.generate import generate_payloads

    provider_name = sys.argv[1] if len(sys.argv) > 1 else "mock"
    bot = TargetChatbot(provider_name=provider_name)
    payloads = generate_payloads()
    results = run_payloads(bot, payloads)
    errors = sum(1 for r in results if r.error)
    print(f"\nDone. {len(results)} sent, {errors} errored.")
