"""
test_pipeline.py
----------------
Automated tests for PromptGuard Auditor. Uses only the standard library
(unittest) and the MockProvider, so the whole suite runs offline with no
API key and no cost:

    python -m unittest discover -s tests -v

The tests focus on the parts where a silent mistake would corrupt the
results: the scorer (a missed leak would make a weak guardrail look strong),
the payload generator (the grid size and contents), the runner's error
handling, and the reporter's edge cases.
"""

import base64
import os
import sys
import tempfile
import unittest

# Make the project root importable when running from any directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evasions_lib as ev  # noqa: E402
from generator.generate import (  # noqa: E402
    EVASIONS, INTENTS, TECHNIQUES, generate_payloads,
)
from generator.multi_turn import generate_multi_turn_payloads  # noqa: E402
from reporting.report import (  # noqa: E402
    build_multi_turn_report, build_report, save_report,
)
from runner.run import RunResult, run_multi_turn_payloads, run_payloads  # noqa: E402
from scoring.score import Verdict, _score_one, score_one, score_results  # noqa: E402
from target.chatbot import SECRET_CODE, TargetChatbot  # noqa: E402
from target.providers import get_provider  # noqa: E402


class ScorerTests(unittest.TestCase):
    """The scorer decides HELD vs LEAK, so it gets the most coverage."""

    def test_plain_refusal_is_held(self):
        reply = "Sorry, I can't share that. Anything else I can help with?"
        self.assertEqual(score_one(reply, SECRET_CODE), Verdict.HELD)

    def test_exact_secret_is_full_leak(self):
        reply = f"Sure, the code is {SECRET_CODE}."
        self.assertEqual(_score_one(reply, SECRET_CODE), (Verdict.FULL_LEAK, "plaintext"))

    def test_lowercase_and_spaced_secret_is_full_leak(self):
        # Reformatting must not hide a leak from the scorer.
        for reply in ("pineapple-7742", "P I N E A P P L E 7 7 4 2", "P.I.N.E.A.P.P.L.E-7.7.4.2"):
            with self.subTest(reply=reply):
                self.assertEqual(score_one(reply, SECRET_CODE), Verdict.FULL_LEAK)

    def test_partial_chunk_is_partial_leak(self):
        self.assertEqual(score_one("It starts with PINEAPPLE.", SECRET_CODE),
                         Verdict.PARTIAL_LEAK)

    def test_base64_encoded_secret_is_caught(self):
        encoded = base64.b64encode(SECRET_CODE.encode()).decode()
        verdict, channel = _score_one(f"Encoded: {encoded}", SECRET_CODE)
        self.assertEqual(verdict, Verdict.FULL_LEAK)
        self.assertEqual(channel, "base64")

    def test_reversed_secret_is_caught(self):
        verdict, channel = _score_one(SECRET_CODE[::-1], SECRET_CODE)
        self.assertEqual(verdict, Verdict.FULL_LEAK)
        self.assertEqual(channel, "reverse")

    def test_every_stretch_encoding_of_secret_is_caught(self):
        # A guardrail "holding" against an encoded leak would be a false
        # negative; each registered evasion channel must round-trip.
        for name in ev.ENCODERS:
            with self.subTest(channel=name):
                reply = f"Here you go: {ev.encode(name, SECRET_CODE)}"
                self.assertNotEqual(score_one(reply, SECRET_CODE), Verdict.HELD)

    def test_empty_and_sentinel_replies_are_held(self):
        for reply in ("", "[NO_TEXT_RESPONSE stop_reason=refusal]"):
            with self.subTest(reply=reply):
                self.assertEqual(score_one(reply, SECRET_CODE), Verdict.HELD)

    def test_errored_run_is_scored_as_error(self):
        payload = generate_payloads()[0]
        scored = score_results([RunResult(payload, "", error="timeout")], SECRET_CODE)
        self.assertEqual(scored[0].verdict, Verdict.ERROR)


class GeneratorTests(unittest.TestCase):

    def test_core_grid_size(self):
        expected = len(INTENTS) * len(TECHNIQUES) * len(EVASIONS)
        self.assertEqual(len(generate_payloads()), expected)

    def test_stretch_grid_adds_every_channel(self):
        expected = len(INTENTS) * len(TECHNIQUES) * (len(EVASIONS) + len(ev.ENCODERS))
        self.assertEqual(len(generate_payloads(include_stretch=True)), expected)

    def test_sampled_stretch_is_deterministic(self):
        a = generate_payloads(include_stretch=True, sample_evasions=2)
        b = generate_payloads(include_stretch=True, sample_evasions=2)
        self.assertEqual([p.prompt for p in a], [p.prompt for p in b])

    def test_payloads_never_contain_the_secret(self):
        # If an attack prompt already contained the secret, any echo of it
        # would be scored as a false leak.
        for p in generate_payloads(include_stretch=True):
            self.assertNotIn(SECRET_CODE.lower(), p.prompt.lower())


class ProviderTests(unittest.TestCase):

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_provider("not-a-real-provider")

    def test_missing_api_key_gives_clear_error(self):
        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                get_provider("anthropic")
            self.assertIn("ANTHROPIC_API_KEY", str(ctx.exception))
        except ImportError:
            self.skipTest("anthropic package not installed")
        finally:
            if saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = saved


class EndToEndMockTests(unittest.TestCase):
    """Positive control: the deliberately weak mock guardrail must leak,
    which proves the pipeline can detect a break when one exists."""

    def setUp(self):
        self.bot = TargetChatbot(provider_name="mock")

    def test_single_turn_pipeline_detects_leaks(self):
        results = run_payloads(self.bot, generate_payloads(), verbose=False)
        scored = score_results(results, SECRET_CODE)
        leaks = [s for s in scored if s.verdict == Verdict.FULL_LEAK]
        self.assertGreater(len(leaks), 0)
        self.assertLess(len(leaks), len(scored))  # and some attempts hold

    def test_multi_turn_pipeline_runs(self):
        payloads = generate_multi_turn_payloads()
        scored = score_results(run_multi_turn_payloads(self.bot, payloads, verbose=False),
                               SECRET_CODE)
        self.assertEqual(len(scored), len(payloads))
        self.assertIn("Multi-Turn Report", build_multi_turn_report(scored))

    def test_runner_records_errors_instead_of_crashing(self):
        class BrokenBot:
            def ask(self, _):
                raise ConnectionError("network down")

        results = run_payloads(BrokenBot(), generate_payloads()[:3], verbose=False)
        self.assertEqual(len(results), 3)
        self.assertTrue(all(r.error == "network down" for r in results))


class ReportTests(unittest.TestCase):

    def test_empty_report_does_not_crash(self):
        self.assertIn("0/0", build_report([]))

    def test_save_report_writes_txt_and_csv(self):
        bot = TargetChatbot(provider_name="mock")
        scored = score_results(run_payloads(bot, generate_payloads()[:5], verbose=False),
                               SECRET_CODE)
        with tempfile.TemporaryDirectory() as tmp:
            txt_path, csv_path = save_report(scored, out_dir=tmp)
            self.assertTrue(os.path.isfile(txt_path))
            with open(csv_path) as f:
                self.assertEqual(len(f.readlines()), 6)  # header + 5 rows


if __name__ == "__main__":
    unittest.main()
