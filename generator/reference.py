"""
reference.py
------------
Loads the Arcanum Prompt Injection Taxonomy's own example prompts (the ones
published behind each entry's "View" on arcanum-sec.com/pitax) as Payloads, so
the guardrail can be tested against the taxonomy's reference attacks rather than
only the home-grown payloads in generate.py.

The prompts live in data/pitax_reference.json, extracted from the official
repo (github.com/Arcanum-Sec/arc_pi_taxonomy) and filtered to the in-scope
entries for this project: the secret / system-prompt-leak / jailbreak intents,
single-turn black-box techniques, and text-based evasions. Harmful-intent,
tool/agent/RAG, local-weight, and non-text entries were excluded.

Attribution (CC BY 4.0): Based on the Arcanum Prompt Injection Taxonomy by
Jason Haddix, Arcanum Information Security (arcanum-sec.com).

Each reference prompt becomes a Payload tagged with its PIT code (e.g.
"PIT-T-56 authority_impersonation") in the `technique` field, so the report
breaks results down by taxonomy entry. Its `intent` records the source category
(pitax:intent / pitax:technique / pitax:evasion) and `evasion` is "reference".
"""

import json
import os

from generator.generate import Payload

_DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "pitax_reference.json",
)


def generate_reference_payloads(path: str = _DATA_PATH) -> list[Payload]:
    """Return one Payload per in-scope PITAX example prompt."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    payloads = []
    for r in data["prompts"]:
        payloads.append(Payload(
            intent=f"pitax:{r['category']}",
            technique=f"{r['pit_code']} {r['id']}",
            evasion="reference",
            prompt=r["prompt"],
        ))
    return payloads


if __name__ == "__main__":
    # Quick check: `python -m generator.reference` prints the count and a sample.
    ps = generate_reference_payloads()
    print(f"Loaded {len(ps)} PITAX reference payloads "
          f"across {len(set(p.technique for p in ps))} taxonomy entries.")
    for p in ps[:5]:
        print(f"  [{p.technique}] {p.prompt[:80]}")
