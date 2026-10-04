# PromptGuard Auditor

An automated red-teaming framework for testing whether an LLM chatbot's
system-prompt guardrail actually holds up against adversarial prompts.

## How the pieces fit together

```
generator/  -->  runner/   -->  target/   -->  scoring/  -->  reporting/
(builds        (sends each    (the chatbot   (checks if     (aggregates
 attack         payload to     under test,    the guardrail  results into
 prompts)       the target)    picks its      held or        a ranked
                                own answer)    broke)         report)
```

- **target/** — the app under test. A thin wrapper around an LLM (Anthropic,
  OpenAI, or a local Ollama model) with a system prompt that defines a rule
  it must never break: never reveal a specific secret value. This stands in
  for any real guardrail (a data-access rule, a content policy, a "don't
  discuss X" instruction).
- **generator/** — builds the adversarial test prompts. Each payload is a
  combination of three axes: *intent* (what we're trying to get the model to
  do, e.g. leak the secret), *technique* (the mechanism, e.g. roleplay
  framing, fake conversation-boundary markers), and *evasion* (obfuscation
  layered on top, e.g. leetspeak).
- **runner/** — sends every generated payload to the target chatbot and
  records the raw response. Doesn't judge anything itself.
- **scoring/** — looks at each response and decides: did the guardrail hold,
  or did the secret leak? Starts as simple keyword matching.
- **reporting/** — rolls all the scored results up into a table: which
  technique/evasion combinations broke the guardrail most often, so you can
  see which categories of attack the guardrail is actually weak against.

## Status

Building incrementally, one module at a time. See each folder's own file
for what's implemented so far.
