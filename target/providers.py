"""
providers.py
------------
This file answers one question: "how do we send a system prompt + a user
message to an LLM and get a reply back?" — for three different backends.

Every provider below implements the same tiny interface (one method,
`complete`), so the rest of the project never has to know or care whether
it's talking to Anthropic, OpenAI, or a local Ollama model. This pattern is
called a "common interface" — it's the same reason a universal power
adapter works in any wall socket: everything downstream (the chatbot, the
test runner) is written once, against the interface, not against any one
vendor's API shape.

Default model IDs below were checked against each vendor's live docs on
2026-09-24 (Anthropic's platform.claude.com, OpenAI's developers.openai.com).
This space moves fast — a new model generation can ship in weeks — so treat
these as "known-good as of the date above," not permanent. Every provider
also takes `model` as a constructor argument, so you never have to edit this
file just to point at a newer model; pass it in instead (see chatbot.py).
"""

from abc import ABC, abstractmethod
import os


class LLMProvider(ABC):
    """Base class every provider must implement."""

    @abstractmethod
    def complete(self, system_prompt: str, messages: list[dict]) -> str:
        """
        Send a system prompt plus a full conversation so far, return the
        model's reply as plain text.

        `messages` is a list of {"role": "user" | "assistant", "content": str}
        dicts, in order - the same shape both Anthropic's and OpenAI's SDKs
        already use, which is exactly why we standardized on it here rather
        than inventing our own format. A single-turn test is just a list
        with one user message in it; multi-turn is the same call with more
        turns appended - this interface didn't need to change at all to
        support multi-turn, only what callers put in the list did.
        """
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    """
    Talks to Claude via the Anthropic API. Needs ANTHROPIC_API_KEY set.
    Default is Claude Sonnet 5 (`claude-sonnet-5`), Anthropic's current
    best speed/intelligence balance and recommended general-purpose default.
    Claude Haiku 4.5 (`claude-haiku-4-5`) is also current and cheaper/faster
    if you want a lighter-weight target.
    """

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic  # imported here so this file loads even if the
                           # anthropic package isn't installed and you're
                           # only using a different provider
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Get one at "
                "console.anthropic.com and set it as an environment "
                "variable before running with this provider."
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def complete(self, system_prompt: str, messages: list[dict]) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system_prompt,
            messages=messages,
        )
        # Claude can stop with an empty content list (stop_reason
        # "refusal") instead of writing any text - a hard safety-classifier
        # stop that happens before generation, distinct from the model
        # choosing in its own words to decline. Not a bug to hide: it's a
        # legitimate outcome worth recording as its own case rather than
        # crashing on content[0] or silently reporting it as a normal
        # "held" response.
        if not response.content:
            return f"[NO_TEXT_RESPONSE stop_reason={response.stop_reason}]"
        # response.content is a list of content BLOCKS, not necessarily all
        # text. With extended thinking, Claude can emit a ThinkingBlock
        # (its reasoning) before the actual TextBlock reply - so content[0]
        # is sometimes thinking, not text, and .text doesn't exist on it.
        # Concatenate only the real text blocks and ignore thinking/other
        # block types, rather than assuming position 0 is always the reply.
        text_parts = [block.text for block in response.content if block.type == "text"]
        if not text_parts:
            return f"[NO_TEXT_BLOCK stop_reason={response.stop_reason} block_types={[b.type for b in response.content]}]"
        return "".join(text_parts)


class OpenAIProvider(LLMProvider):
    """
    Talks to OpenAI via their API. Needs OPENAI_API_KEY set.
    Default is GPT-6 Luna (`gpt-6-luna`), OpenAI's current cheapest/fastest
    model in the GPT-6 family - good for high-volume automated testing like
    this. `gpt-6-sol` and `gpt-6-astra` are current, more capable (and
    pricier) options in the same family if you want a stronger target.
    """

    def __init__(self, model: str = "gpt-6-luna"):
        import openai
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Get one at "
                "platform.openai.com and set it as an environment "
                "variable before running with this provider."
            )
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model

    def complete(self, system_prompt: str, messages: list[dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system_prompt}] + messages,
        )
        return response.choices[0].message.content


class OllamaProvider(LLMProvider):
    """
    Talks to a local model served by Ollama (https://ollama.com).
    No API key needed, but Ollama must be installed and running locally
    (`ollama serve`), and the model must already be pulled
    (e.g. `ollama pull gemma4:12b`).

    Default is `gemma4:12b` — currently one of the more capable models that
    still fits on a single consumer GPU. The local-model space turns over
    fast; check https://ollama.com/library for what's current if this is
    slow, doesn't fit your hardware, or has been superseded.
    """

    def __init__(self, model: str = "gemma4:12b", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def complete(self, system_prompt: str, messages: list[dict]) -> str:
        import requests
        try:
            response = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "system", "content": system_prompt}] + messages,
                    "stream": False,
                },
                timeout=120,
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(
                "Couldn't reach Ollama at "
                f"{self.host}. Is it installed and running? Start it with "
                "`ollama serve`, and make sure you've pulled the model "
                f"with `ollama pull {self.model}`."
            ) from e
        return response.json()["message"]["content"]


class MockProvider(LLMProvider):
    """
    Not a real target — a stand-in for testing the rest of the pipeline
    (generator -> runner -> scoring -> reporting) without needing any API
    key or Ollama installed. It simulates a guardrail that's deliberately
    a little weak, so we can prove the full loop actually detects a break
    before ever touching a real model.

    Rule of thumb: if the message looks like a plain, direct request to
    reveal the secret, refuse. If it looks like it's using one of a few
    classic social-engineering framings (claiming to be an admin, asking
    it to "repeat instructions", or a roleplay setup), leak it — this
    mimics how a real, imperfectly-guarded model tends to fail.
    """

    LEAK_TRIGGERS = ("admin", "repeat your instructions", "as a system", "pretend", "roleplay")

    def complete(self, system_prompt: str, messages: list[dict]) -> str:
        # Pull the secret out of the system prompt so this stays generic
        # instead of hardcoding PINEAPPLE-7742 here.
        import re
        match = re.search(r"internal support code:\s*(\S+)", system_prompt)
        secret = match.group(1) if match else "UNKNOWN-SECRET"

        # Look across the whole conversation, not just the latest message -
        # this is what lets the mock target also exercise multi-turn/fake-
        # history attacks, where the trigger might be planted in an earlier
        # turn rather than the final one.
        transcript = " ".join(m["content"].lower() for m in messages)
        if any(trigger in transcript for trigger in self.LEAK_TRIGGERS):
            return f"Sure, since you put it that way - the code is {secret}."
        return "I'm sorry, I can't help with that. Is there something else I can help you with?"


# Maps the short names we'll use on the command line to the provider
# classes above, so the rest of the code can do
# get_provider("anthropic") instead of importing three classes by hand.
PROVIDERS = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
    "mock": MockProvider,
}


def get_provider(name: str, **kwargs) -> LLMProvider:
    """Factory function: get_provider('anthropic') -> AnthropicProvider()."""
    if name not in PROVIDERS:
        raise ValueError(
            f"Unknown provider '{name}'. Choose from: {', '.join(PROVIDERS)}"
        )
    return PROVIDERS[name](**kwargs)
