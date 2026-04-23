"""LLM-driven remediation agent.

For first-party SAST findings (e.g., a Semgrep `tainted-sql-string` rule),
this agent prompts a Claude or OpenAI model with the offending function body
plus the rule's explanation and proposes a refactor.

Outputs are *suggestions* surfaced as PR review comments; nothing is ever
applied automatically. This matches the PRD's Human-in-the-Loop guardrail
for production-critical branches.
"""

from __future__ import annotations

import logging
import os
import re
import textwrap
from typing import Literal

_MAX_SNIPPET_CHARS = 4000
_MAX_DESC_CHARS = 1000
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

from pydantic import BaseModel

log = logging.getLogger(__name__)

PROVIDERS = ("anthropic", "openai", "noop")


class FixSuggestion(BaseModel):
    rule_id: str
    file_path: str
    line: int
    summary: str
    proposed_diff: str
    confidence: float
    provider: str


class LLMRemediationAgent:
    def __init__(self, provider: Literal["anthropic", "openai", "noop"] = "anthropic", api_key: str = "") -> None:
        if provider not in PROVIDERS:
            raise ValueError(f"unsupported provider {provider}")
        self.provider = provider
        self.api_key = api_key

    def suggest_fix(
        self,
        rule_id: str,
        file_path: str,
        line: int,
        snippet: str,
        rule_description: str,
    ) -> FixSuggestion:
        if self.provider == "noop" or not self.api_key:
            return self._fallback(rule_id, file_path, line, snippet, rule_description)
        try:
            if self.provider == "anthropic":
                return self._anthropic(rule_id, file_path, line, snippet, rule_description)
            return self._openai(rule_id, file_path, line, snippet, rule_description)
        except Exception as e:  # pragma: no cover - depends on external API
            log.warning("LLM call failed (%s); falling back: %s", self.provider, e)
            return self._fallback(rule_id, file_path, line, snippet, rule_description)

    # ----- providers -----

    def _anthropic(self, rule_id, file_path, line, snippet, desc) -> FixSuggestion:
        # Imported lazily so `noop` mode works without the SDK installed.
        import anthropic  # type: ignore

        client = anthropic.Anthropic(api_key=self.api_key)
        prompt = self._build_prompt(rule_id, file_path, line, snippet, desc)
        msg = client.messages.create(
            model=os.environ.get("ASPM_ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in msg.content if hasattr(block, "text"))
        return FixSuggestion(
            rule_id=rule_id,
            file_path=file_path,
            line=line,
            summary=self._extract_summary(text),
            proposed_diff=self._extract_diff(text),
            confidence=0.7,
            provider="anthropic",
        )

    def _openai(self, rule_id, file_path, line, snippet, desc) -> FixSuggestion:
        import openai  # type: ignore

        client = openai.OpenAI(api_key=self.api_key)
        prompt = self._build_prompt(rule_id, file_path, line, snippet, desc)
        resp = client.chat.completions.create(
            model=os.environ.get("ASPM_OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.choices[0].message.content or ""
        return FixSuggestion(
            rule_id=rule_id,
            file_path=file_path,
            line=line,
            summary=self._extract_summary(text),
            proposed_diff=self._extract_diff(text),
            confidence=0.65,
            provider="openai",
        )

    def _fallback(self, rule_id, file_path, line, snippet, desc) -> FixSuggestion:
        # Deterministic suggestion when no LLM is available — useful for
        # local development and unit tests.
        summary = (
            f"Rule {rule_id} flagged code at {file_path}:{line}. "
            "No LLM provider configured; please review the snippet and apply the rule's recommended fix."
        )
        return FixSuggestion(
            rule_id=rule_id,
            file_path=file_path,
            line=line,
            summary=summary,
            proposed_diff="",
            confidence=0.0,
            provider="noop",
        )

    @staticmethod
    def _sanitize(text: str, max_chars: int) -> str:
        """Strip control characters and clamp length to prevent prompt injection."""
        text = _CONTROL_CHARS_RE.sub("", text)
        return text[:max_chars]

    def _build_prompt(self, rule_id, file_path, line, snippet, desc) -> str:
        safe_snippet = self._sanitize(snippet, _MAX_SNIPPET_CHARS)
        safe_desc = self._sanitize(desc, _MAX_DESC_CHARS)
        return textwrap.dedent(
            f"""
            You are a senior security engineer reviewing a pull request.

            A static analysis rule has flagged the following snippet:

            - Rule ID: {rule_id}
            - File: {file_path}:{line}
            - Rule explanation: {safe_desc}

            Snippet:
            ```
            {safe_snippet}
            ```

            Respond with:
            1. A one-paragraph summary of the issue and the recommended fix.
            2. A unified diff (```diff fenced block) that applies the smallest safe change.

            Do not invent context that is not present in the snippet. If the snippet is too small to fix safely, say so explicitly and suggest what additional context is needed.
            """
        ).strip()

    def _extract_summary(self, text: str) -> str:
        # First non-empty paragraph.
        for chunk in text.split("\n\n"):
            chunk = chunk.strip()
            if chunk and not chunk.startswith("```"):
                return chunk
        return text.strip()[:500]

    def _extract_diff(self, text: str) -> str:
        marker = "```diff"
        start = text.find(marker)
        if start == -1:
            return ""
        start += len(marker)
        end = text.find("```", start)
        return text[start:end].strip() if end != -1 else text[start:].strip()
