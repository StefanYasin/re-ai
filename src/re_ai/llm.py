"""Optional narrative drafting through an OpenAI compatible API.

Off unless the caller asks for it. Configuration comes from the environment so
no key ever touches the command line or the report:

    RE_AI_BASE_URL   e.g. https://api.openai.com/v1
    RE_AI_API_KEY    bearer token, any non empty value for local servers
    RE_AI_MODEL      model name, defaults to gpt-4o-mini

OPENAI_BASE_URL, OPENAI_API_KEY and OPENAI_MODEL are used as fallbacks. The
HTTP call is plain urllib so the tool keeps zero runtime dependencies.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .analysis import Analysis

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
MAX_FACTS_CHARS = 6000

SYSTEM_PROMPT = (
    "You are a reverse engineering analyst writing the narrative section of a "
    "static analysis report. Use only the facts provided. Be concrete and "
    "cautious: say what the evidence supports, name what is absent, and avoid "
    "guessing. Never claim the sample was executed. Do not use em dashes. Reply "
    "with markdown and no top level heading."
)

USER_TEMPLATE = """Here are the facts extracted from a binary by a static analysis tool:

{facts}

Write at most 250 words under these three headings:

## What it appears to do
## Notable indicators
## Suggested next steps

Plain prose under each heading, no bullet lists longer than four items, no code
fences. If the facts are too thin to say anything useful, say so in one sentence
under the first heading and keep it short.
"""


class LLMError(RuntimeError):
    """Raised when the optional drafting step cannot be completed."""


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    api_key: str
    model: str
    timeout: float = 60.0

    @property
    def endpoint(self) -> str:
        base = self.base_url.strip().rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"


def resolve_config(env: dict[str, str] | None = None, model: str | None = None) -> LLMConfig:
    """Build a config from environment variables.

    Raises :class:`LLMError` when the base URL or key is missing.
    """
    source = os.environ if env is None else env
    base_url = (
        source.get("RE_AI_BASE_URL")
        or source.get("OPENAI_BASE_URL")
        or DEFAULT_BASE_URL
    ).strip()
    api_key = (source.get("RE_AI_API_KEY") or source.get("OPENAI_API_KEY") or "").strip()
    chosen_model = (model or source.get("RE_AI_MODEL") or source.get("OPENAI_MODEL") or DEFAULT_MODEL).strip()

    if not api_key:
        raise LLMError(
            "no API key found. Set RE_AI_API_KEY (or OPENAI_API_KEY) before using --llm"
        )
    if not base_url:
        raise LLMError("RE_AI_BASE_URL is empty")
    if not chosen_model:
        raise LLMError("no model name resolved. Set RE_AI_MODEL or pass --model")
    return LLMConfig(base_url=base_url, api_key=api_key, model=chosen_model)


def build_facts(analysis: Analysis) -> str:
    """Compact JSON view of the analysis for the prompt."""
    facts = analysis.to_dict()
    facts.pop("strings", None)
    facts["strings"] = {
        "total": len(analysis.strings),
        "interesting": [item.value for item in analysis.strings if item.is_interesting][:25],
    }
    text = json.dumps(facts, indent=1, sort_keys=False)
    if len(text) > MAX_FACTS_CHARS:
        text = text[:MAX_FACTS_CHARS] + "\n... (truncated)"
    return text


def build_prompt(analysis: Analysis) -> str:
    return USER_TEMPLATE.format(facts=build_facts(analysis))


def _clean(text: str) -> str:
    for dash in ("\u2014", "\u2013"):
        text = text.replace(f" {dash} ", ", ").replace(dash, "-")
    return text.strip()


def _post_json(url: str, payload: dict, api_key: str, timeout: float) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "re-ai",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise LLMError(f"API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"could not reach {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise LLMError(f"request to {url} timed out after {timeout} seconds") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMError(f"API returned invalid JSON: {raw[:200]}") from exc


def draft_analysis(
    analysis: Analysis, config: LLMConfig | None = None, env: dict[str, str] | None = None
) -> tuple[str, str]:
    """Return ``(markdown_text, model)`` for the analysis section."""
    cfg = config or resolve_config(env)
    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(analysis)},
        ],
        "temperature": 0.2,
        "max_tokens": 700,
    }
    data = _post_json(cfg.endpoint, payload, cfg.api_key, cfg.timeout)

    choices = data.get("choices") or []
    if not choices:
        raise LLMError("API response contained no choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise LLMError("API response contained no message content")
    return _clean(content), data.get("model") or cfg.model
