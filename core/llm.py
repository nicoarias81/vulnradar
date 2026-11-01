"""
Cliente LLM configurable (proveedor + modelo).

LiteLLM proxy (alias: litellm) es el default de este repo:
POST http://192.168.10.5:4000/v1/chat/completions, clave LITELLM_API_KEY.

xAI (aliases: x, grok, spacexai) usa la Responses API documentada en
https://docs.x.ai — POST https://api.x.ai/v1/responses, clave XAI_API_KEY.

Pytest no llama a la red: los tests mockean HTTP. Humo en vivo:
`python -m core.llm`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import requests
import yaml

from core.db import REPO_ROOT

try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:  # pragma: no cover
    pass

CONFIG_PATH = REPO_ROOT / "config" / "llm.yaml"

# Nombres que el usuario puede poner en LLM_PROVIDER / config/llm.yaml.
PROVIDER_ALIASES = {
    "litellm": "litellm",
    "lite": "litellm",
    "proxy": "litellm",
    "x": "xai",
    "xai": "xai",
    "grok": "xai",
    "spacexai": "xai",
    "spacexsi": "xai",
    "openai": "openai",
    "ollama": "ollama",
    "custom": "custom",
}

PROVIDERS = {
    "litellm": {
        "base_url": "http://192.168.10.5:4000/v1",
        "key_env": "LITELLM_API_KEY",
        "style": "chat",
        "default_model": "qwen3.8-flash",
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "key_env": "XAI_API_KEY",
        "style": "responses",
        "default_model": "grok-4.7",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
        "style": "chat",
        "default_model": "gpt-4.1-mini",
    },
    "ollama": {
        "base_url": "http://127.0.0.1:11434/v1",
        "key_env": None,
        "style": "chat",
        "default_model": "llama3.2",
    },
    "custom": {
        "base_url": "http://127.0.0.1:11434/v1",
        "key_env": "LLM_API_KEY",
        "style": "chat",
        "default_model": "",
    },
}


class LlmConfigError(ValueError):
    """Proveedor, modelo o clave mal configurados."""


@dataclass(frozen=True)
class LlmConfig:
    provider: str
    model: str
    base_url: str
    api_key: Optional[str]
    style: str
    timeout_seconds: float


def load_llm_config(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    yaml_path: Optional[Path] = None,
) -> LlmConfig:
    """Env pisa YAML. `provider`/`model` explícitos pisan ambos."""
    environ = env if env is not None else os.environ
    file_cfg = _read_yaml(yaml_path or CONFIG_PATH)

    raw_provider = (
        provider
        or environ.get("LLM_PROVIDER")
        or file_cfg.get("provider")
        or "litellm"
    )
    resolved = PROVIDER_ALIASES.get(str(raw_provider).strip().lower())
    if not resolved:
        known = ", ".join(sorted(PROVIDER_ALIASES))
        raise LlmConfigError(f"Proveedor LLM desconocido: {raw_provider!r}. Usá uno de: {known}")

    spec = PROVIDERS[resolved]
    timeout = float(environ.get("LLM_TIMEOUT_SECONDS") or file_cfg.get("timeout_seconds") or 60)
    base_url = (environ.get("LLM_BASE_URL") or spec["base_url"]).rstrip("/")
    style = (environ.get("LLM_API_STYLE") or spec["style"]).strip().lower()
    model_name = (
        model
        or environ.get("LLM_MODEL")
        or file_cfg.get("model")
        or spec["default_model"]
    )
    if not model_name:
        raise LlmConfigError("LLM_MODEL (o config/llm.yaml model) es obligatorio.")

    key_env = spec["key_env"]
    api_key = None
    if key_env:
        api_key = (environ.get(key_env) or environ.get("LLM_API_KEY") or "").strip() or None
        if not api_key:
            raise LlmConfigError(f"Falta la API key ({key_env} o LLM_API_KEY).")

    return LlmConfig(
        provider=resolved,
        model=str(model_name).strip(),
        base_url=base_url,
        api_key=api_key,
        style=style,
        timeout_seconds=timeout,
    )


def complete(
    prompt: str,
    *,
    system: Optional[str] = None,
    config: Optional[LlmConfig] = None,
    session: Optional[requests.Session] = None,
) -> str:
    """Una completion de texto. `session` inyectable para tests."""
    cfg = config or load_llm_config()
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    return complete_messages(messages, config=cfg, session=session)


def complete_messages(
    messages: list[dict[str, str]],
    *,
    config: Optional[LlmConfig] = None,
    session: Optional[requests.Session] = None,
) -> str:
    cfg = config or load_llm_config()
    http = session or requests
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"

    if cfg.style == "responses":
        url = f"{cfg.base_url}/responses"
        payload: dict[str, Any] = {
            "model": cfg.model,
            "input": messages,
            "store": False,
        }
    elif cfg.style == "chat":
        url = f"{cfg.base_url}/chat/completions"
        payload = {"model": cfg.model, "messages": messages}
    else:
        raise LlmConfigError(f"LLM_API_STYLE no soportado: {cfg.style!r} (responses|chat)")

    response = http.post(url, json=payload, headers=headers, timeout=cfg.timeout_seconds)
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        body = (response.text or "")[:500]
        raise LlmConfigError(f"LLM HTTP {response.status_code}: {body}") from exc

    data = response.json()
    text = _extract_text(data, cfg.style)
    if not text:
        raise LlmConfigError("El LLM devolvió una respuesta vacía.")
    return text


def _extract_text(data: Mapping[str, Any], style: str) -> str:
    if style == "responses":
        direct = data.get("output_text")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        chunks: list[str] = []
        for item in data.get("output") or []:
            if not isinstance(item, Mapping):
                continue
            for part in item.get("content") or []:
                if isinstance(part, Mapping) and part.get("type") in ("output_text", "text"):
                    value = part.get("text") or ""
                    if value:
                        chunks.append(str(value))
        return "".join(chunks).strip()

    choices = data.get("choices") or []
    if choices:
        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        return str(content).strip()
    return ""


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return loaded if isinstance(loaded, dict) else {}


def list_models(
    *,
    config: Optional[LlmConfig] = None,
    session: Optional[requests.Session] = None,
) -> list[str]:
    """GET /models del proxy. Útil para ver los ids que LiteLLM expone."""
    cfg = config or load_llm_config()
    http = session or requests
    headers = {}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    response = http.get(f"{cfg.base_url}/models", headers=headers, timeout=cfg.timeout_seconds)
    response.raise_for_status()
    data = response.json()
    return [item.get("id") for item in data.get("data") or [] if item.get("id")]


def _smoke() -> int:
    """Humo en vivo: lista modelos y una completion mínima. No imprime la API key."""
    cfg = load_llm_config()
    print(f"provider={cfg.provider} model={cfg.model} base_url={cfg.base_url}")
    try:
        models = list_models(config=cfg)
        print("models=" + ",".join(models[:20]))
        if models and cfg.model not in models:
            print(f"warning: {cfg.model!r} is not in /models; the proxy may alias it anyway.")
    except Exception as exc:
        print(f"aviso: no pude listar /models ({exc})")
    text = complete("Reply with exactly OK.", system="You are a ping probe. No extra text.")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_smoke())
