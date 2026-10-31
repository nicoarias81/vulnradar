"""Cliente LLM: config y HTTP mockeado. Sin red, sin API keys reales."""
from pathlib import Path

import pytest
import yaml

from core.llm import LlmConfigError, complete, load_llm_config


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            raise requests.HTTPError(response=self)


class _FakeSession:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return _FakeResponse(self.payload, self.status_code)


def _env_xai(**extra):
    env = {
        "XAI_API_KEY": "test-key",
        "LLM_PROVIDER": "x",
        "LLM_MODEL": "grok-4.7",
    }
    env.update(extra)
    return env


def test_alias_x_resuelve_a_xai(tmp_path: Path):
    cfg = load_llm_config(env=_env_xai(), yaml_path=tmp_path / "missing.yaml")

    assert cfg.provider == "xai"
    assert cfg.model == "grok-4.7"
    assert cfg.base_url == "https://api.x.ai/v1"
    assert cfg.style == "responses"
    assert cfg.api_key == "test-key"


def test_env_pisa_yaml(tmp_path: Path):
    yaml_path = tmp_path / "llm.yaml"
    yaml_path.write_text(
        yaml.safe_dump({"provider": "openai", "model": "yaml-model", "timeout_seconds": 12}),
        encoding="utf-8",
    )

    cfg = load_llm_config(
        env={
            "LLM_PROVIDER": "xai",
            "LLM_MODEL": "grok-4.7",
            "XAI_API_KEY": "from-env",
            "LLM_TIMEOUT_SECONDS": "90",
        },
        yaml_path=yaml_path,
    )

    assert cfg.provider == "xai"
    assert cfg.model == "grok-4.7"
    assert cfg.timeout_seconds == 90


def test_argumentos_pisan_env(tmp_path: Path):
    cfg = load_llm_config(
        provider="ollama",
        model="llama3.2",
        env=_env_xai(),
        yaml_path=tmp_path / "missing.yaml",
    )

    assert cfg.provider == "ollama"
    assert cfg.model == "llama3.2"
    assert cfg.api_key is None
    assert cfg.style == "chat"


def test_proveedor_desconocido(tmp_path: Path):
    with pytest.raises(LlmConfigError, match="desconocido"):
        load_llm_config(env={"LLM_PROVIDER": "acme", "LLM_MODEL": "x"}, yaml_path=tmp_path / "n.yaml")


def test_xai_sin_key_falla(tmp_path: Path):
    with pytest.raises(LlmConfigError, match="XAI_API_KEY"):
        load_llm_config(
            env={"LLM_PROVIDER": "xai", "LLM_MODEL": "grok-4.7"},
            yaml_path=tmp_path / "n.yaml",
        )


def test_complete_xai_usa_responses_y_no_guarda(tmp_path: Path):
    session = _FakeSession({"output_text": "  OK  "})
    cfg = load_llm_config(env=_env_xai(), yaml_path=tmp_path / "n.yaml")

    text = complete("ping", system="probe", config=cfg, session=session)

    assert text == "OK"
    call = session.calls[0]
    assert call["url"] == "https://api.x.ai/v1/responses"
    assert call["json"]["model"] == "grok-4.7"
    assert call["json"]["store"] is False
    assert call["json"]["input"][0] == {"role": "system", "content": "probe"}
    assert call["headers"]["Authorization"] == "Bearer test-key"


def test_litellm_apunta_al_proxy_local(tmp_path: Path):
    cfg = load_llm_config(
        env={"LLM_PROVIDER": "litellm", "LLM_MODEL": "grok-4.7", "LITELLM_API_KEY": "sk-proxy"},
        yaml_path=tmp_path / "n.yaml",
    )

    assert cfg.provider == "litellm"
    assert cfg.base_url == "http://192.168.10.5:4000/v1"
    assert cfg.style == "chat"
    assert cfg.api_key == "sk-proxy"


def test_complete_litellm_usa_chat_completions(tmp_path: Path):
    session = _FakeSession({"choices": [{"message": {"content": "OK"}}]})
    cfg = load_llm_config(
        env={"LLM_PROVIDER": "proxy", "LLM_MODEL": "mi-modelo", "LITELLM_API_KEY": "sk-proxy"},
        yaml_path=tmp_path / "n.yaml",
    )

    text = complete("ping", config=cfg, session=session)

    assert text == "OK"
    call = session.calls[0]
    assert call["url"] == "http://192.168.10.5:4000/v1/chat/completions"
    assert call["json"]["model"] == "mi-modelo"
    assert call["headers"]["Authorization"] == "Bearer sk-proxy"


def test_complete_openai_usa_chat_completions(tmp_path: Path):
    session = _FakeSession({"choices": [{"message": {"content": "hola"}}]})
    cfg = load_llm_config(
        env={"LLM_PROVIDER": "openai", "LLM_MODEL": "gpt-4.1-mini", "OPENAI_API_KEY": "sk-test"},
        yaml_path=tmp_path / "n.yaml",
    )

    text = complete("hola", config=cfg, session=session)

    assert text == "hola"
    assert session.calls[0]["url"] == "https://api.openai.com/v1/chat/completions"
    assert session.calls[0]["json"]["messages"][0]["content"] == "hola"


def test_complete_extrae_output_anidado(tmp_path: Path):
    session = _FakeSession({
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "nested"}]}
        ]
    })
    cfg = load_llm_config(env=_env_xai(), yaml_path=tmp_path / "n.yaml")

    assert complete("x", config=cfg, session=session) == "nested"
