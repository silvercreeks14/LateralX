"""
Analyst chat interface — Air-Gapped, Ollama-Only.
The full loaded timeline is injected as system context so the LLM
can answer precise questions grounded in the actual evidence.
Cloud providers (Groq, Gemini) have been removed.
"""

import os
import requests
from dotenv import load_dotenv
from backend.schema import ForensicEvent, ChatMessage

load_dotenv()

PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower().strip()

_SYSTEM_TEMPLATE = """You are an expert digital forensics analyst assistant. \
You have been given the following security event timeline to investigate:

--- TIMELINE START ---
{timeline}
--- TIMELINE END ---

Answer questions strictly based on the events above. \
Cite specific timestamps, hostnames, usernames, and Event IDs where relevant. \
If the answer cannot be determined from the timeline, say so explicitly. \
Do not invent events or details not present in the data."""


def _build_timeline(events: list[ForensicEvent], max_events: int = 300) -> str:
    lines = []
    for e in sorted(events, key=lambda x: x.timestamp)[:max_events]:
        ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        parts = [ts, f"host={e.source_host}", f"type={e.event_type}"]
        if e.user:
            parts.append(f"user={e.user}")
        if e.event_id:
            parts.append(f"EventID={e.event_id}")
        parts.append(e.description[:200])
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def _call_ollama(system: str, history: list[ChatMessage], message: str) -> str:
    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    messages = [{"role": "system", "content": system}]
    for m in history[-10:]:
        messages.append({"role": m.role, "content": m.content})
    messages.append({"role": "user", "content": message})
    try:
        resp = requests.post(
            f"{base}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
            timeout=180,
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ValueError(
            f"Cannot connect to Ollama at {base}. "
            "Run 'ollama serve' and ensure the model is pulled: "
            f"'ollama pull {model}'"
        )
    except requests.exceptions.Timeout:
        raise ValueError(
            f"Ollama at {base} timed out after 180 s. "
            "The model may be too large for available RAM/VRAM."
        )
    return resp.json()["message"]["content"]


def run_chat(
    message: str,
    history: list[ChatMessage],
    events: list[ForensicEvent],
) -> str:
    """
    Execute one chat turn. The full timeline is injected as system context on
    every turn — stateless, no server-side session required.

    LLM_PROVIDER=none  → returns a static offline message.
    LLM_PROVIDER=ollama → calls local Ollama inference server.
    Any other value    → raises ValueError with remediation hint.
    """
    valid = {"ollama", "none"}
    if PROVIDER not in valid:
        raise ValueError(
            f"Unknown or disallowed LLM_PROVIDER={PROVIDER!r}. "
            f"Air-gap mode only supports: {', '.join(sorted(valid))}. "
            "Update LLM_PROVIDER in .env."
        )

    if PROVIDER == "none":
        return (
            "Chat is not available in offline mode (LLM_PROVIDER=none).\n\n"
            "To enable chat, install Ollama (https://ollama.com), run:\n"
            "  ollama pull llama3.2\n"
            "  ollama serve\n"
            "Then set LLM_PROVIDER=ollama in .env and restart the server.\n\n"
            f"The current investigation has {len(events)} events loaded. "
            "Once Ollama is running you can ask questions grounded in this evidence."
        )

    system = _SYSTEM_TEMPLATE.format(timeline=_build_timeline(events))
    return _call_ollama(system, history, message)
