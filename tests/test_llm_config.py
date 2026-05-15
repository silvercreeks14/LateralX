"""
Tests for air-gapped LLM configuration.
All assertions use local mocks — no network calls are ever made.
"""
import os
import json
import pytest
import importlib
from unittest.mock import patch


# ── Provider validation ───────────────────────────────────────────────────────

def test_unknown_provider_raises():
    """Disallowed LLM_PROVIDER values (including former cloud providers) raise ValueError."""
    with patch.dict(os.environ, {"LLM_PROVIDER": "groq"}):
        import backend.analysis.llm as llm_module
        importlib.reload(llm_module)
        with pytest.raises(ValueError, match="disallowed"):
            llm_module._call_llm("test prompt")


def test_gemini_provider_raises():
    """gemini is no longer a valid provider in air-gap mode."""
    with patch.dict(os.environ, {"LLM_PROVIDER": "gemini"}):
        import backend.analysis.llm as llm_module
        importlib.reload(llm_module)
        with pytest.raises(ValueError, match="disallowed"):
            llm_module._call_llm("test prompt")


def test_auto_provider_raises():
    """auto is no longer valid — it could silently reach cloud endpoints."""
    with patch.dict(os.environ, {"LLM_PROVIDER": "auto"}):
        import backend.analysis.llm as llm_module
        importlib.reload(llm_module)
        with pytest.raises(ValueError, match="disallowed"):
            llm_module._call_llm("test prompt")


def test_completely_unknown_provider_raises():
    """Totally unrecognised values also raise ValueError."""
    with patch.dict(os.environ, {"LLM_PROVIDER": "unknown_provider"}):
        import backend.analysis.llm as llm_module
        importlib.reload(llm_module)
        with pytest.raises(ValueError):
            llm_module._call_llm("test prompt")


def test_none_provider_raises_in_call_llm():
    """_call_llm itself raises when PROVIDER=none; run_full_analysis handles this upstream."""
    with patch.dict(os.environ, {"LLM_PROVIDER": "none"}):
        import backend.analysis.llm as llm_module
        importlib.reload(llm_module)
        with pytest.raises(RuntimeError, match="offline mode"):
            llm_module._call_llm("test prompt")


# ── JSON parser: markdown fence stripping ─────────────────────────────────────

def test_safe_parse_strips_markdown_fences():
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    fenced = '```json\n{"key": "value"}\n```'
    result = llm_module._safe_parse_json(fenced)
    assert result == {"key": "value"}


def test_safe_parse_clean_json():
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    clean = '{"patient_zero_candidate": "HOST-01", "confidence": "high"}'
    result = llm_module._safe_parse_json(clean)
    assert result["confidence"] == "high"


# ── JSON parser: Windows path / backslash escaping ────────────────────────────

def test_safe_parse_windows_path_single_backslash():
    """
    Ollama may emit Windows paths with single backslashes, which are invalid JSON.
    _safe_parse_json must auto-fix and return the correct decoded value.
    """
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    # Simulate Ollama returning malformed JSON with unescaped Windows path
    raw = '{"narrative": "Malware dropped to C:\\Temp\\agent.exe", "confidence": "high"}'
    result = llm_module._safe_parse_json(raw)
    assert result["confidence"] == "high"
    # The decoded string should contain the original single-backslash path
    assert "C:\\Temp\\agent.exe" in result["narrative"]


def test_safe_parse_registry_key_backslashes():
    """Registry key paths with backslashes must also be handled."""
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    raw = '{"initial_access_vector": "Persistence via HKLM\\SOFTWARE\\Microsoft\\Run key"}'
    result = llm_module._safe_parse_json(raw)
    assert "HKLM" in result["initial_access_vector"]


def test_safe_parse_already_valid_json_unchanged():
    """Properly escaped JSON must round-trip without double-escaping."""
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    # Python string with single backslashes — json.dumps will encode them correctly
    original_path = "C:\\Temp\\agent.exe"   # Python value: C:\Temp\agent.exe
    valid = json.dumps({"narrative": f"Malware at {original_path}", "confidence": "medium"})
    # valid JSON text now contains: "C:\\Temp\\agent.exe" (properly escaped)
    result = llm_module._safe_parse_json(valid)
    assert result["confidence"] == "medium"
    # After parsing, decoded value must have the original single-backslash path
    assert original_path in result["narrative"]


def test_safe_parse_raises_on_truly_invalid_json():
    """Completely broken JSON (not a backslash issue) must raise ValueError."""
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    with pytest.raises(ValueError, match="unparseable JSON"):
        llm_module._safe_parse_json("this is not json at all {{{")


# ── _fix_backslashes unit tests ───────────────────────────────────────────────

def test_fix_backslashes_windows_path():
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    raw = r"C:\Temp\agent.exe"
    fixed = llm_module._fix_backslashes(raw)
    # After fixing, each \ becomes \\, making it valid JSON string content
    assert fixed == r"C:\\Temp\\agent.exe"


def test_fix_backslashes_leaves_valid_escapes_intact():
    """\\n, \\t, \\\\, \\" must NOT be double-escaped."""
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    # r'\n' = backslash + n  — valid JSON escape, must be left alone
    assert llm_module._fix_backslashes(r'\n') == r'\n'
    assert llm_module._fix_backslashes(r'\t') == r'\t'
    assert llm_module._fix_backslashes(r'\"') == r'\"'
    # r'\\' = two backslashes — valid JSON escape for literal backslash, must be left alone
    assert llm_module._fix_backslashes('\\\\') == '\\\\'


def test_fix_backslashes_unicode_escape_intact():
    """\\uXXXX sequences must not be mangled."""
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    inp = r'A'  # valid unicode escape for 'A'
    assert llm_module._fix_backslashes(inp) == inp


# ── Ollama connection error ───────────────────────────────────────────────────

def test_ollama_connection_failure_raises_value_error():
    """A refused connection to Ollama must surface as ValueError, not crash."""
    import requests
    import backend.analysis.llm as llm_module
    importlib.reload(llm_module)

    with patch.dict(os.environ, {"LLM_PROVIDER": "ollama", "OLLAMA_BASE_URL": "http://localhost:11434"}):
        importlib.reload(llm_module)
        with patch("backend.analysis.llm.requests.post",
                   side_effect=requests.exceptions.ConnectionError("refused")):
            with pytest.raises(ValueError, match="Cannot connect to Ollama"):
                llm_module._call_ollama("test prompt")

