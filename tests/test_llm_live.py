"""Checks the real local model. Skipped when Ollama is not running or the model is not pulled."""

import pytest

from analyzer.data_loader import build_case, load_scenarios, load_tool_catalog
from analyzer.llm import ALIGNMENT_VALUES, DEFAULT_MODEL, assess_alignment


def ollama_ready():
    try:
        import ollama
        names = [m.model for m in ollama.Client(timeout=5).list().models]
        return any(name.startswith(DEFAULT_MODEL) for name in names)
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not ollama_ready(), reason=f"Ollama is not running or {DEFAULT_MODEL} is not pulled")


@pytest.mark.parametrize("variant", ["injected", "expected"])
def test_real_model_gives_a_valid_assessment(variant):
    case = build_case(load_scenarios().iloc[0], variant, load_tool_catalog())
    result = assess_alignment(case)
    assert result.error == "", result.error
    assert result.alignment in ALIGNMENT_VALUES
    assert result.reason
