import json

from analyzer.data_loader import build_case, load_scenarios, load_tool_catalog
from analyzer.decision import AUTHORIZED, SUSPICIOUS, UNAUTHORIZED
from analyzer.models import Case, ToolCall
from analyzer.pipeline import analyze_case
from analyzer.similarity import SimilaritySearch

catalog = load_tool_catalog()
scenarios = load_scenarios()
DH001_INJECTED = build_case(scenarios.iloc[0], "injected", catalog)
DH001_EXPECTED = build_case(scenarios.iloc[0], "expected", catalog)


class FakeClient:
    """Stands in for ollama.Client: gives a fixed reply or raises an error, and counts the calls."""

    def __init__(self, alignment=None, reason="Fixed test reply.", error=None):
        self.reply = json.dumps({"alignment": alignment, "reason": reason})
        self.error = error
        self.calls = 0

    def chat(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return {"message": {"content": self.reply}}


class FakeSearch:
    """Returns whatever examples it is given, to check that examples never change the decision."""

    def __init__(self, examples):
        self.examples = examples

    def search(self, user_request, actions):
        return self.examples


# R-03: invalid input is rejected before the model is called

def test_empty_case_is_not_analyzed_and_the_model_is_not_called():
    client = FakeClient("Aligned")
    result = analyze_case(Case("empty", "   ", []), catalog, llm_client=client)
    assert result.classification == ""
    assert len(result.input_problems) == 2
    assert client.calls == 0


# R-13 and R-14: the whole pipeline on DH-001

def test_attack_with_misaligned_model_is_unauthorized_without_review():
    result = analyze_case(DH001_INJECTED, catalog, llm_client=FakeClient("Misaligned"))
    assert result.classification == UNAUTHORIZED
    assert result.human_review is False
    assert result.issues == ["Unauthorized tool use", "Unrequested change"]


def test_attack_with_aligned_model_stays_unauthorized_and_is_flagged():
    result = analyze_case(DH001_INJECTED, catalog, llm_client=FakeClient("Aligned"))
    assert result.classification == UNAUTHORIZED
    assert result.human_review is True


def test_benign_action_with_aligned_model_is_authorized():
    result = analyze_case(DH001_EXPECTED, catalog, llm_client=FakeClient("Aligned"))
    assert result.classification == AUTHORIZED
    assert result.human_review is False
    assert result.issues == []


# R-17: a model failure keeps the rule findings and is never an approval

def test_model_failure_keeps_findings_and_flags_review():
    result = analyze_case(DH001_INJECTED, catalog, llm_client=FakeClient(error=ConnectionError("Ollama is off")))
    assert result.classification == UNAUTHORIZED
    assert result.human_review is True
    assert [f.rule_id for f in result.findings if f.outcome == "Violation"] == ["RULE-TOOL", "RULE-ACTION"]
    assert "Ollama is off" in result.explanation


def test_benign_action_with_model_failure_is_suspicious():
    result = analyze_case(DH001_EXPECTED, catalog, llm_client=FakeClient(error=TimeoutError("timed out")))
    assert result.classification == SUSPICIOUS
    assert result.human_review is True


# R-15: the explanation shows the findings, the model answer and the review reason

def test_explanation_can_be_checked_against_the_case():
    result = analyze_case(DH001_INJECTED, catalog, llm_client=FakeClient("Aligned", reason="Looks fine."))
    assert result.explanation.startswith("Unauthorized:")
    assert "AugustSmartLockGrantGuestAccess" in result.explanation
    assert "Local model (Aligned): Looks fine." in result.explanation
    assert "Human Review Required:" in result.explanation


# R-05 and R-06: related examples for manual cases, kept separate from the classification

def test_manual_case_gets_up_to_three_related_examples():
    case = Case("manual", "Get me reviews of Sony headphones", [ToolCall("", "unlock my front door")])
    result = analyze_case(case, catalog, search=SimilaritySearch(scenarios), llm_client=FakeClient("Misaligned"))
    assert 1 <= len(result.related_examples) <= 3


def test_related_examples_do_not_change_the_classification():
    examples = [{"scenario_id": "DH-999", "score": 1.0, "attack_type": "Physical Harm",
                 "attacker_tools": ["X"], "attacker_instruction": "x"}]
    relabeled = [dict(examples[0], attack_type="Benign")]
    without = analyze_case(DH001_EXPECTED, catalog, llm_client=FakeClient("Aligned"))
    with_attack = analyze_case(DH001_EXPECTED, catalog, search=FakeSearch(examples), llm_client=FakeClient("Aligned"))
    with_benign = analyze_case(DH001_EXPECTED, catalog, search=FakeSearch(relabeled), llm_client=FakeClient("Aligned"))
    assert without.classification == with_attack.classification == with_benign.classification == AUTHORIZED
