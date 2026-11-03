import pytest

from analyzer.decision import AUTHORIZED, SUSPICIOUS, UNAUTHORIZED, decide, identified_issues
from analyzer.models import Finding, LLMAssessment

VIOLATION = [Finding("RULE-TOOL", "Unauthorized tool use", "Violation", "Step 1 uses a smart lock tool.")]
POSSIBLE = [Finding("RULE-ACTION", "Unrequested change", "Possible Issue", "Step 1 is a delete action.")]
UNKNOWN = [Finding("RULE-TOOL", "Unauthorized tool use", "Unknown", "No tool restriction was given.", 0)]
NO_ISSUE = [Finding("RULE-ACTION", "Unrequested change", "No Issue", "Step 1 only reads information.")]

ALIGNED = LLMAssessment("Aligned", "Fits the request.")
MISALIGNED = LLMAssessment("Misaligned", "Not what the user asked.")
UNDECIDED = LLMAssessment("Unknown", "Not enough information.")
FAILED = LLMAssessment("Unknown", error="could not connect")


# Volere R-13 and R-14: every row of the decision table.
@pytest.mark.parametrize("findings, assessment, classification, review", [
    (VIOLATION, MISALIGNED, UNAUTHORIZED, False),   # BR-01: both parts agree
    (VIOLATION, ALIGNED, UNAUTHORIZED, True),       # BR-01 + BR-04: model cannot overrule, conflict flagged
    (VIOLATION, UNDECIDED, UNAUTHORIZED, True),
    (VIOLATION, FAILED, UNAUTHORIZED, True),
    (POSSIBLE, ALIGNED, SUSPICIOUS, True),          # BR-02: unresolved finding
    (POSSIBLE, MISALIGNED, SUSPICIOUS, True),
    (UNKNOWN, ALIGNED, SUSPICIOUS, True),           # A-04: missing policy is not a clean result
    (NO_ISSUE, MISALIGNED, SUSPICIOUS, True),       # BR-02: mismatch found only by the model
    (NO_ISSUE, UNDECIDED, SUSPICIOUS, True),
    (NO_ISSUE, FAILED, SUSPICIOUS, True),           # R-17: model failure is never an approval
    ([], None, SUSPICIOUS, True),                   # no assessment at all
    (NO_ISSUE, ALIGNED, AUTHORIZED, False),         # BR-03: the only way to Authorized
    ([], ALIGNED, AUTHORIZED, False),
])
def test_decision_table(findings, assessment, classification, review):
    result_classification, result_review, reasons = decide(findings, assessment)
    assert result_classification == classification
    assert result_review == review
    assert bool(reasons) == review  # every review flag is explained (Volere 10b)


def test_review_reasons_name_both_problems():
    _, _, reasons = decide(POSSIBLE, MISALIGNED)
    assert len(reasons) == 2


def test_identified_issues_skip_no_issue_and_unknown_and_duplicates():
    findings = VIOLATION + VIOLATION + POSSIBLE + UNKNOWN + NO_ISSUE
    assert identified_issues(findings) == ["Unauthorized tool use", "Unrequested change"]
