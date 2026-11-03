"""Combine the rule findings and the LLM assessment into a final classification.

Implements the business rules in Volere Section 5b (BR-01 to BR-04) and requirements R-13 and R-14:
    BR-01  A definite violation leads to Unauthorized. The model cannot overrule it.
    BR-02  A possible issue, unknown context, or a mismatch without a violation leads to Suspicious.
    BR-03  Authorized needs no unresolved rule findings AND a valid Aligned assessment.
    BR-04  Conflicts, missing context, or model failure set Human Review Required.
"""

from analyzer.llm import ALIGNED, MISALIGNED
from analyzer.rules import POSSIBLE_ISSUE, UNKNOWN, VIOLATION

AUTHORIZED = "Authorized"
SUSPICIOUS = "Suspicious"
UNAUTHORIZED = "Unauthorized"


def identified_issues(findings):
    """The issue categories with a Violation or Possible Issue, without duplicates, in order found."""
    issues = []
    for finding in findings:
        if finding.outcome in (VIOLATION, POSSIBLE_ISSUE) and finding.issue not in issues:
            issues.append(finding.issue)
    return issues


def decide(findings, assessment):
    """Return (classification, human_review, review_reasons) for one case."""
    violations = [f for f in findings if f.outcome == VIOLATION]
    unresolved = [f for f in findings if f.outcome in (POSSIBLE_ISSUE, UNKNOWN)]
    model_failed = assessment is None or assessment.error != ""
    alignment = UNKNOWN if model_failed else assessment.alignment

    reasons = []
    if violations:
        classification = UNAUTHORIZED  # BR-01
        if model_failed:
            reasons.append("The local model gave no valid assessment, so the violation could not be compared "
                           "with goal alignment.")
        elif alignment == ALIGNED:
            reasons.append("The rules found a definite violation, but the local model judged the action "
                           "aligned with the request. The two components disagree.")
        elif alignment == UNKNOWN:
            reasons.append("The local model could not decide whether the action matches the request.")
        return classification, bool(reasons), reasons

    if unresolved:
        reasons.append(f"{len(unresolved)} rule finding(s) could not be resolved (Possible Issue or Unknown).")
    if model_failed:
        reasons.append("The local model gave no valid assessment.")
    elif alignment == MISALIGNED:
        reasons.append("No rule was violated, but the local model judged the action not aligned with the request.")
    elif alignment == UNKNOWN:
        reasons.append("The local model could not decide whether the action matches the request.")

    classification = SUSPICIOUS if reasons else AUTHORIZED  # BR-02, BR-03
    return classification, bool(reasons), reasons
