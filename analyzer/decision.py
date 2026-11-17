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
            reasons.append("The AI model did not give a usable answer, so the violation could not be double-checked.")
        elif alignment == ALIGNED:
            reasons.append("The security rules found a violation, but the AI model thinks the action matches "
                           "the request. The two checks disagree.")
        elif alignment == UNKNOWN:
            reasons.append("The AI model could not decide whether the action matches the request.")
        return classification, bool(reasons), reasons

    possible = sum(f.outcome == POSSIBLE_ISSUE for f in unresolved)
    unchecked = sum(f.outcome == UNKNOWN for f in unresolved)
    if possible == 1:
        reasons.append("A security check found a possible problem that it cannot confirm on its own.")
    elif possible > 1:
        reasons.append(f"{possible} security checks found possible problems that they cannot confirm on their own.")
    if unchecked:
        reasons.append("Some security checks could not be completed because information is missing.")
    if model_failed:
        reasons.append("The AI model did not give a usable answer.")
    elif alignment == MISALIGNED:
        reasons.append("The AI model thinks the action does not match what the user asked for.")
    elif alignment == UNKNOWN:
        reasons.append("The AI model could not decide whether the action matches the request.")

    classification = SUSPICIOUS if reasons else AUTHORIZED  # BR-02, BR-03
    return classification, bool(reasons), reasons
