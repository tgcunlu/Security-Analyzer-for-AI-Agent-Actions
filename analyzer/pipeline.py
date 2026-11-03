"""The action-analysis pipeline: validation -> rules -> local LLM -> decision.

This is the main entry point used by the app (Volere Section 6, R-03, R-06, R-13 to R-15).
"""

from analyzer.decision import AUTHORIZED, UNAUTHORIZED, decide, identified_issues
from analyzer.llm import assess_alignment
from analyzer.models import AnalysisResult
from analyzer.rules import NO_ISSUE, check_case
from analyzer.validation import validate_case

SUMMARIES = {
    UNAUTHORIZED: "A security rule found a definite violation.",
    AUTHORIZED: ("No rule found a problem and the local model judged the action aligned with the request. "
                 "This is not a safety guarantee."),
}
SUSPICIOUS_SUMMARY = "No definite violation was found, but the case has unresolved concerns."


def explain(classification, findings, assessment, review_reasons):
    """A short explanation that can be checked against the case: summary, findings, model, review."""
    lines = [f"{classification}: {SUMMARIES.get(classification, SUSPICIOUS_SUMMARY)}"]
    for finding in findings:
        if finding.outcome != NO_ISSUE:
            lines.append(f"- {finding.rule_id} ({finding.outcome}): {finding.detail}")
    if assessment.error:
        lines.append(f"- Local model: {assessment.error}")
    else:
        lines.append(f"- Local model ({assessment.alignment}): {assessment.reason}")
    if review_reasons:
        lines.append("Human Review Required: " + " ".join(review_reasons))
    return "\n".join(lines)


def analyze_case(case, catalog, search=None, llm_client=None, **llm_options):
    """Analyze one case and return an AnalysisResult. The proposed action is never executed.

    search: a SimilaritySearch, given for manual cases to find related benchmark examples.
    llm_client and llm_options (e.g. model="...") are passed on to assess_alignment.
    """
    problems = validate_case(case)
    if problems:  # R-03: stop before the rules and the model are used
        return AnalysisResult(case.case_id, input_problems=problems,
                              explanation="The case was not analyzed: " + " ".join(problems))

    findings = check_case(case, catalog)
    assessment = assess_alignment(case, client=llm_client, **llm_options)
    classification, review, reasons = decide(findings, assessment)

    # R-06: similar examples are looked up only after the decision and never used by it.
    related = search.search(case.user_request, case.actions) if search is not None else []

    return AnalysisResult(
        case_id=case.case_id,
        classification=classification,
        human_review=review,
        issues=identified_issues(findings),
        explanation=explain(classification, findings, assessment, reasons),
        review_reasons=reasons,
        findings=findings,
        assessment=assessment,
        related_examples=related,
    )
