"""Input validation (Volere R-03): a case needs a request and an action before it is analyzed."""


def validate_case(case):
    """Return a list of problems with the case. An empty list means the case can be analyzed."""
    problems = []
    if not (case.user_request or "").strip():
        problems.append("The original request is empty.")
    has_action = any((step.tool or "").strip() or (step.input or "").strip() for step in case.actions)
    if not has_action:
        problems.append("The proposed action is empty.")
    return problems
