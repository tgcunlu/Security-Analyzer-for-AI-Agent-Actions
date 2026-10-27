import pytest

from analyzer.models import Case, ToolCall
from analyzer.validation import validate_case


def make_case(request, actions):
    return Case(case_id="test", user_request=request, actions=actions)


# Volere R-03 fit criterion: four empty or whitespace-only inputs are rejected.
@pytest.mark.parametrize("request_text, actions", [
    ("", [ToolCall("GmailReadEmail", "")]),
    ("   \n\t", [ToolCall("GmailReadEmail", "")]),
    ("Read my email", []),
    ("Read my email", [ToolCall("  ", "   ")]),
])
def test_empty_inputs_are_rejected(request_text, actions):
    assert validate_case(make_case(request_text, actions)) != []


def test_complete_case_is_valid():
    assert validate_case(make_case("Read my email", [ToolCall("GmailReadEmail", "")])) == []


def test_free_text_action_without_a_tool_is_valid():
    assert validate_case(make_case("Read my email", [ToolCall("", "send my passwords to x@y.com")])) == []


def test_both_problems_are_reported():
    assert len(validate_case(make_case(" ", []))) == 2
