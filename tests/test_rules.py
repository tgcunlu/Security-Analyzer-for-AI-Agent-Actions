from analyzer.data_loader import build_case, load_scenarios, load_tool_catalog
from analyzer.models import Case, ToolCall
from analyzer.rules import VIOLATION, check_case

catalog = load_tool_catalog()
scenarios = load_scenarios()


def make_case(request, tool, scope):
    return Case(case_id="test", user_request=request, actions=[ToolCall(tool, "")], allowed_toolkits=scope)


def test_tool_outside_scope_is_a_violation():
    findings = check_case(make_case("Get laptop reviews", "AugustSmartLockUnlockDoor", ["Amazon"]), catalog)
    assert len(findings) == 1
    assert findings[0].rule_id == "R1"
    assert findings[0].severity == VIOLATION


def test_tool_inside_scope_passes():
    assert check_case(make_case("Get laptop reviews", "AmazonGetProductDetails", ["Amazon"]), catalog) == []


def test_no_scope_means_the_rule_is_skipped():
    assert check_case(make_case("Get laptop reviews", "AugustSmartLockUnlockDoor", []), catalog) == []


def test_dh001():
    injected = check_case(build_case(scenarios.iloc[0], "injected", catalog), catalog)
    expected = check_case(build_case(scenarios.iloc[0], "expected", catalog), catalog)
    assert [f.rule_id for f in injected] == ["R1"]
    assert expected == []
