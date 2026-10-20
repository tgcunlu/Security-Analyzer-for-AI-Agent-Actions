from analyzer.data_loader import build_case, load_scenarios, load_tool_catalog


def test_scenario_counts():
    scenarios = load_scenarios()
    assert len(scenarios) == 1054
    assert (scenarios["family"] == "DH").sum() == 510
    assert (scenarios["family"] == "DS").sum() == 544


def test_first_scenario():
    first = load_scenarios().iloc[0]
    assert first["scenario_id"] == "DH-001"
    assert first["user_tool"] == "AmazonGetProductDetails"
    assert first["attacker_tools"] == ["AugustSmartLockGrantGuestAccess"]


def test_tool_catalog():
    catalog = load_tool_catalog()
    assert len(catalog) == 330
    assert catalog["AmazonGetProductDetails"]["toolkit"] == "Amazon"


def test_every_benchmark_tool_is_in_the_catalog():
    catalog = load_tool_catalog()
    for row in load_scenarios().itertuples():
        assert row.user_tool in catalog
        for tool in row.attacker_tools:
            assert tool in catalog


def test_injected_case():
    first = load_scenarios().iloc[0]
    case = build_case(first, "injected", load_tool_catalog())
    assert case.case_id == "DH-001/injected"
    assert case.expected_label == "attack"
    assert [step.tool for step in case.actions] == ["AugustSmartLockGrantGuestAccess"]
    assert case.allowed_toolkits == ["Amazon"]


def test_data_stealing_case_has_an_email_step():
    scenarios = load_scenarios()
    first_ds = scenarios[scenarios["family"] == "DS"].iloc[0]
    case = build_case(first_ds, "injected", load_tool_catalog())
    assert len(case.actions) == 2
    assert case.actions[1].tool == "GmailSendEmail"
    assert "amy.watson@gmail.com" in case.actions[1].input


def test_expected_case():
    first = load_scenarios().iloc[0]
    case = build_case(first, "expected", load_tool_catalog())
    assert case.expected_label == "benign"
    assert case.actions[0].tool == "AmazonGetProductDetails"
