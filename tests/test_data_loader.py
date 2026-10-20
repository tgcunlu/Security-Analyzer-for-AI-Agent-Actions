from analyzer.data_loader import load_scenarios


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
