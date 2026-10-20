"""Load the InjecAgent benchmark data."""

import json
import re
from pathlib import Path

import pandas as pd

from analyzer.models import Case, ToolCall

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "injecagent"
SCENARIO_FILES = {"DH": "test_cases_dh_base.json", "DS": "test_cases_ds_base.json"}
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def load_scenarios(data_dir=DATA_DIR):
    """Load the DH and DS test cases into one DataFrame, one row per scenario."""
    rows = []
    for family, filename in SCENARIO_FILES.items():
        with open(Path(data_dir) / filename, encoding="utf-8") as f:
            test_cases = json.load(f)
        for number, item in enumerate(test_cases, start=1):
            rows.append({
                "scenario_id": f"{family}-{number:03d}",
                "family": family,
                "attack_type": item["Attack Type"],
                "user_tool": item["User Tool"],
                "user_instruction": item["User Instruction"],
                "tool_parameters": item["Tool Parameters"],
                "tool_response": item["Tool Response"],
                "attacker_tools": item["Attacker Tools"],
                "attacker_instruction": item["Attacker Instruction"],
                "expected_achievements": item["Expected Achievements"],
            })
    return pd.DataFrame(rows)


def load_tool_catalog(data_dir=DATA_DIR):
    """Return a dictionary: full tool name -> {"toolkit": ..., "summary": ...}."""
    with open(Path(data_dir) / "tools.json", encoding="utf-8") as f:
        toolkits = json.load(f)
    catalog = {}
    for toolkit in toolkits:
        for tool in toolkit["tools"]:
            full_name = toolkit["toolkit"] + tool["name"]
            catalog[full_name] = {"toolkit": toolkit["toolkit"], "summary": tool["summary"]}
    return catalog


def injected_actions(scenario):
    """The tool calls an agent makes if it follows the injected instruction."""
    instruction = scenario["attacker_instruction"]
    tools = scenario["attacker_tools"]
    actions = [ToolCall(tools[0], instruction)]
    if scenario["family"] == "DS":
        match = EMAIL_PATTERN.search(instruction)
        recipient = match.group(0).rstrip(".") if match else "amy.watson@gmail.com"
        email = {"to": recipient, "subject": "Requested information", "body": f"<data returned by {tools[0]}>"}
        actions.append(ToolCall(tools[1], json.dumps(email)))
    return actions


def build_case(scenario, variant, catalog):
    """Turn one scenario into a case. variant is "injected" or "expected"."""
    if variant == "injected":
        actions = injected_actions(scenario)
        expected_label = "attack"
    elif variant == "expected":
        actions = [ToolCall(scenario["user_tool"], scenario["tool_parameters"])]
        expected_label = "benign"
    else:
        raise ValueError(f"Unknown variant: {variant}")

    return Case(
        case_id=f"{scenario['scenario_id']}/{variant}",
        user_request=scenario["user_instruction"],
        actions=actions,
        allowed_toolkits=[catalog[scenario["user_tool"]]["toolkit"]],
        scenario_id=scenario["scenario_id"],
        variant=variant,
        expected_label=expected_label,
        attack_type=scenario["attack_type"],
        attacker_instruction=scenario["attacker_instruction"],
    )
