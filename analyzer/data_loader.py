"""Load the InjecAgent benchmark data."""

import json
from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "injecagent"
SCENARIO_FILES = {"DH": "test_cases_dh_base.json", "DS": "test_cases_ds_base.json"}


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
