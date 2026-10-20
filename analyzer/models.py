"""Data classes shared by the analyzer components."""

from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """One step of an agent action: the tool it calls and the input it gives."""

    tool: str
    input: str = ""


@dataclass
class Case:
    """A user request together with the action an agent attempted."""

    case_id: str
    user_request: str
    actions: list
    allowed_toolkits: list = field(default_factory=list)
    user_tool: str = ""
    scenario_id: str = ""
    variant: str = ""
    expected_label: str = ""
    attack_type: str = ""
    attacker_instruction: str = ""


@dataclass
class Finding:
    """A security problem that one rule found in one step of an action."""

    rule_id: str
    issue: str
    severity: str
    detail: str
    step: int = 1
