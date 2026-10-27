"""Data classes shared by the analyzer components."""

from dataclasses import dataclass, field


@dataclass
class ToolCall:
    """One step of an agent action: the tool it calls and the input it gives."""

    tool: str
    input: str = ""


@dataclass
class Case:
    """A user request together with the action an agent attempted.

    allowed_toolkits and forbidden_data are optional security restrictions.
    An empty list means no restriction was given for the case.
    """

    case_id: str
    user_request: str
    actions: list
    allowed_toolkits: list = field(default_factory=list)
    forbidden_data: list = field(default_factory=list)
    allowed_destinations: list = field(default_factory=list)
    user_tool: str = ""
    scenario_id: str = ""
    variant: str = ""
    expected_label: str = ""
    attack_type: str = ""
    attacker_instruction: str = ""


@dataclass
class Finding:
    """The outcome of one security rule for one step (step 0 means the whole case)."""

    rule_id: str
    issue: str
    outcome: str
    detail: str
    step: int = 1


@dataclass
class LLMAssessment:
    """The local model's judgement of whether the action serves the user's request.

    alignment is "Aligned", "Misaligned" or "Unknown". error is empty when the model answered correctly.
    """

    alignment: str
    reason: str = ""
    error: str = ""
