from dataclasses import dataclass, field
from typing import Any


@dataclass
class PhaseState:
    messages: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    round: int = 0
    completed: bool = False


@dataclass
class SultanateState:
    target: str
    phase: str = ""
    config: Any | None = None

    scout_report: dict | None = None
    planner_report: dict | None = None
    raider_report: dict | None = None

    scout_phase: PhaseState = field(default_factory=PhaseState)
    planner_phase: PhaseState = field(default_factory=PhaseState)
    raider_phase: PhaseState = field(default_factory=PhaseState)

    final_report: str = ""
