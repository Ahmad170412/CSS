"""
CSS Data Models
"""

from css.models.state import SultanateState, PhaseState
from css.models.report import generate_report, generate_json_report

__all__ = [
    "SultanateState",
    "PhaseState",
    "generate_report",
    "generate_json_report",
]