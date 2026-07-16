"""
Cyber Sultanate System (CSS) - Autonomous Penetration Testing Framework

A three-phase LLM-driven penetration testing agent:
  SCOUT  -> Reconnaissance (nmap, whatweb, gobuster, etc.)
  PLANNER -> Vulnerability analysis (searchsploit, NVD, nikto)
  RAIDER  -> Exploitation (sqlmap, hydra, metasploit)
"""

__version__ = "0.1.0"

from css.engine import Sultanate
from css.config import Config, Target
from css.models.state import SultanateState, PhaseState
from css.models.report import generate_report, generate_json_report

__all__ = [
    "Sultanate",
    "Config",
    "Target",
    "SultanateState",
    "PhaseState",
    "generate_report",
    "generate_json_report",
]