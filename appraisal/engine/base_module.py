"""
Base class for every Appraisal: DEX skill module.
Each module is a skill — with a type, a name, and a run() method.
"""

from abc import ABC, abstractmethod
from typing import List
from appraisal.models import Finding, SkillType
from appraisal.engine.loader import AnalysisContext


class BaseModule(ABC):
    """Every skill module inherits from this."""

    SKILL_NAME: str       = "Unnamed Skill"
    SKILL_TYPE: SkillType = SkillType.PASSIVE
    DESCRIPTION: str      = ""

    def __init__(self):
        self._findings: List[Finding] = []

    @abstractmethod
    def run(self, ctx: AnalysisContext) -> List[Finding]:
        """Execute the skill. Return a list of findings."""
        ...

    def _add(self, finding: Finding):
        self._findings.append(finding)

    @property
    def findings(self) -> List[Finding]:
        return self._findings

    def __repr__(self):
        return f"[{self.SKILL_TYPE.value}] {self.SKILL_NAME}"
