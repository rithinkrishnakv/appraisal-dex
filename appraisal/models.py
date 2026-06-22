"""
Core data models for Appraisal: DEX
The Appraisal Window — every vulnerability is a card with stats, rank, and proof.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import json
import time


class Rank(Enum):
    """Appraisal rank system — from informational noise to full annihilation."""
    F   = ("F",   "Informational",  "#808080", 0.0)
    D   = ("D",   "Hardening",      "#00BFFF", 2.0)
    C   = ("C",   "Low",            "#00FF7F", 4.0)
    B   = ("B",   "Medium",         "#FFD700", 6.0)
    A   = ("A",   "High",           "#FF8C00", 8.0)
    S   = ("S",   "Critical",       "#FF4444", 9.0)
    SS  = ("SS",  "Devastating",    "#FF00FF", 9.5)
    SSS = ("SSS", "Extinction",     "#FFFFFF", 10.0)

    def __init__(self, label, description, color, base_score):
        self.label = label
        self.description = description
        self.color = color
        self.base_score = base_score

    @classmethod
    def from_cvss(cls, score: float) -> "Rank":
        if score == 0.0:   return cls.F
        if score < 3.0:    return cls.D
        if score < 5.0:    return cls.C
        if score < 7.0:    return cls.B
        if score < 9.0:    return cls.A
        if score < 9.5:    return cls.S
        if score < 10.0:   return cls.SS
        return cls.SSS


class SkillType(Enum):
    PASSIVE = "PASSIVE"
    ACTIVE  = "ACTIVE"
    UNIQUE  = "UNIQUE"
    HIDDEN  = "HIDDEN"
    DIVINE  = "DIVINE"


@dataclass
class CVSSVector:
    """CVSS v3.1 vector with auto-score calculation."""
    AV:  str = "N"   # Attack Vector:        N=Network, A=Adjacent, L=Local, P=Physical
    AC:  str = "L"   # Attack Complexity:    L=Low, H=High
    PR:  str = "N"   # Privileges Required:  N=None, L=Low, H=High
    UI:  str = "N"   # User Interaction:     N=None, R=Required
    S:   str = "U"   # Scope:                U=Unchanged, C=Changed
    C:   str = "N"   # Confidentiality:      N=None, L=Low, H=High
    I:   str = "N"   # Integrity:            N=None, L=Low, H=High
    A:   str = "N"   # Availability:         N=None, L=Low, H=High

    _AV_SCORES  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC_SCORES  = {"L": 0.77, "H": 0.44}
    _PR_SCORES  = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_SCORES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI_SCORES  = {"N": 0.85, "R": 0.62}
    _CIA_SCORES = {"N": 0.00, "L": 0.22, "H": 0.56}

    def score(self) -> float:
        av  = self._AV_SCORES.get(self.AV, 0.85)
        ac  = self._AC_SCORES.get(self.AC, 0.77)
        ui  = self._UI_SCORES.get(self.UI, 0.85)
        c   = self._CIA_SCORES.get(self.C, 0.0)
        i   = self._CIA_SCORES.get(self.I, 0.0)
        a   = self._CIA_SCORES.get(self.A, 0.0)

        if self.S == "C":
            pr = self._PR_SCORES_CHANGED.get(self.PR, 0.85)
        else:
            pr = self._PR_SCORES.get(self.PR, 0.85)

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        if self.S == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        if self.S == "U":
            base = min(impact + exploitability, 10)
        else:
            base = min(1.08 * (impact + exploitability), 10)

        # Round up to nearest 0.1
        import math
        return math.ceil(base * 10) / 10

    def vector_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
                f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")


@dataclass
class PoC:
    """Proof-of-Concept artifact — the exploit in your hands."""
    type: str           # adb_command | html_page | frida_script | curl_command | python_script
    title: str
    description: str
    code: str
    ready_to_run: bool = True


@dataclass
class Finding:
    """A single appraisal result — one flaw, fully appraised."""
    id: str
    title: str
    category: str
    description: str
    technical_detail: str
    cvss: CVSSVector
    evidence: List[str] = field(default_factory=list)
    pocs: List[PoC] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    _rank: Optional[Rank] = field(default=None, repr=False)

    @property
    def rank(self) -> Rank:
        if self._rank:
            return self._rank
        return Rank.from_cvss(self.cvss.score())

    @property
    def cvss_score(self) -> float:
        if self._rank:
            return self._rank.base_score
        return self.cvss.score()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "rank": self.rank.label,
            "rank_description": self.rank.description,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss.vector_string(),
            "description": self.description,
            "technical_detail": self.technical_detail,
            "evidence": self.evidence,
            "affected_components": self.affected_components,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "pocs": [
                {
                    "type": p.type,
                    "title": p.title,
                    "description": p.description,
                    "code": p.code,
                    "ready_to_run": p.ready_to_run,
                }
                for p in self.pocs
            ],
        }


@dataclass
class AppraisalResult:
    """The full appraisal session result."""
    apk_path: str
    package_name: str
    app_name: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    findings: List[Finding] = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    tool_version: str = "1.0.0"

    @property
    def stats(self) -> Dict[str, int]:
        counts = {r.label: 0 for r in Rank}
        for f in self.findings:
            counts[f.rank.label] += 1
        return counts

    @property
    def highest_rank(self) -> Optional[Rank]:
        if not self.findings:
            return None
        rank_order = [Rank.SSS, Rank.SS, Rank.S, Rank.A, Rank.B, Rank.C, Rank.D, Rank.F]
        for r in rank_order:
            if any(f.rank == r for f in self.findings):
                return r
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": {
                "tool": "Appraisal: DEX",
                "version": self.tool_version,
                "timestamp": self.timestamp,
                "scan_duration_seconds": round(self.scan_duration, 2),
            },
            "target": {
                "apk_path": self.apk_path,
                "package_name": self.package_name,
                "app_name": self.app_name,
                "version_name": self.version_name,
                "version_code": self.version_code,
                "min_sdk": self.min_sdk,
                "target_sdk": self.target_sdk,
            },
            "summary": {
                "total_findings": len(self.findings),
                "highest_rank": self.highest_rank.label if self.highest_rank else "CLEAN",
                "by_rank": self.stats,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
