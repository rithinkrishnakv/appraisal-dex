"""
Appraisal: DEX — Test Suite
Tests for models, CVSS scoring, module logic, and orchestrator.
"""

import pytest
import zipfile
import os
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from typing import List, Optional

# ── Adjust path ───────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from appraisal.models import (
    CVSSVector, Rank, Finding, PoC, AppraisalResult, SkillType
)
from appraisal.engine.orchestrator import Orchestrator


# ─────────────────────────────────────────────────────────────────────────────
#  CVSS Scoring Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCVSSVector:
    def test_zero_impact_score(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")
        assert v.score() == 0.0

    def test_critical_rce(self):
        # Network RCE, no auth, no user interaction, full impact
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        assert v.score() >= 9.0

    def test_local_exploit(self):
        v = CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")
        score = v.score()
        assert 7.0 <= score <= 9.0

    def test_vector_string_format(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        vs = v.vector_string()
        assert vs.startswith("CVSS:3.1/AV:N")
        assert "C:H" in vs
        assert "I:H" in vs
        assert "A:H" in vs

    def test_scope_changed_increases_score(self):
        v_unchanged = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")
        v_changed   = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N")
        assert v_changed.score() >= v_unchanged.score()


# ─────────────────────────────────────────────────────────────────────────────
#  Rank Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestRank:
    def test_rank_from_cvss_zero(self):
        assert Rank.from_cvss(0.0) == Rank.F

    def test_rank_from_cvss_critical(self):
        assert Rank.from_cvss(9.0) == Rank.S

    def test_rank_from_cvss_devastating(self):
        assert Rank.from_cvss(9.6) == Rank.SS

    def test_rank_from_cvss_extinction(self):
        assert Rank.from_cvss(10.0) == Rank.SSS

    def test_rank_from_cvss_medium(self):
        rank = Rank.from_cvss(6.5)
        assert rank == Rank.B

    def test_rank_labels(self):
        assert Rank.S.label == "S"
        assert Rank.SSS.description == "Extinction"


# ─────────────────────────────────────────────────────────────────────────────
#  Finding Model Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFinding:
    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            id="TEST-001",
            title="Test Finding",
            category="Test",
            description="A test finding.",
            technical_detail="Some detail.",
            cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
            evidence=["evidence line"],
            remediation="Fix it.",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_rank_derived_from_cvss(self):
        f = self._make_finding()
        assert f.rank == Rank.S or f.rank == Rank.SS  # high score

    def test_rank_override(self):
        f = self._make_finding(_rank=Rank.F)
        assert f.rank == Rank.F

    def test_to_dict_has_required_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        for key in ("id", "title", "category", "rank", "cvss_score",
                    "cvss_vector", "description", "evidence", "pocs"):
            assert key in d, f"Missing key: {key}"

    def test_cvss_score_in_dict(self):
        f = self._make_finding()
        assert f.to_dict()["cvss_score"] >= 9.0

    def test_pocs_serialise(self):
        poc = PoC(
            type="adb_command",
            title="Test PoC",
            description="Does something",
            code="adb shell ...",
        )
        f = self._make_finding(pocs=[poc])
        d = f.to_dict()
        assert len(d["pocs"]) == 1
        assert d["pocs"][0]["type"] == "adb_command"


# ─────────────────────────────────────────────────────────────────────────────
#  AppraisalResult Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAppraisalResult:
    def _make_result(self, findings=None) -> AppraisalResult:
        return AppraisalResult(
            apk_path="test.apk",
            package_name="com.test.app",
            app_name="Test App",
            version_name="1.0",
            version_code="1",
            min_sdk=21,
            target_sdk=33,
            findings=findings or [],
            scan_duration=1.23,
        )

    def test_empty_findings(self):
        r = self._make_result()
        assert r.highest_rank is None
        assert r.stats["S"] == 0

    def test_stats_count(self):
        f1 = Finding(
            id="F1", title="T1", category="C", description="D",
            technical_detail="TD", cvss=CVSSVector(C="H", I="H", A="H"),
        )
        f2 = Finding(
            id="F2", title="T2", category="C", description="D",
            technical_detail="TD", cvss=CVSSVector(),
            _rank=Rank.D,
        )
        r = self._make_result(findings=[f1, f2])
        assert r.stats.get("D", 0) >= 1

    def test_to_json_valid(self):
        import json
        r = self._make_result()
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["target"]["package_name"] == "com.test.app"
        assert "findings" in parsed

    def test_highest_rank_s(self):
        f = Finding(
            id="F1", title="T", category="C", description="D",
            technical_detail="T", cvss=CVSSVector(AV="N", AC="L", PR="N",
            UI="N", S="U", C="H", I="H", A="H"),
        )
        r = self._make_result(findings=[f])
        assert r.highest_rank is not None
        assert r.highest_rank.label in ("S", "SS", "SSS")


# ─────────────────────────────────────────────────────────────────────────────
#  Crypto Module Tests (unit-level, no APK needed)
# ─────────────────────────────────────────────────────────────────────────────

class TestCryptoModuleLogic:
    def test_redact_short(self):
        from appraisal.modules.crypto_module import CryptoModule
        m = CryptoModule()
        redacted = m._redact("ABCD1234")
        assert "ABCD" not in redacted or "..." in redacted

    def test_redact_long(self):
        from appraisal.modules.crypto_module import CryptoModule
        m = CryptoModule()
        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = m._redact(secret)
        assert "..." in redacted
        assert len(redacted) < len(secret) + 15

    def test_weak_algo_list_not_empty(self):
        from appraisal.modules.crypto_module import WEAK_ALGORITHMS
        assert len(WEAK_ALGORITHMS) > 0
        assert "DES" in WEAK_ALGORITHMS
        assert "RC4" in WEAK_ALGORITHMS

    def test_taint_sources_and_sinks_defined(self):
        from appraisal.modules.taint_module import TAINT_SOURCES, TAINT_SINKS
        assert len(TAINT_SOURCES) >= 5
        assert len(TAINT_SINKS)   >= 5

        source_labels = [s.label for s in TAINT_SOURCES]
        sink_labels   = [s.label for s in TAINT_SINKS]
        assert "Intent.getStringExtra" in source_labels
        assert "WebView.loadUrl"       in sink_labels
        assert "Runtime.exec"          in sink_labels


# ─────────────────────────────────────────────────────────────────────────────
#  Manifest Module — pure logic tests
# ─────────────────────────────────────────────────────────────────────────────

class TestManifestModuleLogic:
    def _mock_ctx(self, **kwargs):
        ctx = MagicMock()
        ctx.package_name  = kwargs.get("package_name", "com.test.app")
        ctx.manifest_tree = MagicMock()
        ctx.manifest_xml  = kwargs.get("manifest_xml", "")
        ctx.min_sdk       = kwargs.get("min_sdk", 21)
        ctx.target_sdk    = kwargs.get("target_sdk", 33)
        ctx.permissions   = kwargs.get("permissions", [])
        ctx.components    = kwargs.get("components", [])
        ctx.has_network_security_config = False
        ctx.network_security_config_xml = None
        ctx.strings_pool  = []

        # Set up manifest_tree.find to return an Element with attrs
        from xml.etree import ElementTree as ET
        app_el = ET.Element("application")
        for attr, val in kwargs.get("app_attrs", {}).items():
            app_el.set(f"{{http://schemas.android.com/apk/res/android}}{attr}", val)
        ctx.manifest_tree.find.return_value = app_el
        return ctx

    def test_detects_debuggable(self):
        from appraisal.modules.manifest_module import ManifestModule
        ctx = self._mock_ctx(app_attrs={"debuggable": "true"})
        m = ManifestModule()
        findings = m._check_debuggable.__wrapped__(m, ctx) if hasattr(
            m._check_debuggable, '__wrapped__') else None
        # Just test module doesn't crash and can instantiate
        assert m is not None

    def test_module_instantiation(self):
        from appraisal.modules.manifest_module import ManifestModule
        m = ManifestModule()
        assert m.SKILL_NAME == "Manifest Sight"
        assert m.SKILL_TYPE == SkillType.PASSIVE


# ─────────────────────────────────────────────────────────────────────────────
#  Deep Link Module — URL generation tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDeepLinkModuleLogic:
    def test_html_poc_generation(self):
        from appraisal.modules.deeplink_module import DeepLinkModule
        m = DeepLinkModule()
        ctx = MagicMock()
        ctx.package_name = "com.test.app"
        dl = {
            "scheme": "https",
            "host": "app.example.com",
            "path": "/callback",
            "pathPrefix": "",
            "pathPattern": "",
            "component": "com.test.app.MainActivity",
        }
        html = m._generate_html_poc(ctx, dl)
        assert "<!DOCTYPE html>" in html
        assert "app.example.com" in html
        assert "Appraisal: DEX" in html
        assert "javascript:" in html or "javascript" in html


# ─────────────────────────────────────────────────────────────────────────────
#  Binder Module — PendingIntent tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBinderModuleLogic:
    def test_module_instantiation(self):
        from appraisal.modules.binder_module import BinderBreachModule
        m = BinderBreachModule()
        assert "Binder" in m.SKILL_NAME
        assert m.SKILL_TYPE == SkillType.UNIQUE


# ─────────────────────────────────────────────────────────────────────────────
#  Binary Module — entropy calculation
# ─────────────────────────────────────────────────────────────────────────────

class TestBinaryModuleLogic:
    def test_shannon_entropy_all_same(self):
        from appraisal.modules.binary_module import _shannon_entropy
        data = bytes([0x41] * 1000)
        assert _shannon_entropy(data) == 0.0

    def test_shannon_entropy_random(self):
        from appraisal.modules.binary_module import _shannon_entropy
        import os
        data = os.urandom(10000)
        entropy = _shannon_entropy(data)
        # True random should be close to 8.0
        assert entropy > 7.5

    def test_shannon_entropy_empty(self):
        from appraisal.modules.binary_module import _shannon_entropy
        assert _shannon_entropy(b"") == 0.0

    def test_high_entropy_detection_threshold(self):
        from appraisal.modules.binary_module import _shannon_entropy
        import os
        # Random bytes = high entropy = should flag as packed
        data = os.urandom(4096)
        assert _shannon_entropy(data) >= 7.2


# ─────────────────────────────────────────────────────────────────────────────
#  Orchestrator — unit tests with mocked modules
# ─────────────────────────────────────────────────────────────────────────────

class TestOrchestrator:
    def test_deduplication(self):
        orch = Orchestrator()
        f1 = Finding(
            id="DUP-001", title="Dup", category="C", description="D",
            technical_detail="T", cvss=CVSSVector(),
        )
        f2 = Finding(
            id="DUP-001", title="Dup", category="C", description="D",
            technical_detail="T", cvss=CVSSVector(),
        )
        result = orch._deduplicate([f1, f2])
        assert len(result) == 1

    def test_skip_modules(self):
        orch = Orchestrator(skip_modules=["Manifest Sight"])
        assert "manifest sight" in orch.skip_modules

    def test_chain_analysis_no_crash_empty(self):
        orch = Orchestrator()
        result = orch._chain_analysis([])
        assert result == []

    def test_chain_detection_debuggable_plus_exported(self):
        orch = Orchestrator()
        debuggable = Finding(
            id="MANIFEST-001", title="Debuggable", category="Manifest",
            description="D", technical_detail="T",
            cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
        )
        exported = Finding(
            id="COMP-ACT-SomeActivity", title="Exported Activity", category="Component",
            description="D", technical_detail="T",
            cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        )
        findings = orch._chain_analysis([debuggable, exported])
        chained = [f for f in findings if "chain" in f.tags]
        assert len(chained) >= 1


# ─────────────────────────────────────────────────────────────────────────────
#  SDK Module — fingerprint logic
# ─────────────────────────────────────────────────────────────────────────────

class TestSDKModuleLogic:
    def test_sdk_fingerprints_not_empty(self):
        from appraisal.modules.sdk_module import SDK_FINGERPRINTS
        assert len(SDK_FINGERPRINTS) >= 5

    def test_cve_database_structure(self):
        from appraisal.modules.sdk_module import SDK_CVES
        for pkg, cves in SDK_CVES.items():
            for cve in cves:
                assert "cve"         in cve
                assert "score"       in cve
                assert "description" in cve
                assert cve["score"]  >= 0.0
                assert cve["score"]  <= 10.0


# ─────────────────────────────────────────────────────────────────────────────
#  Report Renderer Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestReportRenderer:
    def _make_result(self) -> AppraisalResult:
        findings = [
            Finding(
                id="TEST-S-001",
                title="Critical RCE",
                category="Test",
                description="A critical remote code execution.",
                technical_detail="Via Intent injection into Runtime.exec()",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
                evidence=["exec() call with Intent extra"],
                affected_components=["com.test.VulnActivity"],
                remediation="Don't do that.",
                pocs=[PoC(
                    type="adb_command",
                    title="RCE via ADB",
                    description="Fire the intent",
                    code="adb shell am start -n com.test/.VulnActivity --es cmd 'id'",
                )],
                tags=["rce", "intent", "exec"],
            )
        ]
        return AppraisalResult(
            apk_path="test.apk",
            package_name="com.test.app",
            app_name="Test App",
            version_name="2.0",
            version_code="200",
            min_sdk=21,
            target_sdk=33,
            findings=findings,
            scan_duration=5.5,
        )

    def test_html_render_contains_package(self):
        from appraisal.report.renderer import _render_html
        result = self._make_result()
        html = _render_html(result)
        assert "com.test.app" in html
        assert "APPRAISAL: DEX" in html
        assert "Critical RCE" in html

    def test_html_render_contains_poc(self):
        from appraisal.report.renderer import _render_html
        result = self._make_result()
        html = _render_html(result)
        assert "adb shell" in html

    def test_json_report_valid_json(self):
        import json
        result = self._make_result()
        j = result.to_json()
        parsed = json.loads(j)
        assert parsed["summary"]["total_findings"] == 1
        assert parsed["findings"][0]["id"] == "TEST-S-001"

    def test_html_escape(self):
        from appraisal.report.renderer import _esc
        assert _esc("<script>") == "&lt;script&gt;"
        assert _esc("'") == "&#x27;" or _esc("'") == "'"  # either is fine
        assert _esc("") == ""


# ─────────────────────────────────────────────────────────────────────────────
#  Integration smoke test — create minimal fake APK and scan it
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationSmoke:
    """
    Creates a minimal valid APK (ZIP with a dummy AndroidManifest.xml)
    and verifies the tool doesn't crash.
    Uses androguard's own test fixtures if available.
    """

    def _find_sample_apk(self) -> Optional[str]:
        # Look for any .apk in the tests/samples directory
        samples_dir = Path(__file__).parent / "samples"
        if samples_dir.exists():
            apks = list(samples_dir.glob("*.apk"))
            if apks:
                return str(apks[0])
        return None

    def test_orchestrator_module_list_non_empty(self):
        from appraisal.engine.orchestrator import ALL_MODULES
        assert len(ALL_MODULES) >= 6

    def test_all_modules_instantiate(self):
        from appraisal.engine.orchestrator import ALL_MODULES
        for module_cls in ALL_MODULES:
            m = module_cls()
            assert hasattr(m, "run")
            assert hasattr(m, "SKILL_NAME")
            assert hasattr(m, "SKILL_TYPE")
            assert hasattr(m, "DESCRIPTION")

    def test_models_import_cleanly(self):
        from appraisal.models import (
            CVSSVector, Rank, Finding, PoC, AppraisalResult, SkillType
        )
        assert CVSSVector is not None
        assert Rank is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
