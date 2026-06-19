"""
SKILL: Chain Forge [DIVINE]
The master orchestrator. Loads the target. Runs every skill module.
Chains findings. Produces the final AppraisalResult.
"""

import time
import traceback
from typing import List, Optional, Dict, Type
from appraisal.engine.loader import load_apk, AnalysisContext
from appraisal.engine.base_module import BaseModule
from appraisal.models import AppraisalResult, Finding, Rank
from appraisal.modules.manifest_module   import ManifestModule
from appraisal.modules.component_module  import ComponentExposureModule
from appraisal.modules.deeplink_module   import DeepLinkModule
from appraisal.modules.taint_module      import TaintAnalysisModule
from appraisal.modules.crypto_module     import CryptoModule
from appraisal.modules.binary_module     import BinaryHardeningModule
from appraisal.modules.sdk_module        import SDKFingerprintModule
from appraisal.modules.binder_module     import BinderBreachModule


ALL_MODULES: List[Type[BaseModule]] = [
    ManifestModule,
    ComponentExposureModule,
    DeepLinkModule,
    TaintAnalysisModule,
    CryptoModule,
    BinaryHardeningModule,
    SDKFingerprintModule,
    BinderBreachModule,
]


class ModuleError(Exception):
    """Raised when a module fails during execution."""
    def __init__(self, module_name: str, error: Exception):
        self.module_name = module_name
        self.original    = error
        super().__init__(f"[{module_name}] {error}")


class Orchestrator:
    """
    The master skill. Loads target, runs all modules, returns AppraisalResult.
    """

    def __init__(
        self,
        modules: Optional[List[Type[BaseModule]]] = None,
        verbose: bool = False,
        skip_modules: Optional[List[str]] = None,
    ):
        self.module_classes  = modules or ALL_MODULES
        self.verbose         = verbose
        self.skip_modules    = [s.lower() for s in (skip_modules or [])]
        self._status_cb      = None          # optional progress callback(msg: str)
        self.module_errors: List[ModuleError] = []
        self.module_timings: Dict[str, float] = {}

    def set_status_callback(self, cb):
        """Register a callback for real-time progress updates."""
        self._status_cb = cb

    def _status(self, msg: str):
        if self._status_cb:
            self._status_cb(msg)

    def run(self, apk_path: str) -> AppraisalResult:
        """
        Full appraisal run.
        Returns AppraisalResult with all findings from all modules.
        """
        total_start = time.time()

        # ── Load APK ──────────────────────────────────────────────────────────
        self._status("Loading APK and parsing DEX bytecode...")
        ctx = load_apk(apk_path)
        self._status(f"Target locked: {ctx.package_name} v{ctx.version_name}")

        all_findings: List[Finding] = []

        # ── Run modules ───────────────────────────────────────────────────────
        for module_cls in self.module_classes:
            module = module_cls()
            name   = module.SKILL_NAME
            skill  = module.SKILL_TYPE.value

            if name.lower() in self.skip_modules:
                self._status(f"[SKIP] [{skill}] {name}")
                continue

            self._status(f"[{skill}] {name}...")
            t_start = time.time()

            try:
                findings = module.run(ctx)
                all_findings.extend(findings)
                elapsed = time.time() - t_start
                self.module_timings[name] = elapsed
                self._status(
                    f"  ✓ {name} — {len(findings)} finding(s) [{elapsed:.1f}s]"
                )
            except Exception as e:
                elapsed = time.time() - t_start
                self.module_timings[name] = elapsed
                err = ModuleError(name, e)
                self.module_errors.append(err)
                self._status(f"  ✗ {name} — ERROR: {e}")
                if self.verbose:
                    traceback.print_exc()

        # ── Chain analysis ────────────────────────────────────────────────────
        all_findings = self._deduplicate(all_findings)
        all_findings = self._chain_analysis(all_findings)
        all_findings.sort(key=lambda f: f.cvss_score, reverse=True)

        total_elapsed = time.time() - total_start

        return AppraisalResult(
            apk_path     = apk_path,
            package_name = ctx.package_name,
            app_name     = ctx.app_name,
            version_name = ctx.version_name,
            version_code = ctx.version_code,
            min_sdk      = ctx.min_sdk,
            target_sdk   = ctx.target_sdk,
            findings     = all_findings,
            scan_duration= total_elapsed,
        )

    # ── Deduplication ─────────────────────────────────────────────────────────

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove exact duplicate findings by ID."""
        seen = set()
        unique = []
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                unique.append(f)
        return unique

    # ── Vulnerability chaining ────────────────────────────────────────────────

    def _chain_analysis(self, findings: List[Finding]) -> List[Finding]:
        """
        Detect and annotate vulnerability chains.
        A chain is when multiple findings combine for greater impact.

        Example chains:
        - debuggable + exported activity = trivial full data dump (S-rank escalation)
        - cleartext + taint flow = confirmed MitM data theft chain
        - no root detection + no frida detection = fully open to dynamic analysis
        """
        ids = {f.id for f in findings}
        finding_map = {f.id: f for f in findings}

        # Chain 1: Debuggable + Exported Activity → Trivial Data Exfiltration
        if "MANIFEST-001" in ids:
            exported_acts = [
                f for f in findings
                if f.id.startswith("COMP-ACT-") and f.cvss_score >= 6.0
            ]
            if exported_acts:
                for act_finding in exported_acts[:3]:
                    act_finding.title = "⚡ [CHAIN] " + act_finding.title
                    act_finding.description = (
                        "VULNERABILITY CHAIN DETECTED: This exported activity is combined "
                        "with android:debuggable=true (MANIFEST-001). Together, "
                        "these allow any ADB-connected attacker to: (1) attach a JDWP debugger, "
                        "(2) start this activity with forged Intent extras, "
                        "(3) extract all private app data via run-as. "
                        "Full device access. No root needed.\n\n"
                    ) + act_finding.description
                    act_finding._rank = Rank.SS
                    act_finding.tags.append("chain")
                    act_finding.tags.append("debuggable-chain")

        # Chain 2: No Cert Pinning + Taint Flow to Network → Confirmed MitM Data Theft
        no_pin = "BINARY-NOPIN" in ids
        taint_flows = [f for f in findings if "TAINT-" in f.id and f.cvss_score >= 8.0]
        if no_pin and taint_flows:
            for tf in taint_flows[:2]:
                tf.title = "⚡ [CHAIN] " + tf.title
                tf.description = (
                    "VULNERABILITY CHAIN DETECTED: No certificate pinning (BINARY-NOPIN) "
                    "combined with this taint flow means an attacker can intercept TLS traffic "
                    "AND exploit the taint flow simultaneously. "
                    "Network interception becomes trivial when pinning is absent.\n\n"
                ) + tf.description
                tf.tags.append("chain")
                tf.tags.append("no-pinning-chain")

        # Chain 3: Custom scheme deep link + unvalidated WebView → XSS/data theft
        deep_links = [f for f in findings if "DEEPLINK-CUSTOM-" in f.id]
        webview_js = [f for f in findings if "TAINT-WEBVIEW-JS" in f.id]
        if deep_links and webview_js:
            for dl in deep_links[:1]:
                dl.title = "⚡ [CHAIN] " + dl.title
                dl.description = (
                    "VULNERABILITY CHAIN: Custom scheme deep link + JavaScript-enabled WebView. "
                    "An attacker app registers the same custom scheme, intercepts the deep link, "
                    "injects a javascript: URL, and executes arbitrary JS in the WebView context. "
                    "Cookie theft, DOM manipulation, and data exfiltration are trivial.\n\n"
                ) + dl.description
                dl._rank = Rank.SS
                dl.tags.append("chain")

        # Chain 4: Exported Content Provider + No Backup Restriction → DB dump + backup
        providers = [f for f in findings if "COMP-PRV-" in f.id]
        backup    = finding_map.get("MANIFEST-002")
        if providers and backup:
            backup.title = "⚡ [CHAIN] " + backup.title
            backup.description = (
                "VULNERABILITY CHAIN: ADB backup enabled + exported Content Provider(s). "
                "The Content Provider exposes database access directly; "
                "the backup vulnerability allows the entire /databases/ directory "
                "to be extracted in one shot via adb backup. "
                "Two independent paths to full database exfiltration.\n\n"
            ) + backup.description
            backup.tags.append("chain")

        return findings
