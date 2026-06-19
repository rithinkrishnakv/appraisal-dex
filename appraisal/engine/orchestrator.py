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

# Core modules
from appraisal.modules.manifest_module          import ManifestModule
from appraisal.modules.component_module         import ComponentExposureModule
from appraisal.modules.deeplink_module          import DeepLinkModule
from appraisal.modules.taint_module             import TaintAnalysisModule
from appraisal.modules.crypto_module            import CryptoModule
from appraisal.modules.binary_module            import BinaryHardeningModule
from appraisal.modules.sdk_module               import SDKFingerprintModule
from appraisal.modules.binder_module            import BinderBreachModule
# OWASP Mobile Top 10 modules
from appraisal.modules.credential_module        import CredentialModule
from appraisal.modules.supply_chain_module      import SupplyChainSentinelModule
from appraisal.modules.auth_module              import AuthModule
from appraisal.modules.input_validation_module  import InputValidationModule
from appraisal.modules.network_privacy_module   import NetworkPrivacyModule
from appraisal.modules.misconfig_storage_module import MisconfigStorageModule


ALL_MODULES: List[Type[BaseModule]] = [
    # ── Core skill modules ───────────────────────────────────────────────────
    ManifestModule,            # [PASSIVE] Manifest Sight
    ComponentExposureModule,   # [ACTIVE]  Component Exposure Scanner
    DeepLinkModule,            # [ACTIVE]  Deep Link Interceptor
    TaintAnalysisModule,       # [ACTIVE]  Taint Walk
    CryptoModule,              # [UNIQUE]  Cipher Sight
    BinaryHardeningModule,     # [UNIQUE]  Binary Hardening Auditor
    SDKFingerprintModule,      # [HIDDEN]  Supply Chain Scanner
    BinderBreachModule,        # [UNIQUE]  Binder Breach
    # ── OWASP Mobile Top 10 ─────────────────────────────────────────────────
    CredentialModule,          # M1  — Improper Credential Usage
    SupplyChainSentinelModule, # M2  — Inadequate Supply Chain Security
    AuthModule,                # M3  — Insecure Authentication/Authorization
    InputValidationModule,     # M4  — Insufficient Input/Output Validation
    NetworkPrivacyModule,      # M5/M6/M7 — Network, Privacy, Binary Protections
    MisconfigStorageModule,    # M8/M9/M10 — Misconfiguration, Storage, Crypto
]


class ModuleError(Exception):
    def __init__(self, module_name: str, error: Exception):
        self.module_name = module_name
        self.original    = error
        super().__init__(f"[{module_name}] {error}")


class Orchestrator:
    def __init__(
        self,
        modules: Optional[List[Type[BaseModule]]] = None,
        verbose: bool = False,
        skip_modules: Optional[List[str]] = None,
    ):
        self.module_classes  = modules or ALL_MODULES
        self.verbose         = verbose
        self.skip_modules    = [s.lower() for s in (skip_modules or [])]
        self._status_cb      = None
        self.module_errors: List[ModuleError] = []
        self.module_timings: Dict[str, float] = {}

    def set_status_callback(self, cb):
        self._status_cb = cb

    def _status(self, msg: str):
        if self._status_cb:
            self._status_cb(msg)

    def run(self, apk_path: str) -> AppraisalResult:
        total_start = time.time()
        self._status("Loading APK and parsing DEX bytecode...")
        ctx = load_apk(apk_path)
        self._status(f"Target locked: {ctx.package_name} v{ctx.version_name}")

        all_findings: List[Finding] = []

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
                self._status(f"  ✓ {name} — {len(findings)} finding(s) [{elapsed:.1f}s]")
            except Exception as e:
                elapsed = time.time() - t_start
                self.module_timings[name] = elapsed
                err = ModuleError(name, e)
                self.module_errors.append(err)
                self._status(f"  ✗ {name} — ERROR: {e}")
                if self.verbose:
                    traceback.print_exc()

        all_findings = self._deduplicate(all_findings)
        all_findings = self._chain_analysis(all_findings)
        all_findings.sort(key=lambda f: f.cvss_score, reverse=True)

        return AppraisalResult(
            apk_path     = apk_path,
            package_name = ctx.package_name,
            app_name     = ctx.app_name,
            version_name = ctx.version_name,
            version_code = ctx.version_code,
            min_sdk      = ctx.min_sdk,
            target_sdk   = ctx.target_sdk,
            findings     = all_findings,
            scan_duration= time.time() - total_start,
        )

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        seen = set()
        unique = []
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                unique.append(f)
        return unique

    def _chain_analysis(self, findings: List[Finding]) -> List[Finding]:
        ids = {f.id for f in findings}
        finding_map = {f.id: f for f in findings}

        # Chain 1: Debuggable + Exported Activity
        if "MANIFEST-001" in ids:
            exported_acts = [f for f in findings
                             if f.id.startswith("COMP-ACT-") and f.cvss_score >= 6.0]
            for act in exported_acts[:3]:
                act.title = "⚡ [CHAIN] " + act.title
                act.description = (
                    "VULNERABILITY CHAIN: debuggable=true (MANIFEST-001) + exported Activity. "
                    "Full data exfiltration with no root needed.\n\n"
                ) + act.description
                act._rank = Rank.SS
                act.tags.append("chain")

        # Chain 2: No Cert Pinning + Taint Flow
        if "BINARY-NOPIN" in ids:
            taint_flows = [f for f in findings if "TAINT-" in f.id and f.cvss_score >= 8.0]
            for tf in taint_flows[:2]:
                tf.title = "⚡ [CHAIN] " + tf.title
                tf.description = (
                    "VULNERABILITY CHAIN: No cert pinning + taint flow = confirmed MitM + data theft.\n\n"
                ) + tf.description
                tf.tags.append("chain")

        # Chain 3: Custom scheme deep link + JS WebView
        deep_links = [f for f in findings if "DEEPLINK-CUSTOM-" in f.id]
        webview_js = [f for f in findings if "TAINT-WEBVIEW-JS" in f.id]
        if deep_links and webview_js:
            for dl in deep_links[:1]:
                dl.title = "⚡ [CHAIN] " + dl.title
                dl._rank = Rank.SS
                dl.tags.append("chain")

        # Chain 4: Exported Content Provider + Backup
        providers = [f for f in findings if "COMP-PRV-" in f.id]
        backup    = finding_map.get("MANIFEST-002")
        if providers and backup:
            backup.title = "⚡ [CHAIN] " + backup.title
            backup.tags.append("chain")

        # Chain 5: Client-side auth + Exported Activity (M3 + Component)
        client_auth = finding_map.get("M3-CLIENT-AUTH")
        exported_acts_chain = [f for f in findings if "COMP-ACT-" in f.id]
        if client_auth and exported_acts_chain:
            client_auth.title = "⚡ [CHAIN] " + client_auth.title
            client_auth.description = (
                "VULNERABILITY CHAIN: Client-side auth flags + exported activities. "
                "Privilege escalation to admin via forged Intent with isAdmin=true.\n\n"
            ) + client_auth.description
            client_auth._rank = Rank.SS
            client_auth.tags.append("chain")

        # Chain 6: Hardcoded credential + Firebase open access
        hardcoded_cred = any("M1-CRED-" in f.id for f in findings)
        firebase_open  = any("M8-FIREBASE" in f.id for f in findings)
        if hardcoded_cred and firebase_open:
            for f in findings:
                if "M8-FIREBASE" in f.id:
                    f.title = "⚡ [CHAIN] " + f.title
                    f.description = (
                        "VULNERABILITY CHAIN: Hardcoded Firebase API key + open database rules. "
                        "Attacker extracts key from APK, accesses open Firebase DB without auth.\n\n"
                    ) + f.description
                    f._rank = Rank.SS
                    f.tags.append("chain")

        return findings
