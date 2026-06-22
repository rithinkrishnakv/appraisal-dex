"""
SKILL: Chain Forge [DIVINE]
The master orchestrator. Loads the target. Runs every skill module.
Chains findings. Produces the final AppraisalResult.
"""

import time
import os
import traceback
import logging
import atexit
import concurrent.futures
from typing import List, Optional, Dict, Type

from appraisal.engine.loader import load_apk, AnalysisContext
from appraisal.engine.base_module import BaseModule
from appraisal.models import AppraisalResult, Finding, Rank

from appraisal.modules.manifest_module          import ManifestModule
from appraisal.modules.component_module         import ComponentExposureModule
from appraisal.modules.deeplink_module          import DeepLinkModule
from appraisal.modules.taint_module             import TaintAnalysisModule, TaintStringPoolModule
from appraisal.modules.crypto_module            import CryptoModule
from appraisal.modules.binary_module            import BinaryHardeningModule
from appraisal.modules.sdk_module               import SDKFingerprintModule
from appraisal.modules.binder_module            import BinderBreachModule
from appraisal.modules.credential_module        import CredentialModule
from appraisal.modules.supply_chain_module      import SupplyChainSentinelModule
from appraisal.modules.auth_module              import AuthModule
from appraisal.modules.input_validation_module  import InputValidationModule
from appraisal.modules.network_privacy_module   import NetworkPrivacyModule
from appraisal.modules.misconfig_storage_module import MisconfigStorageModule

diagnostic_logger = logging.getLogger("appraisal.diagnostics")

ALL_MODULES: List[Type[BaseModule]] = [
    ManifestModule, ComponentExposureModule, DeepLinkModule,
    TaintAnalysisModule, TaintStringPoolModule, CryptoModule,
    BinaryHardeningModule, SDKFingerprintModule, BinderBreachModule,
    CredentialModule, SupplyChainSentinelModule, AuthModule,
    InputValidationModule, NetworkPrivacyModule, MisconfigStorageModule,
]

class ModuleError(Exception):
    def __init__(self, module_name: str, error: Exception):
        self.module_name = module_name
        self.original    = error
        super().__init__(f"[{module_name}] {error}")


# ── Process Pool Worker Lifecycle ──────────────────────────────────────────────
_worker_ctx: Optional[AnalysisContext] = None

def _init_worker(apk_path: str):
    """
    Sub-process initializer. Androguard's complex C-state cannot be pickled.
    Instead, each worker builds its own pristine context.
    """
    global _worker_ctx
    try:
        _worker_ctx = load_apk(apk_path)
        _worker_ctx.__enter__() # Manage memory mapped file descriptor lifecycle
        atexit.register(_worker_ctx.close)
    except Exception as e:
        diagnostic_logger.error(f"Worker failed to load APK {apk_path}: {e}")
        raise

def _run_module_worker(module_cls_name: str, module_cls: Type[BaseModule]):
    global _worker_ctx
    if _worker_ctx is None:
        return module_cls_name, [], 0.0, "Worker context not initialized"
        
    module = module_cls()
    t_start = time.time()
    try:
        findings = module.run(_worker_ctx)
        return module_cls_name, findings, time.time() - t_start, None
    except Exception as e:
        diagnostic_logger.error(f"[{module_cls_name}] Crash during execution: {e}", exc_info=True)
        return module_cls_name, [], time.time() - t_start, traceback.format_exc()


# ── Primary Orchestrator ───────────────────────────────────────────────────────
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
        self._status("Loading APK metadata mapping...")
        
        # Fast initialization via memory map inside context manager
        try:
            with load_apk(apk_path) as main_ctx:
                package_name = main_ctx.package_name
                app_name     = main_ctx.app_name
                version_name = main_ctx.version_name
                version_code = main_ctx.version_code
                min_sdk      = main_ctx.min_sdk
                target_sdk   = main_ctx.target_sdk
        except Exception as e:
            self._status(f"Fatal error loading APK: {e}")
            raise

        self._status(f"Target locked: {package_name} v{version_name}")

        all_findings: List[Finding] = []
        
        # Protect memory: limit the pool size to prevent mapping collisions on huge APKs
        max_workers = min(os.cpu_count() or 1, 4)

        with concurrent.futures.ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=_init_worker,
            initargs=(apk_path,)
        ) as executor:
            futures = {}
            for module_cls in self.module_classes:
                name = module_cls.SKILL_NAME
                skill = getattr(module_cls, "SKILL_TYPE", None)
                skill_val = skill.value if skill else "UNKNOWN"

                if name.lower() in self.skip_modules:
                    self._status(f"[SKIP] [{skill_val}] {name}")
                    continue

                self._status(f"Dispatching [{skill_val}] {name} to worker pool...")
                future = executor.submit(_run_module_worker, name, module_cls)
                futures[future] = name

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    mod_name, findings, elapsed, err = future.result()
                    self.module_timings[mod_name] = elapsed
                    if err:
                        self.module_errors.append(ModuleError(mod_name, Exception(err)))
                        short_err = err.splitlines()[-1] if err.strip() else "Unknown Error"
                        self._status(f"  ✗ {mod_name} — ERROR: {short_err}")
                        if self.verbose:
                            print(err)
                    else:
                        all_findings.extend(findings)
                        self._status(f"  ✓ {mod_name} — {len(findings)} finding(s) [{elapsed:.1f}s]")
                except Exception as e:
                    self.module_timings[name] = 0.0
                    self.module_errors.append(ModuleError(name, e))
                    self._status(f"  ✗ {name} — FATAL WORKER CRASH: {e}")
                    if self.verbose:
                        traceback.print_exc()

        all_findings = self._deduplicate(all_findings)
        all_findings = self._chain_analysis(all_findings)
        all_findings.sort(key=lambda f: f.cvss_score, reverse=True)

        return AppraisalResult(
            apk_path     = apk_path,
            package_name = package_name,
            app_name     = app_name,
            version_name = version_name,
            version_code = version_code,
            min_sdk      = min_sdk,
            target_sdk   = target_sdk,
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

        if "MANIFEST-001" in ids:
            exported_acts = [f for f in findings if f.id.startswith("COMP-ACT-") and f.cvss_score >= 6.0]
            for act in exported_acts[:3]:
                act.title = "⚡ [CHAIN] " + act.title
                act.description = "VULNERABILITY CHAIN: debuggable=true + exported Activity.\n\n" + act.description
                act._rank = Rank.SS
                act.tags.append("chain")

        if "BINARY-NOPIN" in ids:
            taint_flows = [f for f in findings if "TAINT-" in f.id and f.cvss_score >= 8.0]
            for tf in taint_flows[:2]:
                tf.title = "⚡ [CHAIN] " + tf.title
                tf.description = "VULNERABILITY CHAIN: No cert pinning + taint flow = confirmed MitM + data theft.\n\n" + tf.description
                tf.tags.append("chain")

        deep_links = [f for f in findings if "DEEPLINK-CUSTOM-" in f.id]
        webview_js = [f for f in findings if "TAINT-WEBVIEW-JS" in f.id]
        if deep_links and webview_js:
            for dl in deep_links[:1]:
                dl.title = "⚡ [CHAIN] " + dl.title
                dl._rank = Rank.SS
                dl.tags.append("chain")

        providers = [f for f in findings if "COMP-PRV-" in f.id]
        backup    = finding_map.get("MANIFEST-002")
        if providers and backup:
            backup.title = "⚡ [CHAIN] " + backup.title
            backup.tags.append("chain")

        client_auth = finding_map.get("M3-CLIENT-AUTH")
        exported_acts_chain = [f for f in findings if "COMP-ACT-" in f.id]
        if client_auth and exported_acts_chain:
            client_auth.title = "⚡ [CHAIN] " + client_auth.title
            client_auth.description = "VULNERABILITY CHAIN: Client-side auth flags + exported activities.\n\n" + client_auth.description
            client_auth._rank = Rank.SS
            client_auth.tags.append("chain")

        hardcoded_cred = any("M1-CRED-" in f.id for f in findings)
        firebase_open  = any("M8-FIREBASE" in f.id for f in findings)
        if hardcoded_cred and firebase_open:
            for f in findings:
                if "M8-FIREBASE" in f.id:
                    f.title = "⚡ [CHAIN] " + f.title
                    f.description = "VULNERABILITY CHAIN: Hardcoded Firebase API key + open database rules.\n\n" + f.description
                    f._rank = Rank.SS
                    f.tags.append("chain")

        return findings
