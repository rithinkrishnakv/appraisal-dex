"""
SKILL: Network Sentinel [ACTIVE]
OWASP M5 — Insecure Communication
OWASP M6 — Inadequate Privacy Controls
OWASP M7 — Insufficient Binary Protections

Three skills in one file — all network, privacy, and binary hardening
findings that aren't covered by existing modules.
"""

import re
from typing import List
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


class NetworkPrivacyModule(BaseModule):
    SKILL_NAME  = "Network & Privacy Sentinel"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "OWASP M5/M6/M7 — TLS config, PII leakage, privacy controls, binary protections"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        # M5 — Insecure Communication
        self._check_tls_version(ctx)
        self._check_hostname_verification(ctx)
        self._check_trust_all_certs(ctx)
        self._check_plaintext_endpoints(ctx)
        # M6 — Inadequate Privacy Controls
        self._check_pii_in_logs(ctx)
        self._check_pii_in_analytics(ctx)
        self._check_external_storage_pii(ctx)
        self._check_clipboard_leakage(ctx)
        self._check_screenshot_allowed(ctx)
        # M7 — Insufficient Binary Protections
        self._check_stack_canary(ctx)
        self._check_position_independent(ctx)
        return self._findings

    # ══════════════════════════════════════════════════════════════════════════
    # M5 — Insecure Communication
    # ══════════════════════════════════════════════════════════════════════════

    def _check_tls_version(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        WEAK_PROTOCOLS = {
            "SSLv3":   "SSLv3 — broken by POODLE attack (CVE-2014-3566)",
            "TLSv1":   "TLS 1.0 — deprecated by RFC 8996, BEAST attack vector",
            "TLSv1.1": "TLS 1.1 — deprecated by RFC 8996",
            "TLS_RSA": "RSA key exchange — no forward secrecy",
        }
        for proto, desc in WEAK_PROTOCOLS.items():
            if proto in pool:
                self._add(Finding(
                    id=f"M5-TLS-{proto.replace('.','_').replace('_','_')}",
                    title=f"Weak TLS Protocol/Cipher Enabled: {proto}",
                    category="Insecure Communication (M5)",
                    description=(
                        f"{desc}. "
                        "Explicitly enabling deprecated TLS versions allows downgrade attacks "
                        "where a network attacker forces negotiation of the weaker protocol, "
                        "then exploits its known vulnerabilities to decrypt traffic."
                    ),
                    technical_detail=f"Protocol string '{proto}' found in DEX string pool.",
                    cvss=CVSSVector(AV="A", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=[f"Weak protocol '{proto}' in DEX pool"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Allow only TLS 1.2 and TLS 1.3. "
                        "Remove all SSLv3, TLSv1, and TLSv1.1 from enabled protocols. "
                        "Use SSLContext.getInstance(\"TLSv1.3\") or configure via network_security_config.xml."
                    ),
                    tags=["m5", "tls", "weak-protocol", proto.lower()],
                ))

    def _check_hostname_verification(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        BYPASS_PATTERNS = [
            "ALLOW_ALL_HOSTNAME_VERIFIER",
            "AllowAllHostnameVerifier",
            "NullHostnameVerifier",
            "getAcceptedIssuers.*return null",
            "return true.*HostnameVerifier",
        ]
        for pattern in BYPASS_PATTERNS:
            if re.search(pattern, pool):
                self._add(Finding(
                    id=f"M5-HOSTNAME-{pattern[:20].upper().replace(' ','_').replace('*','_')}",
                    title=f"Hostname Verification Disabled: {pattern[:40]}",
                    category="Insecure Communication (M5)",
                    description=(
                        f"Hostname verification is disabled via '{pattern}'. "
                        "Without hostname verification, a TLS connection accepts any valid certificate "
                        "from any server, even if the hostname doesn't match. "
                        "This makes TLS completely useless against MitM attacks — "
                        "any certificate from any CA passes validation."
                    ),
                    technical_detail=f"Hostname bypass pattern '{pattern}' in DEX.",
                    cvss=CVSSVector(AV="A", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=[f"Hostname bypass: {pattern}"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Remove all AllowAllHostnameVerifier instances. "
                        "Use the default HttpsURLConnection hostname verifier. "
                        "OkHttp uses secure hostname verification by default — don't override it."
                    ),
                    tags=["m5", "hostname-verification", "tls", "mitm"],
                ))

    def _check_trust_all_certs(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        TRUST_ALL = [
            "checkClientTrusted",
            "checkServerTrusted",
            "X509TrustManager",
            "TrustAllCerts",
            "NaiveTrustManager",
            "permissive",
        ]
        found = [p for p in TRUST_ALL if p in pool]
        if len(found) >= 2:  # Likely a custom TrustManager
            self._add(Finding(
                id="M5-TRUST-ALL-CERTS",
                title="Custom TrustManager — Possible Certificate Validation Bypass",
                category="Insecure Communication (M5)",
                description=(
                    "A custom X509TrustManager implementation was detected. "
                    "Custom TrustManagers are frequently implemented incorrectly — "
                    "returning void in checkServerTrusted() (accepting all certs) "
                    "or not throwing CertificateException on invalid certs. "
                    "This is one of the most common and dangerous Android security mistakes."
                ),
                technical_detail=f"Custom TrustManager patterns: {found}",
                cvss=CVSSVector(AV="A", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"TrustManager pattern: {p}" for p in found[:3]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Delete the custom TrustManager entirely. "
                    "Use the system default TrustManager which validates against trusted CAs. "
                    "For certificate pinning, use OkHttp CertificatePinner or network_security_config.xml."
                ),
                pocs=[PoC(
                    type="frida_script",
                    title="Universal SSL Pinning/TrustManager Bypass",
                    description="Bypass all custom TrustManager implementations",
                    code=(
                        f"// Appraisal: DEX — Universal TLS Bypass\n"
                        f"// frida -U -f {ctx.package_name} -l ssl_bypass.js --no-pause\n\n"
                        f"Java.perform(function() {{\n"
                        f"  var TrustManager = Java.registerClass({{\n"
                        f"    name: 'com.appraisal.dex.UniversalTrustManager',\n"
                        f"    implements: [Java.use('javax.net.ssl.X509TrustManager')],\n"
                        f"    methods: {{\n"
                        f"      checkClientTrusted: function(chain, authType) {{ }},\n"
                        f"      checkServerTrusted: function(chain, authType) {{ }},\n"
                        f"      getAcceptedIssuers: function() {{ return []; }}\n"
                        f"    }}\n"
                        f"  }});\n"
                        f"  var SSLContext = Java.use('javax.net.ssl.SSLContext');\n"
                        f"  var ctx = SSLContext.getInstance('TLS');\n"
                        f"  ctx.init(null, [TrustManager.$new()], null);\n"
                        f"  SSLContext.getDefault.implementation = function() {{ return ctx; }};\n"
                        f"  console.log('[+] Universal TLS bypass active');\n"
                        f"}});"
                    ),
                )],
                tags=["m5", "trust-all-certs", "tls", "ssl-bypass"],
            ))

    def _check_plaintext_endpoints(self, ctx: AnalysisContext):
        pool = "\n".join(ctx.strings_pool)
        http_urls = re.findall(r'http://[a-zA-Z0-9.\-_/:%@?=&+#]{5,}', pool)
        # Filter out common non-sensitive http:// (schema URIs, localhost, etc.)
        real_urls = [
            u for u in http_urls
            if not any(skip in u for skip in [
                "schemas.android", "www.w3.org", "localhost", "127.0.0.1",
                "schemas.microsoft", "dublincore", "purl.org",
            ])
        ]
        if real_urls:
            unique = list(set(real_urls))[:10]
            self._add(Finding(
                id="M5-PLAINTEXT-URLS",
                title=f"Plaintext HTTP Endpoints Hardcoded ({len(unique)} found)",
                category="Insecure Communication (M5)",
                description=(
                    f"{len(unique)} hardcoded HTTP (non-TLS) endpoint URLs found in the binary. "
                    "Traffic to these endpoints is unencrypted and visible to any network observer. "
                    "Even non-sensitive endpoints can leak device identifiers, auth tokens "
                    "in query parameters, or session cookies in headers."
                ),
                technical_detail=f"HTTP URLs: {unique[:5]}",
                cvss=CVSSVector(AV="A", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                evidence=[f"HTTP URL: {u}" for u in unique[:5]],
                affected_components=[ctx.package_name],
                remediation="Replace all http:// endpoints with https://. Enforce with network_security_config.xml.",
                tags=["m5", "cleartext", "http", "endpoint"],
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # M6 — Inadequate Privacy Controls
    # ══════════════════════════════════════════════════════════════════════════

    def _check_pii_in_logs(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        PII_TERMS = [
            "email", "phone", "phoneNumber", "phone_number",
            "ssn", "social_security", "creditCard", "credit_card",
            "dob", "date_of_birth", "address", "location",
            "firstName", "lastName", "first_name", "last_name",
            "imei", "deviceId", "device_id", "userId", "user_id",
        ]
        found_pii = [p for p in PII_TERMS if p.lower() in pool.lower()]
        has_logging = any(l in pool for l in ["Log.d", "Log.v", "Log.i", "println"])

        if found_pii and has_logging:
            self._add(Finding(
                id="M6-PII-LOGS",
                title="PII Field Names + Logging Detected — Privacy Data Leakage Risk",
                category="Inadequate Privacy Controls (M6)",
                description=(
                    f"PII-related field names ({found_pii[:5]}) and logging calls co-exist. "
                    "If personal identifiable information is written to Android Logcat, "
                    "it's accessible to any app with READ_LOGS permission (many OEM apps have this) "
                    "and to anyone with ADB access. "
                    "This may violate GDPR, CCPA, and DPDP Act requirements."
                ),
                technical_detail=f"PII fields: {found_pii[:8]}. Log calls present.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[f"PII field in DEX: {p}" for p in found_pii[:5]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Audit all Log.* calls to ensure no PII is logged. "
                    "Use ProGuard to strip log calls: "
                    "-assumenosideeffects class android.util.Log { *; }. "
                    "Implement a custom Logger that redacts PII fields automatically."
                ),
                tags=["m6", "pii", "logging", "privacy", "gdpr"],
            ))

    def _check_pii_in_analytics(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        ANALYTICS = ["Mixpanel", "Amplitude", "Segment", "Heap", "FullStory",
                     "Hotjar", "Firebase.Analytics", "logEvent", "track(", "identify("]
        PII_PROPS = ["email", "phone", "name", "userId", "ssn", "dob"]

        has_analytics = any(a in pool for a in ANALYTICS)
        has_pii       = any(p in pool.lower() for p in PII_PROPS)

        if has_analytics and has_pii:
            found_sdks = [a for a in ANALYTICS if a in pool]
            self._add(Finding(
                id="M6-PII-ANALYTICS",
                title=f"PII Potentially Sent to Analytics SDKs: {', '.join(found_sdks[:3])}",
                category="Inadequate Privacy Controls (M6)",
                description=(
                    f"Analytics SDKs ({found_sdks[:3]}) are present alongside "
                    "PII-related field names. "
                    "If user PII (email, phone, name) is passed to analytics events, "
                    "it is transmitted to third-party servers outside your control. "
                    "This likely violates GDPR Article 25 (data minimization), "
                    "App Store privacy policies, and the EU-US Data Privacy Framework."
                ),
                technical_detail=f"Analytics: {found_sdks}. PII fields: {[p for p in PII_PROPS if p in pool.lower()]}",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[f"Analytics SDK: {s}" for s in found_sdks[:3]],
                affected_components=found_sdks[:3],
                remediation=(
                    "Hash or pseudonymize all user identifiers before analytics events. "
                    "Never send raw PII to analytics platforms. "
                    "Audit all .track(), .identify(), and logEvent() calls. "
                    "Implement a data classification policy for analytics."
                ),
                tags=["m6", "pii", "analytics", "privacy", "gdpr", "data-collection"],
            ))

    def _check_external_storage_pii(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if ("getExternalStorageDirectory" in pool or
                "getExternalFilesDir" in pool or
                "Environment.DIRECTORY" in pool):
            self._add(Finding(
                id="M6-EXTERNAL-STORAGE",
                title="External Storage Used — Data Accessible to All Apps",
                category="Inadequate Privacy Controls (M6)",
                description=(
                    "The app writes to external storage (SD card / shared storage). "
                    "On Android < 10, any app with READ_EXTERNAL_STORAGE can read "
                    "everything written here. "
                    "On Android 10+ (scoped storage), other apps in the same media category "
                    "may still access the data. "
                    "Sensitive data (logs, user content, downloads) must never be on external storage."
                ),
                technical_detail="getExternalStorageDirectory/getExternalFilesDir in DEX.",
                cvss=CVSSVector(AV="L", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["External storage access API in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use internal storage (getFilesDir, getCacheDir) for sensitive data. "
                    "Use scoped storage APIs (MediaStore) for user-shareable content only. "
                    "Encrypt any data that must go to external storage."
                ),
                tags=["m6", "external-storage", "privacy", "data-exposure"],
            ))

    def _check_clipboard_leakage(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "ClipboardManager" in pool and "setPrimaryClip" in pool:
            self._add(Finding(
                id="M6-CLIPBOARD",
                title="Data Written to System Clipboard — Privacy Leakage Risk",
                category="Inadequate Privacy Controls (M6)",
                description=(
                    "The app writes to the system clipboard via ClipboardManager. "
                    "On Android < 10, any app with BIND_ACCESSIBILITY_SERVICE or "
                    "a READ_CLIPBOARD workaround can silently read clipboard contents. "
                    "On Android 10-12, apps can silently read the clipboard while focused. "
                    "If sensitive data (passwords, tokens, PII) is copied, it's exposed."
                ),
                technical_detail="ClipboardManager.setPrimaryClip() in DEX.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["ClipboardManager.setPrimaryClip() in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Avoid putting sensitive data on the clipboard. "
                    "For password managers: clear the clipboard after a timeout (30s). "
                    "On Android 13+, use ClipDescription.MIMETYPE_TEXT_SENSITIVE_CONTENT "
                    "to mark clipboard content as sensitive."
                ),
                tags=["m6", "clipboard", "privacy", "pii"],
                _rank=Rank.C,
            ))

    def _check_screenshot_allowed(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        # FLAG_SECURE prevents screenshots
        if "FLAG_SECURE" not in pool:
            self._add(Finding(
                id="M6-NO-FLAG-SECURE",
                title="FLAG_SECURE Not Detected — Screenshots and Screen Recording Allowed",
                category="Inadequate Privacy Controls (M6)",
                description=(
                    "WindowManager.FLAG_SECURE was not detected. "
                    "Without FLAG_SECURE, any app with RECORD_SCREEN or casting capability "
                    "can capture the app's screen content including passwords, "
                    "payment details, and personal data shown in the UI. "
                    "Screen capture also appears in the Recent Apps switcher thumbnail."
                ),
                technical_detail="FLAG_SECURE (WindowManager.LayoutParams.FLAG_SECURE) not found in DEX.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="R", S="U", C="H", I="N", A="N"),
                evidence=["FLAG_SECURE not detected in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Add to all Activities containing sensitive data: "
                    "getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, "
                    "WindowManager.LayoutParams.FLAG_SECURE). "
                    "For a base Activity, set this in onCreate() globally."
                ),
                tags=["m6", "screenshot", "flag-secure", "privacy"],
                _rank=Rank.C,
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # M7 — Insufficient Binary Protections
    # ══════════════════════════════════════════════════════════════════════════

    def _check_stack_canary(self, ctx: AnalysisContext):
        """Check native libraries for stack canary protection."""
        import zipfile, struct
        if not ctx.has_native_libs:
            return

        missing_canary = []
        try:
            with zipfile.ZipFile(ctx.apk_path, "r") as zf:
                for lib in ctx.native_lib_names[:5]:
                    try:
                        data = zf.read(lib)
                        # Stack canary symbol presence in ELF
                        has_canary = b"__stack_chk_fail" in data or b"__stack_chk_guard" in data
                        if not has_canary:
                            missing_canary.append(lib)
                    except Exception:
                        continue
        except Exception:
            pass

        if missing_canary:
            self._add(Finding(
                id="M7-NO-STACK-CANARY",
                title=f"Native Libraries Missing Stack Canary Protection ({len(missing_canary)} libs)",
                category="Insufficient Binary Protections (M7)",
                description=(
                    f"Native libraries ({missing_canary[:3]}) do not appear to have "
                    "stack canary protection (__stack_chk_fail not found). "
                    "Without stack canaries, buffer overflow vulnerabilities in native code "
                    "can be exploited to overwrite the return address and redirect execution "
                    "to attacker-controlled shellcode or ROP chains."
                ),
                technical_detail=(
                    f"Libraries missing __stack_chk_fail: {missing_canary}\n"
                    "Stack canaries detect stack-based buffer overflows before function return."
                ),
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"No stack canary in: {lib}" for lib in missing_canary[:3]],
                affected_components=missing_canary[:3],
                remediation=(
                    "Compile native code with -fstack-protector-strong. "
                    "In Android.mk: LOCAL_CFLAGS += -fstack-protector-strong. "
                    "In CMakeLists.txt: add_compile_options(-fstack-protector-strong)."
                ),
                tags=["m7", "stack-canary", "native", "binary-protection"],
                _rank=Rank.C,
            ))

    def _check_position_independent(self, ctx: AnalysisContext):
        """Check if native libs are compiled as PIE (Position Independent Executables)."""
        import zipfile
        if not ctx.has_native_libs:
            return

        non_pie = []
        try:
            with zipfile.ZipFile(ctx.apk_path, "r") as zf:
                for lib in ctx.native_lib_names[:5]:
                    try:
                        data = zf.read(lib)
                        if len(data) < 64:
                            continue
                        # ELF header: e_type at offset 16 (2 bytes)
                        # ET_DYN = 3 (shared/PIE), ET_EXEC = 2 (non-PIE)
                        if data[:4] == b"\x7fELF":
                            e_type = struct.unpack_from("<H", data, 16)[0]
                            if e_type == 2:  # ET_EXEC = non-PIE
                                non_pie.append(lib)
                    except Exception:
                        continue
        except Exception:
            pass

        if non_pie:
            self._add(Finding(
                id="M7-NO-PIE",
                title=f"Native Libraries Not Position-Independent ({len(non_pie)} non-PIE)",
                category="Insufficient Binary Protections (M7)",
                description=(
                    f"Native libraries ({non_pie[:3]}) are compiled as ET_EXEC (non-PIE) "
                    "rather than ET_DYN (PIE). "
                    "Non-PIE binaries load at fixed memory addresses, defeating ASLR "
                    "(Address Space Layout Randomization). "
                    "This makes ROP (Return-Oriented Programming) and code reuse attacks "
                    "significantly easier as memory addresses are predictable."
                ),
                technical_detail=f"Non-PIE ELF (e_type=ET_EXEC) libraries: {non_pie}",
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"Non-PIE library: {lib}" for lib in non_pie[:3]],
                affected_components=non_pie[:3],
                remediation=(
                    "Compile all native libraries as shared objects with PIE: "
                    "LOCAL_CFLAGS += -fPIC -pie. "
                    "All Android native libraries should be .so files (ET_DYN), never executables."
                ),
                tags=["m7", "pie", "aslr", "native", "binary-protection"],
                _rank=Rank.C,
            ))
