"""
SKILL: Credential Sight [PASSIVE]
OWASP M1 — Improper Credential Usage

Finds hardcoded credentials, insecure credential storage,
cleartext passwords in config/properties files, and auth token mishandling.
Everything that lets an attacker walk in the front door.
"""

import re
from typing import List, Tuple
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


# Patterns: (regex, label, severity)
CREDENTIAL_PATTERNS: List[Tuple[str, str, str]] = [
    # Passwords
    (r'(?i)password\s*[=:]\s*["\']([^"\']{4,})["\']',       "Hardcoded Password",          "high"),
    (r'(?i)passwd\s*[=:]\s*["\']([^"\']{4,})["\']',          "Hardcoded Password (passwd)",  "high"),
    (r'(?i)pwd\s*[=:]\s*["\']([^"\']{4,})["\']',             "Hardcoded Password (pwd)",     "high"),
    # Tokens
    (r'(?i)access_token\s*[=:]\s*["\']([A-Za-z0-9._\-]{20,})["\']', "Hardcoded Access Token", "critical"),
    (r'(?i)refresh_token\s*[=:]\s*["\']([A-Za-z0-9._\-]{20,})["\']',"Hardcoded Refresh Token","critical"),
    (r'(?i)bearer\s+([A-Za-z0-9._\-]{20,})',                  "Hardcoded Bearer Token",      "critical"),
    (r'(?i)auth_token\s*[=:]\s*["\']([A-Za-z0-9._\-]{16,})["\']', "Hardcoded Auth Token",   "critical"),
    # API keys
    (r'(?i)api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Hardcoded API Key",      "critical"),
    (r'(?i)client[_-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',"OAuth Client Secret","critical"),
    (r'(?i)client[_-]?id\s*[=:]\s*["\']([A-Za-z0-9_\-]{8,})["\']', "OAuth Client ID",       "medium"),
    # Database / connection strings
    (r'(?i)jdbc:[a-z]+://[^\s"\']{10,}',                      "JDBC Connection String",      "critical"),
    (r'(?i)mongodb(\+srv)?://[^\s"\']{10,}',                  "MongoDB Connection String",   "critical"),
    (r'(?i)mysql://[^\s"\']{10,}',                            "MySQL Connection String",     "critical"),
    (r'(?i)postgres(?:ql)?://[^\s"\']{10,}',                  "PostgreSQL Connection String", "critical"),
    (r'(?i)redis://[^\s"\']{8,}',                             "Redis Connection String",     "high"),
    # Username patterns
    (r'(?i)username\s*[=:]\s*["\']([a-zA-Z0-9_@.\-]{3,})["\']',    "Hardcoded Username",    "medium"),
    # Private endpoints with creds in URL
    (r'https?://[A-Za-z0-9._\-]+:[A-Za-z0-9._\-@!#$%]+@[^\s"\']+', "Credentials in URL",    "critical"),
]

# Properties files often left in APK assets
SENSITIVE_FILE_PATTERNS = [
    "assets/config.properties",
    "assets/app.properties",
    "assets/database.properties",
    "assets/credentials.properties",
    "assets/secrets.properties",
    "assets/keystore.properties",
    "res/raw/config",
    "res/values/secrets.xml",
    "assets/.env",
    "assets/env.properties",
    "assets/local.properties",
]

# Auth scheme indicators without proper implementation
INSECURE_AUTH_PATTERNS = [
    (r'(?i)basic\s+[A-Za-z0-9+/]{10,}={0,2}',          "Base64 Basic Auth Hardcoded"),
    (r'(?i)Authorization["\s:]+Basic\s+[A-Za-z0-9+/]{10,}', "Basic Auth Header Hardcoded"),
    (r'(?i)digest\s+username=["\'][^"\']+["\']',          "Digest Auth Credentials"),
]


class CredentialModule(BaseModule):
    SKILL_NAME  = "Credential Sight"
    SKILL_TYPE  = SkillType.PASSIVE
    DESCRIPTION = "OWASP M1 — Improper credential usage: hardcoded secrets, insecure storage, credential leakage"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_string_pool_credentials(ctx)
        self._check_sensitive_asset_files(ctx)
        self._check_insecure_auth_schemes(ctx)
        self._check_credential_in_shared_prefs(ctx)
        self._check_credential_in_logs(ctx)
        self._check_account_manager_usage(ctx)
        return self._findings

    # ── String pool credential sweep ─────────────────────────────────────────

    def _check_string_pool_credentials(self, ctx: AnalysisContext):
        pool = "\n".join(ctx.strings_pool)
        seen = set()

        for pattern, label, severity in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, pool, re.IGNORECASE)
            if not matches:
                continue

            key = label
            if key in seen:
                continue
            seen.add(key)

            flat = [m if isinstance(m, str) else " ".join(m) for m in matches[:3]]
            redacted = [self._redact(v) for v in flat]

            cvss = (CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")
                    if severity == "critical" else
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N")
                    if severity == "high" else
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"))

            self._add(Finding(
                id=f"M1-CRED-{label[:25].upper().replace(' ','_').replace('(','').replace(',','')}",
                title=f"Hardcoded Credential in DEX: {label}",
                category="Improper Credential Usage (M1)",
                description=(
                    f"{label} found hardcoded in the application's DEX string pool. "
                    "Any user who downloads and decompiles the APK can extract these credentials. "
                    "No reverse engineering skills required — strings are plaintext in the DEX."
                ),
                technical_detail=(
                    f"Pattern: {label}\n"
                    f"Occurrences: {len(matches)}\n"
                    f"Samples (redacted): {redacted}"
                ),
                cvss=cvss,
                evidence=[f"{label}: {r}" for r in redacted],
                affected_components=[ctx.package_name],
                remediation=(
                    "Never hardcode credentials in source code. "
                    "Use Android Keystore for cryptographic keys. "
                    "Fetch secrets from a secure backend at runtime. "
                    "Use BuildConfig fields only for non-sensitive config, not secrets. "
                    "Rotate all exposed credentials immediately."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Extract Credentials via APK Decompilation",
                    description="Extract the hardcoded credential from the APK without a device",
                    code=(
                        f"# Step 1: Decompile the APK with jadx\n"
                        f"jadx -d decompiled/ {ctx.apk_path}\n\n"
                        f"# Step 2: Search for the credential pattern\n"
                        f"grep -r -i '{label.lower().split()[0]}' decompiled/ --include='*.java'\n\n"
                        f"# Step 3: Extract strings directly from DEX\n"
                        f"strings classes.dex | grep -iE 'password|token|key|secret|auth'\n\n"
                        f"# Step 4: Use apktool and grep\n"
                        f"apktool d {ctx.apk_path} -o apktool_out/\n"
                        f"grep -r -iE 'password|api.key|token|secret' apktool_out/"
                    ),
                )],
                references=[
                    "https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
                tags=["m1", "hardcoded-credential", "owasp-mobile", label.lower().replace(" ","_")],
            ))

    # ── Sensitive asset files ─────────────────────────────────────────────────

    def _check_sensitive_asset_files(self, ctx: AnalysisContext):
        found_files = [f for f in ctx.file_list
                       if any(f.lower().endswith(p.lower()) or p.lower() in f.lower()
                              for p in SENSITIVE_FILE_PATTERNS)]

        if found_files:
            self._add(Finding(
                id="M1-SENSITIVE-ASSETS",
                title="Sensitive Configuration/Properties Files Found in APK",
                category="Improper Credential Usage (M1)",
                description=(
                    "Configuration or properties files that may contain credentials "
                    "were found packaged inside the APK. "
                    "Files in assets/, res/raw/, and res/values/ are trivially extractable "
                    "using unzip — no decompilation required."
                ),
                technical_detail=f"Sensitive files: {found_files}",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[f"Sensitive file in APK: {f}" for f in found_files[:5]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Remove all configuration files containing credentials from the APK. "
                    "Use encrypted SharedPreferences or Android Keystore instead. "
                    "Fetch runtime configuration from a secure backend over mTLS."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Extract Config Files from APK",
                    description="Unzip APK and read all config/properties files",
                    code=(
                        f"# APK is a ZIP — extract directly\n"
                        f"cp {ctx.apk_path} target.zip && unzip target.zip -d extracted/\n\n"
                        f"# Read all found config files\n"
                        + "\n".join(f"cat extracted/{f}" for f in found_files[:5])
                    ),
                )],
                tags=["m1", "config-file", "assets", "credentials"],
            ))

    # ── Insecure auth scheme detection ────────────────────────────────────────

    def _check_insecure_auth_schemes(self, ctx: AnalysisContext):
        pool = "\n".join(ctx.strings_pool)
        for pattern, label in INSECURE_AUTH_PATTERNS:
            if re.search(pattern, pool, re.IGNORECASE):
                self._add(Finding(
                    id=f"M1-AUTH-{label[:20].upper().replace(' ','_')}",
                    title=f"Insecure Auth Scheme Hardcoded: {label}",
                    category="Improper Credential Usage (M1)",
                    description=(
                        f"{label} found in DEX string pool. "
                        "Basic/Digest authentication credentials hardcoded in the binary "
                        "are extractable by anyone with APK access and are sent in "
                        "base64 (not encrypted) over the network."
                    ),
                    technical_detail=f"Pattern detected: {label}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=[f"{label} detected in DEX string pool"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Replace Basic/Digest auth with OAuth 2.0 + PKCE or mTLS. "
                        "If Basic auth must be used, fetch credentials at runtime from "
                        "a secure source — never hardcode them."
                    ),
                    tags=["m1", "basic-auth", "auth-scheme"],
                ))

    # ── Credential in SharedPreferences ──────────────────────────────────────

    def _check_credential_in_shared_prefs(self, ctx: AnalysisContext):
        """Detect patterns where credentials are written to SharedPreferences in plaintext."""
        CRED_KEYS = [
            "password", "passwd", "pwd", "token", "access_token",
            "auth_token", "secret", "api_key", "apikey", "pin",
            "credentials", "credential",
        ]
        pool = " ".join(ctx.strings_pool)
        found_keys = [k for k in CRED_KEYS if k in pool.lower()]

        if "putString" in pool and found_keys:
            self._add(Finding(
                id="M1-PREFS-CRED",
                title="Potential Plaintext Credential Storage in SharedPreferences",
                category="Improper Credential Usage (M1)",
                description=(
                    "SharedPreferences.putString() is used alongside credential-related "
                    f"key names ({found_keys[:5]}). "
                    "SharedPreferences are stored as plaintext XML in the app's private directory. "
                    "On rooted devices or via ADB backup, these files are trivially readable. "
                    "Tokens and passwords stored here can be exfiltrated without authentication."
                ),
                technical_detail=(
                    f"putString() detected with credential key patterns: {found_keys[:8]}\n"
                    f"SharedPreferences file location: /data/data/{ctx.package_name}/shared_prefs/*.xml"
                ),
                cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[
                    "SharedPreferences.putString() in DEX",
                    f"Credential key names in string pool: {found_keys[:5]}",
                ],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use EncryptedSharedPreferences (Jetpack Security): "
                    "EncryptedSharedPreferences.create(context, 'prefs', masterKey, "
                    "AES256_SIV, AES256_GCM). "
                    "For auth tokens, use Android Keystore-backed storage."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Read SharedPreferences on Rooted Device",
                    description="Extract plaintext credentials from SharedPreferences XML",
                    code=(
                        f"# On rooted device:\n"
                        f"adb shell su -c 'cat /data/data/{ctx.package_name}/shared_prefs/*.xml'\n\n"
                        f"# Via ADB backup (no root):\n"
                        f"adb backup -f backup.ab -noapk {ctx.package_name}\n"
                        f"java -jar abe.jar unpack backup.ab backup.tar\n"
                        f"tar xf backup.tar && cat apps/{ctx.package_name}/sp/*.xml"
                    ),
                )],
                references=["https://developer.android.com/topic/security/data"],
                tags=["m1", "shared-preferences", "plaintext-storage"],
            ))

    # ── Credential in Logcat ──────────────────────────────────────────────────

    def _check_credential_in_logs(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        LOG_PATTERNS = ["Log.d", "Log.v", "Log.i", "Log.e", "Log.w", "System.out.println"]
        CRED_NEAR   = ["password", "token", "secret", "key", "auth", "credential"]

        has_logging = any(p in pool for p in LOG_PATTERNS)
        has_cred    = any(c in pool.lower() for c in CRED_NEAR)

        if has_logging and has_cred:
            self._add(Finding(
                id="M1-LOG-CRED",
                title="Potential Credential Logging to Logcat",
                category="Improper Credential Usage (M1)",
                description=(
                    "Logging calls (Log.d/v/i) and credential-related strings co-exist "
                    "in this application. If credentials or tokens are logged — even in "
                    "'debug' builds — they appear in the Android system log readable "
                    "by any app with READ_LOGS permission (granted to many OEM apps) "
                    "or any connected ADB session."
                ),
                technical_detail=(
                    "Logging API + credential key names detected in same binary. "
                    "Requires manual verification of actual log call arguments."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["Log.*() calls + credential strings co-present in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Audit all Log.* calls and remove any that print sensitive data. "
                    "Use ProGuard rule: -assumenosideeffects class android.util.Log { *; } "
                    "to strip all log calls from release builds."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Monitor Logcat for Credential Leakage",
                    description="Watch for sensitive data in real-time log output",
                    code=(
                        f"# Stream logcat and grep for credential patterns\n"
                        f"adb logcat -v time | grep -iE 'password|token|secret|key|auth|bearer|jwt'\n\n"
                        f"# Package-specific logs only\n"
                        f"adb logcat --pid=$(adb shell pidof -s {ctx.package_name}) -v time"
                    ),
                )],
                tags=["m1", "logging", "credential-leak"],
                _rank=Rank.C,
            ))

    # ── AccountManager usage ──────────────────────────────────────────────────

    def _check_account_manager_usage(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "AccountManager" not in pool:
            return

        if "getPassword" in pool or "peekAuthToken" in pool:
            self._add(Finding(
                id="M1-ACCOUNTMGR",
                title="AccountManager.getPassword() or peekAuthToken() Detected",
                category="Improper Credential Usage (M1)",
                description=(
                    "AccountManager.getPassword() or peekAuthToken() is used. "
                    "These methods retrieve stored account credentials in plaintext. "
                    "Any app with GET_ACCOUNTS + USE_CREDENTIALS permissions "
                    "(or MANAGE_ACCOUNTS on older Android) can call these methods "
                    "to extract stored passwords and tokens for registered accounts."
                ),
                technical_detail="AccountManager.getPassword/peekAuthToken in DEX pool.",
                cvss=CVSSVector(AV="L", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["AccountManager.getPassword() or peekAuthToken() in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use getAuthToken() with proper token lifecycle management. "
                    "Never store raw passwords in AccountManager — store auth tokens only. "
                    "Implement token refresh flows instead of storing long-lived credentials."
                ),
                tags=["m1", "account-manager", "credential-storage"],
            ))

    @staticmethod
    def _redact(value: str, keep: int = 6) -> str:
        v = str(value).strip()
        if len(v) <= keep * 2:
            return "*" * min(len(v), 8)
        return v[:keep] + "..." + v[-3:] + f" [{len(v)} chars]"
