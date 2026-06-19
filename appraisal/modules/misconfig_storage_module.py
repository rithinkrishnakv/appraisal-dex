"""
SKILL: Config & Storage Auditor [ACTIVE]
OWASP M8 — Security Misconfiguration
OWASP M9 — Insecure Data Storage
OWASP M10 — Insufficient Cryptography (coverage supplement to CryptoModule)

Catches misconfigurations not covered elsewhere:
StrictMode leaks, screen overlay protection, database encryption,
file permission errors, and cryptographic protocol choices.
"""

import re
import zipfile
from typing import List
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


class MisconfigStorageModule(BaseModule):
    SKILL_NAME  = "Config & Storage Auditor"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "OWASP M8/M9/M10 — Security misconfig, insecure data storage, crypto gaps"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        # M8 — Security Misconfiguration
        self._check_strictmode_leak(ctx)
        self._check_webview_misconfiguration(ctx)
        self._check_intent_filter_misconfiguration(ctx)
        self._check_firebase_rules(ctx)
        # M9 — Insecure Data Storage
        self._check_world_readable_files(ctx)
        self._check_sqlite_unencrypted(ctx)
        self._check_realm_unencrypted(ctx)
        self._check_sensitive_in_cache(ctx)
        self._check_internal_storage_modes(ctx)
        # M10 — Insufficient Cryptography
        self._check_custom_crypto(ctx)
        self._check_predictable_seed(ctx)
        self._check_ssl_error_handler(ctx)
        return self._findings

    # ══════════════════════════════════════════════════════════════════════════
    # M8 — Security Misconfiguration
    # ══════════════════════════════════════════════════════════════════════════

    def _check_strictmode_leak(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "StrictMode" in pool and ("penaltyLog" in pool or "penaltyDeath" in pool):
            self._add(Finding(
                id="M8-STRICTMODE",
                title="StrictMode Configuration Detected in Release Build",
                category="Security Misconfiguration (M8)",
                description=(
                    "StrictMode with penaltyLog or penaltyDeath is configured. "
                    "If active in release builds, StrictMode logs internal app state "
                    "(disk reads on main thread, unencrypted network, etc.) to Logcat, "
                    "exposing architectural details to any ADB-connected observer."
                ),
                technical_detail="StrictMode + penaltyLog/penaltyDeath in DEX.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=["StrictMode in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Wrap StrictMode setup in: if (BuildConfig.DEBUG) { ... }. "
                    "Never enable StrictMode in release builds."
                ),
                tags=["m8", "strictmode", "misconfiguration", "logging"],
                _rank=Rank.D,
            ))

    def _check_webview_misconfiguration(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        DANGEROUS_SETTINGS = {
            "setGeolocationEnabled": "WebView Geolocation — exposes user location to web content",
            "setSavePassword":       "WebView password saving — credentials stored in plaintext",
            "setDatabaseEnabled":    "WebView database (Web SQL) — deprecated, security risk",
            "setDomStorageEnabled":  "WebView DOM Storage — persistent key-value in WebView context",
        }
        for setting, desc in DANGEROUS_SETTINGS.items():
            if setting in pool:
                self._add(Finding(
                    id=f"M8-WEBVIEW-{setting[:20].upper()}",
                    title=f"Dangerous WebView Setting: {setting}",
                    category="Security Misconfiguration (M8)",
                    description=(
                        f"{setting}() is called. {desc}. "
                        "WebView security misconfigurations expand the attack surface "
                        "for content injection, data theft, and capability abuse."
                    ),
                    technical_detail=f"{setting}() in DEX string pool.",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="N", A="N"),
                    evidence=[f"{setting}() in DEX"],
                    affected_components=[ctx.package_name],
                    remediation=f"Call {setting}(false) unless absolutely required and justified.",
                    tags=["m8", "webview", "misconfiguration", setting.lower()],
                    _rank=Rank.D,
                ))

    def _check_intent_filter_misconfiguration(self, ctx: AnalysisContext):
        """Check for implicit broadcast receivers for dangerous system actions."""
        DANGEROUS_BROADCASTS = [
            ("android.intent.action.PACKAGE_ADDED",     "New package installed — can trigger malware auto-start"),
            ("android.intent.action.PACKAGE_REPLACED",  "Package replaced — can detect app updates"),
            ("android.intent.action.NEW_OUTGOING_CALL", "Outgoing call intercepted"),
            ("android.hardware.action.NEW_PICTURE",     "New photos taken — privacy implication"),
        ]
        for comp in ctx.components:
            if comp.component_type != "receiver":
                continue
            for ifilter in comp.intent_filters:
                for action in ifilter.get("actions", []):
                    for dangerous, desc in DANGEROUS_BROADCASTS:
                        if action == dangerous:
                            self._add(Finding(
                                id=f"M8-DANGEROUS-BCAST-{action.split('.')[-1][:20]}",
                                title=f"Dangerous Broadcast Receiver: {action.split('.')[-1]}",
                                category="Security Misconfiguration (M8)",
                                description=(
                                    f"Broadcast receiver listening for {action}. {desc}. "
                                    "Receiving this broadcast may trigger sensitive operations "
                                    "or leak information about device activity."
                                ),
                                technical_detail=f"Receiver: {comp.name}, Action: {action}",
                                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                                evidence=[f"<action android:name=\"{action}\"/>"],
                                affected_components=[comp.name],
                                remediation=(
                                    "Evaluate if this broadcast is necessary. "
                                    "Add android:permission to restrict who can trigger the receiver. "
                                    "Consider using WorkManager or JobScheduler instead."
                                ),
                                tags=["m8", "broadcast", "misconfiguration", "receiver"],
                                _rank=Rank.D,
                            ))

    def _check_firebase_rules(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        # Detect Firebase usage without rules enforcement hint
        if "firebase" in pool.lower() and "firebaseio.com" in pool.lower():
            # Look for the project URL
            match = re.search(r'([a-z0-9\-]+)\.firebaseio\.com', pool)
            if match:
                project_id = match.group(1)
                self._add(Finding(
                    id="M8-FIREBASE-RULES",
                    title=f"Firebase Realtime Database Detected — Verify Security Rules",
                    category="Security Misconfiguration (M8)",
                    description=(
                        f"Firebase Realtime Database at {project_id}.firebaseio.com is used. "
                        "The most common Firebase misconfiguration is overly permissive rules: "
                        '".read": true, ".write": true — '
                        "which allows unauthenticated read/write access to the entire database. "
                        "This affects millions of apps and is easily testable."
                    ),
                    technical_detail=f"Firebase project: {project_id}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=[f"Firebase URL: {project_id}.firebaseio.com"],
                    affected_components=["Firebase", ctx.package_name],
                    remediation=(
                        "Audit Firebase Security Rules immediately. "
                        'Replace any ".read": true or ".write": true with auth-gated rules: '
                        '".read": "auth != null && auth.uid == $uid". '
                        "Enable Firebase App Check to cryptographically verify requests come from your app."
                    ),
                    pocs=[PoC(
                        type="curl_command",
                        title="Test Firebase Open Access",
                        description="Check if database is publicly readable",
                        code=(
                            f"# Test unauthenticated read access\n"
                            f"curl -s 'https://{project_id}.firebaseio.com/.json?print=pretty'\n\n"
                            f"# Test specific nodes\n"
                            f"curl -s 'https://{project_id}.firebaseio.com/users.json'\n"
                            f"curl -s 'https://{project_id}.firebaseio.com/messages.json'\n"
                            f"curl -s 'https://{project_id}.firebaseio.com/orders.json'\n\n"
                            f"# Test write access\n"
                            f"curl -X PUT 'https://{project_id}.firebaseio.com/appraisal_test.json' \\\n"
                            f"     -d '{{\"pwned\":\"by_appraisal_dex\"}}'"
                        ),
                    )],
                    tags=["m8", "firebase", "misconfiguration", "open-database"],
                ))

    # ══════════════════════════════════════════════════════════════════════════
    # M9 — Insecure Data Storage
    # ══════════════════════════════════════════════════════════════════════════

    def _check_world_readable_files(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        WORLD_MODES = [
            "MODE_WORLD_READABLE",
            "MODE_WORLD_WRITEABLE",
            "0666", "0644",
        ]
        found = [m for m in WORLD_MODES if m in pool]
        if found:
            self._add(Finding(
                id="M9-WORLD-READABLE",
                title="World-Readable/Writable File Permissions Detected",
                category="Insecure Data Storage (M9)",
                description=(
                    f"File creation with world-readable/writable permissions ({found}) detected. "
                    "MODE_WORLD_READABLE was deprecated in API 17 and removed in API 24 "
                    "because any app on the device can read these files. "
                    "Private app files must use MODE_PRIVATE only."
                ),
                technical_detail=f"World-mode constants: {found}",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[f"World-mode permission: {m}" for m in found],
                affected_components=[ctx.package_name],
                remediation=(
                    "Replace all MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE with MODE_PRIVATE. "
                    "Use ContentProvider with proper permission enforcement to share data between apps."
                ),
                tags=["m9", "world-readable", "file-permissions", "data-storage"],
            ))

    def _check_sqlite_unencrypted(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        has_sqlite = ("SQLiteDatabase" in pool or "SQLiteOpenHelper" in pool
                      or "Room" in pool)
        has_sqlcipher = "SQLCipher" in pool or "net.zetetic.database" in pool

        if has_sqlite and not has_sqlcipher:
            # Check for sensitive data indicators
            SENSITIVE_TABLES = ["user", "account", "token", "message", "payment",
                                 "credential", "health", "medical", "transaction"]
            pool_lower = pool.lower()
            found_tables = [t for t in SENSITIVE_TABLES if t in pool_lower]

            if found_tables:
                self._add(Finding(
                    id="M9-SQLITE-UNENCRYPTED",
                    title="Unencrypted SQLite Database With Sensitive Table Names",
                    category="Insecure Data Storage (M9)",
                    description=(
                        f"SQLite database is used without encryption (SQLCipher not detected). "
                        f"Sensitive table names found: {found_tables[:5]}. "
                        "SQLite databases are stored at "
                        f"/data/data/{ctx.package_name}/databases/ in plaintext. "
                        "On rooted devices or via ADB backup, the entire database is accessible."
                    ),
                    technical_detail=(
                        f"SQLite detected. SQLCipher not found.\n"
                        f"Sensitive table indicators: {found_tables}"
                    ),
                    cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                    evidence=[f"Sensitive table: {t}" for t in found_tables[:5]],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Use SQLCipher (net.zetetic:android-database-sqlcipher) "
                        "to encrypt the database at rest. "
                        "Key derivation: use a key derived from the user's PIN via PBKDF2, "
                        "backed by Android Keystore."
                    ),
                    pocs=[PoC(
                        type="adb_command",
                        title="Dump Unencrypted SQLite Database",
                        description="Extract and read the database on a rooted device",
                        code=(
                            f"# Copy database to accessible location\n"
                            f"adb shell su -c 'cp -r /data/data/{ctx.package_name}/databases/ /sdcard/db_dump/'\n"
                            f"adb pull /sdcard/db_dump/ ./stolen_dbs/\n\n"
                            f"# Dump all tables\n"
                            f"for db in ./stolen_dbs/*.db; do\n"
                            f"  echo \"=== $db ===\"\n"
                            f"  sqlite3 \"$db\" .tables\n"
                            f"  sqlite3 \"$db\" .dump\n"
                            f"done"
                        ),
                    )],
                    tags=["m9", "sqlite", "unencrypted", "data-storage"],
                ))

    def _check_realm_unencrypted(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "io.realm" in pool or "RealmDatabase" in pool:
            if "encryptionKey" not in pool and "RealmConfiguration.Builder" in pool:
                self._add(Finding(
                    id="M9-REALM-UNENCRYPTED",
                    title="Realm Database Used Without Encryption Key",
                    category="Insecure Data Storage (M9)",
                    description=(
                        "Realm database is used without an encryption key configuration. "
                        "Unencrypted Realm databases store all data in plaintext at "
                        f"/data/data/{ctx.package_name}/files/. "
                        "These files can be extracted on rooted devices."
                    ),
                    technical_detail="Realm detected, no encryptionKey() in RealmConfiguration.Builder.",
                    cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                    evidence=["Realm without encryptionKey in DEX"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Configure Realm with a 64-byte encryption key from Android Keystore: "
                        "RealmConfiguration config = new RealmConfiguration.Builder()"
                        ".encryptionKey(getKey()).build();"
                    ),
                    tags=["m9", "realm", "unencrypted", "data-storage"],
                ))

    def _check_sensitive_in_cache(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if ("getCacheDir" in pool or "getExternalCacheDir" in pool) and \
                any(s in pool.lower() for s in ["token", "password", "credential", "auth"]):
            self._add(Finding(
                id="M9-CACHE-SENSITIVE",
                title="Sensitive Data May Be Written to Cache Directory",
                category="Insecure Data Storage (M9)",
                description=(
                    "getCacheDir() is used alongside authentication/credential strings. "
                    "Cache directories can be cleared by the system without notice and "
                    "are accessible on rooted devices. "
                    "Tokens or credentials written to cache may survive after 'logout' "
                    "if the cache isn't explicitly cleared."
                ),
                technical_detail="getCacheDir + credential strings co-present.",
                cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["getCacheDir + credential strings in DEX"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Never store credentials or tokens in cache directories. "
                    "Clear the cache explicitly on logout: "
                    "context.getCacheDir().delete(). "
                    "Use EncryptedSharedPreferences or Keystore for auth material."
                ),
                tags=["m9", "cache", "credential-storage", "data-storage"],
                _rank=Rank.C,
            ))

    def _check_internal_storage_modes(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "openFileOutput" in pool and "MODE_PRIVATE" not in pool:
            self._add(Finding(
                id="M9-FILE-MODE",
                title="openFileOutput() Without MODE_PRIVATE",
                category="Insecure Data Storage (M9)",
                description=(
                    "openFileOutput() is called without confirmed use of MODE_PRIVATE. "
                    "Using MODE_APPEND or not specifying the mode correctly "
                    "could result in files being created with broader permissions. "
                    "Always explicitly pass MODE_PRIVATE."
                ),
                technical_detail="openFileOutput without MODE_PRIVATE in DEX.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=["openFileOutput without MODE_PRIVATE"],
                affected_components=[ctx.package_name],
                remediation="Always use: openFileOutput(filename, Context.MODE_PRIVATE).",
                tags=["m9", "file-mode", "data-storage"],
                _rank=Rank.D,
            ))

    # ══════════════════════════════════════════════════════════════════════════
    # M10 — Insufficient Cryptography (supplement to crypto_module.py)
    # ══════════════════════════════════════════════════════════════════════════

    def _check_custom_crypto(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        CUSTOM_CRYPTO_SIGNS = [
            "XOR", "xor", "caesar", "rot13", "base64", "Base64",
            "scramble", "obfuscate", "encode", "custom_encrypt",
        ]
        if ("encrypt" in pool.lower() or "decrypt" in pool.lower()):
            found = [s for s in CUSTOM_CRYPTO_SIGNS if s in pool]
            if "XOR" in found or "xor" in found or "rot13" in found or "caesar" in found:
                self._add(Finding(
                    id="M10-CUSTOM-CRYPTO",
                    title="Home-Grown Cryptography Detected (XOR / ROT / Caesar)",
                    category="Insufficient Cryptography (M10)",
                    description=(
                        "Custom/homemade cryptographic operations (XOR, ROT13, Caesar cipher) "
                        "were detected alongside encryption/decryption logic. "
                        "Custom cryptographic implementations are virtually always broken — "
                        "they may provide obfuscation but zero real confidentiality. "
                        "XOR encryption is trivially reversible with known plaintext."
                    ),
                    technical_detail=f"Custom crypto indicators: {found}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                    evidence=[f"Custom crypto: {f}" for f in found[:5]],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Replace all custom crypto with standard JCE algorithms: "
                        "AES-256-GCM for symmetric, RSA-OAEP for asymmetric. "
                        "Use Android Keystore for key management. "
                        "Never implement your own cryptographic primitives."
                    ),
                    tags=["m10", "custom-crypto", "xor", "weak-encryption"],
                ))

    def _check_predictable_seed(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        PREDICTABLE_SEEDS = [
            "currentTimeMillis", "System.currentTimeMillis",
            "nanoTime", "hashCode",
        ]
        if "SecureRandom" in pool or "Random" in pool:
            found = [s for s in PREDICTABLE_SEEDS if s in pool]
            if found and "SecureRandom" not in pool:
                self._add(Finding(
                    id="M10-PREDICTABLE-SEED",
                    title="Predictable Random Seed (System.currentTimeMillis) for Security Use",
                    category="Insufficient Cryptography (M10)",
                    description=(
                        f"Random number generation seeded with predictable values ({found}) "
                        "is used in a security context. "
                        "System.currentTimeMillis() as a seed reduces the keyspace to "
                        "milliseconds since epoch — easily brute-forceable by an attacker "
                        "who knows the approximate generation time."
                    ),
                    technical_detail=f"Predictable seed patterns: {found}",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=[f"Predictable seed: {f}" for f in found[:3]],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Use java.security.SecureRandom without manual seeding. "
                        "SecureRandom seeds itself from /dev/urandom automatically. "
                        "Never seed SecureRandom manually unless you have a cryptographic DRBG."
                    ),
                    tags=["m10", "predictable-seed", "weak-random", "crypto"],
                ))

    def _check_ssl_error_handler(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "onReceivedSslError" in pool:
            if "proceed" in pool:
                self._add(Finding(
                    id="M10-SSL-ERROR-PROCEED",
                    title="WebView.onReceivedSslError Calls handler.proceed() — TLS Errors Ignored",
                    category="Insufficient Cryptography (M10)",
                    description=(
                        "WebView.onReceivedSslError() is overridden and appears to call "
                        "handler.proceed() — accepting all TLS errors including expired certs, "
                        "hostname mismatches, and self-signed certs. "
                        "This completely disables TLS validation in the WebView, "
                        "making HTTPS connections equivalent to HTTP from a security standpoint."
                    ),
                    technical_detail="onReceivedSslError + proceed() in DEX string pool.",
                    cvss=CVSSVector(AV="A", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=["onReceivedSslError with proceed() in DEX"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Remove handler.proceed() from onReceivedSslError(). "
                        "The default implementation calls handler.cancel() — "
                        "which is the correct, secure behavior. "
                        "Fix the underlying TLS certificate issues instead of suppressing errors."
                    ),
                    pocs=[PoC(
                        type="frida_script",
                        title="Confirm SSL Error Handler Bypass",
                        description="Hook onReceivedSslError to confirm proceed() is called",
                        code=(
                            f"Java.perform(function() {{\n"
                            f"  var WebViewClient = Java.use('android.webkit.WebViewClient');\n"
                            f"  WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {{\n"
                            f"    console.log('[+] SSL Error intercepted: ' + error.toString());\n"
                            f"    console.log('[+] Primary error: ' + error.getPrimaryError());\n"
                            f"    console.log('[+] URL: ' + error.getUrl());\n"
                            f"    handler.proceed();  // Confirm the app proceeds despite SSL error\n"
                            f"    console.log('[+] handler.proceed() called — TLS bypass confirmed');\n"
                            f"  }};\n"
                            f"}});"
                        ),
                    )],
                    tags=["m10", "ssl-error", "tls", "webview", "mitm"],
                ))
