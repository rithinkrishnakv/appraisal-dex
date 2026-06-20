"""
SKILL: Supply Chain Scanner [HIDDEN]
Fingerprints embedded third-party SDKs, cross-references their versions
against a known-vulnerable catalog, detects phantom permission escalation,
and exposes hardcoded SDK credentials.
"""

import re
from typing import List, Dict, Tuple, Optional
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank

# SDK fingerprint database:
# (package_prefix, sdk_name, category, known_risks)
SDK_FINGERPRINTS: List[Tuple[str, str, str, List[str]]] = [
    ("com.facebook.ads",        "Meta Audience Network",   "Advertising",
     ["Data collection without explicit consent", "Tracks users across apps"]),
    ("com.google.android.gms",  "Google Play Services",    "Platform",
     ["Device attestation bypass possible on old versions", "Privacy data collection"]),
    ("com.google.firebase",     "Firebase SDK",             "Backend",
     ["Misconfigured Realtime DB public read", "Exposed API keys in google-services.json"]),
    ("com.appsflyer",           "AppsFlyer",               "Analytics",
     ["Device fingerprinting", "Cross-app user tracking"]),
    ("com.adjust.sdk",          "Adjust",                   "Analytics",
     ["Device fingerprinting", "Precise location tracking"]),
    ("com.mopub",               "MoPub",                    "Advertising",
     ["CVE-2021-36380: Code execution via malicious ad", "SDK deprecated (Twitter acquisition)"]),
    ("com.unity3d.ads",         "Unity Ads",               "Advertising",
     ["File access permissions via ad WebView", "Canvas fingerprinting"]),
    ("com.stripe.android",      "Stripe",                   "Payment",
     ["PCI DSS scope implications", "API key exposure risk in logs"]),
    ("com.braintreepayments",   "Braintree",                "Payment",
     ["PCI DSS scope", "Tokenization bypass if cert pinning absent"]),
    ("io.branch.referral",      "Branch.io",               "Deep Links",
     ["URI scheme hijacking enabled by SDK", "Device fingerprinting"]),
    ("com.onesignal",           "OneSignal",               "Push Notifications",
     ["Firebase token exposure", "User tracking via notification ID"]),
    ("com.crashlytics",         "Firebase Crashlytics",    "Crash Reporting",
     ["May log sensitive stack frames containing user data", "Crash reports contain device info"]),
    ("com.newrelic.android",    "New Relic",               "APM",
     ["Network traffic monitoring captures auth headers", "Full stack traces in reports"]),
    ("com.chartboost",          "Chartboost",              "Advertising",
     ["Old versions: remote WebView URL execution", "Aggressive device ID collection"]),
    ("com.ironsource.mediationsdk", "IronSource",          "Mediation",
     ["Aggressive permission requests via manifest merger", "Device fingerprinting"]),
    ("com.flurry",              "Yahoo Flurry",            "Analytics",
     ["Legacy: cleartext log transmission", "Persistent device tracking"]),
    ("okhttp3",                 "OkHttp",                   "Networking",
     ["Version-dependent TLS configuration", "Certificate pinning bypass if misconfigured"]),
    ("retrofit2",               "Retrofit",                 "Networking",
     ["Gson deserialization gadget chains if exposed", "Logging interceptor credential leak"]),
    ("com.squareup.picasso",    "Picasso",                  "Image Loading",
     ["file:// scheme in image URL loads local files", "Cache poisoning if URLs are user-controlled"]),
    ("com.bumptech.glide",      "Glide",                   "Image Loading",
     ["file:// load via intent extra can leak private files", "Disk cache poisoning"]),
    ("com.jakewharton.timber",  "Timber",                  "Logging",
     ["Debug tree may log sensitive data to Logcat in release builds"]),
]

# Known CVEs by SDK package prefix
SDK_CVES: Dict[str, List[Dict]] = {
    "com.mopub": [
        {"cve": "CVE-2021-36380", "score": 9.8,
         "description": "Remote code execution via malicious ad creative in MoPub SDK < 5.18.0"},
    ],
    "com.squareup.okhttp": [
        {"cve": "CVE-2016-2402", "score": 5.9,
         "description": "Certificate pinning bypass via certificate chain manipulation"},
    ],
    "com.facebook.android": [
        {"cve": "CVE-2020-1889", "score": 6.5,
         "description": "Access token exposure in URL parameters"},
    ],
}

# Developer-declared permissions (these are intentional)
# vs permissions introduced silently by SDKs (phantom permissions)
PHANTOM_PERMISSION_SDKS: Dict[str, List[str]] = {
    "com.google.android.gms": [
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.WAKE_LOCK",
        "android.permission.ACCESS_NETWORK_STATE",
    ],
    "com.facebook.ads": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
    ],
    "com.ironsource.mediationsdk": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ],
    "com.unity3d.ads": [
        "android.permission.RECORD_AUDIO",
    ],
    "io.branch.referral": [
        "android.permission.ACCESS_FINE_LOCATION",
    ],
}


class SDKFingerprintModule(BaseModule):
    SKILL_NAME  = "Supply Chain Scanner"
    SKILL_TYPE  = SkillType.HIDDEN
    DESCRIPTION = "Third-party SDK fingerprinting, CVE mapping, phantom permission detection, credential exposure"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        detected_sdks = self._fingerprint_sdks(ctx)
        self._check_sdk_cves(ctx, detected_sdks)
        self._check_phantom_permissions(ctx, detected_sdks)
        self._check_firebase_config(ctx)
        self._check_sdk_credentials(ctx)
        self._check_sdk_logging(ctx, detected_sdks)
        return self._findings

    # ── SDK Fingerprinting ────────────────────────────────────────────────────

    def _fingerprint_sdks(self, ctx: AnalysisContext) -> List[Tuple[str, str, str, List[str]]]:
        """Identify embedded SDKs by package prefix scanning."""
        detected = []
        try:
            class_names = set()
            for cls in ctx.app_classes:
                cls_str = str(cls.name).replace("/", ".").strip("L;")
                class_names.add(cls_str)

            for prefix, sdk_name, category, risks in SDK_FINGERPRINTS:
                if any(c.startswith(prefix) for c in class_names):
                    detected.append((prefix, sdk_name, category, risks))
                    self._add(Finding(
                        id=f"SDK-{sdk_name[:20].upper().replace(' ','_').replace('.','_')}",
                        title=f"Third-Party SDK Detected: {sdk_name} ({category})",
                        category="Supply Chain Risk",
                        description=(
                            f"The {sdk_name} SDK ({category}) is embedded in this application. "
                            "Third-party SDKs expand the attack surface and may introduce "
                            "known vulnerabilities, excessive data collection, or "
                            "permissions beyond what the app itself requests."
                        ),
                        technical_detail=(
                            f"Package prefix: {prefix}\n"
                            f"Category: {category}\n"
                            f"Known risks: {'; '.join(risks)}"
                        ),
                        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                        evidence=[f"Classes with prefix {prefix} found in DEX"],
                        affected_components=[prefix],
                        remediation=(
                            f"Review {sdk_name} documentation for security hardening options. "
                            "Pin the SDK version in build.gradle. "
                            "Audit what data the SDK collects and ensure your privacy policy covers it."
                        ),
                        tags=["sdk", "supply-chain", category.lower().replace(" ", "-")],
                        _rank=Rank.D,
                    ))
        except Exception:
            pass

        return detected

    # ── CVE cross-reference ───────────────────────────────────────────────────

    def _check_sdk_cves(self, ctx: AnalysisContext,
                        detected_sdks: List[Tuple[str, str, str, List[str]]]):
        for prefix, sdk_name, category, _ in detected_sdks:
            cves = SDK_CVES.get(prefix, [])
            for cve_info in cves:
                self._add(Finding(
                    id=f"SDK-CVE-{cve_info['cve'].replace('-','_')}",
                    title=f"{cve_info['cve']} in {sdk_name} — CVSS {cve_info['score']}",
                    category="Known Vulnerability (CVE)",
                    description=(
                        f"The embedded {sdk_name} SDK has a known CVE: {cve_info['cve']}. "
                        f"{cve_info['description']}. "
                        "This vulnerability may affect this application if the SDK version "
                        "is not patched."
                    ),
                    technical_detail=(
                        f"CVE: {cve_info['cve']}\n"
                        f"Score: {cve_info['score']}\n"
                        f"SDK: {sdk_name} ({prefix})\n"
                        f"Description: {cve_info['description']}"
                    ),
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U",
                                    C="H" if cve_info['score'] >= 7 else "L",
                                    I="H" if cve_info['score'] >= 9 else "L",
                                    A="N"),
                    evidence=[f"SDK {prefix} detected; CVE {cve_info['cve']} applies"],
                    affected_components=[prefix],
                    remediation=(
                        f"Update {sdk_name} to the latest patched version. "
                        f"Check {cve_info['cve']} on NVD for affected versions: "
                        f"https://nvd.nist.gov/vuln/detail/{cve_info['cve']}"
                    ),
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve_info['cve']}"],
                    tags=["cve", "sdk", "known-vulnerability"],
                ))

    # ── Phantom permission escalation ─────────────────────────────────────────

    def _check_phantom_permissions(self, ctx: AnalysisContext,
                                    detected_sdks: List[Tuple[str, str, str, List[str]]]):
        """Find permissions introduced by SDKs that the app developer didn't explicitly request."""
        # We approximate developer intent: if the SDK is present AND the permission is in
        # the final manifest, it may have been injected by the SDK's manifest merger.
        for prefix, sdk_name, _, _ in detected_sdks:
            phantom_perms = PHANTOM_PERMISSION_SDKS.get(prefix, [])
            for perm in phantom_perms:
                if perm in ctx.permissions:
                    short_perm = perm.replace("android.permission.", "")
                    self._add(Finding(
                        id=f"SDK-PHANTOM-{prefix[:15].replace('.','_')}-{short_perm[:15]}",
                        title=f"Phantom Permission via {sdk_name}: {short_perm}",
                        category="Permission Escalation",
                        description=(
                            f"The permission {perm} appears in the final merged manifest "
                            f"and may have been introduced by the {sdk_name} SDK, "
                            "not by the app developer explicitly. "
                            "Manifest merger silently combines SDK permissions with app permissions. "
                            "This means the app has more permissions than its developers intended."
                        ),
                        technical_detail=(
                            f"SDK: {sdk_name} (prefix: {prefix})\n"
                            f"Permission: {perm}\n"
                            f"Source: Likely injected via AAR manifest merger"
                        ),
                        cvss=CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="L", I="N", A="N"),
                        evidence=[
                            f"Permission {perm} in merged manifest",
                            f"SDK {sdk_name} detected in DEX",
                        ],
                        affected_components=[ctx.package_name, prefix],
                        remediation=(
                            f"Explicitly remove the permission in manifest: "
                            f"<uses-permission android:name=\"{perm}\" tools:node=\"remove\"/>. "
                            f"Audit {sdk_name}'s data collection settings to limit what it accesses."
                        ),
                        tags=["phantom-permission", "sdk", "manifest-merger"],
                        _rank=Rank.D,
                    ))

    # ── Firebase / google-services.json exposure ──────────────────────────────

    def _check_firebase_config(self, ctx: AnalysisContext):
        """Check for Firebase misconfiguration and exposed project credentials."""
        firebase_files = [f for f in ctx.file_list if "google-services" in f.lower()
                          or "firebase" in f.lower()]

        string_pool = " ".join(ctx.strings_pool)

        # Look for Firebase project IDs and API keys
        firebase_api_key = re.search(r'AIza[0-9A-Za-z\-_]{35}', string_pool)
        firebase_project = re.search(r'([a-z0-9\-]+\.firebaseio\.com)', string_pool)
        firebase_storage = re.search(r'([a-z0-9\-]+\.appspot\.com)', string_pool)

        if firebase_api_key or firebase_project:
            findings_evidence = []
            if firebase_api_key:
                key = firebase_api_key.group(0)
                findings_evidence.append(f"Firebase API key: {key[:10]}...{key[-4:]}")
            if firebase_project:
                findings_evidence.append(f"Firebase project: {firebase_project.group(0)}")
            if firebase_storage:
                findings_evidence.append(f"Firebase Storage bucket: {firebase_storage.group(0)}")

            self._add(Finding(
                id="SDK-FIREBASE-EXPOSED",
                title="Firebase Configuration Exposed — Project Credentials in Binary",
                category="Supply Chain Risk",
                description=(
                    "Firebase API keys and project identifiers are embedded in the application. "
                    "While Firebase API keys are technically 'public' (restricted by rules), "
                    "an exposed project ID allows attackers to probe Realtime Database rules, "
                    "Firestore rules, and Storage rules directly. "
                    "Misconfigured rules (the most common Firebase mistake) lead to "
                    "complete database exposure."
                ),
                technical_detail=(
                    "Firebase config embedded in binary.\n"
                    "Attack vectors:\n"
                    "1. Test Realtime DB: GET https://<project>.firebaseio.com/.json\n"
                    "2. Test Firestore rules via REST API\n"
                    "3. Test Storage rules: list bucket contents\n"
                    "4. Abuse FCM server key for push notification spoofing"
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=findings_evidence,
                affected_components=["Firebase", ctx.package_name],
                remediation=(
                    "Configure strict Firebase Security Rules. "
                    "Restrict Firebase API key to only required APIs in Google Cloud Console. "
                    "Enable Firebase App Check to ensure only your app can access Firebase resources. "
                    "Audit database/storage rules regularly."
                ),
                pocs=[PoC(
                    type="curl_command",
                    title="Test Firebase Realtime Database Open Access",
                    description="Check if the Realtime Database is publicly readable",
                    code=(
                        f"# Test if Realtime DB is open (returns data = misconfigured)\n"
                        + (
                            f"curl -s 'https://{firebase_project.group(0)}/.json?print=pretty' | head -50\n\n"
                            f"# Test specific paths\n"
                            f"curl -s 'https://{firebase_project.group(0)}/users/.json?print=pretty' | head -20\n"
                            f"curl -s 'https://{firebase_project.group(0)}/messages/.json?print=pretty' | head -20"
                            if firebase_project else
                            "# Extract project URL from google-services.json in APK resources\n"
                            "curl -s 'https://<PROJECT_ID>.firebaseio.com/.json?print=pretty'"
                        )
                    ),
                )],
                references=["https://firebase.google.com/docs/database/security"],
                tags=["firebase", "sdk", "misconfiguration", "credentials"],
            ))

    # ── SDK credential hunting ────────────────────────────────────────────────

    def _check_sdk_credentials(self, ctx: AnalysisContext):
        """Find SDK-specific API keys/tokens in string pool."""
        SDK_KEY_PATTERNS = [
            (r'AIza[0-9A-Za-z\-_]{35}',          "Google/Firebase API Key"),
            (r'AAAA[A-Za-z0-9_-]{134,}:',         "FCM Server Key"),
            (r'EAA[A-Za-z0-9]+',                   "Facebook App Access Token"),
            (r'[0-9]{15}\|[A-Za-z0-9]+',          "Facebook App ID|Secret"),
        ]
        string_pool = " ".join(ctx.strings_pool)
        for pattern, label in SDK_KEY_PATTERNS:
            matches = re.findall(pattern, string_pool)
            if matches:
                redacted = [m[:8] + "..." + m[-4:] for m in matches[:3]]
                self._add(Finding(
                    id=f"SDK-CRED-{label[:20].upper().replace(' ','_')}",
                    title=f"SDK Credential Exposed in Binary: {label}",
                    category="Hardcoded Credentials",
                    description=(
                        f"A {label} was found embedded in the application binary. "
                        "SDK credentials allow direct access to backend services — "
                        "an attacker can use these to send push notifications, "
                        "query analytics, or abuse paid API quotas."
                    ),
                    technical_detail=f"Pattern: {label}. Redacted samples: {redacted}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                    evidence=[f"{label}: {r}" for r in redacted],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Restrict API key scope in the provider's dashboard. "
                        "Implement server-side proxy for sensitive SDK operations. "
                        "Rotate the exposed credential immediately."
                    ),
                    tags=["credentials", "sdk", "api-key"],
                ))

    # ── SDK logging in release builds ─────────────────────────────────────────

    def _check_sdk_logging(self, ctx: AnalysisContext,
                            detected_sdks: List[Tuple[str, str, str, List[str]]]):
        """Check if Timber debug trees or SDK loggers are active in release."""
        string_pool = " ".join(ctx.strings_pool)

        if "DebugTree" in string_pool or "Timber.plant" in string_pool:
            self._add(Finding(
                id="SDK-TIMBER-DEBUG",
                title="Timber DebugTree May Be Active in Release Build",
                category="Information Disclosure",
                description=(
                    "Timber.DebugTree is present in the binary. "
                    "If planted in the production build, all Timber log statements "
                    "are emitted to Android LogCat, where any app with READ_LOGS "
                    "or a connected ADB session can read them. "
                    "This may expose tokens, user data, internal URLs, and error details."
                ),
                technical_detail=(
                    "Timber.DebugTree found in DEX. "
                    "Check if Timber.plant(new DebugTree()) is conditional on BuildConfig.DEBUG."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["Timber.DebugTree in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Ensure Timber is planted only in debug builds: "
                    "if (BuildConfig.DEBUG) { Timber.plant(new DebugTree()); }. "
                    "In production, use a crash-reporting tree (Crashlytics) "
                    "that redacts sensitive fields."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Read LogCat Output for Sensitive Data",
                    description="Monitor app log output in real time",
                    code=(
                        f"# Stream all logs from target package\n"
                        f"adb logcat --pid=$(adb shell pidof {ctx.package_name}) -v time\n\n"
                        f"# Filter for sensitive patterns\n"
                        f"adb logcat -v time | grep -iE 'token|password|key|secret|auth|jwt|bearer|cookie'"
                    ),
                )],
                tags=["logging", "timber", "information-disclosure"],
                _rank=Rank.C,
            ))
