"""
SKILL: Manifest Sight [PASSIVE]
Reads and judges every dangerous configuration in the AndroidManifest
and network_security_config.xml. The app's skeleton laid bare.
"""

import re
from typing import List, Optional
from xml.etree import ElementTree as ET

from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(el: ET.Element, name: str) -> Optional[str]:
    return el.get(f"{{{ANDROID_NS}}}{name}")


class ManifestModule(BaseModule):
    SKILL_NAME  = "Manifest Sight"
    SKILL_TYPE  = SkillType.PASSIVE
    DESCRIPTION = "Parses AndroidManifest.xml and security config for structural design flaws"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_debuggable(ctx)
        self._check_backup(ctx)
        self._check_cleartext_traffic(ctx)
        self._check_network_security_config(ctx)
        self._check_sdk_versions(ctx)
        self._check_dangerous_permissions(ctx)
        self._check_allow_task_reparenting(ctx)
        self._check_uses_cleartext_in_manifest(ctx)
        return self._findings

    # ── Debuggable ────────────────────────────────────────────────────────────
    def _check_debuggable(self, ctx: AnalysisContext):
        app_el = ctx.manifest_tree.find("application")
        if app_el is None:
            return
        if _attr(app_el, "debuggable") == "true":
            self._add(Finding(
                id="MANIFEST-001",
                title="Application is Debuggable",
                category="Manifest Configuration",
                description=(
                    "The application has android:debuggable=\"true\" set in its manifest. "
                    "This enables ADB debugging on any device, even non-rooted production hardware. "
                    "An attacker with USB access can attach a debugger, inspect memory, "
                    "extract secrets, and bypass certificate pinning trivially."
                ),
                technical_detail=(
                    "android:debuggable=\"true\" in <application> tag. "
                    "This allows: adb shell run-as <package> to access private app data, "
                    "JDWP debugger attachment, memory inspection, and method hooking "
                    "without root on Android < 10."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
                evidence=[f"android:debuggable=\"true\" in AndroidManifest.xml"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Remove android:debuggable from the manifest entirely, or ensure it is "
                    "only set via buildTypes { debug { debuggable true } } and NEVER in release builds. "
                    "Verify with: aapt dump badging app.apk | grep debuggable"
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Extract Private App Data via run-as",
                        description="Since the app is debuggable, run-as grants shell access to private data",
                        code=(
                            f"# Step 1: Get a shell on the device\n"
                            f"adb shell\n\n"
                            f"# Step 2: Run as the target app (no root needed)\n"
                            f"run-as {ctx.package_name}\n\n"
                            f"# Step 3: Read private shared preferences, databases, files\n"
                            f"cat shared_prefs/*.xml\n"
                            f"ls databases/\n"
                            f"cp databases/main.db /sdcard/exfil.db\n\n"
                            f"# Step 4: Attach JDWP debugger\n"
                            f"adb jdwp  # find the PID\n"
                            f"adb forward tcp:8700 jdwp:<PID>\n"
                            f"# Then connect with jdb or Android Studio debugger at localhost:8700"
                        ),
                    ),
                ],
                references=[
                    "https://developer.android.com/guide/topics/manifest/application-element#debug",
                    "https://cwe.mitre.org/data/definitions/215.html",
                ],
                tags=["debuggable", "manifest", "adb", "jdwp"],
            ))

    # ── Backup ────────────────────────────────────────────────────────────────
    def _check_backup(self, ctx: AnalysisContext):
        app_el = ctx.manifest_tree.find("application")
        if app_el is None:
            return
        allow_backup = _attr(app_el, "allowBackup")
        # Default is true if not set and targetSdk < 31
        if allow_backup == "true" or (allow_backup is None and ctx.target_sdk < 31):
            self._add(Finding(
                id="MANIFEST-002",
                title="Full Application Backup Enabled (ADB Backup Exfiltration)",
                category="Manifest Configuration",
                description=(
                    "android:allowBackup is enabled. Any user or attacker with USB access "
                    "can extract the entire application data directory — including databases, "
                    "tokens, session cookies, and cached credentials — using adb backup. "
                    "No root required. No confirmation dialog on Android < 11."
                ),
                technical_detail=(
                    f"android:allowBackup=\"true\" (or implicit default for targetSdk {ctx.target_sdk}). "
                    "Extracts: /data/data/{ctx.package_name}/shared_prefs/, databases/, files/, cache/. "
                    "The resulting .ab file can be unpacked with Android Backup Extractor."
                ),
                cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[
                    f"android:allowBackup not explicitly false" if allow_backup is None
                    else "android:allowBackup=\"true\"",
                    f"targetSdk: {ctx.target_sdk}"
                ],
                affected_components=[ctx.package_name],
                remediation=(
                    "Set android:allowBackup=\"false\" in the <application> tag. "
                    "For Android 12+ (API 31+), use android:dataExtractionRules to granularly "
                    "control what gets backed up. Never back up tokens, keys, or session data."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Full ADB Backup & Data Extraction",
                        description="Extract entire app private data directory, no root required",
                        code=(
                            f"# Step 1: Create backup (user may need to confirm on device)\n"
                            f"adb backup -f {ctx.package_name}.ab -noapk {ctx.package_name}\n\n"
                            f"# Step 2: Download Android Backup Extractor\n"
                            f"# https://github.com/nelenkov/android-backup-extractor\n\n"
                            f"# Step 3: Convert to tar\n"
                            f"java -jar abe.jar unpack {ctx.package_name}.ab {ctx.package_name}.tar\n\n"
                            f"# Step 4: Extract and inspect\n"
                            f"tar -xvf {ctx.package_name}.tar\n"
                            f"find . -name '*.xml' -o -name '*.db' -o -name '*.json' | xargs grep -l 'token\\|password\\|key\\|secret\\|auth'"
                        ),
                    ),
                ],
                references=[
                    "https://developer.android.com/guide/topics/data/autobackup",
                    "https://github.com/nelenkov/android-backup-extractor",
                    "https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage",
                ],
                tags=["backup", "data-exfiltration", "adb", "manifest"],
            ))

    # ── Cleartext traffic (manifest-level) ───────────────────────────────────
    def _check_cleartext_traffic(self, ctx: AnalysisContext):
        app_el = ctx.manifest_tree.find("application")
        if app_el is None:
            return
        cleartext = _attr(app_el, "usesCleartextTraffic")
        # Default true for targetSdk < 28
        if cleartext == "true" or (cleartext is None and ctx.target_sdk < 28):
            self._add(Finding(
                id="MANIFEST-003",
                title="Cleartext HTTP Traffic Permitted",
                category="Network Security",
                description=(
                    "The application permits unencrypted HTTP traffic either explicitly via "
                    "android:usesCleartextTraffic=\"true\" or by targeting API < 28. "
                    "Any network traffic sent over HTTP is visible to passive network observers "
                    "and trivially intercepted via ARP spoofing or rogue Wi-Fi."
                ),
                technical_detail=(
                    f"usesCleartextTraffic: {cleartext or 'unset (defaults true for targetSdk {ctx.target_sdk})'}. "
                    "Attacker on same network can passively read all HTTP traffic including auth tokens, "
                    "session cookies, and API responses."
                ),
                cvss=CVSSVector(AV="A", AC="H", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                evidence=[f"android:usesCleartextTraffic=\"{cleartext or 'not set'}\"",
                          f"targetSdk: {ctx.target_sdk}"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Set android:usesCleartextTraffic=\"false\". "
                    "Migrate all endpoints to HTTPS. Use a network_security_config.xml to enforce this."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="MitM Interception Setup",
                        description="Configure device to route through Burp Suite proxy for HTTP interception",
                        code=(
                            "# Set up Burp Suite as proxy (device and attacker on same network)\n"
                            "adb shell settings put global http_proxy <ATTACKER_IP>:8080\n\n"
                            "# All cleartext HTTP traffic now flows through Burp\n"
                            "# No certificate installation needed for HTTP\n\n"
                            "# Restore after testing:\n"
                            "adb shell settings put global http_proxy :0"
                        ),
                    ),
                ],
                tags=["cleartext", "http", "mitm", "network"],
            ))

    # ── Network Security Config deep parse ───────────────────────────────────
    def _check_network_security_config(self, ctx: AnalysisContext):
        if not ctx.has_network_security_config or not ctx.network_security_config_xml:
            return

        try:
            nsc = ET.fromstring(ctx.network_security_config_xml)
        except ET.ParseError:
            return

        # User certificate trust
        for trust_anchors in nsc.iter("trust-anchors"):
            for certs in trust_anchors.findall("certificates"):
                src = certs.get("src", "")
                if src == "user":
                    overrides_pins = certs.get("overridesPins", "false")
                    self._add(Finding(
                        id="MANIFEST-004",
                        title="Network Security Config Trusts User-Added CA Certificates",
                        category="Network Security",
                        description=(
                            "The network_security_config.xml trusts certificates from the user "
                            "certificate store. Any certificate installed by the device user — "
                            "including a Burp Suite or mitmproxy CA — is trusted for TLS validation. "
                            "This makes SSL/TLS interception trivially easy for any attacker "
                            "who can socially engineer the user to install a certificate."
                        ),
                        technical_detail=(
                            f"<certificates src=\"user\"> found in <trust-anchors>. "
                            f"overridesPins={overrides_pins}. "
                            "Certificate pinning is bypassed if overridesPins=true."
                        ),
                        cvss=CVSSVector(AV="A", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                        evidence=["<certificates src=\"user\"/> in network_security_config.xml"],
                        affected_components=[ctx.package_name],
                        remediation=(
                            "Remove <certificates src=\"user\"/> from production builds. "
                            "Use <certificates src=\"system\"/> only. "
                            "Consider certificate pinning for sensitive domains."
                        ),
                        pocs=[
                            PoC(
                                type="adb_command",
                                title="Install Proxy CA and Intercept TLS Traffic",
                                description="Install Burp CA as user cert to intercept all HTTPS",
                                code=(
                                    "# Step 1: Export Burp CA (DER format from Burp > Proxy > Options > CA Certificate)\n"
                                    "# Step 2: Push to device\n"
                                    "adb push burp-ca.der /sdcard/burp-ca.cer\n\n"
                                    "# Step 3: Install via Settings > Security > Install from Storage\n"
                                    "# OR via ADB (Android 7+):\n"
                                    "adb shell am start -n com.android.settings/.Settings\\$SecuritySettingsActivity\n\n"
                                    "# Step 4: Configure proxy\n"
                                    "adb shell settings put global http_proxy <BURP_IP>:8080\n\n"
                                    "# All HTTPS traffic is now visible in Burp Suite"
                                ),
                            ),
                        ],
                        tags=["tls", "mitm", "certificate", "network-security-config"],
                    ))

        # Pinning misconfigurations
        for domain_config in nsc.iter("domain-config"):
            for pin_set in domain_config.findall("pin-set"):
                expiry = pin_set.get("expiration")
                pins = pin_set.findall("pin")
                domains = [d.text for d in domain_config.findall("domain") if d.text]
                if not pins:
                    self._add(Finding(
                        id="MANIFEST-005",
                        title=f"Empty Certificate Pin-Set (Pins Absent for {', '.join(domains)})",
                        category="Network Security",
                        description=(
                            f"A <pin-set> is declared for {domains} but contains no <pin> elements. "
                            "An empty pin-set results in the pinning check always passing — "
                            "effectively disabling certificate pinning entirely while giving "
                            "the false impression that pinning is enforced."
                        ),
                        technical_detail=(
                            f"<pin-set expiration=\"{expiry}\"> with 0 <pin> children "
                            f"for domain(s): {domains}"
                        ),
                        cvss=CVSSVector(AV="A", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                        evidence=[f"Empty <pin-set> for domains: {domains}"],
                        affected_components=domains,
                        remediation=(
                            "Add valid SHA-256 pin hashes: <pin digest=\"SHA-256\">base64hash==</pin>. "
                            "Always include a backup pin for a different CA/key. "
                            "Set a realistic expiration date and rotate before it lapses."
                        ),
                        tags=["certificate-pinning", "tls", "network-security-config"],
                    ))

        # Check for wildcard domains
        for domain in nsc.iter("domain"):
            if domain.text and domain.text.startswith("*"):
                self._add(Finding(
                    id="MANIFEST-006",
                    title=f"Wildcard Domain in Network Security Config: {domain.text}",
                    category="Network Security",
                    description=(
                        f"A wildcard domain ({domain.text}) in network_security_config.xml "
                        "applies security rules (or exceptions) to all subdomains. "
                        "If this domain is in a <debug-overrides> or has cleartext permitted, "
                        "a broad surface is exposed."
                    ),
                    technical_detail=f"Wildcard domain element: <domain>{domain.text}</domain>",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    evidence=[f"Wildcard domain: {domain.text}"],
                    affected_components=[ctx.package_name],
                    remediation="Use explicit domain names instead of wildcards where possible.",
                    tags=["network-security-config", "wildcard", "tls"],
                ))

    # ── SDK version risks ─────────────────────────────────────────────────────
    def _check_sdk_versions(self, ctx: AnalysisContext):
        if ctx.min_sdk < 21:
            self._add(Finding(
                id="MANIFEST-007",
                title=f"Dangerously Low minSdkVersion ({ctx.min_sdk})",
                category="Platform Security",
                description=(
                    f"The app supports Android {ctx.min_sdk} (pre-Lollipop). "
                    "Devices running these versions lack modern security protections: "
                    "no SELinux enforcement, weak TLS defaults, no Verified Boot, "
                    "and numerous unpatched kernel vulnerabilities. "
                    "The attack surface includes decade-old exploits."
                ),
                technical_detail=(
                    f"minSdkVersion={ctx.min_sdk}. "
                    "API < 16: addJavascriptInterface is RCE by default. "
                    "API < 17: WebView JS bridge has no @JavascriptInterface restriction. "
                    "API < 21: SSLv3/RC4 may be negotiated."
                ),
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                evidence=[f"minSdkVersion=\"{ctx.min_sdk}\" in AndroidManifest.xml"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Raise minSdkVersion to at least 26 (Android 8.0) to gain "
                    "modern TLS defaults, improved SELinux policies, and removal of "
                    "dozens of legacy attack surfaces."
                ),
                tags=["sdk-version", "legacy", "platform"],
            ))

    # ── Dangerous permissions ─────────────────────────────────────────────────
    def _check_dangerous_permissions(self, ctx: AnalysisContext):
        HIGH_RISK_PERMISSIONS = {
            "android.permission.READ_CONTACTS":          ("Privacy", "Access to all contacts"),
            "android.permission.READ_CALL_LOG":          ("Privacy", "Full call history"),
            "android.permission.PROCESS_OUTGOING_CALLS": ("Privacy", "Intercept outgoing calls"),
            "android.permission.RECORD_AUDIO":           ("Surveillance", "Microphone access"),
            "android.permission.ACCESS_FINE_LOCATION":   ("Tracking", "Precise GPS location"),
            "android.permission.CAMERA":                 ("Surveillance", "Camera access"),
            "android.permission.READ_SMS":               ("Privacy", "Read all SMS messages"),
            "android.permission.RECEIVE_SMS":            ("Privacy", "Intercept incoming SMS"),
            "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Privilege", "Screen reader / keylogger capability"),
            "android.permission.SYSTEM_ALERT_WINDOW":    ("UI", "Draw over other apps (tapjacking)"),
            "android.permission.REQUEST_INSTALL_PACKAGES": ("Installation", "Silently install APKs"),
            "android.permission.WRITE_SETTINGS":         ("System", "Modify system settings"),
            "android.permission.BIND_DEVICE_ADMIN":      ("Admin", "Device administrator privilege"),
            "android.permission.READ_PHONE_STATE":       ("Privacy", "IMEI, phone number, carrier"),
        }
        found = []
        for perm, (category, impact) in HIGH_RISK_PERMISSIONS.items():
            if perm in ctx.permissions:
                found.append((perm, category, impact))

        for perm, category, impact in found:
            short = perm.replace("android.permission.", "")
            self._add(Finding(
                id=f"MANIFEST-PERM-{short[:20]}",
                title=f"High-Risk Permission Declared: {short}",
                category="Permission Model",
                description=(
                    f"The application declares {perm}. "
                    f"Impact: {impact}. "
                    "If this permission is not strictly necessary for core functionality, "
                    "it represents unnecessary attack surface and privacy risk."
                ),
                technical_detail=f"Permission category: {category}. Full name: {perm}",
                cvss=CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="L", I="N", A="N"),
                evidence=[f"<uses-permission android:name=\"{perm}\"/>"],
                affected_components=[ctx.package_name],
                remediation=(
                    f"Audit whether {perm} is truly required. "
                    "If required, document the justification. "
                    "Request at runtime only when needed, not at app launch."
                ),
                tags=["permission", "privacy", category.lower()],
                _rank=Rank.D,
            ))

    # ── Allow task reparenting (tapjacking vector) ────────────────────────────
    def _check_allow_task_reparenting(self, ctx: AnalysisContext):
        app_el = ctx.manifest_tree.find("application")
        if app_el is None:
            return
        if _attr(app_el, "allowTaskReparenting") == "true":
            self._add(Finding(
                id="MANIFEST-008",
                title="allowTaskReparenting Enabled (Task Hijacking Vector)",
                category="Application Security",
                description=(
                    "android:allowTaskReparenting=\"true\" allows a malicious app to move "
                    "an activity from its original task into a different task. "
                    "This is the basis of the Android task hijacking attack: a malicious app "
                    "can substitute itself in the recent apps screen, capturing user input "
                    "intended for the legitimate app."
                ),
                technical_detail=(
                    "When a malicious app with the same taskAffinity is started, "
                    "it can pull the target activity into its own task, "
                    "effectively hijacking the UI."
                ),
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                evidence=["android:allowTaskReparenting=\"true\""],
                affected_components=[ctx.package_name],
                remediation=(
                    "Remove android:allowTaskReparenting or set it to false. "
                    "Set android:taskAffinity=\"\" (empty string) on sensitive activities "
                    "to prevent them from being reparented."
                ),
                tags=["task-hijacking", "tapjacking", "ui", "manifest"],
            ))

    # ── Cleartext in manifest domains ─────────────────────────────────────────
    def _check_uses_cleartext_in_manifest(self, ctx: AnalysisContext):
        """Check for HTTP URLs hardcoded directly in the manifest."""
        manifest_str = ctx.manifest_xml
        http_urls = re.findall(r'http://[^\s"<>]+', manifest_str)
        http_urls = [u for u in http_urls if not u.startswith("http://schemas")]
        if http_urls:
            self._add(Finding(
                id="MANIFEST-009",
                title="Hardcoded HTTP URLs Found in AndroidManifest.xml",
                category="Network Security",
                description=(
                    "One or more HTTP (non-TLS) URLs are hardcoded directly in the manifest. "
                    "These may be used for deep links, intent filters, or metadata — "
                    "and represent cleartext communication channels."
                ),
                technical_detail=f"HTTP URLs found in manifest: {http_urls[:10]}",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=http_urls[:10],
                affected_components=[ctx.package_name],
                remediation="Replace all http:// URLs with https:// equivalents.",
                tags=["cleartext", "http", "manifest", "hardcoded"],
                _rank=Rank.D,
            ))
