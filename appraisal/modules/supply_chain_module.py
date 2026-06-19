"""
SKILL: Supply Chain Sentinel [HIDDEN]
OWASP M2 — Inadequate Supply Chain Security

Audits the build artifact for signing integrity, dependency confusion vectors,
embedded build metadata leakage, debug artifact contamination,
and repackaging indicators.
"""

import re
import zipfile
import hashlib
from typing import List, Dict
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


# Known debug/test certificate SHA-256 fingerprints
DEBUG_CERT_INDICATORS = [
    "Android Debug",
    "Unknown",
    "androiddebugkey",
    "debug.keystore",
    "cn=android debug",
]

# Build metadata files that shouldn't be in release APKs
DEBUG_ARTIFACTS = [
    "classes-debug.dex",
    "proguard_map.txt",
    "mapping.txt",
    "seeds.txt",
    "usage.txt",
    ".kotlin_module",
    "META-INF/build-data.properties",
]

# Dependency confusion: internal package names that could be squatted
INTERNAL_PKG_PATTERNS = [
    r'com\.internal\.',
    r'com\.corp\.',
    r'com\.private\.',
    r'internal\.',
    r'\.internal\.',
    r'\.dev\.',
    r'\.staging\.',
    r'\.test\.',
]


class SupplyChainSentinelModule(BaseModule):
    SKILL_NAME  = "Supply Chain Sentinel"
    SKILL_TYPE  = SkillType.HIDDEN
    DESCRIPTION = "OWASP M2 — Build pipeline integrity, signing validation, debug artifact detection, repackaging"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_apk_signing(ctx)
        self._check_debug_artifacts(ctx)
        self._check_build_metadata_leakage(ctx)
        self._check_repackaging_indicators(ctx)
        self._check_dependency_confusion(ctx)
        self._check_v1_only_signing(ctx)
        self._check_test_code_in_release(ctx)
        return self._findings

    # ── APK Signing validation ────────────────────────────────────────────────

    def _check_apk_signing(self, ctx: AnalysisContext):
        """Check APK signature scheme and debug certificate usage."""
        meta_inf_files = [f for f in ctx.file_list if f.startswith("META-INF/")]
        sig_files = [f for f in meta_inf_files
                     if f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".EC")]
        sf_files  = [f for f in meta_inf_files if f.endswith(".SF")]

        if not sig_files and not sf_files:
            self._add(Finding(
                id="M2-UNSIGNED",
                title="APK Contains No Signature Files — Possibly Unsigned",
                category="Supply Chain Security (M2)",
                description=(
                    "No JAR signature files (.RSA/.DSA/.SF) were found in META-INF/. "
                    "An unsigned or improperly signed APK can be installed on devices "
                    "with unknown sources enabled and cannot be verified by the OS "
                    "as originating from the claimed developer. "
                    "This also means the APK may have been tampered with post-build."
                ),
                technical_detail=(
                    f"META-INF files: {meta_inf_files}\n"
                    "No .RSA/.DSA/.EC or .SF signature file found."
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="H", A="N"),
                evidence=["No signature files in META-INF/"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Sign the APK with a production keystore using apksigner. "
                    "Use APK Signature Scheme v2 and v3 for Android 7+. "
                    "Never distribute unsigned APKs."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Verify APK Signature",
                    description="Check whether the APK is properly signed",
                    code=(
                        f"# Check signature with apksigner\n"
                        f"apksigner verify --verbose {ctx.apk_path}\n\n"
                        f"# Check with jarsigner\n"
                        f"jarsigner -verify -verbose -certs {ctx.apk_path}\n\n"
                        f"# Check with keytool\n"
                        f"keytool -printcert -jarfile {ctx.apk_path}"
                    ),
                )],
                tags=["m2", "unsigned", "signing", "supply-chain"],
            ))
            return

        # Check for debug certificate
        try:
            with zipfile.ZipFile(ctx.apk_path, "r") as zf:
                for sig_file in sig_files:
                    try:
                        cert_data = zf.read(sig_file).decode("latin-1", errors="ignore").lower()
                        for indicator in DEBUG_CERT_INDICATORS:
                            if indicator.lower() in cert_data:
                                self._add(Finding(
                                    id="M2-DEBUG-CERT",
                                    title="Debug/Test Certificate Detected in Production APK",
                                    category="Supply Chain Security (M2)",
                                    description=(
                                        f"The APK appears to be signed with a debug or test certificate "
                                        f"(indicator: '{indicator}'). "
                                        "Debug certificates are generated automatically by Android Studio "
                                        "and their private keys are the same across all Android development "
                                        "installations. An attacker who extracts the common debug keystore "
                                        "can sign malicious APKs that will be accepted as updates."
                                    ),
                                    technical_detail=f"Debug indicator '{indicator}' found in {sig_file}",
                                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="H", A="N"),
                                    evidence=[f"Debug cert indicator in {sig_file}: {indicator}"],
                                    affected_components=[ctx.package_name],
                                    remediation=(
                                        "Generate a production keystore with keytool and sign with apksigner. "
                                        "Store the production keystore securely (not in the repository). "
                                        "Enable Google Play App Signing for additional protection."
                                    ),
                                    tags=["m2", "debug-cert", "signing", "supply-chain"],
                                ))
                                break
                    except Exception:
                        continue
        except Exception:
            pass

    # ── Debug artifacts in release build ─────────────────────────────────────

    def _check_debug_artifacts(self, ctx: AnalysisContext):
        found = [f for f in ctx.file_list
                 if any(art.lower() in f.lower() for art in DEBUG_ARTIFACTS)]

        if found:
            self._add(Finding(
                id="M2-DEBUG-ARTIFACTS",
                title="Debug/Build Artifacts Found in Release APK",
                category="Supply Chain Security (M2)",
                description=(
                    "Debug or build artifacts were found packaged in the APK. "
                    "ProGuard mapping files reveal original class/method names, "
                    "defeating obfuscation entirely. "
                    "Build metadata files expose the build environment and toolchain. "
                    "These artifacts should never be included in release builds."
                ),
                technical_detail=f"Debug artifacts found: {found}",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=[f"Debug artifact in APK: {f}" for f in found[:5]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Configure your build pipeline to strip debug artifacts from release APKs. "
                    "Ensure mapping.txt is stored securely server-side for crash deobfuscation — "
                    "never ship it in the APK. "
                    "Add to .gitignore and release build config: -keepattributes SourceFile,LineNumberTable."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Extract ProGuard Mapping to Defeat Obfuscation",
                    description="If mapping.txt is present, use it to deobfuscate the entire app",
                    code=(
                        f"# Extract mapping file\n"
                        f"unzip {ctx.apk_path} mapping.txt -d ./\n\n"
                        f"# Deobfuscate a stack trace using retrace\n"
                        f"retrace.sh mapping.txt obfuscated_stack_trace.txt\n\n"
                        f"# Or with jadx — loads mapping automatically\n"
                        f"jadx -d decompiled/ --deobf-resugar-cfg mapping.txt {ctx.apk_path}"
                    ),
                )],
                tags=["m2", "debug-artifacts", "proguard-mapping", "supply-chain"],
                _rank=Rank.C,
            ))

    # ── Build metadata leakage ────────────────────────────────────────────────

    def _check_build_metadata_leakage(self, ctx: AnalysisContext):
        """Detect internal paths, CI server details, developer info in string pool."""
        pool = "\n".join(ctx.strings_pool)

        # Internal build paths
        build_path_patterns = [
            (r'/home/[a-zA-Z0-9_]+/', "Developer home directory path"),
            (r'/Users/[a-zA-Z0-9_]+/', "macOS developer home path"),
            (r'C:\\Users\\[a-zA-Z0-9_]+\\', "Windows developer home path"),
            (r'/var/jenkins/', "Jenkins CI path"),
            (r'/opt/buildagent/', "TeamCity build agent path"),
            (r'\.gradle/caches/', "Gradle cache path"),
            (r'\.m2/repository/', "Maven local repo path"),
        ]

        found_paths = []
        for pattern, label in build_path_patterns:
            matches = re.findall(pattern, pool)
            if matches:
                found_paths.append((label, matches[:2]))

        if found_paths:
            evidence = [f"{label}: {paths}" for label, paths in found_paths[:5]]
            self._add(Finding(
                id="M2-BUILD-META",
                title="Build Environment Paths Leaked in Binary",
                category="Supply Chain Security (M2)",
                description=(
                    "Internal build environment paths (developer home directories, "
                    "CI/CD server paths, build tool caches) are embedded in the compiled binary. "
                    "This leaks information about your internal infrastructure, "
                    "developer usernames, and build toolchain that can be used for "
                    "targeted attacks against your development environment."
                ),
                technical_detail="\n".join(evidence),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=evidence,
                affected_components=[ctx.package_name],
                remediation=(
                    "Configure the compiler to strip debug info: "
                    "-g:none in javac, minifyEnabled true in Gradle. "
                    "Use reproducible builds to prevent metadata injection. "
                    "Run the build in a clean container to avoid path leakage."
                ),
                tags=["m2", "build-metadata", "info-disclosure", "supply-chain"],
                _rank=Rank.D,
            ))

    # ── Repackaging indicators ────────────────────────────────────────────────

    def _check_repackaging_indicators(self, ctx: AnalysisContext):
        """Detect signs that this APK may have been repackaged (tampered with)."""
        # Check for multiple DEX files beyond what's expected
        dex_files = [f for f in ctx.file_list if re.match(r'classes\d*\.dex', f)]

        # Check for injected files in unusual locations
        unusual_locations = [
            f for f in ctx.file_list
            if (f.startswith("assets/") and f.endswith(".dex")) or
               (f.startswith("res/") and f.endswith(".so")) or
               f.endswith(".jar") or
               (f.startswith("assets/") and f.endswith(".apk"))
        ]

        if unusual_locations:
            self._add(Finding(
                id="M2-REPACKAGE-INDICATOR",
                title="Unusual File Locations Suggest Possible Repackaging/Injection",
                category="Supply Chain Security (M2)",
                description=(
                    "Files were found in unusual APK locations that may indicate "
                    "the APK has been repackaged, tampered with, or had malicious "
                    "code injected post-compilation. "
                    "DEX files in assets/, .so files in res/, or embedded APKs/JARs "
                    "are common indicators of malware droppers or repackaged apps."
                ),
                technical_detail=f"Unusual files: {unusual_locations}",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                evidence=[f"Suspicious file: {f}" for f in unusual_locations[:5]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Verify the APK signature matches your production signing key. "
                    "Implement runtime integrity checks using PackageManager.getSignatures(). "
                    "Use Google Play App Signing and only distribute via official channels."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Inspect and Extract Injected Files",
                    description="Extract and examine the suspicious embedded files",
                    code=(
                        f"# Extract the APK\n"
                        f"unzip {ctx.apk_path} -d extracted/\n\n"
                        + "\n".join(
                            f"# Examine: {f}\n"
                            f"file extracted/{f}\n"
                            f"strings extracted/{f} | head -50"
                            for f in unusual_locations[:3]
                        )
                    ),
                )],
                tags=["m2", "repackaging", "tampering", "malware-indicator"],
            ))

    # ── Dependency confusion ──────────────────────────────────────────────────

    def _check_dependency_confusion(self, ctx: AnalysisContext):
        """Find internal package names that could be squatted on public repos."""
        pool = " ".join(ctx.strings_pool)
        internal_pkgs = []

        for pattern in INTERNAL_PKG_PATTERNS:
            matches = re.findall(pattern, pool)
            if matches:
                internal_pkgs.extend(matches)

        # Also scan class names
        try:
            for cls in ctx.analysis.get_classes():
                cls_name = str(cls.name).replace("/", ".").strip("L;")
                for pattern in INTERNAL_PKG_PATTERNS:
                    if re.search(pattern, cls_name, re.IGNORECASE):
                        internal_pkgs.append(cls_name.split(".")[0] + "." + cls_name.split(".")[1]
                                             if "." in cls_name else cls_name)
                        break
        except Exception:
            pass

        if internal_pkgs:
            unique = list(set(internal_pkgs))[:5]
            self._add(Finding(
                id="M2-DEP-CONFUSION",
                title="Internal Package Names Detected — Dependency Confusion Risk",
                category="Supply Chain Security (M2)",
                description=(
                    "Package names with internal/private naming conventions were detected "
                    f"({unique[:3]}). "
                    "If these correspond to internal dependencies fetched from a private "
                    "package registry, a dependency confusion attack is possible: "
                    "an attacker publishes a malicious package with the same name to a "
                    "public registry (npm, PyPI, Maven Central), which the build system "
                    "may prefer over the private one."
                ),
                technical_detail=f"Internal package patterns found: {unique}",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"Internal package: {p}" for p in unique[:5]],
                affected_components=[ctx.package_name],
                remediation=(
                    "Scope all internal packages with a unique namespace prefix "
                    "that cannot be registered publicly. "
                    "Use dependency pinning with hash verification. "
                    "Configure Gradle/Maven to prefer private registry over public. "
                    "Consider publishing internal packages to the public registry as 'reserved' stubs."
                ),
                references=["https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"],
                tags=["m2", "dependency-confusion", "supply-chain", "build-pipeline"],
                _rank=Rank.C,
            ))

    # ── APK Signature Scheme v1 only ─────────────────────────────────────────

    def _check_v1_only_signing(self, ctx: AnalysisContext):
        """Detect APKs using only JAR signing (v1) without v2/v3."""
        has_v1 = any(f.endswith(".SF") for f in ctx.file_list)
        # v2/v3 signatures are in the APK signing block — not a regular ZIP entry
        # We detect v2/v3 absence by looking for the block magic bytes
        has_v2_v3 = False
        try:
            with open(ctx.apk_path, "rb") as f:
                content = f.read()
                # APK Signing Block magic
                if b"APK Sig Block 42" in content:
                    has_v2_v3 = True
        except Exception:
            pass

        if has_v1 and not has_v2_v3 and ctx.target_sdk >= 24:
            self._add(Finding(
                id="M2-V1-SIGN-ONLY",
                title="APK Uses Only v1 JAR Signing — Missing v2/v3 Signature Scheme",
                category="Supply Chain Security (M2)",
                description=(
                    "The APK uses only JAR signing (v1 scheme) without APK Signature Scheme v2 or v3. "
                    "v1 JAR signing has a known vulnerability: files can be injected into the APK "
                    "ZIP after signing without invalidating the signature, because JAR signing "
                    "only covers individual ZIP entries, not the ZIP structure itself. "
                    "This is the Janus vulnerability (CVE-2017-13156)."
                ),
                technical_detail=(
                    "v1 signature present (META-INF/*.SF found). "
                    "APK Signing Block v2/v3 magic not detected. "
                    f"targetSdk: {ctx.target_sdk} (v2 supported from API 24+)."
                ),
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                evidence=["v1 JAR signature only, no v2/v3 APK Signing Block"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Sign with APK Signature Scheme v2 and v3: "
                    "apksigner sign --ks keystore.jks --min-sdk-version 24 app.apk. "
                    "In build.gradle: signingConfig { v1SigningEnabled true; v2SigningEnabled true; v3SigningEnabled true }"
                ),
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-13156"],
                tags=["m2", "jar-signing", "janus", "cve-2017-13156", "signing"],
            ))

    # ── Test code in release ──────────────────────────────────────────────────

    def _check_test_code_in_release(self, ctx: AnalysisContext):
        """Detect test/debug code classes shipped in release builds."""
        TEST_INDICATORS = [
            "junit", "JUnit", "MockK", "Mockito", "Espresso",
            "androidx.test", "robolectric", "TestRunner",
            "DebugActivity", "TestActivity", "StagingConfig",
            "BuildConfig.DEBUG",
        ]
        pool = " ".join(ctx.strings_pool)
        found = [ind for ind in TEST_INDICATORS if ind in pool]

        if found:
            test_classes = []
            try:
                for cls in ctx.analysis.get_classes():
                    cls_str = str(cls.name).lower()
                    if any(t.lower() in cls_str for t in ["test", "mock", "espresso", "junit"]):
                        test_classes.append(str(cls.name))
            except Exception:
                pass

            if test_classes:
                self._add(Finding(
                    id="M2-TEST-IN-RELEASE",
                    title="Test/Debug Classes Found in Release APK",
                    category="Supply Chain Security (M2)",
                    description=(
                        "Test framework classes (JUnit, Mockito, Espresso) or test activities "
                        "were found in the release APK. "
                        "Test code increases attack surface, may expose internal test utilities, "
                        "backdoors, or mock configurations that bypass security controls. "
                        "Test classes should be stripped entirely from production builds."
                    ),
                    technical_detail=(
                        f"Test indicators: {found[:5]}\n"
                        f"Test classes: {test_classes[:5]}"
                    ),
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                    evidence=[f"Test class: {c}" for c in test_classes[:5]],
                    affected_components=test_classes[:3],
                    remediation=(
                        "Ensure test dependencies are declared as testImplementation or "
                        "androidTestImplementation in build.gradle — never as implementation. "
                        "Use build variants to separate debug/test code from production."
                    ),
                    tags=["m2", "test-code", "debug-build", "supply-chain"],
                    _rank=Rank.D,
                ))
