"""
SKILL: Binary Hardening Auditor [UNIQUE]
Checks for missing binary protections: root detection bypasses,
emulator detection patterns, native lib entropy (packed code),
anti-tamper signature checks, and ProGuard/obfuscation assessment.
"""

import math
import re
import struct
from typing import List, Dict
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class BinaryHardeningModule(BaseModule):
    SKILL_NAME  = "Binary Hardening Auditor"
    SKILL_TYPE  = SkillType.UNIQUE
    DESCRIPTION = "Detects missing binary protections, root/emulator checks, and packed native libraries"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_obfuscation(ctx)
        self._check_root_detection(ctx)
        self._check_emulator_detection(ctx)
        self._check_anti_tamper(ctx)
        self._check_native_lib_entropy(ctx)
        self._check_frida_detection(ctx)
        self._check_ssl_pinning_implementation(ctx)
        self._check_proguard_effectiveness(ctx)
        return self._findings

    # ── Obfuscation / ProGuard assessment ────────────────────────────────────

    def _check_obfuscation(self, ctx: AnalysisContext):
        """Estimate whether the app is obfuscated by checking class/method naming patterns."""
        short_class_count = 0
        total_class_count = 0

        try:
            for cls in ctx.app_classes:
                cls_name = str(cls.name)
                # Skip android/java system classes
                if cls_name.startswith("Landroid/") or cls_name.startswith("Ljava/"):
                    continue
                total_class_count += 1
                # Short names (a, b, c, aa, ab etc.) = obfuscated
                short_name = cls_name.split("/")[-1].rstrip(";")
                if len(short_name) <= 2:
                    short_class_count += 1
        except Exception:
            pass

        if total_class_count == 0:
            return

        obfuscation_ratio = short_class_count / total_class_count

        if obfuscation_ratio < 0.3:
            self._add(Finding(
                id="BINARY-NOOBF",
                title="Application Lacks Code Obfuscation (ProGuard/R8 Not Detected)",
                category="Binary Hardening",
                description=(
                    f"Only {obfuscation_ratio:.0%} of application classes appear obfuscated. "
                    "Without ProGuard or R8 obfuscation, the application's class names, "
                    "method names, and logic are fully readable after decompilation. "
                    "An attacker can decompile and understand the complete application logic "
                    "in minutes using tools like jadx or Bytecode Viewer."
                ),
                technical_detail=(
                    f"Short-named classes: {short_class_count}/{total_class_count} "
                    f"({obfuscation_ratio:.1%}). "
                    "Threshold for 'obfuscated': >30% single/double-char class names."
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=[f"Obfuscation ratio: {obfuscation_ratio:.1%} ({short_class_count}/{total_class_count} short-named classes)"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Enable R8 full mode in build.gradle: "
                    "buildTypes { release { minifyEnabled true; shrinkResources true; "
                    "proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro' } }. "
                    "Use -repackageclasses '' and -allowaccessmodification for maximum obfuscation."
                ),
                tags=["obfuscation", "proguard", "reverse-engineering"],
                _rank=Rank.D,
            ))

    # ── Root detection ────────────────────────────────────────────────────────

    def _check_root_detection(self, ctx: AnalysisContext):
        ROOT_INDICATORS = [
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "com.topjohnwu.magisk",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "daemonsu",
            "RootBeer",
            "SafetyNet",
            "ro.build.tags",
            "test-keys",
        ]

        string_pool = " ".join(ctx.strings_pool)
        found_checks = [ind for ind in ROOT_INDICATORS if ind in string_pool]

        if found_checks:
            # App has root detection — generate bypass PoC
            self._add(Finding(
                id="BINARY-ROOTDETECT",
                title="Root Detection Implemented — Frida Bypass PoC Generated",
                category="Runtime Defense",
                description=(
                    "Root detection checks are present in the application. "
                    "While this is a security control, it can be bypassed using Frida "
                    "to hook and return false from all detection methods. "
                    "This finding provides a bypass script to verify the detection "
                    "can be circumvented by a motivated attacker."
                ),
                technical_detail=(
                    f"Root check indicators found: {found_checks[:10]}"
                ),
                cvss=CVSSVector(AV="P", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                evidence=found_checks[:5],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use multiple layers of root detection. "
                    "Implement native (JNI) checks that are harder to hook. "
                    "Use Google Play Integrity API for server-side device integrity verification. "
                    "Combine with certificate pinning and runtime integrity checks."
                ),
                pocs=[PoC(
                    type="frida_script",
                    title="Root Detection Universal Bypass",
                    description="Hooks all common root detection patterns, returns safe values",
                    code=self._generate_root_bypass_frida(ctx),
                )],
                tags=["root-detection", "frida", "bypass", "runtime-defense"],
                _rank=Rank.D,
            ))
        else:
            # No root detection — this IS the vulnerability
            self._add(Finding(
                id="BINARY-NOROOT",
                title="No Root/Jailbreak Detection Implemented",
                category="Runtime Defense",
                description=(
                    "The application does not detect whether it is running on a rooted device. "
                    "On rooted devices, an attacker can: read the app's private data directly, "
                    "attach a debugger, inject Frida, bypass SSL pinning, "
                    "and manipulate app behavior at runtime — all without triggering any defenses."
                ),
                technical_detail="No root detection strings found in DEX string pool.",
                cvss=CVSSVector(AV="P", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["No root detection indicators in string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Implement root detection using RootBeer library or custom checks: "
                    "check for su binary, Magisk files, test-keys build tags, "
                    "and dangerous app packages. "
                    "Use Google Play Integrity API for server-side verification."
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Access Private Data on Rooted Device",
                    description="On a rooted device, extract all private app data",
                    code=(
                        f"# On a rooted device:\n"
                        f"adb shell su -c 'cp -r /data/data/{ctx.package_name}/ /sdcard/app_data/'\n"
                        f"adb pull /sdcard/app_data/ ./stolen_data/\n\n"
                        f"# Read databases directly\n"
                        f"adb shell su -c 'sqlite3 /data/data/{ctx.package_name}/databases/main.db .dump'\n\n"
                        f"# Read all shared preferences\n"
                        f"adb shell su -c 'cat /data/data/{ctx.package_name}/shared_prefs/*.xml'"
                    ),
                )],
                tags=["root-detection", "missing-control", "runtime-defense"],
            ))

    # ── Emulator detection ────────────────────────────────────────────────────

    def _check_emulator_detection(self, ctx: AnalysisContext):
        EMULATOR_STRINGS = [
            "goldfish", "ranchu", "sdk_gphone", "generic",
            "ro.product.model", "ro.hardware", "ro.bootloader",
            "isEmulator", "Build.FINGERPRINT",
            "QEMU", "Genymotion", "BlueStacks",
        ]
        string_pool = " ".join(ctx.strings_pool)
        found = [s for s in EMULATOR_STRINGS if s in string_pool]

        if not found:
            self._add(Finding(
                id="BINARY-NOEMU",
                title="No Emulator Detection Implemented",
                category="Runtime Defense",
                description=(
                    "The application does not detect emulated environments. "
                    "Security researchers and attackers routinely perform analysis "
                    "on Android emulators (AVD, Genymotion, BlueStacks). "
                    "Without emulator detection, dynamic analysis and automation are trivial."
                ),
                technical_detail="No emulator detection strings found in DEX string pool.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                evidence=["No emulator detection strings in DEX pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Check build properties: Build.FINGERPRINT, Build.MODEL, Build.HARDWARE. "
                    "Check for emulator-specific files: /dev/socket/qemud, /dev/qemu_pipe. "
                    "Use Google Play Integrity API."
                ),
                tags=["emulator-detection", "missing-control"],
                _rank=Rank.D,
            ))

    # ── Anti-tamper / signature check ─────────────────────────────────────────

    def _check_anti_tamper(self, ctx: AnalysisContext):
        TAMPER_STRINGS = [
            "getPackageInfo", "GET_SIGNATURES", "SHA", "signature",
            "PackageManager", "certificates", "signingInfo",
            "hashCode", "apkHash", "checksum",
        ]
        string_pool = " ".join(ctx.strings_pool)
        found = [s for s in TAMPER_STRINGS if s in string_pool]

        if found:
            self._add(Finding(
                id="BINARY-ANTITAMPER",
                title="Signature/Tamper Check Detected — Frida Bypass PoC Generated",
                category="Runtime Defense",
                description=(
                    "The application appears to verify its own signature or APK integrity. "
                    "This prevents simple APK patching/repackaging attacks. "
                    "However, signature checks can be bypassed with Frida by hooking "
                    "getPackageInfo() to return the expected signature hash."
                ),
                technical_detail=f"Tamper detection indicators: {found[:8]}",
                cvss=CVSSVector(AV="P", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                evidence=found[:5],
                affected_components=[ctx.package_name],
                remediation=(
                    "Implement tamper detection in native code (harder to hook). "
                    "Verify APK signature via server-side challenge-response. "
                    "Use Google Play Integrity API for cryptographic device/app attestation."
                ),
                pocs=[PoC(
                    type="frida_script",
                    title="Anti-Tamper Signature Check Bypass",
                    description="Hook PackageManager.getPackageInfo() to spoof signature",
                    code=self._generate_antitamper_frida(ctx),
                )],
                tags=["anti-tamper", "signature-check", "frida-bypass"],
                _rank=Rank.D,
            ))

    # ── Native library entropy analysis ──────────────────────────────────────

    def _check_native_lib_entropy(self, ctx: AnalysisContext):
        if not ctx.has_native_libs:
            return

        HIGH_ENTROPY_THRESHOLD = 7.2  # bits/byte — packed/encrypted code

        import zipfile
        try:
            with zipfile.ZipFile(ctx.apk_path, "r") as zf:
                for lib_path in ctx.native_lib_names:
                    try:
                        lib_data = zf.read(lib_path)
                    except Exception:
                        continue

                    if len(lib_data) < 1024:
                        continue

                    entropy = _shannon_entropy(lib_data)

                    if entropy >= HIGH_ENTROPY_THRESHOLD:
                        lib_name = lib_path.split("/")[-1]
                        self._add(Finding(
                            id=f"BINARY-ENTROPY-{lib_name[:20].replace('.','_').replace('-','_')}",
                            title=f"High-Entropy Native Library (Possible Packing/Encryption): {lib_name}",
                            category="Binary Analysis",
                            description=(
                                f"Native library {lib_name} has a Shannon entropy of {entropy:.2f} bits/byte "
                                f"(threshold: {HIGH_ENTROPY_THRESHOLD}). "
                                "High entropy strongly indicates packed, encrypted, or compressed code sections. "
                                "This is a common technique to hide malicious functionality, "
                                "bypass static analysis, and conceal reverse engineering indicators."
                            ),
                            technical_detail=(
                                f"File: {lib_path}\n"
                                f"Size: {len(lib_data):,} bytes\n"
                                f"Shannon entropy: {entropy:.4f} bits/byte\n"
                                f"Threshold: {HIGH_ENTROPY_THRESHOLD} (normal ELF: ~6.0)"
                            ),
                            cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                            evidence=[f"{lib_name}: entropy={entropy:.2f} bits/byte"],
                            affected_components=[lib_path],
                            remediation=(
                                "Investigate with Ghidra (headless mode): "
                                f"analyzeHeadless /tmp/project GhidraProject -import {lib_name} -postScript PrintStrings.java. "
                                "Check for runtime unpacking via Frida native hooks on mmap/mprotect."
                            ),
                            tags=["native-lib", "entropy", "packing", "obfuscation"],
                            _rank=Rank.D,
                        ))
        except Exception:
            pass

    # ── Frida detection ───────────────────────────────────────────────────────

    def _check_frida_detection(self, ctx: AnalysisContext):
        FRIDA_STRINGS = ["frida", "FRIDA", "gadget", "re.frida", "lief", "__frida"]
        string_pool = " ".join(ctx.strings_pool)
        found = [s for s in FRIDA_STRINGS if s in string_pool]

        if not found:
            self._add(Finding(
                id="BINARY-NOFRIDA",
                title="No Frida/Instrumentation Framework Detection",
                category="Runtime Defense",
                description=(
                    "The application does not detect Frida or similar dynamic instrumentation frameworks. "
                    "Frida is the primary tool used by security researchers to hook methods, "
                    "bypass SSL pinning, dump memory, and trace execution at runtime. "
                    "Without detection, an attacker can instrument the app invisibly."
                ),
                technical_detail="No Frida detection strings in DEX pool.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["No Frida/gadget detection strings found"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Detect Frida by scanning /proc/self/maps for frida-agent. "
                    "Check for suspicious ports (27042 default Frida port). "
                    "Scan loaded libraries for frida/gadget patterns. "
                    "Use native code for detection."
                ),
                pocs=[PoC(
                    type="frida_script",
                    title="Frida Agent Injection Baseline",
                    description="Verify Frida injection works undetected on this target",
                    code=self._generate_frida_baseline(ctx),
                )],
                tags=["frida-detection", "missing-control", "dynamic-analysis"],
                _rank=Rank.C,
            ))

    # ── SSL Pinning implementation quality ───────────────────────────────────

    def _check_ssl_pinning_implementation(self, ctx: AnalysisContext):
        PINNING_CLASSES = [
            "CertificatePinner", "TrustManager", "X509TrustManager",
            "checkServerTrusted", "OkHttpClient", "TrustKit",
            "PublicKeyPin",
        ]
        string_pool = " ".join(ctx.strings_pool)
        found = [c for c in PINNING_CLASSES if c in string_pool]

        if not found:
            self._add(Finding(
                id="BINARY-NOPIN",
                title="No Certificate Pinning Implementation Detected",
                category="Network Security",
                description=(
                    "No certificate pinning implementation was found. "
                    "Without pinning, any trusted CA certificate (including those installed "
                    "by enterprise MDM, government, or a compromised CA) can perform "
                    "a Man-in-the-Middle attack on the app's TLS traffic."
                ),
                technical_detail=(
                    "No CertificatePinner, TrustKit, or custom X509TrustManager found. "
                    "OkHttp, Retrofit, or Volley are not configured with certificate pinning."
                ),
                cvss=CVSSVector(AV="A", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["No certificate pinning classes in DEX pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Implement OkHttp CertificatePinner: "
                    "new CertificatePinner.Builder().add(\"hostname\", \"sha256/hash\").build(). "
                    "Or use network_security_config.xml <pin-set>. "
                    "Always include a backup pin and set a reasonable expiration."
                ),
                tags=["certificate-pinning", "tls", "mitm", "missing-control"],
            ))

    # ── ProGuard effectiveness ────────────────────────────────────────────────

    def _check_proguard_effectiveness(self, ctx: AnalysisContext):
        """Check if ProGuard mapping file left sensitive class names visible."""
        sensitive_class_patterns = [
            r'[Pp]assword', r'[Cc]redential', r'[Aa]uth[Tt]oken',
            r'[Pp]rivate[Kk]ey', r'[Ss]ecret', r'[Ee]ncrypt',
            r'[Pp]ayment', r'[Cc]heckout', r'[Bb]illing',
        ]
        try:
            sensitive_classes = []
            for cls in ctx.app_classes:
                cls_str = str(cls.name)
                for pat in sensitive_class_patterns:
                    if re.search(pat, cls_str):
                        sensitive_classes.append(cls_str.replace("/", ".").strip("L;"))
                        break

            if sensitive_classes:
                self._add(Finding(
                    id="BINARY-CLASSNAMES",
                    title="Sensitive Class Names Readable Post-Compilation",
                    category="Binary Hardening",
                    description=(
                        "Sensitive class names containing security-relevant keywords "
                        "are still readable in the compiled bytecode. "
                        "This gives attackers a roadmap to the most interesting code paths "
                        "without needing to reverse the entire binary."
                    ),
                    technical_detail=f"Sensitive classes: {sensitive_classes[:10]}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    evidence=[f"Class: {c}" for c in sensitive_classes[:5]],
                    affected_components=sensitive_classes[:5],
                    remediation=(
                        "Enable full ProGuard/R8 obfuscation including class renaming. "
                        "Add -repackageclasses '' to your proguard-rules.pro."
                    ),
                    tags=["class-names", "obfuscation", "reverse-engineering"],
                    _rank=Rank.D,
                ))
        except Exception:
            pass

    # ── Frida script generators ───────────────────────────────────────────────

    def _generate_root_bypass_frida(self, ctx: AnalysisContext) -> str:
        return f"""\
// Appraisal: DEX — Root Detection Universal Bypass
// Inject with: frida -U -f {ctx.package_name} -l root_bypass.js --no-pause

Java.perform(function() {{
  console.log("[*] Appraisal: DEX - Root Bypass Active");

  // Hook RootBeer
  try {{
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {{
      console.log("[+] RootBeer.isRooted() -> false");
      return false;
    }};
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {{ return false; }};
  }} catch(e) {{ console.log("[-] RootBeer not found"); }}

  // Hook File existence checks for su
  var File = Java.use('java.io.File');
  File.exists.implementation = function() {{
    var path = this.getAbsolutePath();
    var suPaths = ['/system/bin/su','/system/xbin/su','/sbin/su',
                   '/system/su','/system/bin/.ext/.su'];
    for(var i = 0; i < suPaths.length; i++) {{
      if(path.indexOf(suPaths[i]) !== -1) {{
        console.log("[+] Spoofing File.exists() for: " + path);
        return false;
      }}
    }}
    return this.exists();
  }};

  // Hook Runtime.exec() for 'su' checks
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function(cmd) {{
    if(cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {{
      console.log("[+] Blocking exec: " + cmd);
      throw Java.use('java.io.IOException').$new("File not found");
    }}
    return this.exec(cmd);
  }};

  // Hook PackageManager for Magisk/SuperSU package checks
  var PackageManager = Java.use('android.app.ApplicationPackageManager');
  PackageManager.getPackageInfo.overload(
    'java.lang.String','int'
  ).implementation = function(pkg, flags) {{
    var badApps = ['com.topjohnwu.magisk','com.noshufou.android.su',
                   'eu.chainfire.supersu','com.koushikdutta.superuser'];
    for(var i = 0; i < badApps.length; i++) {{
      if(pkg === badApps[i]) {{
        console.log("[+] Blocking package check: " + pkg);
        throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new();
      }}
    }}
    return this.getPackageInfo(pkg, flags);
  }};

  // Hook Build.TAGS check
  var Build = Java.use('android.os.Build');
  Object.defineProperty(Build, 'TAGS', {{
    get: function() {{ return "release-keys"; }}
  }});

  console.log("[*] Root bypass hooks installed successfully");
}});
"""

    def _generate_antitamper_frida(self, ctx: AnalysisContext) -> str:
        return f"""\
// Appraisal: DEX — Anti-Tamper / Signature Check Bypass
// Usage: frida -U -f {ctx.package_name} -l antitamper.js --no-pause

Java.perform(function() {{
  console.log("[*] Anti-tamper bypass starting...");

  // Step 1: Get the real signature to spoof
  var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var pm = ctx.getPackageManager();

  try {{
    var PackageInfo = pm.getPackageInfo(ctx.getPackageName(),
      Java.use('android.content.pm.PackageManager').GET_SIGNATURES.value);
    var realSig = PackageInfo.signatures.value[0].toCharsString();
    console.log("[*] Real signature captured: " + realSig.substring(0, 20) + "...");

    // Step 2: Hook getPackageInfo to always return real signature
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload(
      'java.lang.String', 'int'
    ).implementation = function(pkg, flags) {{
      var result = this.getPackageInfo(pkg, flags);
      if(pkg === '{ctx.package_name}' && flags & 64) {{  // 64 = GET_SIGNATURES
        console.log("[+] Spoofing signature for: " + pkg);
        // signatures.value is already the real one, no spoof needed
        // If running patched APK, override here with the original signature bytes
      }}
      return result;
    }};

    // Step 3: Hook MessageDigest to intercept APK hash checks
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(input) {{
      var result = this.digest(input);
      console.log("[*] MessageDigest.digest() called, algorithm: " + this.getAlgorithm());
      return result;  // Return real hash — spoof if needed
    }};

    console.log("[*] Anti-tamper hooks installed");
  }} catch(e) {{
    console.log("[-] Error: " + e);
  }}
}});
"""

    def _generate_frida_baseline(self, ctx: AnalysisContext) -> str:
        return f"""\
// Appraisal: DEX — Frida Baseline Injection Agent
// Verifies Frida works and dumps initial app state
// Usage: frida -U -f {ctx.package_name} -l baseline.js --no-pause

Java.perform(function() {{
  console.log("\\n╔══════════════════════════════════════╗");
  console.log("║  Appraisal: DEX — Frida Baseline     ║");
  console.log("║  Target: {ctx.package_name[:30]:<30} ║");
  console.log("╚══════════════════════════════════════╝\\n");

  // Dump SharedPreferences
  try {{
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferencesImpl.getString.implementation = function(key, defVal) {{
      var result = this.getString(key, defVal);
      if(result && result.length > 0) {{
        console.log("[PREF] " + key + " = " + result);
      }}
      return result;
    }};
    console.log("[*] SharedPreferences hook active");
  }} catch(e) {{}}

  // Hook crypto operations
  try {{
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {{
      console.log("[CRYPTO] Cipher.doFinal(" + Java.use('android.util.Base64').encodeToString(
        input, 0) + ")");
      return this.doFinal(input);
    }};
    console.log("[*] Cipher hook active");
  }} catch(e) {{}}

  // Hook network calls
  try {{
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {{
      console.log("[NET] URL.openConnection: " + this.toString());
      return this.openConnection();
    }};
    console.log("[*] URL hook active");
  }} catch(e) {{}}

  // Dump current Activity
  try {{
    var ActivityThread = Java.use('android.app.ActivityThread');
    var currentApp = ActivityThread.currentApplication();
    console.log("[*] Package: " + currentApp.getPackageName());
    console.log("[*] Data dir: " + currentApp.getApplicationInfo().dataDir.value);
  }} catch(e) {{}}

  console.log("\\n[*] Baseline agent installed. All hooks active.\\n");
}});
"""
