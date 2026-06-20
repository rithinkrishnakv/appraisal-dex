/**
 * Appraisal: DEX — Frida Script Collection
 * Dynamic companion to static findings.
 * 
 * Usage: frida -U -f <package> -l <script>.js --no-pause
 * 
 * Scripts:
 *   1. Universal SSL Bypass
 *   2. Root Detection Bypass
 *   3. Biometric Auth Bypass
 *   4. Anti-Tamper / Signature Check Bypass
 *   5. SharedPreferences Monitor
 *   6. Crypto Operation Tracer
 *   7. Network Traffic Logger
 *   8. Intent Inspector
 *   9. File I/O Monitor
 *  10. Heap Memory Secret Extractor
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG — set your target package and which hooks to enable
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = {
    TARGET_PACKAGE:   "REPLACE_WITH_PACKAGE",  // e.g. "com.example.app"
    ENABLE_SSL:       true,
    ENABLE_ROOT:      true,
    ENABLE_BIO:       true,
    ENABLE_TAMPER:    true,
    ENABLE_PREFS:     true,
    ENABLE_CRYPTO:    true,
    ENABLE_NETWORK:   false,   // noisy — enable when needed
    ENABLE_INTENT:    true,
    ENABLE_FILEIO:    false,   // very noisy
    ENABLE_HEAP:      false,   // expensive — use for secret hunting only
};

// ─────────────────────────────────────────────────────────────────────────────
// BANNER
// ─────────────────────────────────────────────────────────────────────────────
Java.perform(function () {
    console.log("\n╔══════════════════════════════════════════════╗");
    console.log("║  ⚔  Appraisal: DEX — Dynamic Agent          ║");
    console.log("║  Target: " + CONFIG.TARGET_PACKAGE.padEnd(36) + "║");
    console.log("╚══════════════════════════════════════════════╝\n");

    // ─────────────────────────────────────────────────────────────────────────
    // 1. UNIVERSAL SSL / CERTIFICATE PINNING BYPASS
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_SSL) {
        try {
            // OkHttp3 CertificatePinner
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function (host, peerCerts) {
                console.log("[SSL] OkHttp3 pin bypass for: " + host);
            };
            console.log("[+] OkHttp3 CertificatePinner hooked");
        } catch (e) {}

        try {
            // TrustKit
            var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
            TrustKit.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function () {
                console.log("[SSL] TrustKit bypass");
                return true;
            };
        } catch (e) {}

        try {
            // Register a trust-everything TrustManager
            var TrustManager = Java.registerClass({
                name: "com.appraisal.dex.BypassTM",
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {
                        console.log("[SSL] checkServerTrusted bypassed");
                    },
                    getAcceptedIssuers: function () { return []; }
                }
            });

            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var ctx = SSLContext.getInstance("TLS");
            ctx.init(null, [TrustManager.$new()], null);
            SSLContext.getDefault.implementation = function () { return ctx; };
            console.log("[+] Universal TrustManager bypass active");
        } catch (e) { console.log("[-] TrustManager bypass failed: " + e); }

        try {
            // Hostname verifier
            var HostnameVerifier = Java.registerClass({
                name: "com.appraisal.dex.BypassHV",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function (hostname, session) {
                        console.log("[SSL] Hostname verify bypassed for: " + hostname);
                        return true;
                    }
                }
            });
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier.$new());
            console.log("[+] HostnameVerifier bypass active");
        } catch (e) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. ROOT DETECTION BYPASS
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_ROOT) {
        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                var rootPaths = ["/system/bin/su", "/system/xbin/su", "/sbin/su",
                    "/system/su", "/system/bin/.ext/.su", "/system/usr/we-need-root",
                    "/system/app/Superuser.apk", "/data/local/xbin/su"];
                for (var i = 0; i < rootPaths.length; i++) {
                    if (path.indexOf(rootPaths[i]) !== -1) {
                        console.log("[ROOT] Blocked File.exists() for: " + path);
                        return false;
                    }
                }
                return this.exists();
            };

            // Block su execution
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
                    console.log("[ROOT] Blocked exec: " + cmd);
                    throw Java.use("java.io.IOException").$new("No such file");
                }
                return this.exec(cmd);
            };

            // Spoof Build.TAGS
            var Build = Java.use("android.os.Build");
            Build.TAGS.value = "release-keys";

            // Block Magisk/SuperSU package checks
            var PM = Java.use("android.app.ApplicationPackageManager");
            PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
                var blocked = ["com.topjohnwu.magisk", "eu.chainfire.supersu",
                    "com.noshufou.android.su", "com.koushikdutta.superuser"];
                for (var i = 0; i < blocked.length; i++) {
                    if (pkg === blocked[i]) {
                        console.log("[ROOT] Blocked package check: " + pkg);
                        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                    }
                }
                return this.getPackageInfo(pkg, flags);
            };

            console.log("[+] Root detection bypass active");
        } catch (e) { console.log("[-] Root bypass error: " + e); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. BIOMETRIC AUTHENTICATION BYPASS
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_BIO) {
        try {
            var BioCB = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationCallback");
            BioCB.onAuthenticationSucceeded.implementation = function (result) {
                console.log("[BIO] BiometricPrompt bypass triggered");
                this.onAuthenticationSucceeded(result);
            };
        } catch (e) {}

        try {
            var BioCBX = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
            BioCBX.onAuthenticationSucceeded.implementation = function (result) {
                console.log("[BIO] AndroidX BiometricPrompt bypass triggered");
                this.onAuthenticationSucceeded(result);
            };
        } catch (e) {}

        try {
            var FPCB = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback");
            FPCB.onAuthenticationSucceeded.implementation = function (result) {
                console.log("[BIO] FingerprintManager bypass triggered");
                this.onAuthenticationSucceeded(result);
            };
        } catch (e) {}

        console.log("[+] Biometric bypass hooks installed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. ANTI-TAMPER / SIGNATURE CHECK BYPASS
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_TAMPER) {
        try {
            var PM2 = Java.use("android.app.ApplicationPackageManager");
            var realSig = null;

            // Capture real signature on first call, then always return it
            PM2.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
                var result = this.getPackageInfo(pkg, flags);
                if (pkg === CONFIG.TARGET_PACKAGE && flags & 64) {
                    if (!realSig && result.signatures && result.signatures.value) {
                        realSig = result.signatures.value;
                        console.log("[TAMPER] Real signature captured");
                    } else if (realSig) {
                        result.signatures.value = realSig;
                        console.log("[TAMPER] Signature spoofed");
                    }
                }
                return result;
            };

            console.log("[+] Anti-tamper bypass active");
        } catch (e) { console.log("[-] Anti-tamper bypass failed: " + e); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. SHAREDPREFERENCES MONITOR
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_PREFS) {
        try {
            var SPImpl = Java.use("android.app.SharedPreferencesImpl");

            SPImpl.getString.implementation = function (key, defVal) {
                var result = this.getString(key, defVal);
                if (result && result.length > 0) {
                    console.log("[PREFS] GET " + key + " = " + result);
                }
                return result;
            };

            SPImpl.getBoolean.implementation = function (key, defVal) {
                var result = this.getBoolean(key, defVal);
                console.log("[PREFS] GET_BOOL " + key + " = " + result);
                return result;
            };

            var SPEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
            SPEditor.putString.implementation = function (key, value) {
                console.log("[PREFS] PUT " + key + " = " + value);
                return this.putString(key, value);
            };

            console.log("[+] SharedPreferences monitor active");
        } catch (e) { console.log("[-] SharedPreferences hook failed: " + e); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. CRYPTO OPERATION TRACER
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_CRYPTO) {
        try {
            var Cipher = Java.use("javax.crypto.Cipher");
            var B64 = Java.use("android.util.Base64");

            Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
                var modeStr = mode === 1 ? "ENCRYPT" : mode === 2 ? "DECRYPT" : mode.toString();
                try {
                    var keyBytes = key.getEncoded();
                    console.log("[CRYPTO] Cipher.init " + modeStr + " | algorithm=" +
                        this.getAlgorithm() + " | key=" + B64.encodeToString(keyBytes, 0));
                } catch (ex) {
                    console.log("[CRYPTO] Cipher.init " + modeStr + " | algorithm=" + this.getAlgorithm());
                }
                return this.init(mode, key);
            };

            Cipher.doFinal.overload("[B").implementation = function (input) {
                var result = this.doFinal(input);
                console.log("[CRYPTO] doFinal IN  = " + B64.encodeToString(input, 0));
                console.log("[CRYPTO] doFinal OUT = " + B64.encodeToString(result, 0));
                return result;
            };

            // MessageDigest
            var MD = Java.use("java.security.MessageDigest");
            MD.digest.overload("[B").implementation = function (input) {
                var result = this.digest(input);
                console.log("[CRYPTO] MessageDigest." + this.getAlgorithm() +
                    " IN=" + B64.encodeToString(input, 0) +
                    " OUT=" + B64.encodeToString(result, 0));
                return result;
            };

            console.log("[+] Crypto tracer active");
        } catch (e) { console.log("[-] Crypto hook failed: " + e); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. NETWORK TRAFFIC LOGGER
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_NETWORK) {
        try {
            var URL = Java.use("java.net.URL");
            URL.openConnection.overload().implementation = function () {
                console.log("[NET] URL.openConnection: " + this.toString());
                return this.openConnection();
            };

            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Request = Java.use("okhttp3.Request");
            console.log("[+] Network logger active (partial — use proxy for full capture)");
        } catch (e) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. INTENT INSPECTOR
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_INTENT) {
        try {
            var Activity = Java.use("android.app.Activity");

            Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
                console.log("[INTENT] startActivity: " + intent.toString());
                var extras = intent.getExtras();
                if (extras) {
                    var keys = extras.keySet().toArray();
                    for (var i = 0; i < keys.length; i++) {
                        console.log("[INTENT]   extra: " + keys[i] + " = " + extras.get(keys[i]));
                    }
                }
                return this.startActivity(intent);
            };

            var Context = Java.use("android.content.ContextWrapper");
            Context.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
                console.log("[INTENT] sendBroadcast: " + intent.getAction());
                return this.sendBroadcast(intent);
            };

            console.log("[+] Intent inspector active");
        } catch (e) { console.log("[-] Intent hook failed: " + e); }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 9. FILE I/O MONITOR
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_FILEIO) {
        try {
            var FOS = Java.use("java.io.FileOutputStream");
            FOS.$init.overload("java.lang.String").implementation = function (path) {
                console.log("[FILE] FileOutputStream: " + path);
                return this.$init(path);
            };

            var FIS = Java.use("java.io.FileInputStream");
            FIS.$init.overload("java.lang.String").implementation = function (path) {
                console.log("[FILE] FileInputStream: " + path);
                return this.$init(path);
            };

            console.log("[+] File I/O monitor active");
        } catch (e) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 10. HEAP MEMORY SECRET EXTRACTOR
    // Dumps all String objects from heap — finds decrypted secrets at runtime
    // ─────────────────────────────────────────────────────────────────────────
    if (CONFIG.ENABLE_HEAP) {
        console.log("[HEAP] Starting heap scan — this may take a moment...");
        setTimeout(function () {
            var secrets = [];
            Java.choose("java.lang.String", {
                onMatch: function (str) {
                    try {
                        var s = str.toString();
                        // High-entropy or credential-like strings
                        if (s.length > 20 && s.length < 500) {
                            var hasUpper = /[A-Z]/.test(s);
                            var hasLower = /[a-z]/.test(s);
                            var hasDigit = /[0-9]/.test(s);
                            var hasSpecial = /[+/=_\-]/.test(s);
                            if (hasUpper && hasLower && hasDigit) {
                                secrets.push(s);
                            }
                        }
                    } catch (e) {}
                },
                onComplete: function () {
                    console.log("\n[HEAP] Scan complete. Potential secrets (" + secrets.length + "):");
                    secrets.slice(0, 50).forEach(function (s, i) {
                        console.log("[HEAP] [" + i + "] " + s);
                    });
                }
            });
        }, 5000);  // Wait 5s for app to initialize and decrypt
    }

    console.log("\n[*] Appraisal: DEX agent fully loaded. All configured hooks active.\n");
});
