# OWASP Mobile Top 10 Coverage Matrix

**Appraisal: DEX v1.1.0** — Complete detection coverage for the OWASP Mobile Top 10 (2024 edition).

---

## Coverage Overview

| # | OWASP Category | Module | Skill Type | Rank Range | PoC |
|---|---|---|---|---|---|
| M1 | Improper Credential Usage | Credential Sight | `[PASSIVE]` | D → SSS | ✓ |
| M2 | Inadequate Supply Chain Security | Supply Chain Sentinel | `[HIDDEN]` | D → S | ✓ |
| M3 | Insecure Authentication/Authorization | Auth Breach | `[ACTIVE]` | C → SS | ✓ |
| M4 | Insufficient Input/Output Validation | Input Sentinel | `[ACTIVE]` | C → S | ✓ |
| M5 | Insecure Communication | Network & Privacy Sentinel | `[ACTIVE]` | C → S | ✓ |
| M6 | Inadequate Privacy Controls | Network & Privacy Sentinel | `[ACTIVE]` | C → A | ✓ |
| M7 | Insufficient Binary Protections | Binary Hardening + Network & Privacy | `[UNIQUE]` | C → A | ✓ |
| M8 | Security Misconfiguration | Config & Storage Auditor | `[ACTIVE]` | D → S | ✓ |
| M9 | Insecure Data Storage | Config & Storage Auditor | `[ACTIVE]` | C → S | ✓ |
| M10 | Insufficient Cryptography | Cipher Sight + Config & Storage | `[UNIQUE]` | C → S | ✓ |

---

## M1 — Improper Credential Usage

**Module:** `Credential Sight` — `appraisal/modules/credential_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M1-CRED-*` | Hardcoded passwords, tokens, API keys, OAuth secrets, connection strings in DEX string pool | S |
| `M1-SENSITIVE-ASSETS` | Config/properties files (`.env`, `credentials.properties`, `secrets.xml`) packaged in APK | A |
| `M1-AUTH-*` | Hardcoded Basic Auth / Digest Auth headers | S |
| `M1-PREFS-CRED` | Credential field names + SharedPreferences.putString() without encryption | B |
| `M1-LOG-CRED` | Credential strings + Log.*() calls co-present — plaintext credential logging | C |
| `M1-ACCOUNTMGR` | AccountManager.getPassword() / peekAuthToken() — extracts plaintext credentials | B |

**Also covered by:** `Cipher Sight` (M1-CRYPTO-SECRET-*) for AWS keys, JWTs, Firebase keys, Stripe tokens.

---

## M2 — Inadequate Supply Chain Security

**Module:** `Supply Chain Sentinel` — `appraisal/modules/supply_chain_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M2-UNSIGNED` | No signature files in META-INF — unsigned APK | A |
| `M2-DEBUG-CERT` | Debug/test certificate (`androiddebugkey`) in production APK | A |
| `M2-DEBUG-ARTIFACTS` | `mapping.txt`, `proguard_map.txt`, build data in APK | C |
| `M2-BUILD-META` | Internal dev paths (`/home/user/`, `/var/jenkins/`) in binary | D |
| `M2-REPACKAGE-INDICATOR` | DEX in assets/, JARs in APK, embedded APKs — repackaging/injection | A |
| `M2-DEP-CONFUSION` | Internal package namespace patterns susceptible to dependency confusion | C |
| `M2-V1-SIGN-ONLY` | JAR signing only, no v2/v3 APK Signing Block — Janus (CVE-2017-13156) | A |
| `M2-TEST-IN-RELEASE` | JUnit/Mockito/Espresso test classes in release APK | D |

**Also covered by:** `Supply Chain Scanner` (SDK fingerprinting + CVE mapping), `Binary Hardening Auditor` (ProGuard/obfuscation check).

---

## M3 — Insecure Authentication / Authorization

**Module:** `Auth Breach` — `appraisal/modules/auth_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M3-CLIENT-AUTH` | Auth flags (isAdmin, isPremium, userRole) read from SharedPreferences/Intent | S |
| `M3-BIOMETRIC-NOCRYPTO` | BiometricPrompt without CryptoObject binding — Frida bypass PoC included | S |
| `M3-JWT-NONE` | JWT `alg=none` pattern — signature verification disabled | S |
| `M3-JWT-SECRET` | Hardcoded JWT signing secret in binary | S |
| `M3-SESSION-STORAGE` | Session tokens in unencrypted SharedPreferences | B |
| `M3-INTENT-AUTH-BYPASS` | skipAuth / bypassLogin flags + exported activities | S |
| `M3-WEBVIEW-AUTH` | Auth tokens accessible via WebView CookieManager + JS | A |

---

## M4 — Insufficient Input / Output Validation

**Module:** `Input Sentinel` — `appraisal/modules/input_validation_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M4-DESER-*` | Unsafe deserialization: ObjectInputStream, XMLDecoder, FastJSON, Jackson | S–A |
| `M4-XXE` | XML parser without external entity disable — XXE / SSRF / DoS | A |
| `M4-PATH-TRAVERSAL` | File I/O + user input without getCanonicalPath() | S |
| `M4-SQLI-RAW` | rawQuery/execSQL without parameterized binding | S |
| `M4-CMD-INJECTION` | Runtime.exec/ProcessBuilder + user input — command injection / RCE | S |
| `M4-OUTPUT-ENCODING` | WebView.loadData without TextUtils.htmlEncode — stored XSS | S |
| `M4-INTENT-REDIRECT` | Nested Intent dispatch from Parcelable extra — component bypass | S |
| `M4-ZIP-SLIP` | ZipInputStream without canonicalization — Zip Slip path traversal | S |

**Also covered by:** `Taint Walk` (static source→sink flow for all injection patterns), `Binder Breach` (Parcelable mismatch).

---

## M5 — Insecure Communication

**Module:** `Network & Privacy Sentinel` — `appraisal/modules/network_privacy_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M5-TLS-*` | Weak TLS: SSLv3, TLSv1.0, TLSv1.1, RSA key exchange | A |
| `M5-HOSTNAME-*` | AllowAllHostnameVerifier / NullHostnameVerifier / return true bypass | S |
| `M5-TRUST-ALL-CERTS` | Custom X509TrustManager — certificate validation bypass + Frida bypass PoC | S |
| `M5-PLAINTEXT-URLS` | Hardcoded http:// endpoint URLs in DEX string pool | B |

**Also covered by:** `Manifest Sight` (cleartext traffic, NSC user cert trust, empty pin-sets), `Binary Hardening Auditor` (missing cert pinning).

---

## M6 — Inadequate Privacy Controls

**Module:** `Network & Privacy Sentinel` — `appraisal/modules/network_privacy_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M6-PII-LOGS` | PII field names (email, phone, SSN, DOB) + Log.*() calls | A |
| `M6-PII-ANALYTICS` | Analytics SDKs (Mixpanel, Amplitude, Segment) + PII fields | A |
| `M6-EXTERNAL-STORAGE` | External storage access — readable by all apps pre-Android 10 | B |
| `M6-CLIPBOARD` | ClipboardManager.setPrimaryClip() — clipboard sniffing risk | C |
| `M6-NO-FLAG-SECURE` | Missing FLAG_SECURE — screenshots and screen recording allowed | C |

---

## M7 — Insufficient Binary Protections

**Primary Module:** `Binary Hardening Auditor` — `appraisal/modules/binary_module.py`
**Supplement:** `Network & Privacy Sentinel` (native lib checks)

| Finding ID | Detection | Rank |
|---|---|---|
| `BINARY-NOOBF` | No ProGuard/R8 obfuscation — class names fully readable | D |
| `BINARY-NOROOT` | No root detection — rooted device attacks undetected | B |
| `BINARY-ROOTDETECT` | Root detection present — Frida bypass script generated | D |
| `BINARY-NOEMU` | No emulator detection | D |
| `BINARY-ANTITAMPER` | Signature check present — anti-tamper bypass Frida script | D |
| `BINARY-ENTROPY-*` | High-entropy native library — packed/encrypted code sections | D |
| `BINARY-NOFRIDA` | No Frida/instrumentation detection | C |
| `BINARY-NOPIN` | No certificate pinning — MitM trivially possible | A |
| `BINARY-CLASSNAMES` | Sensitive class names readable post-compilation | D |
| `M7-NO-STACK-CANARY` | Native libraries missing `__stack_chk_fail` — stack BOF exploitable | C |
| `M7-NO-PIE` | Non-PIE native libraries (ET_EXEC) — ASLR defeated | C |

---

## M8 — Security Misconfiguration

**Module:** `Config & Storage Auditor` — `appraisal/modules/misconfig_storage_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M8-STRICTMODE` | StrictMode with penaltyLog in release build | D |
| `M8-WEBVIEW-*` | Dangerous WebView settings: geolocation, password save, DOM storage | D |
| `M8-DANGEROUS-BCAST-*` | Dangerous broadcast receivers (PACKAGE_ADDED, NEW_OUTGOING_CALL) | D |
| `M8-FIREBASE-RULES` | Firebase Realtime Database detected — open rules audit PoC | S |

**Also covered by:** `Manifest Sight` (debuggable, backup, cleartext, NSC misconfig, task reparenting), `Component Exposure Scanner` (all exported components).

---

## M9 — Insecure Data Storage

**Module:** `Config & Storage Auditor` — `appraisal/modules/misconfig_storage_module.py`

| Finding ID | Detection | Rank |
|---|---|---|
| `M9-WORLD-READABLE` | MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE file permissions | A |
| `M9-SQLITE-UNENCRYPTED` | Unencrypted SQLite with sensitive table names (users, tokens, payments) | B |
| `M9-REALM-UNENCRYPTED` | Realm database without encryptionKey() | B |
| `M9-CACHE-SENSITIVE` | getCacheDir() + credential strings — sensitive data in clearable cache | C |
| `M9-FILE-MODE` | openFileOutput() without explicit MODE_PRIVATE | D |

**Also covered by:** `Credential Sight` (M1-PREFS-CRED), `Manifest Sight` (allowBackup + ADB backup PoC).

---

## M10 — Insufficient Cryptography

**Primary Module:** `Cipher Sight` — `appraisal/modules/crypto_module.py`
**Supplement:** `Config & Storage Auditor`

| Finding ID | Detection | Rank |
|---|---|---|
| `CRYPTO-SECRET-*` | All hardcoded secrets: AWS, Google, Firebase, JWT, Stripe, GitHub | S |
| `CRYPTO-ALGO-*` | Weak algorithms: DES, RC2, RC4, MD5, SHA-1, Blowfish/ECB | A |
| `CRYPTO-ECB` | AES in ECB mode or bare `AES` (defaults to ECB) | A |
| `CRYPTO-WEAKRNG` | java.util.Random / Math.random() for security operations | A |
| `CRYPTO-HARDKEY-*` | Hardcoded SecretKeySpec, IvParameterSpec, PBE salt | A |
| `CRYPTO-KDF-ITER` | PBKDF2 iteration count < 10,000 | A |
| `CRYPTO-KDF-REVIEW` | PBKDF2 detected — iteration count needs manual review | D |
| `M10-CUSTOM-CRYPTO` | XOR / ROT13 / Caesar cipher used as encryption | A |
| `M10-PREDICTABLE-SEED` | System.currentTimeMillis() as RNG seed | A |
| `M10-SSL-ERROR-PROCEED` | WebView onReceivedSslError calls handler.proceed() — TLS errors suppressed | S |

---

## Vulnerability Chain Detection

Chains are cross-module findings that combine for exponentially greater impact:

| Chain | Modules Involved | Escalated Rank | Description |
|---|---|---|---|
| ⚡ Chain 1 | MANIFEST-001 + COMP-ACT-* | → SS | Debuggable + exported activity = full data exfiltration without root |
| ⚡ Chain 2 | BINARY-NOPIN + TAINT-* | → SS | No cert pinning + taint flow = confirmed MitM + data theft |
| ⚡ Chain 3 | DEEPLINK-CUSTOM-* + TAINT-WEBVIEW-JS | → SS | Custom scheme + JS WebView = one-click XSS |
| ⚡ Chain 4 | COMP-PRV-* + MANIFEST-002 | → SS | Exported provider + backup = two paths to full DB dump |
| ⚡ Chain 5 | M3-CLIENT-AUTH + COMP-ACT-* | → SS | Client-side auth flags + exported activity = trivial privilege escalation |
| ⚡ Chain 6 | M1-CRED-* + M8-FIREBASE-RULES | → SS | Hardcoded Firebase key + open rules = unauthenticated full DB access |

---

## Finding Statistics

A typical Android app will trigger **20–80 findings** across all 14 modules.
A poorly secured app can trigger **100+**, including multiple chains.

### By OWASP Category (approximate findings per module)

| Module | Typical Findings |
|---|---|
| Manifest Sight | 3–10 |
| Component Exposure Scanner | 2–20 |
| Deep Link Interceptor | 1–8 |
| Taint Walk | 5–30 |
| Cipher Sight | 3–15 |
| Binary Hardening Auditor | 4–10 |
| Supply Chain Scanner | 3–12 |
| Binder Breach | 2–8 |
| Credential Sight (M1) | 2–10 |
| Supply Chain Sentinel (M2) | 2–6 |
| Auth Breach (M3) | 2–7 |
| Input Sentinel (M4) | 3–8 |
| Network & Privacy Sentinel (M5/M6/M7) | 4–12 |
| Config & Storage Auditor (M8/M9/M10) | 4–12 |

---

*Coverage based on OWASP Mobile Application Security Testing Guide (MASTG) and OWASP Mobile Top 10 2024.*
*All findings include CVSS v3.1 vectors, remediation guidance, and PoC artifacts.*
