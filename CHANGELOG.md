# Changelog

All notable changes to Appraisal: DEX are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.2.0] — Unreleased

### Planned
- Dynamic Frida orchestration mode (`--dynamic` flag)
- In-memory DEX dump from running processes
- DexClassLoader runtime interception
- AIDL auto-stub generator (runnable Java test harness)
- Sarif report format for GitHub Code Scanning integration

---

## [1.1.0] — 2025

### Added — Full OWASP Mobile Top 10 Coverage

**M1 — Improper Credential Usage** (`credential_module.py`)
- Hardcoded passwords, tokens, API keys, OAuth secrets, connection strings
- Sensitive config/properties files packaged in APK assets
- Basic/Digest Auth headers hardcoded in binary
- Credential field names in SharedPreferences without encryption
- Credential logging detection (Log.*() + credential strings)
- AccountManager.getPassword() / peekAuthToken() usage

**M2 — Inadequate Supply Chain Security** (`supply_chain_module.py`)
- APK signing validation (unsigned, debug cert detection)
- v1-only JAR signing without v2/v3 APK Signing Block (Janus — CVE-2017-13156)
- Debug artifacts in release APK (mapping.txt, proguard_map.txt, build data)
- Internal build path leakage (/home/user/, /var/jenkins/, etc.)
- Repackaging/injection indicators (DEX in assets, embedded APKs)
- Dependency confusion attack surface detection
- Test/debug classes in release builds (JUnit, Mockito, Espresso)

**M3 — Insecure Authentication/Authorization** (`auth_module.py`)
- Client-side auth flag detection (isAdmin, isPremium, userRole via Intent/SharedPrefs)
- Biometric authentication without CryptoObject — Frida bypass PoC included
- JWT `alg=none` pattern detection
- Hardcoded JWT signing secret in binary
- Session tokens in unencrypted SharedPreferences
- Intent-based authentication bypass flags
- Auth tokens accessible via WebView CookieManager

**M4 — Insufficient Input/Output Validation** (`input_validation_module.py`)
- Unsafe Java deserialization: ObjectInputStream, XMLDecoder, FastJSON, Jackson
- XXE without external entity disable features
- Path traversal without getCanonicalPath() — file I/O + user input
- Raw SQL without parameterized binding
- Command injection: Runtime.exec/ProcessBuilder + user input
- Output encoding failure in WebView.loadData()
- Intent redirection via nested Parcelable Intent
- Zip Slip — ZipInputStream without path canonicalization

**M5/M6/M7 — Network, Privacy, Binary Protections** (`network_privacy_module.py`)
- Weak TLS protocols: SSLv3, TLSv1.0, TLSv1.1, RSA key exchange
- Hostname verification bypass: AllowAllHostnameVerifier, NullHostnameVerifier
- Custom TrustManager (trust-all) + universal Frida SSL bypass script
- Hardcoded HTTP endpoints in DEX string pool
- PII in logs (email, phone, SSN, DOB + Log.*() calls)
- PII sent to analytics SDKs (Mixpanel, Amplitude, Segment, Heap)
- External storage access (readable by all apps pre-Android 10)
- Clipboard leakage via ClipboardManager.setPrimaryClip()
- Missing FLAG_SECURE — screenshots and screen recording allowed
- Native libraries missing stack canary (__stack_chk_fail)
- Non-PIE native libraries (ET_EXEC) — ASLR defeated

**M8/M9/M10 — Misconfiguration, Storage, Cryptography** (`misconfig_storage_module.py`)
- StrictMode with penaltyLog in release builds
- Dangerous WebView settings: geolocation, password save, DOM storage, database
- Dangerous broadcast receivers (PACKAGE_ADDED, NEW_OUTGOING_CALL)
- Firebase Realtime Database — open rules audit with curl PoC
- World-readable/writable file permissions (MODE_WORLD_READABLE)
- Unencrypted SQLite with sensitive table names (users, tokens, payments)
- Realm database without encryption key
- Sensitive data in cache directory
- openFileOutput() without MODE_PRIVATE
- Homegrown cryptography: XOR, ROT13, Caesar cipher
- Predictable RNG seed (System.currentTimeMillis)
- WebView onReceivedSslError with handler.proceed() — TLS errors suppressed

### Added — Chain Detection Extended
- Chain 5: Client-side auth flags + exported activity → SS rank
- Chain 6: Hardcoded Firebase key + open database rules → SS rank

### Added — Infrastructure
- GitHub Actions CI matrix (Python 3.10, 3.11, 3.12)
- GitHub issue templates (bug report, feature request)
- GitHub PR template with module checklist
- `scripts/frida/appraisal_agent.js` — universal Frida agent with 10 hooks:
  SSL bypass, root bypass, biometric bypass, anti-tamper bypass,
  SharedPreferences monitor, crypto tracer, network logger,
  Intent inspector, file I/O monitor, heap secret extractor
- `docs/owasp_coverage.md` — full OWASP coverage matrix with finding IDs
- `docs/writing_modules.md` — contributor guide for new module development
- `tests/test_owasp_modules.py` — 55 new tests for all OWASP modules

### Changed
- Orchestrator: 8 → 14 modules
- Vulnerability chains: 4 → 6
- Test suite: 45 → 100 passing

---

## [1.0.0] — 2025

### Added — Initial Release

**Core Skill Modules (8)**
- `[PASSIVE]` Manifest Sight — manifest/NSC misconfiguration
- `[ACTIVE]`  Component Exposure Scanner — exported IPC attack surface
- `[ACTIVE]`  Deep Link Interceptor — deep link spoofing + HTML PoC generator
- `[ACTIVE]`  Taint Walk — static source-to-sink data flow (13 sources × 16 sinks)
- `[UNIQUE]`  Cipher Sight — cryptographic weakness fingerprinting
- `[UNIQUE]`  Binary Hardening Auditor — packing, root/Frida detection bypass scripts
- `[HIDDEN]`  Supply Chain Scanner — SDK fingerprinting + CVE cross-reference
- `[UNIQUE]`  Binder Breach — PendingIntent, Parcelable mismatch, AIDL

**Core Engine**
- CVSS v3.1 full scoring implementation
- F/D/C/B/A/S/SS/SSS rank system
- Vulnerability chain detection (4 chains)
- PoC artifact export: adb_command, html_page, frida_script, curl_command, python_script
- Terminal appraisal cards via Rich
- JSON + interactive HTML report with filter/copy UI
- CLI: `scan`, `diff`, `info`, `list-modules`
- CI/CD exit codes: 0 (clean), 1 (medium/low), 2 (critical/high)
- 45 tests passing
