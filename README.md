<div align="center">

<img src="banner.svg" alt="Appraisal: DEX — S-Rank Appraisal Skill for Android Binaries" width="100%" />

<br/>

# ⚔ Appraisal: DEX

**Using My S-Rank Appraisal Skill to Expose Vulnerabilities in Android Binaries**

*by [Rimu](https://github.com/rithinkrishnakv)*

[![CI](https://github.com/rithinkrishnakv/appraisal-dex/actions/workflows/ci.yml/badge.svg)](https://github.com/rithinkrishnakv/appraisal-dex/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![OWASP Mobile Top 10](https://img.shields.io/badge/OWASP-Mobile%20Top%2010-red.svg)](docs/owasp_coverage.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-100%20passing-brightgreen.svg)](tests/)

<sub>
<a href="#what-it-does">What It Does</a> ·
<a href="#the-rank-system">Rank System</a> ·
<a href="#skill-modules">Skill Modules</a> ·
<a href="#vulnerability-chain-detection">Chains</a> ·
<a href="#installation">Install</a> ·
<a href="#usage">Usage</a> ·
<a href="#output">Output</a>
</sub>

</div>

---

> In most isekai stories, the Appraisal skill is considered weak. Useless in combat. Overlooked.
>
> This tool disagrees.
>
> Give it an APK. It will tell you every flaw, every secret, every exploitable path —
> ranked, scored, and handed to you with a working PoC.
>
> **That's what S-Rank looks like.**

---

## What It Does

Appraisal: DEX is a professional-grade Android binary analysis tool. Drop an APK in. Get back:

- 🏆 Every vulnerability ranked on an **F → SSS** scale with **CVSS v3.1** scoring
- ⚡ **Vulnerability chains** — combinations that escalate to devastating impact
- 🛠 **Ready-to-run PoC artifacts**: `adb` commands, Frida scripts, HTML attack pages, Python exploits
- 🛡 **Complete OWASP Mobile Top 10** coverage across **14 skill modules**
- 📊 **Interactive HTML report** with filtering, copy buttons, and chain highlighting
- 🔁 **Diff mode** to compare two APK versions — catch regressions before they ship

---

## The Rank System

| Rank | Class | CVSS | What it means |
|:---:|------|------|---------------|
| `F` | Informational | 0.0 | Noise |
| `D` | Hardening | < 3.0 | Security debt |
| `C` | Low | < 5.0 | Needs effort to exploit |
| `B` | Medium | < 7.0 | Exploitable locally |
| `A` | High | < 9.0 | Remotely exploitable |
| `S` | Critical | < 9.5 | Full compromise, PoC ready |
| `SS` | Devastating | < 10.0 | Vulnerability chain |
| `SSS` | Extinction | 10.0 | Supply chain impact |

<div align="center">
<img src="rank-scale.svg" alt="Rank scale from F (noise) to SSS (extinction)" width="100%" />
</div>

---

## Skill Modules

`[PASSIVE]` reads manifest/strings only · `[ACTIVE]` traces real exploit paths · `[UNIQUE]` no other scanner does this · `[HIDDEN]` surfaces what's *not* declared

### Core Skills

| Type | Module | Detects |
|------|--------|---------|
| `[PASSIVE]` | **Manifest Sight** | debuggable, backup, cleartext, NSC misconfig, pin-sets, wildcard domains, dangerous permissions, task reparenting |
| `[ACTIVE]` | **Component Exposure Scanner** | Exported Activities/Services/Receivers/Providers without permission; Content Provider SQLi + path traversal; implicit intent hijacking |
| `[ACTIVE]` | **Deep Link Interceptor** | HTTP/custom scheme deep links; OAuth code injection; autoVerify bypass; ready-to-fire malicious HTML PoC |
| `[ACTIVE]` | **Taint Walk** | Static source→sink: Intent→WebView XSS, Intent→exec() RCE, Intent→SQLi; JS bridge RCE; dangerous WebView flags |
| `[UNIQUE]` | **Cipher Sight** | ECB mode; hardcoded keys/IVs/secrets (AWS, JWT, Firebase, Stripe, GitHub); weak RNG; broken PBKDF2; DES/RC4/MD5 |
| `[UNIQUE]` | **Binary Hardening Auditor** | ProGuard audit; root/emulator/Frida detection + Frida bypass scripts; native lib entropy (packing); anti-tamper bypass |
| `[HIDDEN]` | **Supply Chain Scanner** | 19 SDK fingerprints + CVE cross-reference; phantom permissions via manifest merger; Firebase misconfiguration; Timber logging |
| `[UNIQUE]` | **Binder Breach** | Mutable PendingIntents; Parcelable mismatch (Bundle Mismatch class); AIDL interface fuzzing; ordered/sticky broadcast abuse |

### OWASP Mobile Top 10 Skills

| OWASP | Type | Module | Detects |
|:---:|------|------|---------|
| **M1** | `[PASSIVE]` | **Credential Sight** | Hardcoded passwords/tokens/API keys/connection strings; config files in APK; Basic Auth headers; SharedPreferences plaintext creds; credential logging |
| **M2** | `[HIDDEN]` | **Supply Chain Sentinel** | Debug/unsigned APKs; debug certs; Janus v1-only signing (CVE-2017-13156); mapping.txt leakage; build path leakage; repackaging indicators; dependency confusion; test code in release |
| **M3** | `[ACTIVE]` | **Auth Breach** | Client-side isAdmin/isPremium flags; biometric bypass without CryptoObject + Frida script; JWT `alg=none`; hardcoded JWT secret; session tokens in plaintext SharedPrefs; Intent-based auth bypass |
| **M4** | `[ACTIVE]` | **Input Sentinel** | Java deserialization (ObjectInputStream/FastJSON/XMLDecoder); XXE; path traversal; raw SQLi; command injection; output encoding failure; Intent redirection; Zip Slip |
| **M5** | `[ACTIVE]` | **Network & Privacy Sentinel** | Weak TLS (SSLv3/TLS1.0); hostname bypass; trust-all TrustManager + Frida bypass; hardcoded HTTP endpoints |
| **M6** | `[ACTIVE]` | **Network & Privacy Sentinel** | PII in logs/analytics; external storage; clipboard leakage; missing FLAG_SECURE |
| **M7** | `[UNIQUE]` | **Binary Hardening + Network & Privacy** | Missing stack canary; non-PIE native libs; no ProGuard; no root/Frida/emulator detection |
| **M8** | `[ACTIVE]` | **Config & Storage Auditor** | StrictMode in release; dangerous WebView settings; dangerous broadcast receivers; Firebase open rules |
| **M9** | `[ACTIVE]` | **Config & Storage Auditor** | World-readable files; unencrypted SQLite/Realm; sensitive data in cache; wrong file modes |
| **M10** | `[UNIQUE]` | **Cipher Sight + Config & Storage** | XOR/ROT homegrown crypto; predictable RNG seed; SSL error handler `proceed()` |

→ Full coverage matrix: [`docs/owasp_coverage.md`](docs/owasp_coverage.md)

---

## Vulnerability Chain Detection

Six chains are automatically detected and escalated in rank:

| ⚡ Chain | Modules | Escalated To | Impact |
|---------|---------|:-:|--------|
| Debuggable + Exported Activity | MANIFEST-001 + COMP-ACT | `SS` | Full data exfiltration, no root needed |
| No Cert Pinning + Taint Flow | BINARY-NOPIN + TAINT | `SS` | Confirmed MitM + data theft |
| Custom Deep Link + JS WebView | DEEPLINK + TAINT-WEBVIEW-JS | `SS` | One-click XSS, cookie theft |
| Exported Content Provider + Backup | COMP-PRV + MANIFEST-002 | `SS` | Two independent paths to full DB dump |
| Client-Side Auth + Exported Activity | M3-CLIENT-AUTH + COMP-ACT | `SS` | Trivial privilege escalation to admin |
| Hardcoded Firebase Key + Open Rules | M1-CRED + M8-FIREBASE | `SS` | Unauthenticated full database access |

---

## Installation

```bash
# Requirements: Python 3.10+, Java
git clone https://github.com/rithinkrishnakv/appraisal-dex.git
cd appraisal-dex
pip install -e .
```

Or install directly:
```bash
pip install git+https://github.com/rithinkrishnakv/appraisal-dex.git
```

---

## Usage

```bash
# Basic scan — terminal output
appraisal-dex scan target.apk

# Full output — JSON + interactive HTML + all PoC files
appraisal-dex scan target.apk --json --html --pocs -o ./reports/

# Critical findings only
appraisal-dex scan target.apk --min-rank S

# Skip heavy modules for speed
appraisal-dex scan target.apk --skip "Taint Walk" --skip "Supply Chain Sentinel"

# Version regression — what broke between releases?
appraisal-dex diff app_v1.2.apk app_v1.3.apk --html -o ./diff/

# APK metadata without full scan
appraisal-dex info target.apk

# List all 14 modules
appraisal-dex list-modules
```

---

## Output

### Terminal — Appraisal Cards
```
╔══════════════════════════════════════════════════╗
║  ⚡ [SS] CHAIN: Debuggable + Exported Activity   ║
║  ID: COMP-ACT-MainActivity                       ║
║  CVSS: 9.6  AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H   ║
╠══════════════════════════════════════════════════╣
║  VULNERABILITY CHAIN DETECTED: debuggable=true   ║
║  + exported Activity = full data exfiltration,   ║
║  no root needed.                                 ║
╠══════════════════════════════════════════════════╣
║  PoC:                                            ║
║  adb shell run-as com.example.app ls -la         ║
╚══════════════════════════════════════════════════╝
```

### HTML Report
Interactive report with rank filtering, one-click PoC copy, and chain highlighting.

### PoC Files
Every finding exports ready-to-run artifacts:
```
pocs/
  MANIFEST-001_1.sh              # ADB backup exfiltration
  M3-BIOMETRIC-NOCRYPTO_1.js    # Frida biometric bypass
  DEEPLINK-HTTP_1.html           # Browser deep link attack page
  M5-TRUST-ALL-CERTS_1.js       # Universal SSL bypass
  COMP-PRV-authority_1.sh        # Content provider SQLi
  BINARY-ROOTDETECT_1.js         # Root detection bypass
```

---

## CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: APK Security Scan
  run: appraisal-dex scan app-release.apk --json --min-rank A -o ./security/
  # Exit 0 = clean, Exit 1 = medium/low, Exit 2 = critical/high → blocks build
```

---

## Project Structure

```
appraisal-dex/
├── appraisal/
│   ├── cli.py                        # CLI: scan, diff, info, list-modules
│   ├── models.py                     # CVSSVector, Rank, Finding, PoC, AppraisalResult
│   ├── engine/
│   │   ├── loader.py                 # APK parser → AnalysisContext
│   │   ├── base_module.py            # BaseModule ABC
│   │   └── orchestrator.py           # 14 modules + 6 chain detectors
│   ├── modules/
│   │   ├── manifest_module.py        # [PASSIVE] Manifest Sight
│   │   ├── component_module.py       # [ACTIVE]  Component Exposure Scanner
│   │   ├── deeplink_module.py        # [ACTIVE]  Deep Link Interceptor
│   │   ├── taint_module.py           # [ACTIVE]  Taint Walk
│   │   ├── crypto_module.py          # [UNIQUE]  Cipher Sight
│   │   ├── binary_module.py          # [UNIQUE]  Binary Hardening Auditor
│   │   ├── sdk_module.py             # [HIDDEN]  Supply Chain Scanner
│   │   ├── binder_module.py          # [UNIQUE]  Binder Breach
│   │   ├── credential_module.py      # [PASSIVE] M1 — Credential Sight
│   │   ├── supply_chain_module.py    # [HIDDEN]  M2 — Supply Chain Sentinel
│   │   ├── auth_module.py            # [ACTIVE]  M3 — Auth Breach
│   │   ├── input_validation_module.py# [ACTIVE]  M4 — Input Sentinel
│   │   ├── network_privacy_module.py # [ACTIVE]  M5/M6/M7 — Network & Privacy
│   │   └── misconfig_storage_module.py # [ACTIVE] M8/M9/M10 — Config & Storage
│   └── report/
│       └── renderer.py               # Terminal + JSON + HTML + PoC export
├── scripts/
│   ├── create_test_apk.py            # Test APK generator
│   └── frida/
│       └── appraisal_agent.js        # Universal Frida agent (10 hooks)
├── docs/
│   ├── owasp_coverage.md             # Full OWASP coverage matrix
│   └── writing_modules.md            # Contributor guide
├── tests/
│   ├── test_appraisal.py             # Core tests (45)
│   └── test_owasp_modules.py         # OWASP module tests (55)
└── .github/
    ├── workflows/ci.yml              # Python 3.10/3.11/3.12 CI matrix
    └── ISSUE_TEMPLATE/               # Bug + feature templates
```

---

## Writing a Custom Module

```python
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType
from typing import List

class MyModule(BaseModule):
    SKILL_NAME  = "My Skill"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "Finds a specific vulnerability class"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        if "dangerous_pattern" in " ".join(ctx.strings_pool):
            self._add(Finding(
                id="CUSTOM-001",
                title="Dangerous Pattern Found",
                category="Custom",
                description="...",
                technical_detail="...",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["pattern in DEX"],
                remediation="Fix it.",
                pocs=[PoC(type="adb_command", title="Exploit", description="...", code="adb shell ...")],
            ))
        return self._findings
```

→ Full guide: [`docs/writing_modules.md`](docs/writing_modules.md)

---

## Stats

| Metric | Value |
|--------|-------|
| Skill modules | **14** |
| Vulnerability chains | **6** |
| OWASP M1–M10 coverage | **100%** |
| Test cases | **100 passing** |
| PoC types | **5** (adb, frida, html, python, curl) |
| Lines of code | **~8,500** |

---

## Disclaimer

Appraisal: DEX is intended for:
- Penetration testers with written authorization
- Security researchers studying Android security
- Developers auditing their own applications

Do not use against applications you do not own or have explicit written permission to test.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

*Everything has a weakness. I can see all of them.*

**— Rimu**

</div>
