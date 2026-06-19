# ⚔ Appraisal: DEX

> *Using My S-Rank Appraisal Skill to Expose Vulnerabilities in Android Binaries*

In most isekai stories, the Appraisal skill is considered weak. Useless in combat. Overlooked.

This tool disagrees.

Give it an APK. It will tell you every flaw, every secret, every exploitable path — ranked, scored, and handed to you with a working PoC.

**That's what S-Rank looks like.**

---

## Features

### Skill Modules

| Type | Skill | What It Finds |
|------|-------|---------------|
| `[PASSIVE]` | Manifest Sight | Debuggable flags, backup risks, cleartext traffic, dangerous permissions, NSC misconfig, wildcard domains |
| `[ACTIVE]` | Component Exposure Scanner | Exported Activities/Services/Receivers/Providers without permission, implicit intent hijacking, Content Provider SQLi + path traversal |
| `[ACTIVE]` | Deep Link Interceptor | HTTP/custom scheme deep links, OAuth code injection, auto-verification bypass, ready-to-fire HTML PoC pages |
| `[ACTIVE]` | Taint Walk | Source-to-sink static taint analysis: Intent → WebView XSS, Intent → RCE, Intent → SQLi, JS bridge exposure, file access flags |
| `[UNIQUE]` | Cipher Sight | ECB mode, hardcoded keys/IVs, weak random, broken KDF, hardcoded secrets (AWS keys, JWTs, API keys, Firebase), algorithm weakness |
| `[UNIQUE]` | Binary Hardening Auditor | ProGuard assessment, root/emulator/Frida detection bypass Frida scripts, native lib entropy (packed code detection), anti-tamper bypass |
| `[HIDDEN]` | Supply Chain Scanner | SDK fingerprinting + CVE mapping, phantom permissions via manifest merger, Firebase misconfiguration, Timber debug logging |
| `[UNIQUE]` | Binder Breach | Mutable PendingIntents, Parcelable mismatch (Bundle Mismatch vuln class), AIDL interface fuzzing, ordered broadcast abuse |

### The Appraisal Rank System

Every finding is assigned a rank based on CVSS v3.1 scoring:

| Rank | Class | CVSS Range | What It Means |
|------|-------|------------|---------------|
| `F` | Informational | 0.0 | Noise, not directly exploitable |
| `D` | Hardening | < 3.0 | Security debt, raises attack surface |
| `C` | Low | < 5.0 | Exploitable with significant effort |
| `B` | Medium | < 7.0 | Exploitable by local attacker |
| `A` | High | < 9.0 | Remotely exploitable, partial impact |
| `S` | Critical | < 9.5 | Full compromise, PoC auto-generated |
| `SS` | Devastating | < 10.0 | Vulnerability chain, multi-system impact |
| `SSS` | Extinction | 10.0 | Supply chain issue affecting many apps |

### ⚡ Vulnerability Chain Detection

The orchestrator automatically detects and annotates vulnerability **chains** — where multiple independent findings combine for exponentially greater impact:

- **Debuggable + Exported Activity** → `[SS]` Full data exfiltration, no root needed
- **No Certificate Pinning + Taint Flow** → `[SS]` Confirmed MitM + data theft chain  
- **Custom Deep Link + JS WebView** → `[SS]` One-click XSS, cookie theft
- **Exported Content Provider + Backup Enabled** → Two independent paths to full DB dump

### Ready-to-Run PoC Output

Every S-rank finding ships with a proof-of-concept artifact:

- **`adb_command`** — Fire directly from terminal, copy-paste ready
- **`html_page`** — Host and visit to trigger the attack in a browser
- **`frida_script`** — Inject with `frida -U -f <package> -l script.js`
- **`curl_command`** — Test Firebase/API endpoints directly
- **`python_script`** — Standalone exploit scripts

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/appraisal-dex.git
cd appraisal-dex

# Install (Python 3.10+)
pip install -e .

# Or install dependencies manually
pip install -r requirements.txt
```

### Requirements

- Python 3.10+
- Java (for androguard's internal DEX parsing)
- ADB (optional, for running generated PoCs)
- Frida (optional, for dynamic analysis PoCs)

---

## Usage

### Basic Scan

```bash
appraisal-dex scan target.apk
```

### Full Output — JSON + HTML + PoC Files

```bash
appraisal-dex scan target.apk --json --html --pocs -o ./reports/
```

### Only Critical Findings (S-rank and above)

```bash
appraisal-dex scan target.apk --min-rank S
```

### Skip Slow Modules

```bash
appraisal-dex scan target.apk --skip "Taint Walk" --skip "Supply Chain Scanner"
```

### Version Regression Diff

```bash
appraisal-dex diff app_v1.2.apk app_v1.3.apk --html -o ./diff/
```

### APK Metadata (Fast, No Full Scan)

```bash
appraisal-dex info target.apk
```

### List All Skill Modules

```bash
appraisal-dex list-modules
```

---

## Output Formats

### Terminal — Appraisal Cards

```
╔══════════════════════════════════════╗
║  ⟦ APPRAISAL RESULT ⟧               ║
║  Target  : com.example.banking       ║
║  Finding : Exported Content Provider ║
║  Class   : CRITICAL                  ║
║  Rank    : S                         ║
║  CVSS    : 9.1 (AV:N/AC:L/PR:N)     ║
║  Status  : PoC Generated ✓           ║
╚══════════════════════════════════════╝
```

### JSON Report

Machine-readable output at `report.json`. Contains full finding metadata, CVSS vectors, evidence, PoC code, affected components, and remediation for every finding. Suitable for CI/CD pipeline integration.

### HTML Report

Interactive report at `report.html`:
- Filter findings by rank (S / A / B / ⚡ Chains)
- Syntax-highlighted PoC code with one-click copy
- CVSS vector breakdown per finding
- Full remediation guidance
- Chain detection highlights

### PoC Files

Each finding's PoC exported as a standalone executable file:
```
pocs/
  MANIFEST-001_1.sh          # ADB backup exfiltration
  COMP-ACT-MainActivity_1.sh # Activity launch with intent injection
  TAINT-Intent-WebView_1.sh  # Intent-to-WebView XSS
  BINARY-NOROOT_1.sh         # Rooted device data extraction
  COMP-PRV-authority_2.sh    # Content provider SQLi
  BINARY-ROOTDETECT_1.js     # Frida root bypass script
  DEEPLINK-HTTP_1.html       # Browser-based deep link PoC
```

---

## CI/CD Integration

Appraisal: DEX returns meaningful exit codes:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Clean scan (F/D rank only) |
| `1` | Medium/Low findings (C/B rank) |
| `2` | High/Critical findings (A/S/SS/SSS rank) — **pipeline should fail** |

```yaml
# GitHub Actions example
- name: APK Security Scan
  run: |
    appraisal-dex scan app-release.apk --json --min-rank B -o ./security-report
  continue-on-error: false  # Exit code 2 fails the build

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: ./security-report/
```

---

## Project Structure

```
appraisal-dex/
├── appraisal/
│   ├── __init__.py
│   ├── cli.py                  # CLI entry point (scan, diff, info, list-modules)
│   ├── models.py               # CVSSVector, Rank, Finding, PoC, AppraisalResult
│   ├── engine/
│   │   ├── loader.py           # APK parser → AnalysisContext
│   │   ├── base_module.py      # BaseModule ABC
│   │   └── orchestrator.py     # Module runner + chain detection
│   ├── modules/
│   │   ├── manifest_module.py  # [PASSIVE] Manifest Sight
│   │   ├── component_module.py # [ACTIVE]  Component Exposure Scanner
│   │   ├── deeplink_module.py  # [ACTIVE]  Deep Link Interceptor
│   │   ├── taint_module.py     # [ACTIVE]  Taint Walk
│   │   ├── crypto_module.py    # [UNIQUE]  Cipher Sight
│   │   ├── binary_module.py    # [UNIQUE]  Binary Hardening Auditor
│   │   ├── sdk_module.py       # [HIDDEN]  Supply Chain Scanner
│   │   └── binder_module.py    # [UNIQUE]  Binder Breach
│   └── report/
│       └── renderer.py         # Terminal + JSON + HTML + PoC export
├── tests/
│   └── test_appraisal.py       # Full test suite
├── scripts/
│   └── create_test_apk.py      # Test APK generator
├── docs/
│   └── modules.md              # Module reference
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Adding a Custom Module

```python
# appraisal/modules/my_module.py
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, SkillType
from typing import List

class MyModule(BaseModule):
    SKILL_NAME  = "My Custom Skill"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "Finds a specific vulnerability class"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        
        # Your analysis logic here
        if "dangerous_string" in " ".join(ctx.strings_pool):
            self._add(Finding(
                id="CUSTOM-001",
                title="Dangerous Pattern Found",
                category="Custom",
                description="...",
                technical_detail="...",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["dangerous_string in DEX pool"],
                remediation="Remove the dangerous pattern.",
            ))
        
        return self._findings
```

Then register it in `orchestrator.py`:

```python
from appraisal.modules.my_module import MyModule

ALL_MODULES = [
    ...,
    MyModule,  # Add here
]
```

---

## Disclaimer

Appraisal: DEX is a security research tool intended for:
- Penetration testers with written authorization
- Security researchers studying Android security
- Developers auditing their own applications

Do not use against applications you do not own or have explicit written permission to test. The authors assume no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Everything has a weakness. I can see all of them.*
