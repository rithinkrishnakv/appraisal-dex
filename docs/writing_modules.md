# Writing a Skill Module for Appraisal: DEX

Every vulnerability class is a skill. Every skill is a module.
This guide shows you how to write one from scratch.

---

## Module Anatomy

```python
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank
from typing import List

class MyModule(BaseModule):
    SKILL_NAME  = "My Skill Name"          # Shown in terminal and list-modules
    SKILL_TYPE  = SkillType.ACTIVE         # PASSIVE | ACTIVE | UNIQUE | HIDDEN | DIVINE
    DESCRIPTION = "One-line description"   # What this module finds

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []        # Always reset at the start
        self._check_something(ctx)
        self._check_something_else(ctx)
        return self._findings

    def _check_something(self, ctx: AnalysisContext):
        if "dangerous_pattern" in " ".join(ctx.strings_pool):
            self._add(Finding(
                id="MYMOD-001",
                title="Dangerous Pattern Found",
                category="My Category",
                description="Full human-readable description of the vulnerability.",
                technical_detail="Technical specifics: class name, method, evidence.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["dangerous_pattern in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation="How to fix this.",
                pocs=[PoC(
                    type="adb_command",    # or: frida_script | html_page | python_script | curl_command
                    title="Exploit Title",
                    description="What this PoC does",
                    code="adb shell am start ...",
                )],
                tags=["mytag", "category"],
            ))
```

---

## AnalysisContext — What You Have Access To

```python
ctx.package_name          # str   — e.g. "com.example.app"
ctx.app_name              # str   — human-readable app name
ctx.version_name          # str   — e.g. "3.2.1"
ctx.version_code          # str   — e.g. "321"
ctx.min_sdk               # int   — minimum SDK version
ctx.target_sdk            # int   — target SDK version
ctx.permissions           # List[str] — all declared permissions
ctx.components            # List[ManifestComponent] — all manifest components
ctx.file_list             # List[str] — all files in the APK ZIP
ctx.sha256                # str   — APK SHA-256 hash
ctx.md5                   # str   — APK MD5 hash
ctx.size_bytes            # int   — APK file size
ctx.has_native_libs       # bool  — any .so files present
ctx.native_lib_names      # List[str] — paths of all .so files
ctx.has_network_security_config  # bool
ctx.network_security_config_xml  # Optional[str] — raw XML content
ctx.strings_pool          # List[str] — all DEX string constants
ctx.manifest_xml          # str   — raw manifest XML string
ctx.manifest_tree         # ET.Element — parsed manifest
ctx.analysis              # androguard.Analysis — full bytecode analysis
ctx.dex_list              # List[DEX] — DEX files
ctx.apk                   # androguard.APK — APK object
ctx.apk_path              # str   — absolute path to APK
ctx.raw_bytes             # bytes — raw APK bytes
```

---

## ManifestComponent Fields

```python
comp.name              # str             — full class name
comp.component_type    # str             — "activity" | "service" | "receiver" | "provider"
comp.exported          # Optional[bool]  — True | False | None (not set)
comp.permission        # Optional[str]   — required permission
comp.intent_filters    # List[Dict]      — each dict has "actions", "categories", "data"
comp.authorities       # List[str]       — Content Provider authorities
comp.grant_uri_permissions  # bool
comp.path_permissions  # List[Dict]
```

---

## CVSSVector — CVSS v3.1 Scoring

```python
CVSSVector(
    AV = "N",   # Attack Vector:        N=Network  A=Adjacent  L=Local   P=Physical
    AC = "L",   # Attack Complexity:    L=Low       H=High
    PR = "N",   # Privileges Required:  N=None      L=Low       H=High
    UI = "N",   # User Interaction:     N=None      R=Required
    S  = "U",   # Scope:                U=Unchanged C=Changed
    C  = "H",   # Confidentiality:      N=None      L=Low       H=High
    I  = "H",   # Integrity:            N=None      L=Low       H=High
    A  = "N",   # Availability:         N=None      L=Low       H=High
)

# Score is calculated automatically — no need to hardcode it
vector.score()          # float  e.g. 9.8
vector.vector_string()  # str    e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
```

---

## Rank System

The rank is auto-derived from CVSS score. You can override it:

```python
Finding(
    ...,
    _rank=Rank.S,   # Force a specific rank regardless of CVSS
)
```

| Rank | CVSS Range | Use For |
|------|------------|---------|
| `F`   | 0.0        | Informational, no exploitability |
| `D`   | < 3.0      | Hardening issues, best practices |
| `C`   | < 5.0      | Low severity, needs effort to exploit |
| `B`   | < 7.0      | Medium — exploitable with conditions |
| `A`   | < 9.0      | High — remotely exploitable |
| `S`   | < 9.5      | Critical — automated exploitation |
| `SS`  | < 10.0     | Devastating — chains, widespread impact |
| `SSS` | 10.0       | Extinction — supply chain, multi-app |

---

## PoC Types

| `type` value | File extension | Use for |
|---|---|---|
| `adb_command` | `.sh` | ADB commands, shell interactions |
| `frida_script` | `.js` | Frida dynamic instrumentation |
| `html_page` | `.html` | Browser-based attack pages |
| `python_script` | `.py` | Standalone Python exploits |
| `curl_command` | `.sh` | HTTP/API exploit requests |

---

## Bytecode Analysis — androguard Patterns

```python
# Iterate all classes
for cls in ctx.analysis.get_classes():
    cls_name = str(cls.name)          # e.g. "Lcom/example/MainActivity;"
    
    for method in cls.get_methods():
        method_name = str(method.name)
        
        try:
            m = method.get_method()
            if not m: continue
            code = m.get_code()
            if not code: continue
            
            for ins in code.get_bc().get_instructions():
                ins_str = str(ins)
                # Check for dangerous method calls
                if "loadUrl" in ins_str and "WebView" in ins_str:
                    # Found a WebView.loadUrl() call
                    pass
        except Exception:
            continue

# Scan string pool (fastest approach for most checks)
pool = " ".join(ctx.strings_pool)
if "DangerousClass" in pool:
    pass
```

---

## File Analysis — Reading APK Contents

```python
import zipfile

with zipfile.ZipFile(ctx.apk_path, "r") as zf:
    # List all files
    all_files = zf.namelist()
    
    # Read a specific file
    try:
        content = zf.read("res/xml/network_security_config.xml")
        text = content.decode("utf-8", errors="ignore")
    except KeyError:
        pass  # File doesn't exist
    
    # Check if file exists
    if "assets/config.properties" in ctx.file_list:
        data = zf.read("assets/config.properties")
```

---

## Registering Your Module

**Step 1:** Add to `appraisal/modules/__init__.py`:
```python
from .my_module import MyModule
```

**Step 2:** Add to `ALL_MODULES` in `appraisal/engine/orchestrator.py`:
```python
ALL_MODULES: List[Type[BaseModule]] = [
    ...
    MyModule,   # Add at the appropriate position
]
```

**Step 3:** Add tests in `tests/test_appraisal.py`:
```python
class TestMyModule:
    def test_module_instantiation(self):
        from appraisal.modules.my_module import MyModule
        m = MyModule()
        assert m.SKILL_NAME == "My Skill Name"
        assert m.SKILL_TYPE == SkillType.ACTIVE
    
    def test_detection_logic(self):
        from appraisal.modules.my_module import MyModule
        m = MyModule()
        # ... test specific logic
```

---

## Finding ID Conventions

```
<MODULE>-<SUBCATEGORY>-<SHORT_DESCRIPTOR>

Examples:
  MANIFEST-001              # Numbered for ordered manifest checks
  COMP-ACT-MainActivity     # Component type + short name
  TAINT-Intent-WebView      # Source-sink pair
  CRYPTO-SECRET-AWS         # Crypto + secret type
  M1-CRED-HARDCODED_API_KEY # OWASP category + type
  BINARY-NOPIN              # Binary check name
  SDK-CVE-CVE_2021_36380    # CVE reference
```

Rules:
- All caps
- Hyphens between segments, underscores within
- Max ~50 chars
- Must be unique across all modules
- Stable across versions (used for diff comparison)

---

## Skill Types — When to Use Which

| Type | Use For |
|---|---|
| `PASSIVE` | No active scanning, pure static analysis of what's present |
| `ACTIVE` | Analysis that probes relationships and patterns across the binary |
| `UNIQUE` | Deep analysis requiring specialized knowledge (crypto, bytecode IR) |
| `HIDDEN` | Side-channel or secondary analysis (SDK fingerprinting, metadata) |
| `DIVINE` | Reserved for the orchestrator and chain analysis |

---

## Common Patterns

### Check if a class exists
```python
try:
    classes = {str(c.name) for c in ctx.analysis.get_classes()}
    if "Lcom/example/VulnClass;" in classes:
        # class exists
except Exception:
    pass
```

### Regex against string pool
```python
import re
matches = re.findall(r'AKIA[0-9A-Z]{16}', " ".join(ctx.strings_pool))
```

### Check native lib content
```python
import zipfile
with zipfile.ZipFile(ctx.apk_path) as zf:
    for lib in ctx.native_lib_names:
        data = zf.read(lib)
        if b"__stack_chk_fail" not in data:
            # Missing stack canary
```

### Redact sensitive values for reports
```python
@staticmethod
def _redact(value: str, keep: int = 6) -> str:
    v = str(value).strip()
    if len(v) <= keep * 2:
        return "*" * min(len(v), 8)
    return v[:keep] + "..." + v[-3:] + f" [{len(v)} chars]"
```
