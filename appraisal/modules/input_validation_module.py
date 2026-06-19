"""
SKILL: Input Sentinel [ACTIVE]
OWASP M4 — Insufficient Input/Output Validation

Detects injection sinks, unsafe deserialization, path traversal,
XML/JSON parser misuse, regex DoS, and output encoding failures.
"""

import re
from typing import List
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


class InputValidationModule(BaseModule):
    SKILL_NAME  = "Input Sentinel"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "OWASP M4 — Input/output validation: injection, deserialization, path traversal, XXE, ReDoS"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_unsafe_deserialization(ctx)
        self._check_xxe_vulnerability(ctx)
        self._check_path_traversal_patterns(ctx)
        self._check_sql_injection_patterns(ctx)
        self._check_command_injection(ctx)
        self._check_output_encoding(ctx)
        self._check_intent_redirection(ctx)
        self._check_zip_slip(ctx)
        return self._findings

    # ── Unsafe deserialization ────────────────────────────────────────────────

    def _check_unsafe_deserialization(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)

        DESER_PATTERNS = [
            ("ObjectInputStream",        "Java ObjectInputStream — native Java deserialization"),
            ("readObject",               "readObject() — arbitrary class instantiation"),
            ("Serializable",             "Serializable — unsafe if input is attacker-controlled"),
            ("XMLDecoder",               "XMLDecoder — RCE via crafted XML"),
            ("BeanContextSupport",       "BeanContextSupport gadget chain"),
            ("com.alibaba.fastjson",     "FastJSON — multiple critical RCE CVEs"),
            ("net.sf.json",              "json-lib — deserialization gadgets"),
            ("org.codehaus.jackson",     "Jackson (older) — polymorphic type abuse"),
        ]

        for pattern, label in DESER_PATTERNS:
            if pattern in pool:
                is_critical = any(c in label for c in ["RCE", "ObjectInputStream", "XMLDecoder", "FastJSON"])
                self._add(Finding(
                    id=f"M4-DESER-{pattern[:20].upper().replace('.','_').replace('-','_')}",
                    title=f"Unsafe Deserialization Risk: {label}",
                    category="Insufficient Input Validation (M4)",
                    description=(
                        f"{label} detected. "
                        "Deserializing attacker-controlled data using Java's native serialization "
                        "or vulnerable libraries can lead to Remote Code Execution via gadget chains. "
                        "If the input comes from Intents, network, or Content Providers, "
                        "this is directly exploitable."
                    ),
                    technical_detail=f"Class/pattern '{pattern}' found in DEX string pool.",
                    cvss=(CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
                          if is_critical else
                          CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="H", A="N")),
                    evidence=[f"{pattern} in DEX string pool"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Avoid Java native serialization for untrusted input. "
                        "Use Gson, Moshi, or kotlinx.serialization instead. "
                        "If ObjectInputStream is required, implement a whitelist-based "
                        "resolveClass() override. "
                        "Update FastJSON to 1.2.83+ and enable safeMode."
                    ),
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                        "https://github.com/frohoff/ysoserial",
                    ],
                    tags=["m4", "deserialization", "rce", pattern.lower()],
                ))

    # ── XXE (XML External Entity) ─────────────────────────────────────────────

    def _check_xxe_vulnerability(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)

        XML_PARSERS = ["DocumentBuilder", "SAXParser", "XMLReader", "XPathExpression",
                       "SAXReader", "DOMParser", "XMLInputFactory"]
        has_xml = any(p in pool for p in XML_PARSERS)

        if not has_xml:
            return

        # Check for secure configuration
        SECURE_CONFIG = [
            "setFeature.*XMLConstants",
            "FEATURE_SECURE_PROCESSING",
            "setExpandEntityReferences.*false",
            "disallow-doctype-decl",
            "external-general-entities",
        ]
        pool_check = " ".join(ctx.strings_pool)
        is_secured = any(re.search(p, pool_check) for p in SECURE_CONFIG)

        if not is_secured:
            self._add(Finding(
                id="M4-XXE",
                title="XML Parser Without XXE Protection — External Entity Injection",
                category="Insufficient Input Validation (M4)",
                description=(
                    "An XML parser (DocumentBuilder, SAXParser, XMLReader, etc.) is used "
                    "without disabling external entity processing. "
                    "XXE allows an attacker who controls XML input to: "
                    "read arbitrary files from the device (/data/data/<pkg>/...), "
                    "perform SSRF to internal network endpoints, or cause DoS via billion laughs."
                ),
                technical_detail=(
                    f"XML parser detected: {[p for p in XML_PARSERS if p in pool]}\n"
                    "No XXE-disable features detected in string pool."
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="L"),
                evidence=[f"XML parser without XXE protection: {[p for p in XML_PARSERS if p in pool][:3]}"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Disable external entities on every parser instance:\n"
                    "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                    "factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
                    "factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
                    "factory.setExpandEntityReferences(false);"
                ),
                pocs=[PoC(
                    type="python_script",
                    title="XXE Payload to Read App Private Files",
                    description="XML payload that reads /data/data/<pkg>/shared_prefs/ via XXE",
                    code=(
                        f"# XXE payload — inject into any XML input accepted by the app\n"
                        f"payload = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        f"<!DOCTYPE foo [\n"
                        f"  <!ENTITY xxe SYSTEM \"file:///data/data/{ctx.package_name}/shared_prefs/prefs.xml\">\n"
                        f"]>\n"
                        f"<root><data>&xxe;</data></root>'''\n\n"
                        f"# Billion laughs DoS:\n"
                        f"dos_payload = '''<?xml version=\"1.0\"?>\n"
                        f"<!DOCTYPE lolz [\n"
                        f"  <!ENTITY lol \"lol\">\n"
                        f"  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
                        f"  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n"
                        f"  <!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">\n"
                        f"]>\n"
                        f"<root>&lol9;</root>'''"
                    ),
                )],
                tags=["m4", "xxe", "xml", "injection"],
            ))

    # ── Path traversal detection ──────────────────────────────────────────────

    def _check_path_traversal_patterns(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)

        FILE_OPS = ["FileOutputStream", "FileInputStream", "File(", "openFileOutput",
                    "getFilesDir", "getCacheDir", "openFile"]
        USER_INPUT = ["getStringExtra", "getQueryParameter", "getPathSegments",
                      "getString(", "readLine"]

        has_file  = any(f in pool for f in FILE_OPS)
        has_input = any(i in pool for i in USER_INPUT)

        if has_file and has_input and "canonicalPath" not in pool:
            self._add(Finding(
                id="M4-PATH-TRAVERSAL",
                title="Path Traversal Risk — File Operations With User Input, No Canonicalization",
                category="Insufficient Input Validation (M4)",
                description=(
                    "File I/O operations and user-controlled input are both present, "
                    "but path canonicalization (getCanonicalPath()) was not detected. "
                    "An attacker who controls a filename or path parameter can use "
                    "'../../' sequences to read or write files outside the intended directory, "
                    "potentially accessing other apps' data on a rooted device or "
                    "the app's own private databases."
                ),
                technical_detail=(
                    f"File ops: {[f for f in FILE_OPS if f in pool][:3]}\n"
                    f"Input sources: {[i for i in USER_INPUT if i in pool][:3]}\n"
                    "getCanonicalPath() not detected — no path normalization."
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["File ops + user input without canonicalization"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Always canonicalize file paths before use:\n"
                    "File f = new File(baseDir, userInput);\n"
                    "if (!f.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {\n"
                    "    throw new SecurityException(\"Path traversal detected\");\n"
                    "}"
                ),
                pocs=[PoC(
                    type="adb_command",
                    title="Path Traversal via Intent Extra",
                    description="Pass traversal sequences via Intent filename parameter",
                    code=(
                        f"# Test path traversal via deep link or Intent\n"
                        f"adb shell am start -n {ctx.package_name}/.MainActivity \\\n"
                        f"  --es filename '../../databases/main.db' \\\n"
                        f"  --es path '../../../data/system/packages.xml' \\\n"
                        f"  --es file '/proc/self/maps'\n\n"
                        f"# Via content provider:\n"
                        f"adb shell content read --uri 'content://{ctx.package_name}.provider/../../../etc/hosts'"
                    ),
                )],
                tags=["m4", "path-traversal", "file-io", "injection"],
            ))

    # ── SQL Injection (beyond taint analysis) ─────────────────────────────────

    def _check_sql_injection_patterns(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        RAW_SQL = ["rawQuery", "execSQL", "compileStatement"]
        has_raw = any(s in pool for s in RAW_SQL)

        PARAMETERIZED = ["bindString", "bindLong", "bindBlob", "?"]
        # Check if parameterized queries are also used
        uses_params = sum(1 for p in PARAMETERIZED if p in pool)

        if has_raw and uses_params < 2:
            self._add(Finding(
                id="M4-SQLI-RAW",
                title="Raw SQL Queries Without Parameterization Detected",
                category="Insufficient Input Validation (M4)",
                description=(
                    "rawQuery() or execSQL() are used with limited evidence of "
                    "parameterized queries (bind variables). "
                    "String concatenation in SQL queries allows SQL injection — "
                    "an attacker who controls any part of the query can dump, "
                    "modify, or delete the entire database."
                ),
                technical_detail=(
                    f"Raw SQL methods: {[s for s in RAW_SQL if s in pool]}\n"
                    f"Parameterization indicators: {uses_params}/4 found"
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
                evidence=[f"Raw SQL without full parameterization: {[s for s in RAW_SQL if s in pool]}"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use parameterized queries exclusively:\n"
                    "db.rawQuery(\"SELECT * FROM users WHERE id=?\", new String[]{userId});\n"
                    "Use Room (AndroidX) which prevents raw SQL by default. "
                    "Never concatenate user input into SQL strings."
                ),
                tags=["m4", "sql-injection", "database", "injection"],
            ))

    # ── Command injection ─────────────────────────────────────────────────────

    def _check_command_injection(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "Runtime.getRuntime" in pool or "ProcessBuilder" in pool:
            if any(i in pool for i in ["getStringExtra", "getQueryParameter", "getIntent"]):
                self._add(Finding(
                    id="M4-CMD-INJECTION",
                    title="Command Injection Risk — Runtime.exec() with Potential User Input",
                    category="Insufficient Input Validation (M4)",
                    description=(
                        "Runtime.exec() or ProcessBuilder is used alongside Intent/URI input sources. "
                        "If user-controlled data flows into shell command construction without "
                        "strict sanitization, an attacker can inject shell metacharacters "
                        "(`;`, `|`, `&&`, `$(...)`) to execute arbitrary OS commands."
                    ),
                    technical_detail="Runtime.exec/ProcessBuilder + user input source co-present in DEX.",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
                    evidence=["Runtime.exec() + user input in DEX"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "Never pass user input to Runtime.exec() or ProcessBuilder. "
                        "Use Java APIs instead of shell commands. "
                        "If shell execution is required, use an allowlist and validate "
                        "each argument with a strict regex — never pass raw user strings."
                    ),
                    pocs=[PoC(
                        type="adb_command",
                        title="Command Injection Payload via Intent",
                        description="Inject shell metacharacters via Intent extras",
                        code=(
                            f"adb shell am start -n {ctx.package_name}/.MainActivity \\\n"
                            f"  --es command 'ping 127.0.0.1; id' \\\n"
                            f"  --es input '$(cat /data/data/{ctx.package_name}/databases/main.db | base64)' \\\n"
                            f"  --es param '`id`'"
                        ),
                    )],
                    tags=["m4", "command-injection", "rce", "injection"],
                ))

    # ── Output encoding ───────────────────────────────────────────────────────

    def _check_output_encoding(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if "loadData" in pool or "loadDataWithBaseURL" in pool:
            if "TextUtils.htmlEncode" not in pool and "Html.escapeHtml" not in pool:
                self._add(Finding(
                    id="M4-OUTPUT-ENCODING",
                    title="WebView.loadData Without Output Encoding — Stored XSS Risk",
                    category="Insufficient Input Validation (M4)",
                    description=(
                        "WebView.loadData() or loadDataWithBaseURL() is called without "
                        "detected HTML encoding (TextUtils.htmlEncode / Html.escapeHtml). "
                        "If any user-controlled or server-provided data is inserted into "
                        "the HTML string before loading, it creates a Stored XSS or "
                        "Reflected XSS vulnerability inside the app's WebView context."
                    ),
                    technical_detail="loadData/loadDataWithBaseURL without HTML encoding detected.",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
                    evidence=["WebView.loadData without output encoding"],
                    affected_components=[ctx.package_name],
                    remediation=(
                        "HTML-encode all dynamic content before inserting into HTML: "
                        "TextUtils.htmlEncode(userContent). "
                        "Use a Content Security Policy header. "
                        "Consider using a templating engine that auto-escapes output."
                    ),
                    tags=["m4", "xss", "output-encoding", "webview"],
                ))

    # ── Intent Redirection ────────────────────────────────────────────────────

    def _check_intent_redirection(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if ("getParcelableExtra" in pool or "getSerializableExtra" in pool) \
                and "startActivity" in pool:
            self._add(Finding(
                id="M4-INTENT-REDIRECT",
                title="Intent Redirection — Nested Intent from Parcelable Extra",
                category="Insufficient Input Validation (M4)",
                description=(
                    "The app reads a Parcelable/Serializable Intent from an incoming Intent extra "
                    "and passes it to startActivity() or startService(). "
                    "This is the Intent Redirection vulnerability: an attacker app sends "
                    "a crafted outer Intent containing a malicious inner Intent that targets "
                    "internal non-exported components, bypassing Android's export restrictions."
                ),
                technical_detail=(
                    "getParcelableExtra/getSerializableExtra + startActivity in DEX. "
                    "Classic pattern: PendingIntent or Intent embedded in Intent extra, "
                    "then dispatched by a trusted component."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
                evidence=["Nested Intent dispatch from Parcelable extra"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Validate the embedded Intent before dispatching: "
                    "check getComponent(), getPackage(), and ensure it targets only "
                    "expected components. "
                    "Use PendingIntent.send() with fillIn() only when strictly necessary."
                ),
                references=["https://blog.oversecured.com/Gaining-access-to-arbitrary-Content-Providers/"],
                tags=["m4", "intent-redirection", "nested-intent", "component-bypass"],
            ))

    # ── Zip Slip ─────────────────────────────────────────────────────────────

    def _check_zip_slip(self, ctx: AnalysisContext):
        pool = " ".join(ctx.strings_pool)
        if ("ZipInputStream" in pool or "ZipEntry" in pool or "ZipFile" in pool) \
                and "getCanonicalPath" not in pool:
            self._add(Finding(
                id="M4-ZIP-SLIP",
                title="Zip Slip Risk — ZIP Extraction Without Path Validation",
                category="Insufficient Input Validation (M4)",
                description=(
                    "ZIP file processing (ZipInputStream/ZipEntry) is detected without "
                    "path canonicalization (getCanonicalPath). "
                    "Zip Slip allows an attacker to craft a ZIP archive with entries "
                    "containing '../../' sequences that, when extracted, write files "
                    "outside the intended directory — potentially overwriting app code, "
                    "config files, or native libraries."
                ),
                technical_detail=(
                    "ZipInputStream/ZipEntry without getCanonicalPath() validation.\n"
                    "Attack: craft ZIP with entry name '../../lib/libevil.so'"
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["ZIP processing without path traversal protection"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Validate every ZipEntry name before extraction:\n"
                    "String destPath = new File(destDir, entry.getName()).getCanonicalPath();\n"
                    "if (!destPath.startsWith(destDir.getCanonicalPath() + File.separator)) {\n"
                    "    throw new IOException(\"Zip Slip: \" + entry.getName());\n"
                    "}"
                ),
                tags=["m4", "zip-slip", "path-traversal", "injection"],
            ))
