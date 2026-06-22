"""
SKILL: Component Exposure Scanner [ACTIVE]
Audits every exported component for IPC attack surface.
Exported without permission = open door. We find every open door.
"""

from typing import List, Optional
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext, ManifestComponent
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


class ComponentExposureModule(BaseModule):
    SKILL_NAME  = "Component Exposure Scanner"
    SKILL_TYPE  = SkillType.ACTIVE
    DESCRIPTION = "Audits exported Activities, Services, Receivers, and Providers for unprotected IPC surface"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        exported = [c for c in ctx.components if c.exported is True]

        for comp in exported:
            if comp.component_type == "activity":
                self._audit_activity(ctx, comp)
            elif comp.component_type == "service":
                self._audit_service(ctx, comp)
            elif comp.component_type == "receiver":
                self._audit_receiver(ctx, comp)
            elif comp.component_type == "provider":
                self._audit_provider(ctx, comp)

        self._check_implicit_intent_vulnerabilities(ctx, exported)
        return self._findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _short(self, name: str, pkg: str) -> str:
        """Resolve relative component names."""
        if name.startswith("."):
            return pkg + name
        return name

    def _has_custom_permission(self, comp: ManifestComponent) -> bool:
        if not comp.permission:
            return False
        # System permissions don't protect custom IPC
        return not comp.permission.startswith("android.permission.")

    def _get_actions(self, comp: ManifestComponent) -> List[str]:
        actions = []
        for f in comp.intent_filters:
            actions.extend(f.get("actions", []))
        return actions

    # ── Activity ─────────────────────────────────────────────────────────────

    def _audit_activity(self, ctx: AnalysisContext, comp: ManifestComponent):
        name = self._short(comp.name, ctx.package_name)
        actions = self._get_actions(comp)
        has_protection = self._has_custom_permission(comp)

        # Check for sensitive activity names
        sensitive_keywords = [
            "admin", "debug", "test", "dev", "internal", "hidden",
            "payment", "checkout", "auth", "login", "password", "token",
            "config", "setting", "pref", "backup", "restore",
        ]
        is_sensitive = any(kw in name.lower() for kw in sensitive_keywords)

        if not has_protection:
            cvss = CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U",
                              C="H" if is_sensitive else "L",
                              I="H" if is_sensitive else "L", A="N")
            self._add(Finding(
                id=f"COMP-ACT-{ctx.package_name}_{name.split('.')[-1]}",
                title=f"Unprotected Exported Activity: {name.split('.')[-1]}",
                category="Component Exposure",
                description=(
                    f"Activity {name} is exported without a custom permission. "
                    "Any app on the device can start this activity, pass arbitrary "
                    "intent extras, and potentially trigger unintended UI flows, "
                    "authentication bypasses, or data leaks."
                    + (" This activity name suggests sensitive functionality." if is_sensitive else "")
                ),
                technical_detail=(
                    f"Component: {name}\n"
                    f"Permission: {comp.permission or 'None'}\n"
                    f"Intent filter actions: {actions or 'None (explicit only)'}\n"
                    f"Sensitive name match: {is_sensitive}"
                ),
                cvss=cvss,
                evidence=[
                    f"android:exported=\"true\" on <activity android:name=\"{name}\">",
                    f"No custom android:permission declared",
                ],
                affected_components=[name],
                remediation=(
                    f"Add android:permission=\"{ctx.package_name}.permission.INTERNAL\" "
                    f"to this activity and declare that permission with "
                    f"android:protectionLevel=\"signature\" in the manifest. "
                    "Or set android:exported=\"false\" if the activity is not needed by external apps."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title=f"Launch {name.split('.')[-1]} Directly",
                        description="Any app or attacker with ADB can start this activity directly",
                        code=(
                            f"# Launch the activity directly\n"
                            f"adb shell am start -n {ctx.package_name}/{name}\n\n"
                            f"# Launch with extra data (test for intent injection)\n"
                            f"adb shell am start -n {ctx.package_name}/{name} \\\n"
                            f"  --es 'url' 'javascript:alert(document.cookie)' \\\n"
                            f"  --es 'token' 'INJECTED_TOKEN' \\\n"
                            f"  --ez 'isAdmin' true \\\n"
                            f"  --ei 'userId' 0"
                        ),
                    ),
                ],
                tags=["exported", "activity", "ipc", "intent"],
            ))

    # ── Service ──────────────────────────────────────────────────────────────

    def _audit_service(self, ctx: AnalysisContext, comp: ManifestComponent):
        name = self._short(comp.name, ctx.package_name)
        has_protection = self._has_custom_permission(comp)
        actions = self._get_actions(comp)

        if not has_protection:
            self._add(Finding(
                id=f"COMP-SVC-{ctx.package_name}_{name.split('.')[-1]}",
                title=f"Unprotected Exported Service: {name.split('.')[-1]}",
                category="Component Exposure",
                description=(
                    f"Service {name} is exported without a custom permission. "
                    "External apps can bind to or start this service, "
                    "potentially invoking background operations, triggering sensitive "
                    "business logic, or leaking data via the service's return values."
                ),
                technical_detail=(
                    f"Component: {name}\n"
                    f"Permission: {comp.permission or 'None'}\n"
                    f"Intent filter actions: {actions or 'None'}"
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="L"),
                evidence=[f"android:exported=\"true\" on <service android:name=\"{name}\">"],
                affected_components=[name],
                remediation=(
                    "Add android:permission with protectionLevel=\"signature\" "
                    "or set android:exported=\"false\" if the service is not required externally."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title=f"Start Exported Service",
                        description="Directly invoke the exported service",
                        code=(
                            f"# Start the service\n"
                            f"adb shell am startservice -n {ctx.package_name}/{name}\n\n"
                            f"# Start with intent extras\n"
                            f"adb shell am startservice -n {ctx.package_name}/{name} \\\n"
                            f"  --es 'command' 'FUZZ' \\\n"
                            f"  --es 'data' '../../../etc/passwd'"
                        ),
                    ),
                ],
                tags=["exported", "service", "ipc", "binder"],
            ))

    # ── Receiver ─────────────────────────────────────────────────────────────

    def _audit_receiver(self, ctx: AnalysisContext, comp: ManifestComponent):
        name = self._short(comp.name, ctx.package_name)
        has_protection = self._has_custom_permission(comp)
        actions = self._get_actions(comp)

        # Check for dangerous actions
        dangerous_actions = [
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.PACKAGE_ADDED",
            "android.intent.action.SMS_RECEIVED",
            "android.provider.Telephony.SMS_RECEIVED",
            "android.intent.action.PHONE_STATE",
        ]
        has_dangerous_action = any(a in dangerous_actions for a in actions)

        if not has_protection:
            self._add(Finding(
                id=f"COMP-RCV-{ctx.package_name}_{name.split('.')[-1]}",
                title=f"Unprotected Exported Broadcast Receiver: {name.split('.')[-1]}",
                category="Component Exposure",
                description=(
                    f"BroadcastReceiver {name} is exported without a custom permission. "
                    "Any app can send a broadcast to trigger this receiver's onReceive() handler. "
                    "This can be used to trigger state changes, inject fake system events, "
                    "or cause unintended app behavior."
                    + (" This receiver listens to sensitive system events." if has_dangerous_action else "")
                ),
                technical_detail=(
                    f"Component: {name}\n"
                    f"Permission: {comp.permission or 'None'}\n"
                    f"Listened actions: {actions}"
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U",
                                C="L", I="H" if has_dangerous_action else "L", A="N"),
                evidence=[
                    f"android:exported=\"true\" on <receiver android:name=\"{name}\">",
                    f"Actions: {actions}",
                ],
                affected_components=[name],
                remediation=(
                    "Add android:permission with protectionLevel=\"signature\". "
                    "When sending broadcasts to this receiver internally, "
                    "use sendBroadcast(intent, permission) or LocalBroadcastManager."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Send Spoofed Broadcast to Receiver",
                        description="Trigger the receiver's onReceive() with forged intent",
                        code=(
                            f"# Send a broadcast directly to the receiver\n"
                            f"adb shell am broadcast -n {ctx.package_name}/{name}\n\n"
                            + (
                                f"# Spoof the specific action it listens for\n"
                                f"adb shell am broadcast -a {actions[0]} -n {ctx.package_name}/{name} \\\n"
                                f"  --es 'extra_data' 'INJECTED'"
                                if actions else ""
                            )
                        ),
                    ),
                ],
                tags=["exported", "receiver", "broadcast", "ipc"],
            ))

    # ── Provider ─────────────────────────────────────────────────────────────

    def _audit_provider(self, ctx: AnalysisContext, comp: ManifestComponent):
        name = self._short(comp.name, ctx.package_name)
        has_read_perm  = bool(comp.permission)
        has_write_perm = bool(comp.permission)

        # Check read/write permissions separately in manifest
        # (androguard doesn't expose readPermission/writePermission directly,
        #  but we can check the component's permission field and authorities)

        for authority in comp.authorities:
            # Path traversal PoC
            traversal_uris = [
                f"content://{authority}/../../../data/data/{ctx.package_name}/databases/",
                f"content://{authority}/../../../data/data/{ctx.package_name}/shared_prefs/",
                f"content://{authority}/../../../../etc/passwd",
            ]

            sqli_uris = [
                f"content://{authority}/table' OR '1'='1",
                f"content://{authority}/table?where=1=1 UNION SELECT sqlite_version()--",
            ]

            self._add(Finding(
                id=f"COMP-PRV-{ctx.package_name}_{authority.split('.')[-1].replace('/', '_')}",
                title=f"Exported Content Provider: {name.split('.')[-1]} ({authority})",
                category="Content Provider Exposure",
                description=(
                    f"Content Provider {name} with authority \"{authority}\" is exported "
                    + ("without read/write permissions. " if not has_read_perm else "with permissions. ")
                    + "Content Providers are a frequent source of path traversal and SQL injection "
                    "vulnerabilities. Any app can query, insert, update, or delete data "
                    "if no permission is enforced."
                ),
                technical_detail=(
                    f"Authority: {authority}\n"
                    f"Component: {name}\n"
                    f"Permission: {comp.permission or 'None'}\n"
                    f"grantUriPermissions: {comp.grant_uri_permissions}\n"
                    f"Path permissions: {comp.path_permissions}"
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U",
                                C="H", I="H" if not has_read_perm else "L", A="N"),
                evidence=[
                    f"android:exported=\"true\" on <provider authority=\"{authority}\">",
                    f"readPermission: {comp.permission or 'NONE'}",
                ],
                affected_components=[name, authority],
                remediation=(
                    "Add android:readPermission and android:writePermission with "
                    "protectionLevel=\"signature\". Validate all URI paths server-side. "
                    "Use parameterized queries for all SQL operations. "
                    "Override openFile() with strict path canonicalization."
                ),
                pocs=[
                    PoC(
                        type="adb_command",
                        title="Content Provider Query (Baseline Access Test)",
                        description="Verify the provider responds to unauthenticated queries",
                        code=(
                            f"# Basic query — list all rows\n"
                            f"adb shell content query --uri content://{authority}/\n\n"
                            f"# Try common table names\n"
                            f"adb shell content query --uri content://{authority}/users\n"
                            f"adb shell content query --uri content://{authority}/accounts\n"
                            f"adb shell content query --uri content://{authority}/messages"
                        ),
                    ),
                    PoC(
                        type="adb_command",
                        title="Path Traversal via openFile()",
                        description="Attempt to read arbitrary files outside app sandbox",
                        code=(
                            "# Path traversal attempts via content URI\n"
                            + "\n".join(
                                f"adb shell content read --uri \"{uri}\""
                                for uri in traversal_uris
                            )
                        ),
                    ),
                    PoC(
                        type="python_script",
                        title="SQL Injection Probe via Content Provider",
                        description="Test for SQLi through Android content resolver",
                        code=(
                            "# Run this on-device via adb shell or Termux\n"
                            "# Requires: frida-tools or direct adb content commands\n\n"
                            + "\n".join(
                                f"adb shell content query --uri \"{uri}\""
                                for uri in sqli_uris
                            )
                            + "\n\n"
                            "# Python PoC (run on device via SL4A or scripting layer)\n"
                            "# from android import Android\n"
                            "# droid = Android()\n"
                            f"# droid.contentQueryAttributes('content://{authority}/table', "
                            f"['*'], \"1=1 UNION SELECT sqlite_version(),2,3--\", None)"
                        ),
                    ),
                ],
                tags=["content-provider", "exported", "sql-injection", "path-traversal"],
            ))

            # Grant URI permissions abuse
            if comp.grant_uri_permissions:
                self._add(Finding(
                    id=f"COMP-PRV-GRANT-{ctx.package_name}_{authority.split('.')[-1].replace('/', '_')}",
                    title=f"grantUriPermissions Enabled on Provider: {authority}",
                    category="Content Provider Exposure",
                    description=(
                        f"Content Provider {authority} has grantUriPermissions=true. "
                        "Combined with exported PendingIntents or Activities that pass "
                        "data back to the caller, this can allow permission escalation — "
                        "an unprivileged app receiving a URI grant gains read/write access "
                        "to protected content it would normally be denied."
                    ),
                    technical_detail=(
                        "grantUriPermissions=true means any component with a PendingIntent "
                        "to this provider can grant temporary URI permissions. "
                        "Combined with Intent.FLAG_GRANT_READ_URI_PERMISSION, "
                        "this bypasses the normal permission checks."
                    ),
                    cvss=CVSSVector(AV="L", AC="H", PR="N", UI="R", S="U", C="H", I="L", A="N"),
                    evidence=[f"android:grantUriPermissions=\"true\" on {authority}"],
                    affected_components=[name, authority],
                    remediation=(
                        "Use <grant-uri-permission> child elements to restrict which paths "
                        "can be granted instead of enabling global URI grants. "
                        "Audit all PendingIntents that reference this provider."
                    ),
                    tags=["content-provider", "grant-uri", "permission-escalation"],
                ))

    # ── Implicit Intent Vulnerabilities ──────────────────────────────────────

    def _check_implicit_intent_vulnerabilities(
        self, ctx: AnalysisContext, exported: List[ManifestComponent]
    ):
        """Find components that respond to implicit intents without restrictions."""
        for comp in exported:
            for ifilter in comp.intent_filters:
                actions = ifilter.get("actions", [])
                categories = ifilter.get("categories", [])
                # DEFAULT category + no permission = anyone can trigger
                if (
                    "android.intent.category.DEFAULT" in categories
                    and not comp.permission
                    and comp.component_type in ("activity", "service")
                ):
                    name = self._short(comp.name, ctx.package_name)
                    self._add(Finding(
                        id=f"COMP-IMPLICIT-{ctx.package_name}_{name.split('.')[-1]}",
                        title=f"Implicit Intent Interception Risk: {name.split('.')[-1]}",
                        category="Intent Security",
                        description=(
                            f"{comp.component_type.capitalize()} {name} responds to implicit intents "
                            f"with the DEFAULT category and no permission guard. "
                            "A malicious app declaring the same intent filter with higher priority "
                            "can intercept intents meant for this component, "
                            "stealing data or hijacking UI flows."
                        ),
                        technical_detail=(
                            f"Actions: {actions}\n"
                            f"Categories: {categories}\n"
                            "Intent resolution: implicit (no explicit component name required)"
                        ),
                        cvss=CVSSVector(AV="L", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
                        evidence=[
                            f"android.intent.category.DEFAULT on {name}",
                            f"No android:permission",
                            f"Actions: {actions}",
                        ],
                        affected_components=[name],
                        remediation=(
                            "Use explicit intents (specify component name) for internal communication. "
                            "Add a custom signature-level permission to protect this component. "
                            "Set android:exported=\"false\" if external intent handling is not required."
                        ),
                        tags=["implicit-intent", "interception", "intent-hijacking"],
                    ))
