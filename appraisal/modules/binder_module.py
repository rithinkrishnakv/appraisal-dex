"""
SKILL: Binder Breach [UNIQUE]
IPC attack surface analysis — AIDL interface extraction,
PendingIntent mutability auditing, Parcelable mismatch detection,
and broadcast security validation.
"""

import re
from typing import List, Set
from appraisal.engine.base_module import BaseModule
from appraisal.engine.loader import AnalysisContext
from appraisal.models import Finding, CVSSVector, PoC, SkillType, Rank


class BinderBreachModule(BaseModule):
    SKILL_NAME  = "Binder Breach"
    SKILL_TYPE  = SkillType.UNIQUE
    DESCRIPTION = "IPC attack surface: AIDL, PendingIntent mutability, Parcelable mismatch, broadcast auth"

    def run(self, ctx: AnalysisContext) -> List[Finding]:
        self._findings = []
        self._check_pending_intent_mutability(ctx)
        self._check_parcelable_mismatch(ctx)
        self._check_aidl_interfaces(ctx)
        self._check_ordered_broadcast_abuse(ctx)
        self._check_sticky_broadcasts(ctx)
        self._check_protected_broadcasts(ctx)
        self._check_dynamic_receiver_registration(ctx)
        return self._findings

    # ── PendingIntent mutability ──────────────────────────────────────────────

    def _check_pending_intent_mutability(self, ctx: AnalysisContext):
        """Detect mutable PendingIntents — Android 12 permission bypass vector."""
        MUTABLE_FLAG    = "FLAG_MUTABLE"
        IMMUTABLE_FLAG  = "FLAG_IMMUTABLE"
        PENDING_CLASSES = [
            "PendingIntent.getActivity",
            "PendingIntent.getService",
            "PendingIntent.getBroadcast",
            "PendingIntent.getForegroundService",
        ]

        string_pool = " ".join(ctx.strings_pool)
        has_pending_intent = "PendingIntent" in string_pool
        has_mutable        = MUTABLE_FLAG  in string_pool
        has_immutable      = IMMUTABLE_FLAG in string_pool

        if not has_pending_intent:
            return

        if has_mutable:
            self._add(Finding(
                id="BINDER-PENDING-MUTABLE",
                title="Mutable PendingIntent Detected (FLAG_MUTABLE) — Intent Hijacking Risk",
                category="IPC Security",
                description=(
                    "FLAG_MUTABLE is used when creating a PendingIntent. "
                    "A mutable PendingIntent allows other apps to modify the intent's "
                    "extras before it is dispatched. "
                    "If this PendingIntent is sent to a third-party component (e.g., notification, "
                    "AlarmManager, or MediaSession), a malicious app that receives it can "
                    "fill in blank fields, override extras, or redirect the action "
                    "to a different component — bypassing Android's permission model."
                ),
                technical_detail=(
                    "FLAG_MUTABLE found in DEX string pool alongside PendingIntent usage. "
                    "The canonical attack: malicious app receives PendingIntent via "
                    "an implicit broadcast or shared service, modifies extras, "
                    "and sends it to a privileged system component."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=["FLAG_MUTABLE in PendingIntent creation"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use FLAG_IMMUTABLE unless you explicitly require mutability (e.g., for bubbles). "
                    "On Android 12+ (API 31+), FLAG_IMMUTABLE is the default. "
                    "When mutability is required, always specify all intent extras explicitly — "
                    "never leave them blank for a third party to fill in."
                ),
                pocs=[PoC(
                    type="python_script",
                    title="Mutable PendingIntent Exploitation (Conceptual PoC)",
                    description="Demonstrates how a malicious app hijacks a mutable PendingIntent",
                    code=(
                        "// Attacker app receives the mutable PendingIntent\n"
                        "// (e.g., via notification action or AlarmManager)\n\n"
                        "// Malicious Activity that hijacks the PendingIntent:\n"
                        "public class MaliciousReceiver extends BroadcastReceiver {\n"
                        "    @Override\n"
                        "    public void onReceive(Context ctx, Intent intent) {\n"
                        "        PendingIntent pi = intent.getParcelableExtra(\"pendingIntent\");\n"
                        "        if (pi == null) return;\n"
                        "        \n"
                        "        // Fill in the blank mutable intent with malicious data\n"
                        "        Intent malicious = new Intent();\n"
                        "        malicious.setComponent(new ComponentName(\n"
                        f"            \"{ctx.package_name}\",\n"
                        f"            \"{ctx.package_name}.PrivilegedActivity\"));\n"
                        "        malicious.putExtra(\"isAdmin\", true);\n"
                        "        malicious.putExtra(\"userId\", 0);\n"
                        "        \n"
                        "        try {\n"
                        "            pi.send(ctx, 0, malicious); // Fires with TARGET app's identity\n"
                        "        } catch (PendingIntent.CanceledException e) {}\n"
                        "    }\n"
                        "}"
                    ),
                )],
                references=[
                    "https://blog.oversecured.com/Android-security-vulnerability-leading-to-privilege-escalation/",
                    "https://developer.android.com/reference/android/app/PendingIntent#FLAG_MUTABLE",
                ],
                tags=["pending-intent", "ipc", "intent-hijacking", "privilege-escalation"],
            ))

        if not has_immutable and has_pending_intent:
            self._add(Finding(
                id="BINDER-PENDING-NOFLAG",
                title="PendingIntent Created Without FLAG_IMMUTABLE or FLAG_MUTABLE",
                category="IPC Security",
                description=(
                    "PendingIntent is used without explicitly specifying FLAG_IMMUTABLE "
                    "or FLAG_MUTABLE. On Android < 12 (API 31), this defaults to mutable, "
                    "which is insecure. On Android 12+, this throws an exception. "
                    "Unspecified flags represent either a security bug or a compatibility issue."
                ),
                technical_detail="PendingIntent usage without explicit mutability flag.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="N"),
                evidence=["PendingIntent without FLAG_IMMUTABLE/FLAG_MUTABLE"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Always specify FLAG_IMMUTABLE for PendingIntents that don't require modification: "
                    "PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_IMMUTABLE)."
                ),
                tags=["pending-intent", "ipc", "flag-missing"],
                _rank=Rank.D,
            ))

    # ── Parcelable mismatch detection ─────────────────────────────────────────

    def _check_parcelable_mismatch(self, ctx: AnalysisContext):
        """
        Detect Parcelable implementations where writeToParcel and createFromParcel
        may have asymmetric field counts — the Android permission bypass bug class.
        """
        parcelable_classes = []
        mismatch_candidates = []

        try:
            for cls in ctx.analysis.get_classes():
                cls_name = str(cls.name)
                method_names = [str(m.name) for m in cls.get_methods()]

                has_write  = "writeToParcel"    in method_names
                has_create = "createFromParcel" in method_names

                if has_write and has_create:
                    parcelable_classes.append(cls_name)

                    # Count write/read operations per method as heuristic
                    write_ops = 0
                    read_ops  = 0

                    for method in cls.get_methods():
                        if str(method.name) not in ("writeToParcel", "createFromParcel"):
                            continue
                        try:
                            m = method.get_method()
                            if not m:
                                continue
                            code = m.get_code()
                            if not code:
                                continue
                            for ins in code.get_bc().get_instructions():
                                ins_str = str(ins)
                                if "writeInt" in ins_str or "writeString" in ins_str \
                                        or "writeParcelable" in ins_str or "writeLong" in ins_str \
                                        or "writeFloat" in ins_str or "writeList" in ins_str:
                                    if str(method.name) == "writeToParcel":
                                        write_ops += 1
                                if "readInt" in ins_str or "readString" in ins_str \
                                        or "readParcelable" in ins_str or "readLong" in ins_str \
                                        or "readFloat" in ins_str or "readList" in ins_str:
                                    if str(method.name) == "createFromParcel":
                                        read_ops += 1
                        except Exception:
                            continue

                    # Asymmetric write/read counts = potential mismatch
                    if abs(write_ops - read_ops) >= 2 and (write_ops + read_ops) > 0:
                        mismatch_candidates.append((cls_name, write_ops, read_ops))

        except Exception:
            pass

        for cls_name, writes, reads in mismatch_candidates:
            short = cls_name.split("/")[-1].rstrip(";")
            self._add(Finding(
                id=f"BINDER-PARCEL-{short[:25].replace('$','_')}",
                title=f"Parcelable Write/Read Asymmetry in {short} — Bundle Mismatch Risk",
                category="IPC Security",
                description=(
                    f"Parcelable class {short} has {writes} write operations in writeToParcel() "
                    f"but {reads} read operations in createFromParcel(). "
                    "Asymmetric Parcelable implementations are the root cause of the "
                    "Android Bundle Mismatch vulnerability class — a bug that allows "
                    "privilege escalation by bypassing intent-based permission checks "
                    "at the system level (system_server vs app). "
                    "An attacker can craft a Bundle that is deserialized differently "
                    "by the system server vs the target app."
                ),
                technical_detail=(
                    f"Class: {cls_name}\n"
                    f"writeToParcel() write calls: {writes}\n"
                    f"createFromParcel() read calls: {reads}\n"
                    f"Difference: {abs(writes - reads)} fields"
                ),
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="C", C="H", I="H", A="N"),
                evidence=[
                    f"{short}.writeToParcel: {writes} write ops",
                    f"{short}.createFromParcel: {reads} read ops",
                ],
                affected_components=[cls_name],
                remediation=(
                    "Ensure writeToParcel() and createFromParcel() write/read "
                    "the exact same fields in the exact same order. "
                    "Use Android Studio's auto-generation or Kotlin @Parcelize. "
                    "Add unit tests that round-trip every Parcelable through a Parcel."
                ),
                references=[
                    "https://blog.oversecured.com/Android-Parcel-deserialization-vulnerabilities/",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0928",
                ],
                tags=["parcelable", "bundle-mismatch", "privilege-escalation", "binder"],
            ))

    # ── AIDL interface exposure ───────────────────────────────────────────────

    def _check_aidl_interfaces(self, ctx: AnalysisContext):
        """Find AIDL stub/proxy patterns indicating Binder service interfaces."""
        aidl_classes = []

        try:
            for cls in ctx.analysis.get_classes():
                cls_name = str(cls.name)
                method_names = [str(m.name) for m in cls.get_methods()]

                # AIDL generated classes contain Stub and Proxy inner classes
                is_stub  = "Stub"  in cls_name and "asInterface" in method_names
                is_proxy = "Proxy" in cls_name and "transact"    in method_names

                if is_stub or is_proxy:
                    aidl_classes.append((cls_name, is_stub, method_names))
        except Exception:
            pass

        if not aidl_classes:
            return

        # Group by interface (strip Stub/Proxy suffix)
        interfaces: Set[str] = set()
        for cls_name, is_stub, methods in aidl_classes:
            base = cls_name.replace("$Stub", "").replace("$Proxy", "").replace("Stub", "")
            interfaces.add(base)

        for iface in interfaces:
            # Find methods for this interface
            iface_methods = []
            for cls_name, is_stub, methods in aidl_classes:
                if iface in cls_name:
                    for m in methods:
                        if m not in ("onTransact", "transact", "asBinder",
                                     "asInterface", "attachInterface"):
                            iface_methods.append(m)

            iface_short = iface.split("/")[-1].rstrip(";").replace("$", ".")

            self._add(Finding(
                id=f"BINDER-AIDL-{iface_short[:25].replace('.','_')}",
                title=f"AIDL Binder Interface Exposed: {iface_short}",
                category="IPC Security",
                description=(
                    f"AIDL Binder interface {iface_short} was detected. "
                    "AIDL interfaces define RPC methods callable across process boundaries. "
                    "If the hosting service is exported without permission, "
                    "these methods are callable by any app on the device. "
                    "Bugs in onTransact() handling (null Parcelables, type confusion, "
                    "integer overflow) can lead to privilege escalation or data leaks."
                ),
                technical_detail=(
                    f"Interface: {iface}\n"
                    f"Exposed methods: {list(set(iface_methods))[:15]}\n"
                    "Attack: bind to the service, construct malformed Parcel, call onTransact()"
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
                evidence=[f"AIDL stub/proxy detected: {iface}"],
                affected_components=[iface],
                remediation=(
                    "Protect the hosting service with android:permission=\"protectionLevel:signature\". "
                    "Validate all Parcel inputs in onTransact() before processing. "
                    "Fuzz the interface with null/empty/malformed Parcelables."
                ),
                pocs=[PoC(
                    type="python_script",
                    title="AIDL Interface Binder Fuzzer (Concept)",
                    description="Bind to the service and send malformed transactions",
                    code=(
                        "// Attacker app — bind to target service\n"
                        "Intent intent = new Intent();\n"
                        f"intent.setComponent(new ComponentName(\"{ctx.package_name}\",\n"
                        f"    \"{iface.replace('/', '.').strip('L;')}\"));\n"
                        "bindService(intent, new ServiceConnection() {\n"
                        "    @Override\n"
                        "    public void onServiceConnected(ComponentName name, IBinder binder) {\n"
                        "        // Send malformed transaction codes\n"
                        "        for (int code = 1; code <= 20; code++) {\n"
                        "            Parcel data  = Parcel.obtain();\n"
                        "            Parcel reply = Parcel.obtain();\n"
                        "            try {\n"
                        "                data.writeInterfaceToken(binder.getInterfaceDescriptor());\n"
                        "                data.writeString(null);  // null injection\n"
                        "                data.writeInt(-1);       // negative int\n"
                        "                binder.transact(code, data, reply, 0);\n"
                        "                Log.d(\"FUZZ\", \"Code \" + code + \" succeeded\");\n"
                        "            } catch (Exception e) {\n"
                        "                Log.d(\"FUZZ\", \"Code \" + code + \" threw: \" + e);\n"
                        "            } finally {\n"
                        "                data.recycle(); reply.recycle();\n"
                        "            }\n"
                        "        }\n"
                        "    }\n"
                        "    public void onServiceDisconnected(ComponentName name) {}\n"
                        "}, Context.BIND_AUTO_CREATE);"
                    ),
                )],
                tags=["aidl", "binder", "ipc", "fuzzing"],
            ))

    # ── Ordered broadcast abuse ───────────────────────────────────────────────

    def _check_ordered_broadcast_abuse(self, ctx: AnalysisContext):
        string_pool = " ".join(ctx.strings_pool)
        if "sendOrderedBroadcast" in string_pool:
            self._add(Finding(
                id="BINDER-ORDERED-BCAST",
                title="sendOrderedBroadcast Used — Result Manipulation Risk",
                category="IPC Security",
                description=(
                    "sendOrderedBroadcast() is used. Ordered broadcasts are delivered "
                    "serially to receivers sorted by priority. A high-priority malicious "
                    "receiver can intercept and modify the result data or abort the broadcast "
                    "entirely before it reaches the intended receiver."
                ),
                technical_detail=(
                    "sendOrderedBroadcast in DEX string pool. "
                    "A malicious app can declare a receiver with higher priority "
                    "for the same action and abort/modify the broadcast."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="L"),
                evidence=["sendOrderedBroadcast in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Use LocalBroadcastManager for intra-app communication. "
                    "Add a permission parameter to sendOrderedBroadcast() "
                    "to restrict which receivers can process it."
                ),
                tags=["broadcast", "ordered-broadcast", "interception"],
                _rank=Rank.C,
            ))

    # ── Sticky broadcast usage ────────────────────────────────────────────────

    def _check_sticky_broadcasts(self, ctx: AnalysisContext):
        string_pool = " ".join(ctx.strings_pool)
        if "sendStickyBroadcast" in string_pool:
            self._add(Finding(
                id="BINDER-STICKY-BCAST",
                title="sendStickyBroadcast Used — Deprecated, Data Exposure Risk",
                category="IPC Security",
                description=(
                    "sendStickyBroadcast() is used. Sticky broadcasts persist in the system "
                    "and are delivered to any app that registers a matching receiver — "
                    "even after the original broadcast was sent. "
                    "Any app can call removeStickyBroadcast() if it has the right permission. "
                    "This API is deprecated since API 21 and should not be used."
                ),
                technical_detail="sendStickyBroadcast in DEX pool. Deprecated API, system-wide data exposure.",
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=["sendStickyBroadcast in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Replace sticky broadcasts with explicit bound services, "
                    "SharedPreferences with FileObserver, or LiveData/EventBus for in-app events."
                ),
                tags=["broadcast", "sticky-broadcast", "deprecated"],
                _rank=Rank.C,
            ))

    # ── Protected broadcast spoofing check ───────────────────────────────────

    def _check_protected_broadcasts(self, ctx: AnalysisContext):
        """
        Check if the app registers receivers for system-protected broadcasts
        without verifying the sender — a trust-without-verification pattern.
        """
        PROTECTED_ACTIONS = [
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.PACKAGE_REPLACED",
            "android.intent.action.USER_PRESENT",
            "android.net.conn.CONNECTIVITY_CHANGE",
            "android.intent.action.ACTION_POWER_CONNECTED",
            "android.telephony.action.SIM_CARD_STATE_CHANGED",
        ]

        for comp in ctx.components:
            if comp.component_type != "receiver":
                continue
            for ifilter in comp.intent_filters:
                for action in ifilter.get("actions", []):
                    if action in PROTECTED_ACTIONS and not comp.permission:
                        short = comp.name.split(".")[-1]
                        self._add(Finding(
                            id=f"BINDER-PROTBCAST-{short[:20].replace('$','_')}",
                            title=f"Receiver for Protected Broadcast Without Verification: {action.split('.')[-1]}",
                            category="IPC Security",
                            description=(
                                f"Receiver {comp.name} listens for the protected broadcast "
                                f"\"{action}\" without declaring a permission. "
                                "While this specific action is protected (only system can send it), "
                                "any logic in onReceive() that makes security decisions "
                                "based on action name alone — without verifying the sender — "
                                "is vulnerable to spoofing from future permission changes or "
                                "custom ROM modifications."
                            ),
                            technical_detail=(
                                f"Receiver: {comp.name}\n"
                                f"Action: {action}\n"
                                f"Permission: None"
                            ),
                            cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                            evidence=[f"<action android:name=\"{action}\"/> on {comp.name}"],
                            affected_components=[comp.name],
                            remediation=(
                                "Verify intent sender identity in onReceive() when making "
                                "security-sensitive decisions. "
                                "Add android:permission to restrict who can trigger this receiver."
                            ),
                            tags=["broadcast", "protected-broadcast", "receiver"],
                            _rank=Rank.D,
                        ))

    # ── Dynamic receiver registration ─────────────────────────────────────────

    def _check_dynamic_receiver_registration(self, ctx: AnalysisContext):
        """Detect dynamically registered receivers without permission."""
        string_pool = " ".join(ctx.strings_pool)
        if "registerReceiver" in string_pool:
            self._add(Finding(
                id="BINDER-DYNREG",
                title="Dynamic BroadcastReceiver Registration Detected",
                category="IPC Security",
                description=(
                    "registerReceiver() is called at runtime. "
                    "Dynamically registered receivers inherit the process context "
                    "and are often registered without a permission parameter, "
                    "making them accessible to any broadcaster on the device. "
                    "On Android < 13, dynamic receivers are exported by default."
                ),
                technical_detail=(
                    "registerReceiver() in DEX string pool. "
                    "On Android 13+ (API 33), Context.RECEIVER_EXPORTED or "
                    "RECEIVER_NOT_EXPORTED must be specified."
                ),
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="N"),
                evidence=["registerReceiver() call in DEX string pool"],
                affected_components=[ctx.package_name],
                remediation=(
                    "Pass a permission string to registerReceiver(): "
                    "registerReceiver(receiver, filter, MY_PERMISSION, handler). "
                    "On Android 13+, pass RECEIVER_NOT_EXPORTED as the last flag "
                    "if the receiver is internal only."
                ),
                tags=["dynamic-receiver", "broadcast", "ipc"],
                _rank=Rank.D,
            ))
