#!/usr/bin/env python3
"""
Create a minimal test APK with known vulnerabilities for testing Appraisal: DEX.
This APK is intentionally vulnerable — DO NOT distribute.
"""

import zipfile
import struct
import os
import sys
from pathlib import Path


# Minimal AndroidManifest.xml (binary XML — this is a pre-encoded version)
# For testing purposes we use a raw manifest string that androguard can parse
# In production you'd compile with aapt, but for unit tests we embed a stub.

MANIFEST_CONTENT = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.appraisaldex.test"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="16" android:targetSdkVersion="28" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

    <application
        android:label="VulnTestApp"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="vulnapp" android:host="open" />
            </intent-filter>
        </activity>

        <activity
            android:name=".AdminActivity"
            android:exported="true" />

        <service
            android:name=".BackgroundService"
            android:exported="true" />

        <receiver
            android:name=".BootReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

        <provider
            android:name=".DataProvider"
            android:authorities="com.appraisaldex.test.provider"
            android:exported="true"
            android:grantUriPermissions="true" />

    </application>
</manifest>"""

CLASSES_DEX_STUB = b"dex\n035\x00" + b"\x00" * 100  # Minimal DEX stub


def create_test_apk(output_path: str = "tests/samples/vuln_test.apk"):
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Creating test APK at: {out}")

    with zipfile.ZipFile(str(out), "w", zipfile.ZIP_DEFLATED) as zf:
        # AndroidManifest.xml
        zf.writestr("AndroidManifest.xml", MANIFEST_CONTENT)

        # Minimal classes.dex
        zf.writestr("classes.dex", CLASSES_DEX_STUB)

        # res/xml/network_security_config.xml
        nsc = b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" overridesPins="true"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">*.example.com</domain>
        <pin-set expiration="2020-01-01">
        </pin-set>
    </domain-config>
</network-security-config>"""
        zf.writestr("res/xml/network_security_config.xml", nsc)

        # Dummy resources
        zf.writestr("res/values/strings.xml", b"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">VulnTestApp</string>
    <string name="api_key">AIzaSyBadKeyExample12345678901234</string>
    <string name="firebase_url">https://vuln-test-default-rtdb.firebaseio.com</string>
</resources>""")

        # Native lib stub (high entropy for packing test)
        import os
        zf.writestr("lib/arm64-v8a/libnative.so", os.urandom(4096))

        # META-INF
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")

    print(f"✓ Test APK created: {out} ({out.stat().st_size} bytes)")
    return str(out)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/samples/vuln_test.apk"
    created = create_test_apk(path)
    print(f"\nTest APK ready. Run appraisal:")
    print(f"  python -m appraisal.cli scan {created}")
    print(f"  # OR after pip install -e .")
    print(f"  appraisal-dex scan {created} --html --pocs")
