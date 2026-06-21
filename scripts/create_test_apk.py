#!/usr/bin/env python3
"""
Create a minimal test APK with known vulnerabilities for Appraisal: DEX.
Embeds a valid DEX 035 binary with vulnerability-indicator strings in its pool.
"""

import logging
import sys
try:
    from loguru import logger as _ll
    _ll.remove()
    _ll.add(sys.stderr, level="CRITICAL")
except Exception:
    pass
import zipfile
import base64
import os
import sys
from pathlib import Path


# ── Pre-built, checksum-verified minimal DEX 035 (701 bytes) ─────────────────
# Contains string pool entries for every major vulnerability class:
# AWS key, ECB crypto, auth bypass, firebase, SQLi, XXE, deserialization, etc.
MINIMAL_DEX_B64 = (
    "ZGV4CjAzNQBpsnK9FKlQrRnZ5F6oWqCF9oLl4o7DVVW9AgAAcAAAAHhWNBIAAAAAAAAA"
    "AIkCAAAaAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADl"
    "AQAA2AAAANgAAADaAAAA8AAAAAYBAAAXAQAAKAEAAE4BAABVAQAAagEAAH0BAACRAQAAoQEA"
    "AK0BAACwAQAAwAEAAM8BAADZAQAA7wEAAP8BAAAhAgAAKgIAADMCAABRAgAAbQIAAHgCAACCAgAA"
    "AAAAFEFFUy9FQ0IvUEtDUzVQYWRkaW5nABRBS0lBSU9TRk9ETk43RVhBTVBMRQAPQmlv"
    "bWV0cmljUHJvbXB0AA9Eb2N1bWVudEJ1aWxkZXIAJExjb20vYXBwcmFpc2FsZGV4L3Rl"
    "c3QvTWFpbkFjdGl2aXR5OwAFTG9nLmQAE01PREVfV09STERfUkVBREFCTEUAEU9iamVj"
    "dElucHV0U3RyZWFtABJSdW50aW1lLmdldFJ1bnRpbWUADlNRTGl0ZURhdGFiYXNlAApT"
    "dHJpY3RNb2RlAAFWAA5aaXBJbnB1dFN0cmVhbQANY29tLm9uZXNpZ25hbAAIZmlyZWJh"
    "c2UAFGdldFNoYXJlZFByZWZlcmVuY2VzAA5nZXRTdHJpbmdFeHRyYQAgaHR0cDovL2Fw"
    "aS5pbnRlcm5hbC5leGFtcGxlLmNvbS8AB2lzQWRtaW4AB2xvYWRVcmwAHG15YXBwLWRl"
    "ZmF1bHQuZmlyZWJhc2Vpby5jb20AGnBhc3N3b3JkPXNlY3JldHBhc3N3b3JkMTIzAAlw"
    "dXRTdHJpbmcACHJhd1F1ZXJ5AAV0b2tlbgAEAAAAAAAAAAEAAAAAAAAA"
    "AQAAAB oAAAACIAAAGgAAANgAAAAA"
    "EAAAAQAAAIkCAAA="
)

# The above has a whitespace issue — use the clean verified bytes directly
import struct, zlib, hashlib

def _build_dex() -> bytes:
    """Rebuild the DEX programmatically — guaranteed correct checksums."""
    def uleb128(n):
        r = b''
        while True:
            b = n & 0x7f
            n >>= 7
            if n: b |= 0x80
            r += bytes([b])
            if not n: break
        return r

    STRINGS = sorted(set([
        '', 'V',
        'Lcom/appraisaldex/test/MainActivity;',
        'password=secretpassword123',
        'AKIAIOSFODNN7EXAMPLE',
        'AES/ECB/PKCS5Padding',
        'getStringExtra', 'loadUrl', 'isAdmin',
        'http://api.internal.example.com/',
        'BiometricPrompt', 'ObjectInputStream',
        'MODE_WORLD_READABLE', 'StrictMode',
        'SQLiteDatabase', 'rawQuery',
        'Runtime.getRuntime', 'ZipInputStream',
        'DocumentBuilder', 'firebase',
        'myapp-default.firebaseio.com',
        'Log.d', 'putString', 'token',
        'getSharedPreferences', 'com.onesignal',
    ]))

    STR_IDS_OFF   = 0x70
    STR_IDS_BYTES = len(STRINGS) * 4
    STR_DATA_OFF  = STR_IDS_OFF + STR_IDS_BYTES

    cur = STR_DATA_OFF
    str_data = b''
    str_offs = {}
    for s in STRINGS:
        str_offs[s] = cur
        enc  = s.encode('utf-8')
        item = uleb128(len(enc)) + enc + b'\x00'
        str_data += item
        cur += len(item)

    MAP_OFF = cur
    MAP_ITEMS = [
        (0x0000, 1,            0),
        (0x0001, len(STRINGS), STR_IDS_OFF),
        (0x2002, len(STRINGS), STR_DATA_OFF),
        (0x1000, 1,            MAP_OFF),
    ]
    map_b = struct.pack('<I', len(MAP_ITEMS))
    for t, sz, off in MAP_ITEMS:
        map_b += struct.pack('<HHI', t, 0, sz) + struct.pack('<I', off)

    FILE_SIZE = MAP_OFF + len(map_b)
    DATA_SIZE = FILE_SIZE - STR_DATA_OFF

    def hdr(sig, chk):
        h  = b'dex\n035\x00'
        h += struct.pack('<I', chk)
        h += sig
        h += struct.pack('<I', FILE_SIZE)
        h += struct.pack('<I', 0x70)
        h += struct.pack('<I', 0x12345678)
        h += struct.pack('<II', 0, 0)
        h += struct.pack('<I',  MAP_OFF)
        h += struct.pack('<II', len(STRINGS), STR_IDS_OFF)
        h += struct.pack('<II', 0, 0)
        h += struct.pack('<II', 0, 0)
        h += struct.pack('<II', 0, 0)
        h += struct.pack('<II', 0, 0)
        h += struct.pack('<II', 0, 0)
        h += struct.pack('<II', DATA_SIZE, STR_DATA_OFF)
        assert len(h) == 0x70
        return h

    str_ids = b''.join(struct.pack('<I', str_offs[s]) for s in STRINGS)
    body    = str_ids + str_data + map_b
    f1      = hdr(b'\x00'*20, 0) + body
    sig     = hashlib.sha1(f1[32:]).digest()
    f2      = hdr(sig, 0) + body
    chk     = zlib.adler32(f2[12:]) & 0xFFFFFFFF
    return hdr(sig, chk) + body


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
        <activity android:name=".MainActivity" android:exported="true">
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
        <activity android:name=".AdminActivity" android:exported="true" />
        <service android:name=".BackgroundService" android:exported="true" />
        <receiver android:name=".BootReceiver" android:exported="true">
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


def create_test_apk(output_path: str = "tests/samples/vuln_test.apk") -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    print(f"Building test APK: {out}")

    dex_bytes = _build_dex()

    with zipfile.ZipFile(str(out), "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", MANIFEST_CONTENT)
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("res/xml/network_security_config.xml", b"""<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" overridesPins="true"/>
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">*.example.com</domain>
        <pin-set expiration="2020-01-01"></pin-set>
    </domain-config>
</network-security-config>""")
        zf.writestr("res/values/strings.xml", b"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">VulnTestApp</string>
    <string name="api_key">AIzaSyBadKeyExample12345678901234</string>
    <string name="firebase_url">https://vuln-test-default-rtdb.firebaseio.com</string>
</resources>""")
        zf.writestr("lib/arm64-v8a/libnative.so", os.urandom(4096))
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")

    # Validate it parses correctly — silence logs during check
    for _ln in ["androguard","androguard.core","androguard.core.dex","androguard.core.analysis"]:
        logging.getLogger(_ln).setLevel(logging.CRITICAL)
    for n in ['androguard','androguard.core','androguard.core.dex']:
        logging.getLogger(n).setLevel(logging.CRITICAL)
    from androguard.core.dex import DEX
    with zipfile.ZipFile(str(out)) as zf:
        d = DEX(zf.read("classes.dex"))
        strings = list(d.get_strings())

    size = out.stat().st_size
    print(f"Created: {out} ({size:,} bytes)")
    print(f"DEX:     {len(dex_bytes)} bytes, {len(strings)} strings in pool")
    print(f"Strings: {[s.decode() if isinstance(s,bytes) else s for s in strings[:5]]}...")
    return str(out)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "tests/samples/vuln_test.apk"
    create_test_apk(path)
    print(f"\nRun: appraisal-dex scan {path} --html --json --pocs -o ./test_report")
