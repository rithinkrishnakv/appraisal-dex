"""
SKILL: DEX Dissection [UNIQUE]
The APK loader — turns a binary into a fully parsed analysis context.
Everything the modules need flows from here.
"""

import os
import zipfile
import hashlib
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX


@dataclass
class ManifestComponent:
    """A parsed Android component from the manifest."""
    name: str
    component_type: str          # activity | service | receiver | provider
    exported: Optional[bool]
    permission: Optional[str]
    intent_filters: List[Dict]   = field(default_factory=list)
    authorities: List[str]       = field(default_factory=list)
    grant_uri_permissions: bool  = False
    path_permissions: List[Dict] = field(default_factory=list)
    debuggable: bool             = False
    allow_backup: bool           = False
    other_attrs: Dict            = field(default_factory=dict)


@dataclass
class AnalysisContext:
    """
    The full parsed state of an APK — every module reads from this.
    Built once, shared everywhere.
    """
    apk_path: str
    apk: APK
    dex_list: List[DEX]
    analysis: Analysis
    manifest_xml: str
    manifest_tree: ET.Element
    package_name: str
    app_name: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    permissions: List[str]
    components: List[ManifestComponent]
    file_list: List[str]
    sha256: str
    md5: str
    size_bytes: int
    has_native_libs: bool
    native_lib_names: List[str]
    has_network_security_config: bool
    network_security_config_xml: Optional[str]
    has_backup_rules: bool
    strings_pool: List[str]
    raw_bytes: bytes


ANDROID_NS = "http://schemas.android.com/apk/res/android"

def _attr(element: ET.Element, name: str) -> Optional[str]:
    """Pull an android: attribute from an XML element."""
    return element.get(f"{{{ANDROID_NS}}}{name}")


def _compute_hashes(apk_path: str) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _parse_intent_filters(component_el: ET.Element) -> List[Dict]:
    filters = []
    for ifilter in component_el.findall("intent-filter"):
        f: Dict[str, Any] = {"actions": [], "categories": [], "data": []}
        for action in ifilter.findall("action"):
            name = _attr(action, "name")
            if name:
                f["actions"].append(name)
        for cat in ifilter.findall("category"):
            name = _attr(cat, "name")
            if name:
                f["categories"].append(name)
        for data in ifilter.findall("data"):
            d: Dict[str, Optional[str]] = {
                "scheme": _attr(data, "scheme"),
                "host":   _attr(data, "host"),
                "port":   _attr(data, "port"),
                "path":   _attr(data, "path"),
                "pathPrefix":  _attr(data, "pathPrefix"),
                "pathPattern": _attr(data, "pathPattern"),
                "mimeType":    _attr(data, "mimeType"),
            }
            f["data"].append({k: v for k, v in d.items() if v is not None})
        filters.append(f)
    return filters


def _parse_components(manifest_tree: ET.Element) -> List[ManifestComponent]:
    components = []
    app_el = manifest_tree.find("application")
    if app_el is None:
        return components

    tag_map = {
        "activity":         "activity",
        "activity-alias":   "activity",
        "service":          "service",
        "receiver":         "receiver",
        "provider":         "provider",
    }

    for tag, ctype in tag_map.items():
        for el in app_el.findall(tag):
            name       = _attr(el, "name") or ""
            exported   = _attr(el, "exported")
            permission = _attr(el, "permission")

            exported_bool: Optional[bool] = None
            if exported == "true":
                exported_bool = True
            elif exported == "false":
                exported_bool = False

            intent_filters = _parse_intent_filters(el)

            # Implicitly exported if it has intent filters and exported isn't false
            if exported_bool is None and intent_filters:
                exported_bool = True

            authorities: List[str] = []
            grant_uri = False
            path_permissions: List[Dict] = []
            if ctype == "provider":
                auths = _attr(el, "authorities") or ""
                authorities = [a.strip() for a in auths.split(";") if a.strip()]
                grant_uri = (_attr(el, "grantUriPermissions") or "false").lower() == "true"
                for pp in el.findall("path-permission"):
                    path_permissions.append({
                        "path":            _attr(pp, "path"),
                        "pathPrefix":      _attr(pp, "pathPrefix"),
                        "pathPattern":     _attr(pp, "pathPattern"),
                        "readPermission":  _attr(pp, "readPermission"),
                        "writePermission": _attr(pp, "writePermission"),
                    })

            components.append(ManifestComponent(
                name=name,
                component_type=ctype,
                exported=exported_bool,
                permission=permission,
                intent_filters=intent_filters,
                authorities=authorities,
                grant_uri_permissions=grant_uri,
                path_permissions=path_permissions,
            ))

    return components


def _extract_strings_pool(dex_list: List[DEX]) -> List[str]:
    strings: List[str] = []
    for dex in dex_list:
        try:
            for s in dex.get_strings():
                if isinstance(s, bytes):
                    try:
                        strings.append(s.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
                else:
                    strings.append(str(s))
        except Exception:
            pass
    return strings


def load_apk(apk_path: str) -> AnalysisContext:
    """
    Parse an APK into a full AnalysisContext.
    This is the only entry point every module uses.
    """
    path = Path(apk_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    if not path.suffix.lower() == ".apk":
        raise ValueError(f"Not an APK file: {apk_path}")

    raw_bytes = path.read_bytes()
    sha256, md5 = _compute_hashes(str(path))
    size_bytes   = path.stat().st_size

    apk_obj, dex_list, analysis = AnalyzeAPK(str(path))

    # ── Manifest ──────────────────────────────────────────────────────────────
    manifest_xml = apk_obj.get_android_manifest_xml()
    if hasattr(manifest_xml, "toprettyxml"):
        manifest_str = manifest_xml.toprettyxml()
    else:
        manifest_str = str(manifest_xml)

    try:
        manifest_tree = ET.fromstring(manifest_str)
    except ET.ParseError:
        manifest_tree = ET.Element("manifest")

    # ── Basic metadata ────────────────────────────────────────────────────────
    package_name  = apk_obj.get_package() or "unknown"
    app_name      = apk_obj.get_app_name() or package_name
    version_name  = apk_obj.get_androidversion_name() or "unknown"
    version_code  = apk_obj.get_androidversion_code() or "0"
    min_sdk       = int(apk_obj.get_min_sdk_version() or 1)
    target_sdk    = int(apk_obj.get_target_sdk_version() or 1)
    permissions   = list(apk_obj.get_permissions() or [])

    # ── File inventory ────────────────────────────────────────────────────────
    file_list: List[str] = []
    try:
        with zipfile.ZipFile(str(path), "r") as zf:
            file_list = zf.namelist()
    except Exception:
        pass

    native_lib_names = [f for f in file_list if f.endswith(".so")]
    has_native_libs  = bool(native_lib_names)

    # ── Network security config ───────────────────────────────────────────────
    nsc_path = "res/xml/network_security_config.xml"
    has_nsc  = nsc_path in file_list
    nsc_xml: Optional[str] = None
    if has_nsc:
        try:
            nsc_xml = apk_obj.get_file(nsc_path).decode("utf-8", errors="ignore")
        except Exception:
            pass

    # ── Components ───────────────────────────────────────────────────────────
    components = _parse_components(manifest_tree)

    # ── String pool ──────────────────────────────────────────────────────────
    strings_pool = _extract_strings_pool(dex_list if isinstance(dex_list, list) else [dex_list])

    return AnalysisContext(
        apk_path      = str(path),
        apk           = apk_obj,
        dex_list      = dex_list if isinstance(dex_list, list) else [dex_list],
        analysis      = analysis,
        manifest_xml  = manifest_str,
        manifest_tree = manifest_tree,
        package_name  = package_name,
        app_name      = app_name,
        version_name  = version_name,
        version_code  = str(version_code),
        min_sdk       = min_sdk,
        target_sdk    = target_sdk,
        permissions   = permissions,
        components    = components,
        file_list     = file_list,
        sha256        = sha256,
        md5           = md5,
        size_bytes    = size_bytes,
        has_native_libs     = has_native_libs,
        native_lib_names    = native_lib_names,
        has_network_security_config = has_nsc,
        network_security_config_xml = nsc_xml,
        has_backup_rules    = "res/xml/backup_rules.xml" in file_list,
        strings_pool        = strings_pool,
        raw_bytes           = raw_bytes,
    )
