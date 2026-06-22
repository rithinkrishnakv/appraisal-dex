"""
SKILL: DEX Dissection [UNIQUE]
APK loader — turns a binary into a fully parsed AnalysisContext.

Architecture:
  - Memory-mapped files (zero-copy) replace unbounded .read_bytes()
  - All extraction happens inside a forcibly sandboxed TemporaryDirectory
  - Strict immutability enforced via frozen dataclasses and frozensets
  - Androguard loggers are silenced before any analysis starts
"""

import zipfile
import hashlib
import logging
import tempfile
import mmap
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

diagnostic_logger = logging.getLogger("appraisal.diagnostics")

# ── Silence androguard and all its sub-loggers BEFORE importing analysis ──────
_NOISY_LOGGERS = [
    "androguard", "androguard.core", "androguard.core.analysis",
    "androguard.core.analysis.analysis", "androguard.core.apk",
    "androguard.core.dex", "androguard.core.axml", "androguard.misc",
    "pyaxmlparser",
]
for _name in _NOISY_LOGGERS:
    _log = logging.getLogger(_name)
    _log.setLevel(logging.CRITICAL)
    _log.propagate = False

try:
    from loguru import logger as _loguru_logger
    import sys as _sys_loguru
    _loguru_logger.remove()
    _loguru_logger.add(_sys_loguru.stderr, level="CRITICAL")
except Exception as e:
    diagnostic_logger.warning(f"Could not silence loguru: {e}")

from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX
try:
    from androguard.core.axml import AXMLPrinter
except ImportError:
    from androguard.core.bytecodes.axml import AXMLPrinter

SKIP_PREFIXES = (
    "Landroid/", "Landroidx/", "Lkotlin/", "Lkotlinx/",
    "Ljava/", "Ljavax/", "Lcom/google/android/",
    "Lcom/google/firebase/", "Ldalvik/", "Lsun/",
    "Lorg/apache/", "Lorg/xml/", "Lorg/w3c/",
    "Lcom/android/", "Ljunit/", "Lorg/junit/", "Lorg/mockito/",
)

@dataclass(frozen=True)
class ManifestComponent:
    name: str
    component_type: str
    exported: Optional[bool]
    permission: Optional[str]
    intent_filters: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    authorities: Tuple[str, ...] = field(default_factory=tuple)
    grant_uri_permissions: bool = False
    path_permissions: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class AnalysisContext:
    apk_path: str
    apk: APK
    dex_list: Tuple[DEX, ...]
    analysis: Analysis
    manifest_xml: str
    manifest_tree: ET.Element
    package_name: str
    app_name: str
    version_name: str
    version_code: str
    min_sdk: int
    target_sdk: int
    permissions: Tuple[str, ...]
    components: Tuple[ManifestComponent, ...]
    file_list: Tuple[str, ...]
    sha256: str
    md5: str
    size_bytes: int
    has_native_libs: bool
    native_lib_names: Tuple[str, ...]
    has_network_security_config: bool
    network_security_config_xml: Optional[str]
    has_backup_rules: bool
    strings_pool: frozenset
    raw_bytes: memoryview
    app_classes: Tuple[Any, ...]

    # Internal lifecycle handlers
    _file_handle: Any = field(repr=False, default=None)
    _mmap_handle: Any = field(repr=False, default=None)

    def close(self):
        if self._mmap_handle is not None:
            try: self._mmap_handle.close()
            except Exception: pass
        if self._file_handle is not None:
            try: self._file_handle.close()
            except Exception: pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

ANDROID_NS = "http://schemas.android.com/apk/res/android"

def _attr(element: ET.Element, name: str) -> Optional[str]:
    return element.get(f"{{{ANDROID_NS}}}{name}")

def _safe_int(val: Any, default: int = 1) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def _parse_intent_filters(component_el: ET.Element) -> Tuple[Dict[str, Any], ...]:
    filters = []
    for ifilter in component_el.findall("intent-filter"):
        f: Dict[str, Any] = {"actions": [], "categories": [], "data": []}
        for action in ifilter.findall("action"):
            name = _attr(action, "name")
            if name: f["actions"].append(name)
        for cat in ifilter.findall("category"):
            name = _attr(cat, "name")
            if name: f["categories"].append(name)
        for data in ifilter.findall("data"):
            d = {
                "scheme": _attr(data, "scheme"), "host": _attr(data, "host"),
                "port": _attr(data, "port"), "path": _attr(data, "path"),
                "pathPrefix": _attr(data, "pathPrefix"), "pathPattern": _attr(data, "pathPattern"),
                "mimeType": _attr(data, "mimeType"),
            }
            f["data"].append({k: v for k, v in d.items() if v is not None})
        filters.append(f)
    return tuple(filters)

def _parse_components(manifest_tree: ET.Element) -> Tuple[ManifestComponent, ...]:
    components = []
    app_el = manifest_tree.find("application")
    if app_el is None:
        return tuple()

    tag_map = {
        "activity": "activity", "activity-alias": "activity",
        "service": "service", "receiver": "receiver", "provider": "provider",
    }

    for tag, ctype in tag_map.items():
        for el in app_el.findall(tag):
            name = _attr(el, "name") or ""
            exported = _attr(el, "exported")
            permission = _attr(el, "permission")

            exported_bool = True if exported == "true" else False if exported == "false" else None
            intent_filters = _parse_intent_filters(el)
            if exported_bool is None and intent_filters:
                exported_bool = True

            authorities: List[str] = []
            grant_uri = False
            path_permissions = []
            
            if ctype == "provider":
                auths = _attr(el, "authorities") or ""
                authorities = [a.strip() for a in auths.split(";") if a.strip()]
                grant_uri = (_attr(el, "grantUriPermissions") or "false").lower() == "true"
                for pp in el.findall("path-permission"):
                    path_permissions.append({
                        "path": _attr(pp, "path"), "pathPrefix": _attr(pp, "pathPrefix"),
                        "pathPattern": _attr(pp, "pathPattern"), "readPermission": _attr(pp, "readPermission"),
                        "writePermission": _attr(pp, "writePermission"),
                    })

            components.append(ManifestComponent(
                name=name, component_type=ctype, exported=exported_bool,
                permission=permission, intent_filters=intent_filters,
                authorities=tuple(authorities), grant_uri_permissions=grant_uri,
                path_permissions=tuple(path_permissions),
            ))

    return tuple(components)

def _extract_strings_pool(dex_list: Tuple[DEX, ...]) -> frozenset:
    strings_pool = set()
    for dex in dex_list:
        try:
            for s in dex.get_strings():
                if isinstance(s, bytes):
                    strings_pool.add(s.decode("utf-8", errors="replace"))
                else:
                    strings_pool.add(str(s))
        except Exception as e:
            diagnostic_logger.error(f"Failed to parse strings from DEX: {e}")
    return frozenset(strings_pool)

def _filter_app_classes(analysis: Analysis) -> Tuple[Any, ...]:
    app_classes = []
    try:
        for cls in analysis.get_classes():
            name = str(cls.name)
            if name.startswith(SKIP_PREFIXES):
                continue
            app_classes.append(cls)
    except Exception as e:
        diagnostic_logger.error(f"Failed to filter app classes: {e}")
    return tuple(app_classes)

def load_apk(apk_path: str) -> AnalysisContext:
    path = Path(apk_path).resolve()
    if not path.exists(): raise FileNotFoundError(f"APK not found: {apk_path}")
    if path.suffix.lower() not in (".apk", ".xapk", ".apks"): raise ValueError(f"Not an APK file: {apk_path}")

    size_bytes = path.stat().st_size

    f = open(path, "rb")
    try:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        mv = memoryview(mm)
        
        sha256, md5 = hashlib.sha256(), hashlib.md5()
        chunk_size = 65536
        for i in range(0, len(mv), chunk_size):
            chunk = mv[i:i+chunk_size]
            sha256.update(chunk)
            md5.update(chunk)
    except Exception as e:
        f.close()
        diagnostic_logger.error(f"Failed to memory map APK: {e}")
        raise

    for _name in _NOISY_LOGGERS:
        logging.getLogger(_name).setLevel(logging.CRITICAL)

    with tempfile.TemporaryDirectory(prefix="appraisal_dex_") as _tmpdir:
        old_tempdir = tempfile.tempdir
        tempfile.tempdir = _tmpdir  # Force sandboxing of Androguard output
        try:
            apk_obj, dex_list, analysis = AnalyzeAPK(str(path))
        except Exception as e:
            diagnostic_logger.error(f"AnalyzeAPK fatal error: {e}")
            mm.close()
            f.close()
            raise
        finally:
            tempfile.tempdir = old_tempdir

    try:
        raw_manifest_bytes = apk_obj.get_file("AndroidManifest.xml")
        if raw_manifest_bytes and raw_manifest_bytes.startswith(b'\x03\x00\x08\x00'):
            axml = AXMLPrinter(raw_manifest_bytes)
            manifest_str = axml.get_buff().decode("utf-8", errors="replace")
            manifest_tree = ET.fromstring(manifest_str)
        else:
            manifest_str = raw_manifest_bytes.decode("utf-8", errors="replace") if raw_manifest_bytes else "<manifest></manifest>"
            manifest_tree = ET.fromstring(manifest_str)
    except ET.ParseError as e:
        diagnostic_logger.warning(f"Manifest parse error: {e}. Falling back to empty tree.")
        manifest_str, manifest_tree = "<manifest></manifest>", ET.Element("manifest")
    except Exception as e:
        diagnostic_logger.warning(f"Manifest extraction failed: {e}")
        manifest_str, manifest_tree = "<manifest></manifest>", ET.Element("manifest")

    package_name = apk_obj.get_package() or "unknown"
    app_name = apk_obj.get_app_name() or package_name
    
    try: version_name = apk_obj.get_androidversion_name() or "unknown"
    except Exception as e:
        diagnostic_logger.warning(f"Failed to get version name: {e}")
        version_name = "unknown"
        
    try: version_code = str(apk_obj.get_androidversion_code() or "0")
    except Exception as e:
        diagnostic_logger.warning(f"Failed to get version code: {e}")
        version_code = "0"
        
    min_sdk = _safe_int(apk_obj.get_min_sdk_version(), default=1)
    target_sdk = _safe_int(apk_obj.get_target_sdk_version(), default=1)
    permissions = tuple(apk_obj.get_permissions() or [])

    file_list = []
    try:
        with zipfile.ZipFile(f, "r") as zf:
            file_list = zf.namelist()
    except zipfile.BadZipFile as e:
        diagnostic_logger.warning(f"Bad zip file for file inventory: {e}")
    except Exception as e:
        diagnostic_logger.warning(f"Failed zip inventory: {e}")

    native_lib_names = tuple(n for n in file_list if n.endswith(".so"))
    nsc_path = "res/xml/network_security_config.xml"
    has_nsc = nsc_path in file_list
    nsc_xml = None
    if has_nsc:
        try:
            nsc_xml = apk_obj.get_file(nsc_path).decode("utf-8", errors="ignore")
        except Exception as e:
            diagnostic_logger.warning(f"Failed to decode network security config: {e}")

    dex_list_norm = tuple(dex_list) if isinstance(dex_list, list) else (dex_list,)

    return AnalysisContext(
        apk_path=str(path), apk=apk_obj, dex_list=dex_list_norm, analysis=analysis,
        manifest_xml=manifest_str, manifest_tree=manifest_tree, package_name=package_name,
        app_name=app_name, version_name=version_name, version_code=version_code,
        min_sdk=min_sdk, target_sdk=target_sdk, permissions=permissions,
        components=_parse_components(manifest_tree), file_list=tuple(file_list),
        sha256=sha256.hexdigest(), md5=md5.hexdigest(), size_bytes=size_bytes,
        has_native_libs=bool(native_lib_names), native_lib_names=native_lib_names,
        has_network_security_config=has_nsc, network_security_config_xml=nsc_xml,
        has_backup_rules="res/xml/backup_rules.xml" in file_list,
        strings_pool=_extract_strings_pool(dex_list_norm), raw_bytes=mv,
        app_classes=_filter_app_classes(analysis),
        _file_handle=f, _mmap_handle=mm
    )
