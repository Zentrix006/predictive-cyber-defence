"""
Device type classification for automated Wi-Fi enrollment.

Given a device's self-reported / network-derived attributes (MAC OUI,
DHCP vendor class, user agent, advertised services), infer an AssetType
and a network ZoneType so it can be auto-added to the topology.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from app.models.asset import AssetType, ZoneType, CriticalityLevel

# Well-known OUI prefixes -> vendor -> implied role (lowercase full-prefix strings).
# Only a handful of common ones; unknown OUIs fall through to other signals.
OUI_VENDOR: Dict[str, str] = {
    "00:1a:2b": "siemens",
    "00:0c:29": "vmware",
    "00:50:56": "vmware",
    "08:00:27": "oracle_virtualbox",
    "b8:27:eb": "raspberry_pi",
    "dc:a6:32": "raspberry_pi",
    "e4:5f:01": "raspberry_pi",
    "d8:3a:dd": "raspberry_pi",
    "f8:32:e4": "raspberry_pi",
    "a4:77:33": "sesame",
    "08:3e:8e": "hp",
    "3c:d9:2b": "hp",
    "54:a0:50": "dell",
    "b4:2e:99": "dell",
    "f0:4d:a2": "dell",
    "00:26:bb": "dell",
    "00:14:22": "dell",
    "34:12:98": "apple",
    "a4:83:e7": "apple",
    "f0:18:98": "apple",
    "ac:bc:32": "apple",
    "a8:5c:2c": "apple",
    "00:1e:c2": "cisco",
    "00:0c:85": "cisco",
}

# DHCP vendor class (option 60) / user-agent markers.
_VENDOR_CLASS_UA: List[Tuple[str, str]] = [
    ("MSFT 5.0", "windows"),
    ("MSFT 98", "windows"),
    ("android", "android"),
    ("linux", "linux"),
    ("iOS", "apple_mobile"),
    ("iPhone", "apple_mobile"),
    ("iPad", "apple_mobile"),
    ("Mac OS X", "macos"),
]

_MOBILE_UA = re.compile(r"mobile|android|iphone|ipad", re.I)
_ROUTER_UA = re.compile(r"router|asustek|tplink|d-link|netgear|raspbmc", re.I)
_PRINTER_UA = re.compile(r"printer|epson|hp laserjet|pixma|brother", re.I)
_CAMERA_UA = re.compile(r"camera|network camera|hikvision|axis", re.I)


def _normalise_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(cleaned) < 6:
        return None
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def _oui_vendor(mac: Optional[str]) -> Optional[str]:
    norm = _normalise_mac(mac)
    if not norm:
        return None
    prefixes = [norm[0:8], norm[0:8].replace(":", "")]
    for p in prefixes:
        for oui, vendor in OUI_VENDOR.items():
            if p.replace(":", "").startswith(oui.replace(":", "")):
                return vendor
    return None


def classify_device(
    mac: Optional[str] = None,
    ip: Optional[str] = None,
    hostname: Optional[str] = None,
    user_agent: Optional[str] = None,
    vendor_class: Optional[str] = None,
    services: Optional[List[str]] = None,
) -> Tuple[AssetType, ZoneType, CriticalityLevel, Dict]:
    """
    Return (asset_type, zone, criticality, metadata).

    Priority: explicit DHCP/UA signals, then advertised services, then the
    hostname, then OUI vendor as a last-resort hint.
    """
    services = [s.strip().lower() for s in (services or []) if s and s.strip()]
    ua = (user_agent or "").lower()
    vc = (vendor_class or "").lower()
    hn = (hostname or "").lower()
    vendor = _oui_vendor(mac)

    metadata: Dict = {
        "enrolled_by": "wifi_qr",
        "vendor": vendor,
        "vendor_class": vendor_class,
        "user_agent": user_agent,
        "services": services,
        "hostname": hostname,
    }

    def _result(t: AssetType, z: ZoneType, c: CriticalityLevel, confidence: int):
        metadata["confidence"] = confidence
        return t, z, c, metadata

    # 1. Advertised services reveal true role. Check the most specific
    #    device roles first (printers/cameras/airplay) before generic server
    #    mappings, since printers also advertise _ipp/_http.
    svc = " ".join(services)
    if any(s in svc for s in ("_printer", "_pdl-datastream", "_print._tcp")) or _PRINTER_UA.search(ua):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 100)
    if any(s in svc for s in ("_airplay._tcp", "_raop._tcp")):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 100)
    if _CAMERA_UA.search(ua) or any(s in svc for s in ("_onvif", "_http-alt._tcp")):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 100)
    if any(s in svc for s in ("_adb._tcp", "_googlecast._tcp", "_hap._tcp")):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 100)

    if any(s in svc for s in ("_http._tcp", "_https._tcp", "_ipp._tcp")):
        return _result(AssetType.WEB_SERVER, ZoneType.SERVER_ZONE, CriticalityLevel.HIGH, 100)
    if any(s in svc for s in ("_smb._tcp", "_nfs._tcp", "_cifs._tcp")):
        return _result(AssetType.SERVER, ZoneType.SERVER_ZONE, CriticalityLevel.HIGH, 100)
    if any(s in svc for s in ("_ssh._tcp", "_ftp._tcp", "_telnet._tcp")):
        return _result(AssetType.SERVER, ZoneType.SERVER_ZONE, CriticalityLevel.MEDIUM, 100)

    # 2. Hostname hints (assume admins name infrastructure predictably).
    #    Checked before the generic OS-family mapping so infrastructure boxes
    #    (e.g. "db-primary", "core-router" with a linux vendor class) are not
    #    downgraded to generic workstations.
    if re.search(r"\b(web|www|app|api|api-server)\b", hn):
        return _result(AssetType.WEB_SERVER, ZoneType.SERVER_ZONE, CriticalityLevel.HIGH, 80)
    if re.search(r"\b(db|database|mysql|pgsql|mongo|redis)\b", hn):
        return _result(AssetType.DATABASE, ZoneType.SERVER_ZONE, CriticalityLevel.CRITICAL, 80)
    if re.search(r"\b(dc|domain|ad-dc|controller)\b", hn):
        return _result(AssetType.DOMAIN_CONTROLLER, ZoneType.SERVER_ZONE, CriticalityLevel.CRITICAL, 80)
    if re.search(r"\b(server|srv|nas|file)\b", hn):
        return _result(AssetType.SERVER, ZoneType.SERVER_ZONE, CriticalityLevel.HIGH, 80)
    if re.search(r"\b(printer|plotter|fax)\b", hn):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 80)
    if re.search(r"\b(cam|ipcam|dvr|nvr|sensor)\b", hn):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 80)
    if re.search(r"\b(router|gw|gateway|firewall|switch|ap|access-point)\b", hn):
        return _result(AssetType.ROUTER, ZoneType.MANAGEMENT, CriticalityLevel.HIGH, 80)

    # 3. DHCP vendor class / user-agent => OS family (mobile/workstation).
    for marker, os_family in _VENDOR_CLASS_UA:
        if marker.lower() in vc or marker.lower() in ua:
            metadata["os"] = os_family
            if os_family in ("android", "apple_mobile") or _MOBILE_UA.search(ua):
                return _result(AssetType.WORKSTATION, ZoneType.USER_ZONE, CriticalityLevel.LOW, 90)
            if os_family == "windows":
                return _result(AssetType.WORKSTATION, ZoneType.USER_ZONE, CriticalityLevel.MEDIUM, 90)
            if os_family in ("linux", "macos"):
                return _result(AssetType.WORKSTATION, ZoneType.USER_ZONE, CriticalityLevel.MEDIUM, 90)

    # 4. User-agent device classes (printers/cameras often report their make).
    if _ROUTER_UA.search(ua):
        return _result(AssetType.ROUTER, ZoneType.MANAGEMENT, CriticalityLevel.HIGH, 70)
    if _PRINTER_UA.search(ua):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 70)
    if _CAMERA_UA.search(ua):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 70)

    # 5. OUI vendor as a last hint.
    if vendor in ("raspberry_pi", "sesame", "vmware"):
        return _result(AssetType.IOT_DEVICE, ZoneType.IOT_ZONE, CriticalityLevel.LOW, 40)

    # Default: weak guess until better signals arrive.
    default_type = AssetType.WORKSTATION if vendor not in ("apple", "sesame") else AssetType.IOT_DEVICE
    default_zone = ZoneType.USER_ZONE if default_type is AssetType.WORKSTATION else ZoneType.IOT_ZONE
    metadata["classification"] = "default"
    return _result(AssetType.UNKNOWN, default_zone, CriticalityLevel.LOW, 10)
