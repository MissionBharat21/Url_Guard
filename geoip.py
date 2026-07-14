"""
geoip.py
========
IP geolocation and ASN/ISP lookups. Uses ipwhois (RDAP) for ASN/ISP
data, and falls back to the free ip-api.com HTTP API for city/region/
lat/long when no local MaxMind GeoLite2 database is configured.

If Config.GEOIP_DB_PATH points to a valid GeoLite2-City.mmdb file,
the geoip2 database reader is used instead (fully offline).
"""

import socket
from typing import Any, Dict, Optional

import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

from config import Config
from utils import setup_logger

logger = setup_logger(__name__)

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False


class GeoIPLookup:
    """Resolves geolocation, ASN, and ISP information for an IP address."""

    def __init__(self, ip_address: str, timeout: int = None) -> None:
        """
        Args:
            ip_address: The IPv4 or IPv6 address to look up.
            timeout: HTTP timeout in seconds for the fallback API.
        """
        self.ip_address = ip_address
        self.timeout = timeout or Config.REQUEST_TIMEOUT

    def _rdap_lookup(self) -> Dict[str, Any]:
        """Query RDAP (via ipwhois) for ASN and network ownership data."""
        data: Dict[str, Any] = {"asn": None, "isp": None, "org": None}
        try:
            obj = IPWhois(self.ip_address)
            rdap = obj.lookup_rdap(depth=1)
            data["asn"] = rdap.get("asn")
            data["isp"] = rdap.get("network", {}).get("name") or rdap.get("asn_description")
            data["org"] = rdap.get("asn_description")
        except IPDefinedError:
            data["isp"] = "Private/reserved IP address range"
        except Exception as exc:
            logger.warning(f"GeoIP: RDAP lookup failed for {self.ip_address}: {exc}")
        return data

    def _geoip2_lookup(self) -> Optional[Dict[str, Any]]:
        """Use a local MaxMind GeoLite2-City database, if configured."""
        if not (GEOIP2_AVAILABLE and Config.GEOIP_DB_PATH):
            return None
        try:
            with geoip2.database.Reader(Config.GEOIP_DB_PATH) as reader:
                response = reader.city(self.ip_address)
                return {
                    "country": response.country.name,
                    "region": response.subdivisions.most_specific.name,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                }
        except Exception as exc:
            logger.warning(f"GeoIP: local database lookup failed: {exc}")
            return None

    def _ip_api_fallback(self) -> Dict[str, Any]:
        """Fallback geolocation via the free ip-api.com HTTP endpoint."""
        data: Dict[str, Any] = {
            "country": None, "region": None, "city": None,
            "latitude": None, "longitude": None,
        }
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{self.ip_address}",
                params={"fields": "status,country,regionName,city,lat,lon"},
                timeout=self.timeout,
            )
            payload = resp.json()
            if payload.get("status") == "success":
                data["country"] = payload.get("country")
                data["region"] = payload.get("regionName")
                data["city"] = payload.get("city")
                data["latitude"] = payload.get("lat")
                data["longitude"] = payload.get("lon")
        except requests.RequestException as exc:
            logger.warning(f"GeoIP: ip-api.com fallback failed for {self.ip_address}: {exc}")
        return data

    def lookup(self) -> Dict[str, Any]:
        """
        Combine RDAP (ASN/ISP) and geolocation (country/city/lat/long)
        results into a single dictionary.
        """
        result: Dict[str, Any] = {
            "ip": self.ip_address,
            "asn": None, "isp": None, "org": None,
            "country": None, "region": None, "city": None,
            "latitude": None, "longitude": None,
        }

        result.update(self._rdap_lookup())

        geo = self._geoip2_lookup() or self._ip_api_fallback()
        result.update(geo)

        return result


def resolve_ips(domain: str) -> Dict[str, Optional[str]]:
    """
    Resolve a domain to its primary IPv4 and IPv6 addresses.

    Returns:
        Dict with keys 'ipv4' and 'ipv6' (either may be None).
    """
    ips: Dict[str, Optional[str]] = {"ipv4": None, "ipv6": None}
    try:
        ips["ipv4"] = socket.gethostbyname(domain)
    except socket.gaierror:
        pass

    try:
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
        if addr_info:
            ips["ipv6"] = addr_info[0][4][0]
    except socket.gaierror:
        pass

    return ips
