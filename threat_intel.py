"""Threat intelligence API clients (AbuseIPDB, VirusTotal, AlienVault OTX).

Every client implements the same small interface so the orchestrator can treat
sources uniformly. Raw provider responses are reduced to a compact, normalised
summary; this keeps the cache small and the CLI output consistent.

Design notes (defensive architecture):
    * API keys are read from the environment at call time and are only ever
      sent in request headers: never in URLs, logs, or error messages.
    * All network failures are mapped onto a tiny set of sanitised exceptions
      (``ThreatIntelError`` and subclasses); raw ``requests`` errors, which can
      embed URLs, never escape this module.
    * Every request has explicit timeouts, TLS verification, no redirects and
      a response-size cap.
    * Text returned by third parties is attacker-influenced, so it is stripped
      of control characters (terminal escape-sequence injection) and truncated.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from validators import IoCType

logger = logging.getLogger(__name__)

USER_AGENT = "threat-intel-aggregator/1.0 (+portfolio project)"
REQUEST_TIMEOUT: Tuple[float, float] = (3.05, 10.0)  # (connect, read) seconds
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB hard cap per response

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


# --------------------------------------------------------------------------- #
# Errors and shared types
# --------------------------------------------------------------------------- #
class ThreatIntelError(Exception):
    """Base class: messages are always safe to show to the user."""


class MissingAPIKeyError(ThreatIntelError):
    """The API key for a provider is not configured."""


class RateLimitError(ThreatIntelError):
    """The provider rejected the request because the quota is exhausted."""


class UpstreamError(ThreatIntelError):
    """Network failure or unexpected provider response."""


class RiskLevel(str, Enum):
    """Normalised verdict shared by all providers."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


RISK_RANK: Dict[str, int] = {
    RiskLevel.UNKNOWN.value: 0,
    RiskLevel.CLEAN.value: 1,
    RiskLevel.SUSPICIOUS.value: 2,
    RiskLevel.MALICIOUS.value: 3,
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _clean_text(value: Any, max_len: int = 80) -> str:
    """Make third-party text safe to print: strip control chars and truncate."""
    text = _CONTROL_CHARS.sub("", str(value))
    return text if len(text) <= max_len else text[: max_len - 1] + "..."


def _as_int(value: Any, default: int = 0) -> int:
    """Coerce provider values to int without trusting their shape."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def build_session() -> requests.Session:
    """Create a Session with a bounded retry policy for transient 5xx errors.

    429 is deliberately *not* retried: hammering a rate-limited API only
    burns more of the quota the cache exists to protect.
    """
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=(502, 503, 504),
        allowed_methods=("GET",),
        raise_on_status=False,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return session


# --------------------------------------------------------------------------- #
# Base client
# --------------------------------------------------------------------------- #
class ThreatIntelClient(ABC):
    """Template for a threat intelligence provider."""

    name: str = ""
    env_var: str = ""
    supported_types: FrozenSet[IoCType] = frozenset()

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._session = session or build_session()

    def supports(self, ioc_type: IoCType) -> bool:
        return ioc_type in self.supported_types

    def _api_key(self) -> str:
        key = os.getenv(self.env_var, "").strip()
        if not key:
            raise MissingAPIKeyError(
                f"API key not configured (set {self.env_var} in your .env file)."
            )
        return key

    def query(self, ioc: str, ioc_type: IoCType) -> Dict[str, Any]:
        """Look up an IoC and return a normalised summary dict."""
        key = self._api_key()
        payload = self._fetch(ioc, ioc_type, key)
        if payload is None:  # provider has no record of this indicator
            return {
                "source": self.name,
                "risk_level": RiskLevel.UNKNOWN.value,
                "summary": "Indicator not found in this source.",
                "details": {},
            }
        return self._summarize(payload, ioc_type)

    # -- to be provided by concrete clients -------------------------------- #
    @abstractmethod
    def _fetch(self, ioc: str, ioc_type: IoCType, key: str) -> Optional[Dict[str, Any]]:
        """Perform the HTTP call; return ``None`` when the IoC is not found."""

    @abstractmethod
    def _summarize(self, payload: Dict[str, Any], ioc_type: IoCType) -> Dict[str, Any]:
        """Reduce a raw provider payload to the normalised summary."""

    # -- shared HTTP plumbing ---------------------------------------------- #
    def _get_json(
        self,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            response = self._session.get(
                url,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,  # never follow a redirect with a key attached
                verify=True,            # explicit: TLS verification is mandatory
            )
        except requests.exceptions.Timeout as exc:
            raise UpstreamError(f"{self.name}: request timed out.") from exc
        except requests.exceptions.ConnectionError as exc:
            raise UpstreamError(f"{self.name}: could not connect to the service.") from exc
        except requests.exceptions.RequestException as exc:
            raise UpstreamError(f"{self.name}: request failed ({type(exc).__name__}).") from exc

        status = response.status_code
        if status == 404:
            return None
        if status in (401, 403):
            raise UpstreamError(f"{self.name}: authentication rejected (check your API key).")
        if status == 429:
            raise RateLimitError(f"{self.name}: rate limit or quota exceeded.")
        if status >= 500:
            raise UpstreamError(f"{self.name}: service unavailable (HTTP {status}).")
        if status != 200:
            raise UpstreamError(f"{self.name}: unexpected response (HTTP {status}).")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise UpstreamError(f"{self.name}: response exceeded the size limit.")

        try:
            data = response.json()
        except ValueError as exc:
            raise UpstreamError(f"{self.name}: returned invalid JSON.") from exc
        if not isinstance(data, dict):
            raise UpstreamError(f"{self.name}: returned an unexpected JSON structure.")
        return data


# --------------------------------------------------------------------------- #
# Concrete providers
# --------------------------------------------------------------------------- #
class AbuseIPDBClient(ThreatIntelClient):
    """AbuseIPDB v2 'check' endpoint (IPv4 only)."""

    name = "abuseipdb"
    env_var = "ABUSEIPDB_API_KEY"
    supported_types = frozenset({IoCType.IPV4})
    _URL = "https://api.abuseipdb.com/api/v2/check"

    def _fetch(self, ioc: str, ioc_type: IoCType, key: str) -> Optional[Dict[str, Any]]:
        return self._get_json(
            self._URL,
            headers={"Key": key},
            params={"ipAddress": ioc, "maxAgeInDays": 90},
        )

    def _summarize(self, payload: Dict[str, Any], ioc_type: IoCType) -> Dict[str, Any]:
        data = _as_dict(payload.get("data"))
        score = _as_int(data.get("abuseConfidenceScore"))
        reports = _as_int(data.get("totalReports"))

        if score >= 75:
            risk = RiskLevel.MALICIOUS
        elif score >= 25:
            risk = RiskLevel.SUSPICIOUS
        else:
            risk = RiskLevel.CLEAN

        return {
            "source": self.name,
            "risk_level": risk.value,
            "summary": f"Abuse confidence {score}% across {reports} report(s) in 90 days.",
            "details": {
                "abuse_confidence_score": score,
                "total_reports": reports,
                "distinct_reporters": _as_int(data.get("numDistinctUsers")),
                "country": _clean_text(data.get("countryCode", "n/a")),
                "isp": _clean_text(data.get("isp", "n/a")),
                "usage_type": _clean_text(data.get("usageType", "n/a")),
                "last_reported": _clean_text(data.get("lastReportedAt") or "never"),
            },
        }


class VirusTotalClient(ThreatIntelClient):
    """VirusTotal API v3 (IPs, domains and file hashes)."""

    name = "virustotal"
    env_var = "VIRUSTOTAL_API_KEY"
    supported_types = frozenset({IoCType.IPV4, IoCType.DOMAIN, IoCType.SHA256})
    _BASE = "https://www.virustotal.com/api/v3"
    _PATHS = {
        IoCType.IPV4: "ip_addresses",
        IoCType.DOMAIN: "domains",
        IoCType.SHA256: "files",
    }

    def _fetch(self, ioc: str, ioc_type: IoCType, key: str) -> Optional[Dict[str, Any]]:
        # quote() is defence in depth: the IoC is already validated.
        url = f"{self._BASE}/{self._PATHS[ioc_type]}/{quote(ioc, safe='')}"
        return self._get_json(url, headers={"x-apikey": key})

    def _summarize(self, payload: Dict[str, Any], ioc_type: IoCType) -> Dict[str, Any]:
        attrs = _as_dict(_as_dict(payload.get("data")).get("attributes"))
        stats = _as_dict(attrs.get("last_analysis_stats"))
        malicious = _as_int(stats.get("malicious"))
        suspicious = _as_int(stats.get("suspicious"))
        harmless = _as_int(stats.get("harmless"))
        undetected = _as_int(stats.get("undetected"))
        total = malicious + suspicious + harmless + undetected

        if malicious >= 5:
            risk = RiskLevel.MALICIOUS
        elif malicious >= 1 or suspicious >= 1:
            risk = RiskLevel.SUSPICIOUS
        elif total == 0:
            risk = RiskLevel.UNKNOWN
        else:
            risk = RiskLevel.CLEAN

        details: Dict[str, Any] = {
            "engines_malicious": malicious,
            "engines_suspicious": suspicious,
            "engines_harmless": harmless,
            "engines_undetected": undetected,
            "reputation": _as_int(attrs.get("reputation")),
        }
        if ioc_type is IoCType.IPV4:
            details["country"] = _clean_text(attrs.get("country", "n/a"))
            details["as_owner"] = _clean_text(attrs.get("as_owner", "n/a"))
        elif ioc_type is IoCType.DOMAIN:
            details["registrar"] = _clean_text(attrs.get("registrar", "n/a"))
        else:
            details["file_name"] = _clean_text(attrs.get("meaningful_name", "n/a"))
            details["file_type"] = _clean_text(attrs.get("type_description", "n/a"))

        return {
            "source": self.name,
            "risk_level": risk.value,
            "summary": f"{malicious} of {total} engines flagged this indicator as malicious.",
            "details": details,
        }


class OTXClient(ThreatIntelClient):
    """AlienVault OTX 'general' indicator endpoint (IPs, domains, file hashes)."""

    name = "otx"
    env_var = "OTX_API_KEY"
    supported_types = frozenset({IoCType.IPV4, IoCType.DOMAIN, IoCType.SHA256})
    _BASE = "https://otx.alienvault.com/api/v1/indicators"
    _PATHS = {IoCType.IPV4: "IPv4", IoCType.DOMAIN: "domain", IoCType.SHA256: "file"}

    def _fetch(self, ioc: str, ioc_type: IoCType, key: str) -> Optional[Dict[str, Any]]:
        url = f"{self._BASE}/{self._PATHS[ioc_type]}/{quote(ioc, safe='')}/general"
        return self._get_json(url, headers={"X-OTX-API-KEY": key})

    def _summarize(self, payload: Dict[str, Any], ioc_type: IoCType) -> Dict[str, Any]:
        pulse_info = _as_dict(payload.get("pulse_info"))
        pulse_count = _as_int(pulse_info.get("count"))
        pulses = pulse_info.get("pulses")
        names: List[str] = []
        if isinstance(pulses, list):
            names = [
                _clean_text(_as_dict(p).get("name", "unnamed"))
                for p in pulses[:3]
            ]

        # OTX pulses are community reports: presence implies relevance to
        # threat activity, but absence is not proof of safety, hence UNKNOWN.
        if pulse_count >= 5:
            risk = RiskLevel.MALICIOUS
        elif pulse_count >= 1:
            risk = RiskLevel.SUSPICIOUS
        else:
            risk = RiskLevel.UNKNOWN

        details: Dict[str, Any] = {
            "pulse_count": pulse_count,
            "reputation": _as_int(payload.get("reputation")),
        }
        if names:
            details["recent_pulses"] = names
        if ioc_type is IoCType.IPV4:
            details["country"] = _clean_text(payload.get("country_name") or "n/a")
            details["asn"] = _clean_text(payload.get("asn") or "n/a")

        return {
            "source": self.name,
            "risk_level": risk.value,
            "summary": f"Referenced in {pulse_count} OTX pulse(s).",
            "details": details,
        }


# --------------------------------------------------------------------------- #
# Offline demo client
# --------------------------------------------------------------------------- #
class MockClient(ThreatIntelClient):
    """Deterministic offline provider for demos and tests (``--mock``).

    Needs no API key and makes no network calls. Results are cached under the
    source name ``mock`` so they can never pollute real provider data.
    """

    name = "mock"
    env_var = ""
    supported_types = frozenset(IoCType)

    # Well-known public indicators with fixed, realistic outcomes.
    _FIXTURES: Dict[str, int] = {
        "8.8.8.8": 0,
        "1.1.1.1": 0,
        "example.com": 0,
        # EICAR antivirus test file (harmless by design).
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": 96,
    }

    def __init__(self) -> None:  # no HTTP session needed
        pass

    def query(self, ioc: str, ioc_type: IoCType) -> Dict[str, Any]:
        score = self._FIXTURES.get(ioc)
        if score is None:
            score = hashlib.sha256(ioc.encode("ascii")).digest()[0] % 100

        if score >= 75:
            risk = RiskLevel.MALICIOUS
        elif score >= 25:
            risk = RiskLevel.SUSPICIOUS
        else:
            risk = RiskLevel.CLEAN

        return {
            "source": self.name,
            "risk_level": risk.value,
            "summary": f"Simulated threat score {score}/100 (offline demo data).",
            "details": {"threat_score": score, "ioc_type": ioc_type.value},
        }

    def _fetch(self, ioc: str, ioc_type: IoCType, key: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError  # query() is overridden

    def _summarize(self, payload: Dict[str, Any], ioc_type: IoCType) -> Dict[str, Any]:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
CLIENT_REGISTRY = {
    AbuseIPDBClient.name: AbuseIPDBClient,
    VirusTotalClient.name: VirusTotalClient,
    OTXClient.name: OTXClient,
}


def build_clients(names: List[str], mock: bool = False) -> List[ThreatIntelClient]:
    """Instantiate the requested clients (or the offline mock client)."""
    if mock:
        return [MockClient()]
    return [CLIENT_REGISTRY[name]() for name in names]