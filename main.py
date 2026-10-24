#!/usr/bin/env python3
"""Automated Threat Intelligence API Aggregator: CLI entry point.

Workflow: validate -> check SQLite cache -> query external APIs on a miss ->
update cache -> render a unified report.

Design notes (defensive architecture):
    * Input is validated *before* anything else touches it.
    * A failing cache or a failing provider never aborts the run; the tool
      degrades gracefully and reports what happened.
    * A top-level guard converts any unexpected exception into a one-line
      message. Tracebacks appear only when the user opts in with --verbose.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from dotenv import load_dotenv

from database import CacheDatabase, CacheError
from threat_intel import (
    CLIENT_REGISTRY,
    RISK_RANK,
    RiskLevel,
    ThreatIntelClient,
    ThreatIntelError,
    build_clients,
)
from validators import ValidatedIoC, ValidationError, classify_ioc

logger = logging.getLogger("tia")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INVALID_INPUT = 2
EXIT_NO_RESULTS = 3

_COLORS = {
    RiskLevel.MALICIOUS.value: "\033[91m",
    RiskLevel.SUSPICIOUS.value: "\033[93m",
    RiskLevel.CLEAN.value: "\033[92m",
    RiskLevel.UNKNOWN.value: "\033[90m",
}
_RESET = "\033[0m"
_RULE = "=" * 64
_THIN = "-" * 64


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _open_cache(enabled: bool, ttl_hours: Optional[float]) -> Optional[CacheDatabase]:
    """Initialise the cache; on failure continue without it."""
    if not enabled:
        return None
    cache = CacheDatabase(ttl_hours=ttl_hours)
    try:
        cache.initialize()
    except CacheError as exc:
        logger.warning("Cache unavailable, continuing with live lookups only: %s", exc)
        return None
    return cache


def _cache_get(cache: Optional[CacheDatabase], ioc: ValidatedIoC, source: str):
    if cache is None:
        return None
    try:
        return cache.get(ioc.value, source)
    except CacheError as exc:
        logger.warning("Cache read failed for %s (treating as miss): %s", source, exc)
        return None


def _cache_save(
    cache: Optional[CacheDatabase],
    ioc: ValidatedIoC,
    source: str,
    data: Dict[str, Any],
) -> None:
    if cache is None:
        return
    try:
        cache.save(ioc.value, ioc.ioc_type.value, source, data)
    except CacheError as exc:
        logger.warning("Cache write failed for %s (result still shown): %s", source, exc)


def lookup_ioc(
    ioc: ValidatedIoC,
    clients: Sequence[ThreatIntelClient],
    cache: Optional[CacheDatabase],
    read_cache: bool = True,
) -> Dict[str, Any]:
    """Run the full lookup workflow and return a structured report."""
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    skipped: List[Dict[str, str]] = []

    for client in clients:
        if not client.supports(ioc.ioc_type):
            skipped.append(
                {"source": client.name, "reason": f"does not support {ioc.ioc_type.value}"}
            )
            continue

        # 1) Cache first: protects free-tier API quotas.
        cached = _cache_get(cache, ioc, client.name) if read_cache else None
        if cached is not None:
            results.append(
                {**cached.data, "origin": "cache", "fetched_at": cached.fetched_at}
            )
            continue

        # 2) Cache miss or expired: query the provider.
        try:
            data = client.query(ioc.value, ioc.ioc_type)
        except ThreatIntelError as exc:
            # Failures are reported but never cached.
            errors.append({"source": client.name, "error": str(exc)})
            continue

        # 3) Refresh the cache, then record the live result.
        _cache_save(cache, ioc, client.name, data)
        results.append({**data, "origin": "live", "fetched_at": int(time.time())})

    verdict = max(
        (r["risk_level"] for r in results),
        key=lambda level: RISK_RANK.get(level, 0),
        default=RiskLevel.UNKNOWN.value,
    )
    return {
        "ioc": ioc.value,
        "type": ioc.ioc_type.value,
        "verdict": verdict,
        "queried_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "results": results,
        "errors": errors,
        "skipped": skipped,
    }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def _age(fetched_at: int) -> str:
    seconds = max(0, int(time.time()) - int(fetched_at))
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


def render_report(report: Dict[str, Any], use_color: bool) -> str:
    def paint(level: str, text: str) -> str:
        return f"{_COLORS.get(level, '')}{text}{_RESET}" if use_color else text

    lines = [
        _RULE,
        " THREAT INTELLIGENCE REPORT",
        _RULE,
        f" Indicator : {report['ioc']}",
        f" Type      : {report['type']}",
        f" Verdict   : {paint(report['verdict'], report['verdict'].upper())}",
        f" Queried   : {report['queried_at']}",
    ]

    for result in report["results"]:
        origin = "CACHE, " + _age(result["fetched_at"]) if result["origin"] == "cache" else "LIVE"
        lines += [
            _THIN,
            f" [{result['source']}] ({origin})  risk: "
            f"{paint(result['risk_level'], result['risk_level'].upper())}",
            f"   {result['summary']}",
        ]
        for key, value in result.get("details", {}).items():
            shown = ", ".join(value) if isinstance(value, list) else value
            lines.append(f"   - {key}: {shown}")

    for err in report["errors"]:
        lines += [_THIN, f" [{err['source']}] ERROR: {err['error']}"]
    for skip in report["skipped"]:
        lines.append(f" [{skip['source']}] skipped: {skip['reason']}")

    lines.append(_RULE)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="threat-intel",
        description="Aggregate threat intelligence for an IPv4 address, "
        "domain, or SHA-256 hash.",
        epilog="Only query indicators you are authorised to investigate.",
    )
    parser.add_argument("ioc", nargs="?", help="IoC to look up (prompted if omitted)")
    parser.add_argument(
        "-s", "--sources",
        default=",".join(CLIENT_REGISTRY),
        help="comma-separated sources (default: all)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--mock", action="store_true", help="offline demo mode (no API keys needed)")
    parser.add_argument("--refresh", action="store_true", help="skip cache reads, refresh cache")
    parser.add_argument("--no-cache", action="store_true", help="bypass the cache entirely")
    parser.add_argument("--ttl-hours", type=float, help="cache freshness window (default: 24)")
    parser.add_argument("--purge-cache", action="store_true", help="delete expired cache entries and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging incl. tracebacks")
    return parser.parse_args(argv)


def _select_sources(raw: str) -> List[str]:
    names = [part.strip().lower() for part in raw.split(",") if part.strip()]
    unknown = [n for n in names if n not in CLIENT_REGISTRY]
    if unknown or not names:
        raise ValueError(
            f"Unknown source(s): {', '.join(unknown) or raw!r}. "
            f"Choose from: {', '.join(CLIENT_REGISTRY)}."
        )
    return names


def run(args: argparse.Namespace) -> int:
    load_dotenv()  # keys come from .env / environment, never from source code

    if args.purge_cache:
        cache = _open_cache(True, args.ttl_hours)
        if cache is None:
            return EXIT_ERROR
        try:
            print(f"Removed {cache.purge_expired()} expired cache entrie(s).")
        except CacheError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        return EXIT_OK

    raw = args.ioc
    if raw is None:
        try:
            raw = input("Enter IoC (IPv4 / domain / SHA-256): ")
        except (EOFError, KeyboardInterrupt):
            print("\nNo input provided.", file=sys.stderr)
            return EXIT_INVALID_INPUT

    try:
        ioc = classify_ioc(raw)  # validate BEFORE any processing
    except ValidationError as exc:
        print(f"Invalid input: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    try:
        clients = build_clients(_select_sources(args.sources), mock=args.mock)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT

    cache = _open_cache(not args.no_cache, args.ttl_hours)
    report = lookup_ioc(ioc, clients, cache, read_cache=not args.refresh)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(render_report(report, use_color))

    return EXIT_OK if report["results"] else EXIT_NO_RESULTS


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # last-resort guard: no stack trace for end users
        logger.debug("Unhandled exception", exc_info=True)
        print(
            f"Unexpected error ({type(exc).__name__}). Re-run with --verbose for details.",
            file=sys.stderr,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
    