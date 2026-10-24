<div align="center">

# 🛡️ Automated Threat Intelligence API Aggregator

**A mini-SOAR command-line tool that enriches Indicators of Compromise (IoCs) from multiple threat intelligence feeds, with a local SQLite cache to protect free-tier API quotas.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-unittest-brightgreen)
![Security](https://img.shields.io/badge/focus-defensive%20security-informational)

</div>

---

## 📖 Overview

Analysts triaging an alert often pivot across several portals to answer one question: *"Is this indicator bad?"*
This tool automates that first-pass enrichment. Give it an **IPv4 address, domain, or SHA-256 hash** and it will:

1. **Validate** the input with strict, allow-list regexes.
2. **Check a local SQLite cache** (default freshness: 24 hours) so repeated lookups cost zero API calls.
3. **Query external sources** (AbuseIPDB, VirusTotal, AlienVault OTX) on a cache miss.
4. **Normalise** each provider's response into a common risk level and **aggregate** a single verdict.
5. **Fail gracefully**: missing keys, rate limits, and outages are reported cleanly, never as stack traces.

### Key Features

- 🔎 **Three IoC types**: IPv4, domains (incl. defanged `evil[.]com`), SHA-256 hashes
- ⚡ **SQLite caching** with configurable TTL, corruption handling, and owner-only file permissions
- 🔐 **Zero hardcoded secrets**: keys load from `.env` via `python-dotenv`
- 🧱 **Defensive by design**: parameterised SQL, timeouts, TLS verification, no redirects, response-size caps, terminal-escape sanitisation of third-party text
- 🧩 **Pluggable providers**: add a source by subclassing one small base class
- 🧪 **Offline demo mode** (`--mock`) and a `unittest` suite (no network required)
- 📤 **Human-readable and JSON output** for piping into other tooling

---

## 🏗️ Architecture Workflow

```text
 ┌──────────────┐
 │  User Input  │   python main.py 185.199.108.153
 └──────┬───────┘
        ▼
 ┌──────────────────────────┐   invalid? ──► reject with exit code 2
 │  Validator (validators)  │   • length cap, ASCII-only
 │  regex allow-list        │   • IPv4 / domain / SHA-256 fullmatch
 └──────┬───────────────────┘   • private & reserved IPs refused
        ▼
 ┌──────────────────────────┐   HIT (fresh, < TTL) ─────────────┐
 │  SQLite Cache Check      │                                   │
 │  (database)              │                                   │
 └──────┬───────────────────┘                                   │
        │ MISS / EXPIRED                                        │
        ▼                                                       │
 ┌──────────────────────────┐   per-provider failure is         │
 │  External API Lookup     │   reported, never fatal,          │
 │  (threat_intel)          │   never cached                    │
 │  AbuseIPDB · VT · OTX    │                                   │
 └──────┬───────────────────┘                                   │
        ▼                                                       │
 ┌──────────────────────────┐                                   │
 │  Cache Save (upsert)     │                                   │
 └──────┬───────────────────┘                                   │
        ▼                                                       ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │  CLI Output (main): unified report + aggregated verdict / JSON  │
 └─────────────────────────────────────────────────────────────────┘
```

### Project Structure

```text
threat-intel-aggregator/
├── main.py            # CLI entry point & orchestrator workflow
├── validators.py      # Regex-based IoC validation and classification
├── database.py        # SQLite cache: init, lookup, save, purge
├── threat_intel.py    # API clients (AbuseIPDB, VirusTotal, OTX) + mock
├── tests/             # unittest suite (validators, cache, orchestration)
├── .env.example       # Template for API keys
├── .gitignore
├── requirements.txt
└── README.md
```

---

## ✅ Prerequisites

- Python **3.9+**
- `pip` and `venv`
- Free API keys (optional if you only use `--mock`):
  - [AbuseIPDB](https://www.abuseipdb.com/account/api): IPv4 only
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey): IPs, domains, hashes
  - [AlienVault OTX](https://otx.alienvault.com/settings): IPs, domains, hashes

## ⚙️ Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/jmwai-prog/threat-intel-aggregator.git
cd threat-intel-aggregator

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your API keys
cp .env.example .env
#    then edit .env and paste in your keys (this file is git-ignored)

# 5. (Optional) Run the test suite
python -m unittest discover -v
```

### Configuration

| Variable | Required | Description |
|---|---|---|
| `ABUSEIPDB_API_KEY` | For AbuseIPDB | AbuseIPDB v2 key |
| `VIRUSTOTAL_API_KEY` | For VirusTotal | VirusTotal v3 key |
| `OTX_API_KEY` | For OTX | AlienVault OTX key |
| `CACHE_DB_PATH` | No | SQLite file location (default `threat_intel_cache.db`) |
| `CACHE_TTL_HOURS` | No | Cache freshness window (default `24`) |

---

## 🚀 Usage

```bash
python main.py <IOC> [options]
python main.py                       # prompts interactively for an IoC
```

| Option | Description |
|---|---|
| `-s, --sources` | Comma-separated sources, e.g. `virustotal,otx` (default: all) |
| `--json` | Machine-readable JSON output |
| `--mock` | Offline demo mode, no API keys or network needed |
| `--refresh` | Skip cache reads but refresh the cache |
| `--no-cache` | Bypass the cache entirely |
| `--ttl-hours N` | Override cache freshness window |
| `--purge-cache` | Delete expired cache entries and exit |
| `-v, --verbose` | Debug logging (the only way tracebacks are shown) |

**Exit codes:** `0` success · `1` unexpected error · `2` invalid input · `3` no source returned a result

### Example 1: First lookup (cache miss → live)

```console
$ python main.py 8.8.8.8 --mock
================================================================
 THREAT INTELLIGENCE REPORT
================================================================
 Indicator : 8.8.8.8
 Type      : ipv4
 Verdict   : CLEAN
 Queried   : 2026-10-22T15:23:41Z
----------------------------------------------------------------
 [mock] (LIVE)  risk: CLEAN
   Simulated threat score 0/100 (offline demo data).
   - threat_score: 0
   - ioc_type: ipv4
================================================================
```

### Example 2: Repeat lookup (served from SQLite, zero API calls)

```console
$ python main.py example.com --mock
================================================================
 THREAT INTELLIGENCE REPORT
================================================================
 Indicator : example.com
 Type      : domain
 Verdict   : CLEAN
 Queried   : 2026-10-22T15:23:46Z
----------------------------------------------------------------
 [mock] (CACHE, just now)  risk: CLEAN
   Simulated threat score 0/100 (offline demo data).
   - threat_score: 0
   - ioc_type: domain
================================================================
```

### Example 3: Malicious file hash (EICAR antivirus test file)

```console
$ python main.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f --mock
================================================================
 THREAT INTELLIGENCE REPORT
================================================================
 Indicator : 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
 Type      : sha256
 Verdict   : MALICIOUS
 Queried   : 2026-10-22T15:23:41Z
----------------------------------------------------------------
 [mock] (LIVE)  risk: MALICIOUS
   Simulated threat score 96/100 (offline demo data).
   - threat_score: 96
   - ioc_type: sha256
================================================================
```

### Example 4: Hostile / invalid input is rejected before processing

```console
$ python main.py "8.8.8.8; DROP TABLE ioc_cache"
Invalid input: Input is not a valid IPv4 address, domain name, or SHA-256 hash.

$ python main.py 10.0.0.1
Invalid input: Private, loopback or reserved IP addresses are not queried (avoids leaking internal addressing to third-party services).
```

### Example 5: Missing API keys degrade gracefully (no stack trace)

```console
$ python main.py 1.2.3.4
================================================================
 THREAT INTELLIGENCE REPORT
================================================================
 Indicator : 1.2.3.4
 Type      : ipv4
 Verdict   : UNKNOWN
 Queried   : 2026-10-22T15:23:42Z
----------------------------------------------------------------
 [abuseipdb] ERROR: API key not configured (set ABUSEIPDB_API_KEY in your .env file).
----------------------------------------------------------------
 [virustotal] ERROR: API key not configured (set VIRUSTOTAL_API_KEY in your .env file).
----------------------------------------------------------------
 [otx] ERROR: API key not configured (set OTX_API_KEY in your .env file).
================================================================
```

### Example 6: JSON output for automation

```console
$ python main.py 8.8.8.8 --mock --json
{
  "ioc": "8.8.8.8",
  "type": "ipv4",
  "verdict": "clean",
  "queried_at": "2026-10-22T15:23:46Z",
  "results": [
    {
      "source": "mock",
      "risk_level": "clean",
      "summary": "Simulated threat score 0/100 (offline demo data).",
      "details": { "threat_score": 0, "ioc_type": "ipv4" },
      "origin": "live",
      "fetched_at": 1792682626
    }
  ],
  "errors": [],
  "skipped": []
}
```

---

## 🔒 Security Design Decisions

| Concern | Mitigation |
|---|---|
| Injection (SQL, URL, command) | Strict allow-list regex validation before anything else; parameterised SQL only; IoC is URL-quoted before use in paths |
| ReDoS | Input length capped before regex; patterns are linear and anchored with `fullmatch` |
| Secret exposure | Keys live in `.env` (git-ignored), are sent only in headers, never logged or echoed in errors |
| Information leakage | Private/reserved IPs are never sent to third parties; no stack traces by default |
| Terminal escape injection | Third-party strings stripped of control characters and truncated before printing |
| Hostile/oversized responses | Timeouts, TLS verification, redirects disabled, 2 MiB response cap, shape-checked JSON |
| Quota exhaustion | Cache-first design; 429s are not retried; failures are never cached |
| Cache tampering/corruption | Corrupt rows are detected, deleted and treated as misses; DB file is `chmod 600` |

### Extending with a new provider

Subclass `ThreatIntelClient` in `threat_intel.py`, implement `_fetch()` and `_summarize()`, and register it in `CLIENT_REGISTRY`. The orchestrator, cache, and output layers need no changes.

---

## ⚖️ Legal Disclaimer & Authorized Use

This project is provided for **educational and defensive security purposes only**.

- Only investigate indicators in connection with systems, networks, and incidents you **own or are explicitly authorised** to analyse.
- Comply with each provider's **Terms of Service, API usage policies, and rate limits**. Free-tier keys are generally intended for non-commercial use; review each provider's licence before any commercial or redistributed use.
- Indicators you submit (IPs, domains, hashes) are **sent to third-party services**. Do not submit data that is confidential, regulated, or covered by an NDA or privacy obligation (for example, internal hostnames or customer data) without proper approval.
- Threat intelligence verdicts are **probabilistic and may contain false positives or negatives**. Treat results as one input to human analysis, not as definitive attribution or grounds for punitive action.
- The authors accept **no liability** for misuse or for decisions made from this tool's output. This software is provided "as is", without warranty of any kind.

---

## 🗺️ Roadmap Ideas

- IPv6 support and URL indicators
- Async lookups (`asyncio` + `aiohttp`) for batch mode
- CSV/STIX 2.1 export
- Additional sources (URLhaus, GreyNoise, Shodan)
- GitHub Actions CI with `pytest`, `ruff`, `mypy`, and `pip-audit`

## 📄 License

Add your preferred license (for example MIT) as a `LICENSE` file before publishing.