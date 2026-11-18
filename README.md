# iocx

![tests](https://github.com/<your-username>/iocx/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A fast command-line tool for SOC analysts and threat hunters that pulls Indicators of Compromise out of messy text (threat reports, alert exports, phishing emails, ticket notes), cleans them up, and optionally checks their reputation.

Built from day-to-day MSSP triage work, where IOCs arrive defanged, duplicated, and buried in paragraphs.

## Features

- Extracts URLs, domains, IPv4 addresses, emails, MD5/SHA1/SHA256 hashes, CVE IDs, and MITRE ATT&CK technique IDs
- Automatically refangs input (`hxxps`, `[.]`, `(.)`, `[@]`, `[dot]`) so defanged indicators are not missed
- Defangs output on request so results are safe to paste into tickets and client emails
- Filters private, loopback, and reserved IPs by default to cut noise
- Drops false positive "domains" that are really file names (`update.exe`, `invoice.pdf`)
- Optional enrichment with VirusTotal and AbuseIPDB, with rate limiting for free API tiers
- Output as a table, JSON, or CSV for SIEM import or reporting
- No dependencies for extraction; `requests` only needed for enrichment

## Install

```bash
git clone https://github.com/<your-username>/iocx.git
cd iocx
pip install -r requirements.txt
```

## Usage

```bash
# Scan a file
python iocx.py samples/threat_report.txt

# Pipe from clipboard or another tool
pbpaste | python iocx.py --defang

# Only hashes and IPs, as JSON
python iocx.py report.txt -t sha256 md5 ipv4 -f json

# Export to CSV for a blocklist or SIEM lookup table
python iocx.py report.txt -f csv -o iocs.csv

# Enrich with reputation data
export VT_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
python iocx.py report.txt --enrich
```

## Example

```
$ python iocx.py samples/threat_report.txt --defang

url      hxxps://secure-docs[.]invoice-update[.]com/view?id=8842
email    billing[@]invoice-update[.]com
ipv4     185[.]220[.]101[.]45
ipv4     45[.]142[.]212[.]61
domain   cdn-sync[.]net
domain   invoice-update[.]com
domain   secure-docs[.]invoice-update[.]com
sha256   780c881505aacb5f6b822ea0051d9059674ead2fc8a2a177b6a641caf501135b
sha1     aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
md5      5d41402abc4b2a76b9719d911017c592
cve      CVE-2024-3400
mitre    T1053.005
mitre    T1059.001
```

## Options

| Flag | Description |
|------|-------------|
| `-f, --format` | `table` (default), `json`, or `csv` |
| `-o, --output` | Write results to a file |
| `-t, --types` | Limit to specific IOC types |
| `--defang` | Defang output values |
| `--include-private` | Keep RFC1918 and other non-routable IPs |
| `--enrich` | Query VirusTotal and/or AbuseIPDB |
| `--vt-delay` | Seconds between VT calls (default 15 for the free tier) |

## Running tests

```bash
pip install pytest
pytest -v
```

## Roadmap

- IPv6 support
- Shodan and URLhaus enrichment
- STIX 2.1 bundle output
- Allowlist file to suppress known-good domains

## License

MIT
