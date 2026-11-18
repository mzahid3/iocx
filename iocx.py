#!/usr/bin/env python3
"""
iocx: extract, normalize, defang, and enrich Indicators of Compromise (IOCs)
from unstructured text such as threat reports, alert exports, emails, and logs.

Author: Muhammad N. Zahid
License: MIT
"""
from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time

__version__ = "1.0.0"

# Common file extensions that look like TLDs and cause false positive domains
FILE_EXTS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "py", "sh",
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf",
    "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
    "zip", "rar", "7z", "gz", "tar", "iso", "img", "lnk", "msi", "hta", "tmp",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "dat", "bin", "db", "html", "htm",
}

REFANG_RULES = [
    (re.compile(r"\bh(?:xx|XX|\*\*)p(s?)", re.I), r"http\1"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[@\]|\[at\]|\(at\)", re.I), "@"),
]

PATTERNS = {
    "url": re.compile(r"\bhttps?://[^\s<>\"'\)\]\}]+", re.I),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "domain": re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
    ),
    "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    "sha1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "mitre": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

IOC_TYPES = list(PATTERNS)


def refang(text: str) -> str:
    """Convert defanged indicators (hxxp, [.], [@]) back to their real form."""
    for pattern, repl in REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, ioc_type: str) -> str:
    """Make an indicator safe to paste into tickets, chat, and email."""
    if ioc_type == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.I)
        return value.replace(".", "[.]")
    if ioc_type in ("domain", "ipv4"):
        return value.replace(".", "[.]")
    if ioc_type == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not (ip.is_private or ip.is_loopback or ip.is_reserved
                or ip.is_multicast or ip.is_link_local or ip.is_unspecified)


def extract(text: str, include_private: bool = False) -> dict[str, list[str]]:
    """Extract and deduplicate IOCs from text. Returns {type: [values]}."""
    text = refang(text)
    found: dict[str, set[str]] = {t: set() for t in IOC_TYPES}

    for url in PATTERNS["url"].findall(text):
        found["url"].add(url.rstrip(".,;:!?'\""))

    found["email"] = {e.lower() for e in PATTERNS["email"].findall(text)}

    for ip in PATTERNS["ipv4"].findall(text):
        if include_private or _is_public_ip(ip):
            found["ipv4"].add(ip)

    for dom in PATTERNS["domain"].findall(text):
        dom = dom.lower()
        if dom.rsplit(".", 1)[-1] not in FILE_EXTS:
            found["domain"].add(dom)

    for htype in ("sha256", "sha1", "md5"):
        found[htype] = {h.lower() for h in PATTERNS[htype].findall(text)}

    found["cve"] = {c.upper() for c in PATTERNS["cve"].findall(text)}
    found["mitre"] = set(PATTERNS["mitre"].findall(text))

    return {t: sorted(v) for t, v in found.items() if v}


class Enricher:
    """Optional reputation lookups via VirusTotal and AbuseIPDB."""

    VT_ENDPOINTS = {
        "ipv4": "ip_addresses", "domain": "domains", "url": "urls",
        "md5": "files", "sha1": "files", "sha256": "files",
    }

    def __init__(self, vt_key: str | None, abuse_key: str | None, vt_delay: float):
        try:
            import requests
        except ImportError:
            sys.exit("Enrichment requires 'requests'. Run: pip install requests")
        self.session = requests.Session()
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.vt_delay = vt_delay

    def lookup(self, ioc_type: str, value: str) -> str:
        notes = []
        if self.vt_key and ioc_type in self.VT_ENDPOINTS:
            notes.append(self._virustotal(ioc_type, value))
        if self.abuse_key and ioc_type == "ipv4":
            notes.append(self._abuseipdb(value))
        return " | ".join(n for n in notes if n)

    def _virustotal(self, ioc_type: str, value: str) -> str:
        ident = value
        if ioc_type == "url":
            ident = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/{self.VT_ENDPOINTS[ioc_type]}/{ident}"
        try:
            r = self.session.get(url, headers={"x-apikey": self.vt_key}, timeout=20)
            if r.status_code == 404:
                return "VT: not found"
            r.raise_for_status()
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return f"VT: {stats.get('malicious', 0)}/{sum(stats.values())} malicious"
        except Exception as exc:  # network or quota errors should not kill the run
            return f"VT: error ({exc.__class__.__name__})"
        finally:
            time.sleep(self.vt_delay)

    def _abuseipdb(self, ip: str) -> str:
        try:
            r = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=20,
            )
            r.raise_for_status()
            d = r.json()["data"]
            return f"AbuseIPDB: {d['abuseConfidenceScore']}% ({d.get('countryCode') or '??'})"
        except Exception as exc:
            return f"AbuseIPDB: error ({exc.__class__.__name__})"


def to_rows(iocs: dict[str, list[str]], do_defang: bool) -> list[dict]:
    return [
        {"type": t, "value": defang(v, t) if do_defang else v, "raw": v, "enrichment": ""}
        for t, values in iocs.items() for v in values
    ]


def render(rows: list[dict], fmt: str, out) -> None:
    fields = ["type", "value", "enrichment"]
    if fmt == "json":
        json.dump([{k: r[k] for k in fields} for r in rows], out, indent=2)
        out.write("\n")
    elif fmt == "csv":
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    else:
        if not rows:
            out.write("No IOCs found.\n")
            return
        tw = max(len(r["type"]) for r in rows)
        vw = min(max(len(r["value"]) for r in rows), 80)
        for r in rows:
            line = f"{r['type']:<{tw}}  {r['value']:<{vw}}"
            if r["enrichment"]:
                line += f"  {r['enrichment']}"
            out.write(line.rstrip() + "\n")
        out.write(f"\n{len(rows)} unique IOC(s) found.\n")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="iocx",
        description="Extract, defang, and enrich IOCs from text, files, or stdin.",
    )
    p.add_argument("inputs", nargs="*", help="Files to scan (reads stdin if omitted)")
    p.add_argument("-f", "--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("-o", "--output", help="Write results to a file")
    p.add_argument("-t", "--types", nargs="+", choices=IOC_TYPES,
                   help="Only return these IOC types")
    p.add_argument("--defang", action="store_true", help="Defang output values")
    p.add_argument("--include-private", action="store_true",
                   help="Keep RFC1918, loopback, and other non-routable IPs")
    p.add_argument("--enrich", action="store_true",
                   help="Look up reputation (uses VT_API_KEY / ABUSEIPDB_API_KEY env vars)")
    p.add_argument("--vt-delay", type=float, default=15.0,
                   help="Seconds between VirusTotal calls (free tier is 4/min)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.inputs:
        text = ""
        for path in args.inputs:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text += fh.read() + "\n"
    else:
        if sys.stdin.isatty():
            print("Paste text, then Ctrl-D (Ctrl-Z on Windows):", file=sys.stderr)
        text = sys.stdin.read()

    iocs = extract(text, include_private=args.include_private)
    if args.types:
        iocs = {t: v for t, v in iocs.items() if t in args.types}

    rows = to_rows(iocs, args.defang)

    if args.enrich:
        vt_key, abuse_key = os.getenv("VT_API_KEY"), os.getenv("ABUSEIPDB_API_KEY")
        if not (vt_key or abuse_key):
            print("No API keys set. Export VT_API_KEY and/or ABUSEIPDB_API_KEY.",
                  file=sys.stderr)
        else:
            enricher = Enricher(vt_key, abuse_key, args.vt_delay)
            for i, row in enumerate(rows, 1):
                print(f"[{i}/{len(rows)}] enriching {row['type']} ...", file=sys.stderr)
                row["enrichment"] = enricher.lookup(row["type"], row["raw"])

    if args.output:
        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            render(rows, args.format, fh)
        print(f"Wrote {len(rows)} IOC(s) to {args.output}", file=sys.stderr)
    else:
        render(rows, args.format, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
