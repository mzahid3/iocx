import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from iocx import defang, extract, refang  # noqa: E402

SAMPLE = (Path(__file__).resolve().parents[1] / "samples" / "threat_report.txt").read_text()


def test_refang():
    assert refang("hxxps://evil[.]com") == "https://evil.com"
    assert refang("bad(.)net") == "bad.net"
    assert refang("user[@]corp[.]com") == "user@corp.com"


def test_defang_roundtrip():
    url = "https://evil.com/path"
    assert refang(defang(url, "url")) == url


def test_extracts_hashes_by_length():
    iocs = extract(SAMPLE)
    assert len(iocs["sha256"]) == 1
    assert iocs["md5"] == ["5d41402abc4b2a76b9719d911017c592"]
    assert iocs["sha1"] == ["aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"]


def test_private_ips_filtered_by_default():
    assert "10.20.30.40" not in extract(SAMPLE).get("ipv4", [])
    assert "10.20.30.40" in extract(SAMPLE, include_private=True)["ipv4"]


def test_defanged_ip_is_found():
    assert "185.220.101.45" in extract(SAMPLE)["ipv4"]


def test_file_names_not_treated_as_domains():
    domains = extract(SAMPLE)["domain"]
    assert "update.exe" not in domains
    assert "invoice_2291.zip" not in domains
    assert "cdn-sync.net" in domains


def test_cve_and_mitre():
    iocs = extract(SAMPLE)
    assert iocs["cve"] == ["CVE-2024-3400"]
    assert set(iocs["mitre"]) == {"T1059.001", "T1053.005"}
