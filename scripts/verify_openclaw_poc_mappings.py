#!/usr/bin/env python3
"""Verify PoC-linked OpenClaw mappings against the canonical CVE rules and live NVD metadata."""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_FILE = REPO_ROOT / "configs" / "rules" / "openclaw-cves.yaml"
MAPPING_FILE = REPO_ROOT / "configs" / "rules" / "openclaw-id-mappings.yaml"
POC_FILE = REPO_ROOT / "configs" / "rules" / "pocs.yaml"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def fetch_json(url: str) -> dict:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "AgentScan PoC verifier"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"unreachable fetch failure: {last_error}")


def normalize_rules() -> tuple[dict[str, dict], dict[str, dict]]:
    rules = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))["cves"]
    mappings = yaml.safe_load(MAPPING_FILE.read_text(encoding="utf-8"))["mappings"]

    by_rule_id: dict[str, dict] = {}
    for item in rules:
        rule = dict(item)
        if rule.get("id", "").startswith("CVE-") and not rule.get("cve_id"):
            rule["cve_id"] = rule["id"]
        by_rule_id[rule["id"]] = rule

    by_cve: dict[str, dict] = {}
    for rule in by_rule_id.values():
        cve_id = str(rule.get("cve_id") or "").strip()
        if cve_id:
            by_cve[cve_id] = rule

    for mapping in mappings:
        rule = by_rule_id.get(str(mapping.get("rule_id") or "").strip())
        if not rule:
            continue
        for field in ("cve_id", "cnnvd_id"):
            value = str(mapping.get(field) or "").strip()
            if value:
                rule[field] = value
        cve_id = str(rule.get("cve_id") or "").strip()
        if cve_id:
            by_cve[cve_id] = rule

    return by_rule_id, by_cve


def load_pocs() -> list[dict]:
    return yaml.safe_load(POC_FILE.read_text(encoding="utf-8"))["pocs"]


def extract_expected_fixed(description: str) -> str:
    patterns = [
        r"Prior to version ([0-9]+\.[0-9]+\.[0-9]+)",
        r"before ([0-9]+\.[0-9]+\.[0-9]+)",
        r"Version ([0-9]+\.[0-9]+\.[0-9]+) fixes the issue",
        r"This vulnerability is fixed in ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, description, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def main() -> int:
    _, rules_by_cve = normalize_rules()
    pocs = load_pocs()

    issues: list[str] = []
    live_notes: list[str] = []

    for poc in pocs:
        cve_id = str(poc.get("cve_id") or "").strip()
        if not cve_id:
            continue

        local_rule = rules_by_cve.get(cve_id)
        if not local_rule:
            issues.append(f"{poc['id']}: missing canonical rule for {cve_id}")
            continue

        expected_cnnvd = str(local_rule.get("cnnvd_id") or "").strip()
        actual_cnnvd = str(poc.get("cnnvd_id") or "").strip()
        if actual_cnnvd != expected_cnnvd:
            issues.append(
                f"{poc['id']}: {cve_id} cnnvd mismatch poc={actual_cnnvd or '<empty>'} canonical={expected_cnnvd or '<empty>'}"
            )

        expected_severity = str(local_rule.get("severity") or "").strip().lower()
        actual_severity = str(poc.get("severity") or "").strip().lower()
        if actual_severity != expected_severity:
            issues.append(
                f"{poc['id']}: {cve_id} severity mismatch poc={actual_severity or '<empty>'} canonical={expected_severity or '<empty>'}"
            )

        expected_cvss = float(local_rule.get("cvss", 0) or 0)
        actual_cvss = float(poc.get("cvss", 0) or 0)
        if abs(actual_cvss - expected_cvss) > 1e-9:
            issues.append(f"{poc['id']}: {cve_id} cvss mismatch poc={actual_cvss} canonical={expected_cvss}")

        expected_remediation = str(local_rule.get("remediation") or "").strip()
        actual_remediation = str(poc.get("remediation") or "").strip()
        if actual_remediation != expected_remediation:
            issues.append(
                f"{poc['id']}: {cve_id} remediation mismatch poc={actual_remediation!r} canonical={expected_remediation!r}"
            )

        payload = fetch_json(NVD_API.format(cve_id=cve_id))
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            issues.append(f"{poc['id']}: NVD entry not found for {cve_id}")
            continue

        cve = vulnerabilities[0]["cve"]
        descriptions = cve.get("descriptions") or []
        english = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        if "OpenClaw" not in english:
            issues.append(f"{poc['id']}: {cve_id} NVD description does not mention OpenClaw")

        expected_fixed = extract_expected_fixed(english)
        if expected_fixed and str(local_rule.get("affected_before") or "").strip() != expected_fixed:
            issues.append(
                f"{poc['id']}: {cve_id} affected_before mismatch local={local_rule.get('affected_before')} nvd={expected_fixed}"
            )

        metrics = cve.get("metrics") or {}
        metric = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            if metrics.get(key):
                metric = metrics[key][0]["cvssData"]
                break
        if metric is not None:
            expected_score = float(metric["baseScore"])
            expected_severity = str(metric["baseSeverity"]).lower()
            if abs(float(local_rule.get("cvss", 0) or 0) - expected_score) > 1e-9:
                live_notes.append(
                    f"{poc['id']}: {cve_id} cvss mismatch local={local_rule.get('cvss')} nvd={expected_score}"
                )
            if str(local_rule.get("severity") or "").strip().lower() != expected_severity:
                live_notes.append(
                    f"{poc['id']}: {cve_id} severity mismatch local={local_rule.get('severity')} nvd={expected_severity}"
                )

    print(f"checked_pocs={sum(1 for poc in pocs if str(poc.get('cve_id') or '').strip())}")
    if issues:
        print("issues:")
        for issue in issues:
            print(f"  - {issue}")
        return 1

    print("verified: all PoC-linked rules match the canonical YAML catalog")
    if live_notes:
        print("live_reference_notes:")
        for note in live_notes:
            print(f"  - {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
