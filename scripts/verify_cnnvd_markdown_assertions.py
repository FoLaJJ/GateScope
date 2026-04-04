#!/usr/bin/env python3
"""Verify OpenClaw CVE/CNNVD mappings against the local markdown assertion table.

Default assertion source:
  CNNVD网页漏洞对照-4-3版本.md

Primary purpose:
  - ensure CVE <-> CNNVD mapping stays identical to the manually curated markdown table

Secondary output:
  - report severity mismatches for manual review only
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


ZH_TO_EN_SEVERITY = {
    "超危": "critical",
    "高危": "high",
    "中危": "medium",
    "低危": "low",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--assertion-md",
        type=Path,
        default=Path("CNNVD网页漏洞对照-4-3版本.md"),
        help="Markdown table used as the local CVE/CNNVD assertion baseline",
    )
    return parser.parse_args()


def normalize_text(value: str | None) -> str:
    return " ".join((value or "").split())


def load_markdown_assertions(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) != 6 or parts[0] in {"序号", "----"}:
            continue
        if not re.fullmatch(r"\d+", parts[0]):
            continue
        rows.append(
            {
                "index": parts[0],
                "title_zh": parts[1],
                "cnnvd_id": parts[2],
                "cve_id": parts[3],
                "severity_zh": parts[4],
                "type_zh": parts[5],
            }
        )
    return rows


def load_catalog(repo_root: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    rules = yaml.safe_load((repo_root / "configs" / "rules" / "openclaw-cves.yaml").read_text(encoding="utf-8"))["cves"]
    mappings = yaml.safe_load((repo_root / "configs" / "rules" / "openclaw-id-mappings.yaml").read_text(encoding="utf-8"))["mappings"]

    rules_by_cve: dict[str, dict] = {}
    for item in rules:
        cve_id = normalize_text(str(item.get("cve_id") or item.get("id") or ""))
        if cve_id.startswith("CVE-"):
            rules_by_cve[cve_id] = item

    mappings_by_cve: dict[str, dict] = {}
    for item in mappings:
        cve_id = normalize_text(str(item.get("cve_id") or ""))
        if cve_id:
            mappings_by_cve[cve_id] = item

    return rules_by_cve, mappings_by_cve


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    assertion_md = args.assertion_md if args.assertion_md.is_absolute() else repo_root / args.assertion_md

    rows = load_markdown_assertions(assertion_md)
    rules_by_cve, mappings_by_cve = load_catalog(repo_root)

    stale_assertions: list[str] = []
    missing_mappings: list[str] = []
    mismatched_pairs: list[str] = []
    severity_mismatches: list[str] = []

    for row in rows:
        cve_id = row["cve_id"]
        expected_cnnvd = row["cnnvd_id"]
        if cve_id not in rules_by_cve:
            stale_assertions.append(f"{cve_id} -> {expected_cnnvd}")
            continue
        mapping = mappings_by_cve.get(cve_id)
        if mapping is None:
            missing_mappings.append(f"{cve_id} -> {expected_cnnvd}")
            continue

        actual_cnnvd = normalize_text(str(mapping.get("cnnvd_id") or ""))
        if actual_cnnvd != expected_cnnvd:
            mismatched_pairs.append(f"{cve_id}: expected {expected_cnnvd}, actual {actual_cnnvd or '<empty>'}")

        rule = rules_by_cve.get(cve_id)
        expected_severity = ZH_TO_EN_SEVERITY.get(row["severity_zh"])
        actual_severity = normalize_text(str((rule or {}).get("severity") or ""))
        if expected_severity and actual_severity and expected_severity != actual_severity:
            severity_mismatches.append(
                f"{cve_id}: markdown={row['severity_zh']}({expected_severity}) catalog={actual_severity}"
            )

    print(f"assertion_rows={len(rows)}")
    print(f"stale_assertions={len(stale_assertions)}")
    print(f"missing_mappings={len(missing_mappings)}")
    print(f"mismatched_pairs={len(mismatched_pairs)}")
    print(f"severity_mismatches={len(severity_mismatches)}")

    if stale_assertions:
        print("stale_assertion_examples:")
        for item in stale_assertions[:20]:
            print(f"  - {item}")

    if missing_mappings:
        print("missing_mapping_examples:")
        for item in missing_mappings[:20]:
            print(f"  - {item}")

    if mismatched_pairs:
        print("pair_mismatch_examples:")
        for item in mismatched_pairs[:20]:
            print(f"  - {item}")

    if severity_mismatches:
        print("severity_mismatch_examples:")
        for item in severity_mismatches[:20]:
            print(f"  - {item}")

    if missing_mappings or mismatched_pairs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
