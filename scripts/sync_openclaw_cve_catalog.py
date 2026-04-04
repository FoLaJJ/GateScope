#!/usr/bin/env python3
"""Sync the OpenClaw CVE rule catalog from the official cve.org search service.

Design goals:
1. Use CVE as the only primary rule identifier.
2. Preserve CNNVD as an external mapping from configs/rules/openclaw-id-mappings.yaml.
3. Pull the current OpenClaw corpus from the official cve.org search backend.
4. Keep request volume low and predictable.
5. Optionally align severity with the user-provided CNNVD markdown assertion table.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path
from typing import Any

import yaml

SEARCH_URL = "https://www.cve.org/restapiv1/search"
SEARCH_PAGE_SIZE = 200
USER_AGENT = "ClawScan OpenClaw CVE Sync/1.0"

ZH_TO_EN_SEVERITY = {
    "超危": "critical",
    "高危": "high",
    "中危": "medium",
    "低危": "low",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--query", default="openclaw", help="cve.org search term")
    parser.add_argument("--search-delay", type=float, default=1.3, help="Sleep between cve.org search page requests")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--write", action="store_true", help="Write the refreshed catalog back to YAML")
    parser.add_argument(
        "--assertion-md",
        type=Path,
        default=Path("CNNVD网页漏洞对照-4-3版本.md"),
        help="Local markdown assertion file used to align CVE<->CNNVD pairs and domestic severity labels",
    )
    return parser.parse_args()


def normalize_text(value: str | None) -> str:
    return " ".join((value or "").split())


def normalize_title(value: str | None) -> str:
    title = normalize_text(value)
    if not title:
        return ""

    patterns = [
        r"^OpenClaw\s+[^-]+?\s+-\s+(.+)$",
        r"^OpenClaw\s*-\s+(.+)$",
    ]
    for pattern in patterns:
        match = re.match(pattern, title)
        if match:
            candidate = normalize_text(match.group(1))
            if candidate:
                return candidate

    if title.lower().startswith("openclaw "):
        stripped = normalize_text(title[len("OpenClaw ") :])
        if stripped:
            return stripped
    return title


def version_sort_key(value: str) -> list[tuple[int, Any]]:
    parts: list[tuple[int, Any]] = []
    for token in re.split(r"([0-9]+)", value.lower()):
        if token == "":
            continue
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token))
    return parts


def load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8")


def post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def search_openclaw_records(query: str, timeout: float, delay: float) -> list[dict[str, Any]]:
    all_rows: list[dict[str, Any]] = []
    offset = 0
    total = None
    while total is None or offset < total:
        payload = {
            "query": query,
            "from": offset,
            "size": SEARCH_PAGE_SIZE,
            "sort": {"property": "cveId", "order": "desc"},
        }
        data = post_json(SEARCH_URL, payload, timeout=timeout)
        rows = data.get("data") or []
        total = int(data.get("resultsTotal") or 0)
        all_rows.extend(rows)
        offset += len(rows)
        if offset >= total or not rows:
            break
        time.sleep(delay)
    return all_rows


def load_markdown_assertions(path: Path) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    if not path.is_file():
        return rows

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) != 6 or parts[0] in {"序号", "----"}:
            continue
        if not re.fullmatch(r"\d+", parts[0]):
            continue
        rows[parts[3]] = {
            "title_zh": parts[1],
            "cnnvd_id": parts[2],
            "cve_id": parts[3],
            "severity_zh": parts[4],
            "type_zh": parts[5],
        }
    return rows


def load_existing_rules(repo_root: Path) -> dict[str, dict[str, Any]]:
    rules_doc = load_yaml(repo_root / "configs" / "rules" / "openclaw-cves.yaml")
    by_cve: dict[str, dict[str, Any]] = {}
    for item in rules_doc.get("cves") or []:
        cve_id = normalize_text(str(item.get("cve_id") or item.get("id") or ""))
        if cve_id.startswith("CVE-"):
            by_cve[cve_id] = item
    return by_cve


def english_description(cna: dict[str, Any]) -> str:
    for item in cna.get("descriptions") or []:
        if str(item.get("lang") or "").lower().startswith("en"):
            value = normalize_text(str(item.get("value") or ""))
            if value:
                return value
    return ""


def derive_title(cna: dict[str, Any], description: str) -> str:
    title = normalize_title(cna.get("title"))
    if title:
        return title

    first_sentence = normalize_text(description.split(". ", 1)[0]).rstrip(".")
    if first_sentence:
        return normalize_title(first_sentence)
    return "OpenClaw Vulnerability"


def derive_cvss(metrics: list[dict[str, Any]]) -> tuple[float, str]:
    metric_order = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
    for field in metric_order:
        for item in metrics:
            data = item.get(field) or {}
            score = data.get("baseScore")
            if score is None:
                continue
            severity = normalize_text(str(data.get("baseSeverity") or "")).lower()
            return float(score), severity
    return 0.0, ""


def derive_affected_before(cna: dict[str, Any], title: str, description: str, existing_rule: dict[str, Any] | None) -> str:
    less_than: list[str] = []
    unaffected_versions: list[str] = []

    for affected in cna.get("affected") or []:
        for version in affected.get("versions") or []:
            less = normalize_text(str(version.get("lessThan") or ""))
            if less:
                less_than.append(less)
            status = normalize_text(str(version.get("status") or "")).lower()
            version_value = normalize_text(str(version.get("version") or ""))
            if status == "unaffected" and version_value:
                unaffected_versions.append(version_value)

    if less_than:
        return sorted(set(less_than), key=version_sort_key)[0]
    if unaffected_versions:
        return sorted(set(unaffected_versions), key=version_sort_key)[0]

    for haystack in (title, description):
        for pattern in (
            r"\bOpenClaw\s*<\s*([0-9][0-9A-Za-z_.\-]+)",
            r"\bbefore\s+([0-9][0-9A-Za-z_.\-]+)",
            r"\bprior to\s+([0-9][0-9A-Za-z_.\-]+)",
            r"\bupgrading to version\s+([0-9][0-9A-Za-z_.\-]+)",
            r"\bupgrade to version\s+([0-9][0-9A-Za-z_.\-]+)",
            r"\bresolve this issue\.\s+This patch.*?version\s+([0-9][0-9A-Za-z_.\-]+)",
        ):
            match = re.search(pattern, haystack, re.IGNORECASE)
            if match:
                return normalize_text(match.group(1).rstrip(".,;)"))

    if existing_rule:
        return normalize_text(str(existing_rule.get("affected_before") or ""))
    return ""


def derive_remediation(affected_before: str, existing_rule: dict[str, Any] | None) -> str:
    if affected_before:
        return f"Upgrade to >= {affected_before}"
    if existing_rule:
        return normalize_text(str(existing_rule.get("remediation") or ""))
    return "Upgrade to the latest OpenClaw release that includes the vendor fix"


def infer_chinese_impact(title: str, description: str) -> str:
    text = strings_lower_join(title, description)
    keyword_map = [
        (("command injection", "remote code execution", "code execution", "code injection", "shell", "arbitrary code"), "成功利用后可能导致命令注入或任意代码执行。"),
        (("path traversal", "directory traversal", "symlink", "workspace escape", "sandbox escape", "sandbox boundary", "unc-style"), "成功利用后可能导致目录遍历、越权读写或沙箱边界突破。"),
        (("authentication bypass", "authorization bypass", "access control", "privilege escalation", "allowlist bypass", "policy downgrade", "scope"), "成功利用后可能导致未授权访问、权限提升或安全策略绕过。"),
        (("xss", "cross-site scripting", "prompt injection"), "成功利用后可能导致跨站脚本、提示注入或界面上下文被劫持。"),
        (("ssrf", "server-side request forgery", "proxy"), "成功利用后可能导致服务端请求伪造并访问内网或云元数据资源。"),
        (("information disclosure", "info disclosure", "leak", "disclosure", "credential", "pkce", "oauth state"), "成功利用后可能导致敏感信息、凭证或内部状态泄露。"),
        (("dos", "denial of service", "resource exhaustion", "memory"), "成功利用后可能导致拒绝服务、资源耗尽或稳定性下降。"),
        (("forgery", "spoof", "brute force", "prediction", "replay"), "成功利用后可能导致身份伪造、请求重放或认证被暴力猜解。"),
    ]
    for keywords, impact in keyword_map:
        if any(keyword in text for keyword in keywords):
            return impact
    return "成功利用后会对 OpenClaw 的认证、授权、沙箱隔离或运行安全造成影响。"


def build_description_zh(title: str, affected_before: str, description: str) -> str:
    version_scope = f"受影响版本为 {affected_before} 之前。" if affected_before else ""
    return f"该漏洞与“{title or 'OpenClaw 漏洞'}”相关。{version_scope}{infer_chinese_impact(title, description)}"


def strings_lower_join(*values: str) -> str:
    return " ".join(normalize_text(value).lower() for value in values if normalize_text(value))


def severity_from_assertion(assertion_rows: dict[str, dict[str, str]], cve_id: str) -> str:
    row = assertion_rows.get(cve_id)
    if not row:
        return ""
    return ZH_TO_EN_SEVERITY.get(row.get("severity_zh", ""), "")


def is_relevant_openclaw_record(source: dict[str, Any]) -> bool:
    cna = source.get("containers", {}).get("cna", {})
    haystack = strings_lower_join(
        cna.get("title") or "",
        english_description(cna),
        json.dumps(cna.get("affected") or [], ensure_ascii=False),
    )
    return "openclaw" in haystack


def build_rule_entry(item: dict[str, Any], existing_rules: dict[str, dict[str, Any]], assertion_rows: dict[str, dict[str, str]]) -> dict[str, Any]:
    source = item.get("_source") or {}
    cve_meta = source.get("cveMetadata") or {}
    cve_id = normalize_text(str(cve_meta.get("cveId") or item.get("_id") or ""))
    cna = source.get("containers", {}).get("cna", {})
    existing_rule = existing_rules.get(cve_id)

    description = english_description(cna)
    title = derive_title(cna, description)
    affected_before = derive_affected_before(cna, normalize_text(str(cna.get("title") or "")), description, existing_rule)
    cvss, cvss_severity = derive_cvss(cna.get("metrics") or [])
    severity = severity_from_assertion(assertion_rows, cve_id) or cvss_severity or normalize_text(str((existing_rule or {}).get("severity") or "")).lower() or "medium"
    remediation = derive_remediation(affected_before, existing_rule)
    cnnvd_id = normalize_text(str(assertion_rows.get(cve_id, {}).get("cnnvd_id") or ""))

    entry: dict[str, Any] = {
        "id": cve_id,
        "title": title,
        "severity": severity,
        "cvss": round(cvss, 1),
        "affected_before": affected_before,
        "description": description,
        "remediation": remediation,
        "cve_id": cve_id,
        "description_zh": build_description_zh(title, affected_before, description),
    }
    if cnnvd_id:
        entry["cnnvd_id"] = cnnvd_id
    return entry


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    assertion_md = args.assertion_md if args.assertion_md.is_absolute() else repo_root / args.assertion_md
    rules_path = repo_root / "configs" / "rules" / "openclaw-cves.yaml"

    existing_rules = load_existing_rules(repo_root)
    assertion_rows = load_markdown_assertions(assertion_md)

    try:
        rows = search_openclaw_records(args.query, timeout=args.timeout, delay=args.search_delay)
    except urllib.error.URLError as exc:
        print(f"error: failed to fetch cve.org search results: {exc}", file=sys.stderr)
        return 1

    filtered_rows = [row for row in rows if is_relevant_openclaw_record(row.get("_source") or {})]
    by_cve: dict[str, dict[str, Any]] = {}
    skipped = 0
    for row in filtered_rows:
        entry = build_rule_entry(row, existing_rules, assertion_rows)
        cve_id = entry["cve_id"]
        if cve_id in by_cve:
            skipped += 1
            continue
        by_cve[cve_id] = entry

    ordered_entries = sorted(by_cve.values(), key=lambda item: item["cve_id"], reverse=True)
    today = date.today().isoformat()
    rules_doc = {
        "meta": {
            "updated_at": today,
            "verified_at": today,
            "source_cutoff": today,
            "source": "cve.org restapiv1 search + MITRE CVE Record data + local CNNVD assertion mapping",
            "notes": (
                "Rule catalog now uses CVE as the single primary identifier. "
                "CNNVD stays as an external mapping merged from configs/rules/openclaw-id-mappings.yaml. "
                "Search requests are paged and rate-limited; mapped CVEs may inherit domestic severity from the supplied CNNVD assertion table."
            ),
        },
        "cves": ordered_entries,
    }

    if args.write:
        save_yaml(rules_path, rules_doc)

    print(f"results_total={len(rows)}")
    print(f"filtered_total={len(filtered_rows)}")
    print(f"rules_total={len(ordered_entries)}")
    print(f"assertion_rows={len(assertion_rows)}")
    print(f"duplicates_skipped={skipped}")
    if args.write:
        print(f"updated_file={rules_path.relative_to(repo_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
