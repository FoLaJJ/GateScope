#!/usr/bin/env python3
"""Normalize the OpenClaw rule catalog to CVE + CNNVD only.

This script performs three deterministic actions:
1. Removes GHSA-only rules and GHSA mapping fields.
2. Fetches official CVE titles from the MITRE CVE Record API.
3. Rebuilds generic Chinese descriptions from the normalized rule metadata.
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

API_TEMPLATE = "https://cveawg.mitre.org/api/cve/{cve_id}"
GENERIC_TITLE_PREFIXES = (
    "OpenClaw 安全漏洞",
    "OpenClaw 访问控制错误漏洞",
    "OpenClaw 操作系统命令注入漏洞",
    "OpenClaw 路径遍历漏洞",
    "OpenClaw 代码问题漏洞",
    "OpenClaw 后置链接漏洞",
    "OpenClaw 日志信息泄露漏洞",
    "OpenClaw 跨站脚本漏洞",
    "OpenClaw 参数注入漏洞",
    "OpenClaw 信息泄露漏洞",
    "OpenClaw 代码注入漏洞",
    "OpenClaw 加密问题漏洞",
    "OpenClaw 数据伪造问题漏洞",
    "OpenClaw 竞争条件问题漏洞",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--delay", type=float, default=0.6, help="Seconds to sleep between uncached CVE requests")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--write", action="store_true", help="Write changes back to the YAML files")
    parser.add_argument(
        "--cache-file",
        type=Path,
        default=Path("_data") / "cve-title-cache.json",
        help="Local cache for MITRE CVE titles",
    )
    return parser.parse_args()


def normalize_text(value: str | None) -> str:
    return " ".join((value or "").split())


def normalize_title(title: str) -> str:
    normalized = normalize_text(title)
    if not normalized:
        return normalized

    patterns = [
        r"^OpenClaw\s+[^-]+?\s+-\s+(.+)$",
        r"^OpenClaw\s*-\s+(.+)$",
    ]
    for pattern in patterns:
        match = re.match(pattern, normalized)
        if match:
            candidate = normalize_text(match.group(1))
            if candidate:
                return candidate
    return normalized


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False, width=120)


def load_cache(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return {str(k): normalize_text(str(v)) for k, v in data.items() if normalize_text(str(v))}


def save_cache(path: Path, cache: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, ensure_ascii=False, indent=2, sort_keys=True)


def extract_cve_id(entry: dict[str, Any]) -> str:
    cve_id = normalize_text(str(entry.get("cve_id") or ""))
    if cve_id:
        return cve_id
    rule_id = normalize_text(str(entry.get("id") or entry.get("rule_id") or ""))
    return rule_id if rule_id.startswith("CVE-") else ""


def should_refresh_title(title: str) -> bool:
    normalized = normalize_title(title)
    if not normalized:
        return True
    if normalized.endswith("...") or len(normalized) >= 120:
        return True
    return normalized.startswith(GENERIC_TITLE_PREFIXES)


def fetch_official_title(
    cve_id: str,
    *,
    cache: dict[str, str],
    timeout: float,
    delay: float,
    last_request_at: list[float],
) -> str:
    if cve_id in cache:
        return cache[cve_id]

    now = time.monotonic()
    elapsed = now - last_request_at[0]
    if elapsed < delay:
        time.sleep(delay - elapsed)

    request = urllib.request.Request(
        API_TEMPLATE.format(cve_id=cve_id),
        headers={"User-Agent": "AgentScan OpenClaw Catalog Normalizer"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{cve_id}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{cve_id}: {exc.reason}") from exc
    finally:
        last_request_at[0] = time.monotonic()

    title = normalize_text(payload.get("containers", {}).get("cna", {}).get("title", ""))
    if title:
        cache[cve_id] = title
    return title


def derive_title_from_description(entry: dict[str, Any]) -> str:
    description = normalize_text(str(entry.get("description") or ""))
    if not description:
        return normalize_text(str(entry.get("title") or "")) or "OpenClaw Vulnerability"

    patterns: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(
                r"A remote code execution \(RCE\) vulnerability in .*? allows attackers to execute arbitrary code via (?:an? )?(.+?) attack",
                re.IGNORECASE,
            ),
            "Remote Code Execution via {vector}",
        ),
        (
            re.compile(r"contains an? ([a-z0-9\-\s]+?) vulnerability in ([^,.]+)", re.IGNORECASE),
            "{vuln_type} in {component}",
        ),
        (
            re.compile(r"contains an? ([a-z0-9\-\s]+?) vulnerability where ([^,.]+)", re.IGNORECASE),
            "{vuln_type} via {vector}",
        ),
        (
            re.compile(r"A ([a-z0-9\-\s]+?) vulnerability in ([^,.]+)", re.IGNORECASE),
            "{vuln_type} in {component}",
        ),
    ]
    for pattern, template in patterns:
        match = pattern.search(description)
        if not match:
            continue
        groups = {k: normalize_text(v).strip(" -") for k, v in match.groupdict().items() if v}
        if "vuln_type" not in groups and match.groups():
            groups["vuln_type"] = normalize_text(match.group(1)).strip(" -")
        if "component" not in groups and len(match.groups()) >= 2:
            groups["component"] = normalize_text(match.group(2)).strip(" -")
        if "vector" not in groups and len(match.groups()) >= 2:
            groups["vector"] = normalize_text(match.group(2)).strip(" -")
        if "vector" not in groups and match.groups():
            groups["vector"] = normalize_text(match.group(1)).strip(" -")
        return template.format(**groups).replace("  ", " ").strip()

    first_sentence = description.split(". ", 1)[0].rstrip(".")
    return first_sentence if len(first_sentence) <= 120 else first_sentence[:117].rstrip() + "..."


def infer_chinese_impact(entry: dict[str, Any]) -> str:
    haystack = normalize_text(f"{entry.get('title', '')} {entry.get('description', '')}").lower()
    keyword_map = [
        (("command injection", "code execution", "remote code execution", "code injection", "shell"), "成功利用后可能导致命令注入或任意代码执行。"),
        (("path traversal", "directory traversal", "symlink", "workspace escape", "sandbox escape", "sandbox boundary"), "成功利用后可能导致目录遍历、越权读写或沙箱边界突破。"),
        (("authentication bypass", "authorization bypass", "access control", "privilege escalation", "policy bypass"), "成功利用后可能导致未授权访问、权限提升或安全策略绕过。"),
        (("xss", "cross-site scripting", "prompt injection"), "成功利用后可能导致跨站脚本、提示注入或界面上下文被劫持。"),
        (("ssrf", "server-side request forgery", "redirects", "fetchwithssrfguard"), "成功利用后可能导致服务端请求伪造并访问内网或云元数据资源。"),
        (("information disclosure", "info disclosure", "leak", "credential", "timing"), "成功利用后可能导致敏感信息、凭证或内部状态泄露。"),
        (("denial of service", "dos", "resource exhaustion"), "成功利用后可能导致拒绝服务、资源耗尽或稳定性下降。"),
    ]
    for keywords, impact in keyword_map:
        if any(keyword in haystack for keyword in keywords):
            return impact
    return "成功利用后会对 OpenClaw 的认证、授权、沙箱隔离或运行安全造成影响。"


def build_description_zh(entry: dict[str, Any]) -> str:
    title = normalize_text(str(entry.get("title") or "")) or "OpenClaw 漏洞"
    affected_before = normalize_text(str(entry.get("affected_before") or ""))
    version_scope = f"受影响版本为 {affected_before} 之前。" if affected_before else ""
    return f"该漏洞与“{title}”相关。{version_scope}{infer_chinese_impact(entry)}"


def normalize_rule_entry(entry: dict[str, Any], title: str) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "id": extract_cve_id(entry),
        "title": normalize_title(title or str(entry.get("title") or "")),
        "severity": normalize_text(str(entry.get("severity") or "")),
        "cvss": entry.get("cvss", 0),
        "affected_before": normalize_text(str(entry.get("affected_before") or "")),
        "description": normalize_text(str(entry.get("description") or "")),
        "remediation": normalize_text(str(entry.get("remediation") or "")),
    }
    normalized["cve_id"] = normalized["id"]
    cnnvd_id = normalize_text(str(entry.get("cnnvd_id") or ""))
    if cnnvd_id:
        normalized["cnnvd_id"] = cnnvd_id
    description_zh = build_description_zh(normalized)
    if description_zh:
        normalized["description_zh"] = description_zh
    return normalized


def normalize_mapping_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = extract_cve_id(entry)
    if not cve_id:
        return None
    normalized: dict[str, Any] = {
        "rule_id": cve_id,
        "cve_id": cve_id,
    }
    cnnvd_id = normalize_text(str(entry.get("cnnvd_id") or ""))
    if cnnvd_id:
        normalized["cnnvd_id"] = cnnvd_id
    cve_aliases = [normalize_text(str(value)) for value in entry.get("cve_aliases") or [] if normalize_text(str(value))]
    if cve_aliases:
        normalized["cve_aliases"] = cve_aliases
    cnnvd_aliases = [normalize_text(str(value)) for value in entry.get("cnnvd_aliases") or [] if normalize_text(str(value))]
    if cnnvd_aliases:
        normalized["cnnvd_aliases"] = cnnvd_aliases
    return normalized


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    rules_path = repo_root / "configs" / "rules" / "openclaw-cves.yaml"
    mappings_path = repo_root / "configs" / "rules" / "openclaw-id-mappings.yaml"
    cache_path = args.cache_file if args.cache_file.is_absolute() else repo_root / args.cache_file

    rules_doc = load_yaml(rules_path)
    mappings_doc = load_yaml(mappings_path)
    cache = load_cache(cache_path)
    last_request_at = [0.0]

    normalized_rules: list[dict[str, Any]] = []
    refreshed_titles = 0
    fallback_titles = 0
    removed_ghsa_rules = 0

    for entry in rules_doc.get("cves") or []:
        cve_id = extract_cve_id(entry)
        if not cve_id:
            removed_ghsa_rules += 1
            continue

        current_title = normalize_title(str(entry.get("title") or ""))
        title = current_title
        if should_refresh_title(current_title):
            try:
                official_title = fetch_official_title(
                    cve_id,
                    cache=cache,
                    timeout=args.timeout,
                    delay=args.delay,
                    last_request_at=last_request_at,
                )
            except RuntimeError as exc:
                print(f"warning: {exc}", file=sys.stderr)
                official_title = ""
            if official_title:
                title = normalize_title(official_title)
                refreshed_titles += 1
            else:
                title = normalize_title(derive_title_from_description(entry))
                fallback_titles += 1
        normalized_rules.append(normalize_rule_entry(entry, title))

    normalized_mappings: list[dict[str, Any]] = []
    removed_ghsa_mappings = 0
    for entry in mappings_doc.get("mappings") or []:
        normalized = normalize_mapping_entry(entry)
        if normalized is None:
            removed_ghsa_mappings += 1
            continue
        normalized_mappings.append(normalized)

    today = date.today().isoformat()
    rules_doc["meta"] = {
        "updated_at": today,
        "verified_at": today,
        "source_cutoff": today,
        "source": "MITRE CVE Record API + NVD OpenClaw corpus + CNNVD OpenClaw batch list",
        "notes": (
            "PoC severity/CVSS/remediation are normalized from the matching version rule when cve_id is present. "
            "External IDs are merged from configs/rules/openclaw-id-mappings.yaml and the UI renders CVE/CNNVD identifiers only. "
            "CNNVD aliases include the supplied OpenClaw batch mapping plus previously verified historical mappings."
        ),
    }
    rules_doc["cves"] = normalized_rules
    mappings_doc["mappings"] = normalized_mappings

    if args.write:
        save_yaml(rules_path, rules_doc)
        save_yaml(mappings_path, mappings_doc)
        save_cache(cache_path, cache)

    print(f"rules_total={len(normalized_rules)} removed_ghsa_rules={removed_ghsa_rules}")
    print(f"mappings_total={len(normalized_mappings)} removed_ghsa_mappings={removed_ghsa_mappings}")
    print(f"titles_refreshed={refreshed_titles} titles_fallback={fallback_titles} cache_size={len(cache)}")
    if args.write:
        print(f"updated_files={rules_path.relative_to(repo_root)} {mappings_path.relative_to(repo_root)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
