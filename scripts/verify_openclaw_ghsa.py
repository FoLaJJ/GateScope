#!/usr/bin/env python3
"""Validate local OpenClaw GHSA-only rules against official GitHub advisories."""

from __future__ import annotations

import html
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_FILE = REPO_ROOT / "configs" / "rules" / "openclaw-cves.yaml"
BASE = "https://github.com/openclaw/openclaw/security/advisories"


def fetch(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AgentScan GHSA verifier"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", "ignore")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"unreachable fetch failure: {last_error}")


def load_local_ghsa_rules() -> dict[str, str]:
    data = yaml.safe_load(RULE_FILE.read_text(encoding="utf-8"))
    result: dict[str, str] = {}
    for item in data.get("cves", []):
        ghsa_id = str(item.get("ghsa_id") or "")
        cve_id = str(item.get("cve_id") or "")
        if ghsa_id and not cve_id:
            result[ghsa_id] = str(item.get("title") or "")
    return result


def load_official_advisories() -> dict[str, str]:
    page = 1
    advisories: dict[str, str] = {}
    while True:
        url = BASE if page == 1 else f"{BASE}?page={page}"
        html_text = fetch(url)
        entries = re.findall(
            r'href="/openclaw/openclaw/security/advisories/(GHSA-[A-Za-z0-9\-]+)"[^>]*>\s*([^<]+?)\s*</a>',
            html_text,
        )
        if not entries:
            break
        for ghsa_id, title in entries:
            advisories[ghsa_id] = " ".join(html.unescape(title).split())
        page += 1
    return advisories


def main() -> int:
    local_rules = load_local_ghsa_rules()
    official = load_official_advisories()

    stale_ids: list[str] = []
    mismatched_titles: list[str] = []

    for ghsa_id, local_title in sorted(local_rules.items()):
        official_title = official.get(ghsa_id)
        if not official_title:
            stale_ids.append(ghsa_id)
            continue
        if " ".join(local_title.split()) != official_title:
            mismatched_titles.append(f"{ghsa_id}: local='{local_title}' official='{official_title}'")

    print(f"local_ghsa_rules={len(local_rules)} official_advisories={len(official)}")
    if stale_ids:
        print("stale_ids:")
        for ghsa_id in stale_ids:
            print(f"  - {ghsa_id}")
    if mismatched_titles:
        print("mismatched_titles:")
        for line in mismatched_titles:
            print(f"  - {line}")

    if stale_ids or mismatched_titles:
        return 1

    print("verified: all local GHSA-only rules match official OpenClaw advisories")
    return 0


if __name__ == "__main__":
    sys.exit(main())
