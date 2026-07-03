"""
KEV Tracker — CISA Known Exploited Vulnerabilities
Source: Official CISA KEV catalog JSON feed (no auth, no scraping)
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Built by Tayven Cyber Security (https://tayvensec.com) — MIT License

How it works:
  1. Downloads the full KEV catalog (official JSON)
  2. Diffs it against the previously saved catalog
  3. Records any newly added CVEs to a monthly additions log
  4. Rebuilds the GitHub Pages dashboard
  5. Writes a .new_additions flag so the workflow can open a notification issue
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
ADDITIONS_DIR = DATA_DIR / "additions"
CATALOG_PATH = DATA_DIR / "kev-catalog.json"
FLAG_PATH = ROOT / ".new_additions"


def fetch_catalog() -> dict:
    resp = requests.get(KEV_URL, timeout=60, headers={"User-Agent": "kev-tracker (github.com/TayvenSec/kev-tracker)"})
    resp.raise_for_status()
    return resp.json()


def load_previous() -> dict | None:
    if CATALOG_PATH.exists():
        try:
            return json.loads(CATALOG_PATH.read_text())
        except Exception:
            return None
    return None


def diff_new_entries(new_catalog: dict, old_catalog: dict | None) -> list:
    """Return vulnerabilities present in new_catalog but not in old_catalog."""
    new_vulns = new_catalog.get("vulnerabilities", [])
    if old_catalog is None:
        # First run: don't treat the entire historical catalog as "new".
        # Seed with entries added in the last 7 days so the dashboard isn't empty.
        cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        return [v for v in new_vulns if v.get("dateAdded", "") >= cutoff]

    old_ids = {v.get("cveID") for v in old_catalog.get("vulnerabilities", [])}
    return [v for v in new_vulns if v.get("cveID") not in old_ids]


def record_additions(new_entries: list) -> None:
    """Append new entries to the current month's additions log (JSON + MD)."""
    if not new_entries:
        return

    now = datetime.utcnow()
    prefix = now.strftime("%Y-%m")
    json_path = ADDITIONS_DIR / f"{prefix}-additions.json"
    md_path = ADDITIONS_DIR / f"{prefix}-additions.md"

    # Load existing month log and merge (dedupe by CVE ID)
    existing = []
    if json_path.exists():
        try:
            existing = json.loads(json_path.read_text())
        except Exception:
            existing = []

    existing_ids = {e.get("cveID") for e in existing}
    merged = existing + [e for e in new_entries if e.get("cveID") not in existing_ids]
    merged.sort(key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)

    ADDITIONS_DIR.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(merged, indent=2))

    # Markdown log for humans
    lines = [f"# KEV Additions — {now.strftime('%B %Y')}\n"]
    lines.append(f"CVEs added to the CISA Known Exploited Vulnerabilities catalog this month: **{len(merged)}**\n")
    for v in merged:
        lines.append(f"\n## {v.get('cveID', '')} — {v.get('vulnerabilityName', '')}")
        lines.append(f"- **Vendor/Product:** {v.get('vendorProject', '')} / {v.get('product', '')}")
        lines.append(f"- **Added to KEV:** {v.get('dateAdded', '')}")
        lines.append(f"- **Remediation due:** {v.get('dueDate', '')}")
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        lines.append(f"- **Known ransomware use:** {ransomware}")
        desc = v.get("shortDescription", "").strip()
        if desc:
            lines.append(f"- **Description:** {desc}")
        action = v.get("requiredAction", "").strip()
        if action:
            lines.append(f"- **Required action:** {action}")
    lines.append(f"\n---\n*Data: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · Tracker by [Tayven Cyber Security](https://tayvensec.com)*\n")
    md_path.write_text("\n".join(lines))

    print(f"[SAVE] {json_path.name} ({len(merged)} total this month)")
    print(f"[SAVE] {md_path.name}")


def save_notification_summary(new_entries: list) -> None:
    """Write flag + summary file used by the GitHub Actions issue step."""
    if not new_entries:
        if FLAG_PATH.exists():
            FLAG_PATH.unlink()
        return

    summary_lines = []
    for v in new_entries:
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        ransom_flag = " 🔴 **RANSOMWARE**" if str(ransomware).lower() == "known" else ""
        summary_lines.append(
            f"- **{v.get('cveID','')}** — {v.get('vendorProject','')} {v.get('product','')}: "
            f"{v.get('vulnerabilityName','')}{ransom_flag} (due {v.get('dueDate','')})"
        )
    FLAG_PATH.write_text("\n".join(summary_lines))
    print(f"[FLAG] {len(new_entries)} new KEV entries — notification will fire.")


def main() -> int:
    print(f"\n{'='*60}\n  KEV Tracker — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n{'='*60}\n")

    new_catalog = fetch_catalog()
    total = new_catalog.get("count", len(new_catalog.get("vulnerabilities", [])))
    print(f"[FETCH] Catalog version {new_catalog.get('catalogVersion','?')} — {total} total CVEs")

    old_catalog = load_previous()
    new_entries = diff_new_entries(new_catalog, old_catalog)
    print(f"[DIFF] {len(new_entries)} new entr{'y' if len(new_entries)==1 else 'ies'} since last run")

    # Save the full catalog
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CATALOG_PATH.write_text(json.dumps(new_catalog, indent=2))
    print(f"[SAVE] {CATALOG_PATH.name}")

    record_additions(new_entries)
    save_notification_summary(new_entries)

    from generate_site import build
    build()

    return 0


if __name__ == "__main__":
    sys.exit(main())
