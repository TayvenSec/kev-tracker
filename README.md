# 🎯 KEV Tracker

Daily automated tracking of the **CISA Known Exploited Vulnerabilities (KEV) catalog** — the authoritative list of CVEs confirmed to be exploited in the wild.

New KEV entries are the highest-priority patching signal that exists: these aren't theoretical vulnerabilities, they're being used in real attacks right now.

**🌐 Live dashboard:** [tayvensec.github.io/kev-tracker](https://tayvensec.github.io/kev-tracker/)

Companion tool to the [Patch Tuesday Tracker](https://github.com/TayvenSec/patch-tuesday-tracker), built for the [Tayven Cyber Security Patch Management Series](https://tayvensec.com/patch-management/).

---

## What It Does

Every day at 09:00 UTC it:

1. Downloads the official [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (JSON feed — no scraping)
2. Diffs against the previous day's catalog
3. Records new additions to a monthly log (`data/additions/YYYY-MM-additions.md` + `.json`)
4. Rebuilds the dashboard showing: recent additions, ransomware-linked CVEs, and remediation deadlines due within 14 days
5. Opens a **GitHub Issue notification** listing the new CVEs — with a 🔴 flag when a CVE is linked to known ransomware campaigns

No new entries → no commit, no issue, no noise.

## Data Layout

```
data/
├── kev-catalog.json              # full current catalog (mirror of CISA's)
└── additions/
    ├── 2026-07-additions.json    # this month's new entries (machine-readable)
    └── 2026-07-additions.md      # this month's new entries (human-readable)
```

## Setup

1. Fork/clone, push to GitHub
2. **Settings → Pages** → Deploy from branch → `main` / `docs`
3. **Actions** tab → enable workflows → run **Track KEV Catalog** manually once
4. **Watch → All Activity** to get new-KEV notifications by email

First run seeds the catalog and shows the last 7 days of additions; from then on it tracks day-to-day changes.

## Run Locally

```bash
pip install -r requirements.txt
python collect.py
```

## About Due Dates

Each KEV entry carries a CISA **BOD 22-01 remediation deadline** — binding for US federal agencies, and widely used by everyone else as a prioritisation signal. The dashboard surfaces anything due within 14 days.

## License

MIT — Copyright (c) 2026 Tayven Cyber Security (https://tayvensec.com)
