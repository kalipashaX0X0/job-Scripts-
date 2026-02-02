# 🔍 Advanced CVE & GHSA Tracker

A powerful Python security research tool that extracts CVE data from CVEDetails and enriches it with information from **NIST (NVD)** and **GitHub Security Advisories (GHSA)** — all displayed in a user‑friendly desktop GUI.

---

## 🚀 What This Tool Does

This script automates vulnerability intelligence gathering.

It will:

- 🔎 Extract **CVE IDs** from a CVEDetails product page  
- 📊 Fetch **CVSS scores** from NIST (NVD API)  
- 🧠 Fetch **GitHub Security Advisory (GHSA)** information  
- 🖥 Display everything in a **scrollable GUI dashboard**  
- 📋 Provide **copy buttons** for NIST and GitHub advisory links  
- 🧹 Remove duplicate CVEs automatically  

---

## 🧪 Example Target

https://www.cvedetails.com/vulnerability-list/vendor_id-23551/product_id-87327/Vercel-Next.js.html



---

## 🖼 GUI Output Includes

| Field | Description |
|------|-------------|
| CVE ID | Vulnerability identifier |
| GHSA ID | GitHub advisory ID |
| GH Score | CVSS score from GitHub |
| NIST Score | Official CVSS score |
| Copy NIST | Copy NIST vulnerability link |
| Copy GHSA | Copy GitHub advisory link |

---

## 📦 Requirements

Install dependencies:

```bash
pip install cloudscraper beautifulsoup4 requests
pip install selenium webdriver-manager


tkinter is preinstalled with most Python versions.




🔑 GitHub Token Setup (Recommended)

GitHub API has strict rate limits without authentication.

Create a token:

Visit: https://github.com/settings/tokens

Click Generate new token

No special permissions required

Paste into script:

GITHUB_TOKEN = "your_token_here"


⚠ Never share your token publicly.



▶️ How to Run
python your_script_name.py


Then enter the CVEDetails URL when prompted.

⚙ How It Works
Step 1 — CVE Extraction

Uses Cloudscraper to bypass Cloudflare protection and scrape CVE IDs.

Step 2 — NIST Lookup

Pulls CVSS scores from:

https://services.nvd.nist.gov/rest/json/cves/2.0

Step 3 — GitHub Advisory Mapping

Matches CVEs with:

https://api.github.com/advisories?cve_id=

Step 4 — GUI Dashboard

Tkinter displays structured vulnerability data with copy buttons.

📊 API Rate Limits
Service	Limit	Handling
NIST API	Strict	0.6s delay per request
GitHub (No token)	Very low	May fail
GitHub (With token)	Higher	Recommended
🛠 Possible Enhancements

You can extend this tool with:

CSV export

Excel export

Severity filtering

Multi-page crawling

Exploit‑DB links

Automatic reporting

⚠ Legal & Ethical Use

This tool is intended strictly for:

✔ Security research
✔ Educational purposes
✔ Vulnerability analysis

Users are responsible for complying with:

Website terms of service

API usage policies

Local cybersecurity laws

Do not use this tool for unauthorized scanning, abuse, or malicious activity.

📄 License
MIT License Summary

This project is released under the MIT License, which means:

✅ You are free to:

Use the software

Modify it

Distribute it

Use it in private or commercial projects

❗ Conditions:

You must include the original copyright notice

You must include the license text in copies or substantial portions

🚫 Liability:

The software is provided "as is"

The author is not responsible for damages, misuse, or legal issues resulting from use

You can add the full MIT license text in a separate LICENSE file if publishing the project.

🧠 Project Summary

This project combines:

Web scraping

API integration

Vulnerability intelligence

Desktop GUI development

All in one automated CVE intelligence dashboard.


---

If you want, next we can add:

- `LICENSE` file content  
- Auto CSV export feature  
- Dark mode GUI 😄
