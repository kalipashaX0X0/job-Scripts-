# CVEDetails CVE Extractor

A simple Python tool that extracts **only CVE IDs** from a CVEDetails product vulnerability page.

This script is useful for security researchers, bug bounty hunters, and analysts who want to quickly collect CVE identifiers related to a specific product/version without manually browsing the site.

---

## 📌 Target Example

The script was designed to work with pages like:

https://www.cvedetails.com/vulnerability-list/vendor_id-23551/product_id-87327/Vercel-Next.js.html

But it works with **any CVEDetails vulnerability listing page**.

---

## ⚙️ Features

- Extracts **only CVE IDs** (e.g., `CVE-2024-12345`)
- Removes duplicates automatically
- Uses a **real browser (Selenium)** to bypass bot protection
- Works even if the site loads content dynamically

---

## 🛠 Requirements

Install Python packages:

```bash
pip install selenium webdriver-manager beautifulsoup4
