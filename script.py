import cloudscraper
from bs4 import BeautifulSoup
import requests
import time
import tkinter as tk
from tkinter import ttk, messagebox

def get_nist_data(cve_id):
  
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    nist_web_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        # NIST is very sensitive; sleep to avoid 403 Forbidden
        time.sleep(0.6) 
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            if vulns:
                metrics = vulns[0]['cve'].get('metrics', {})
                # Try to get V3.1, then V3.0, then V2
                for ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if ver in metrics:
                        return metrics[ver][0]['cvssData']['baseScore'], nist_web_url
        return "N/A", nist_web_url
    except:
        return "Error", nist_web_url

def get_github_data(cve_id):
    
    api_url = f"https://api.github.com/advisories?cve_id={cve_id}"
    # Adding a realistic User-Agent prevents GitHub from blocking the request
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > 0:
                advisory = data[0]
                ghsa_id = advisory.get('ghsa_id', 'N/A')
                score = advisory.get('cvss', {}).get('score', 'N/A')
                ghsa_url = f"https://github.com/advisories/{ghsa_id}"
                return ghsa_id, score, ghsa_url
            else:
                return "Not Found", "N/A", "N/A"
        elif response.status_code == 403:
            return "Rate Limited", "N/A", "N/A"
        else:
            return f"Err {response.status_code}", "N/A", "N/A"
    except:
        return "Conn Error", "N/A", "N/A"

def copy_to_clipboard(root, text, label):
  
    if not text or text == "N/A" or "Not Found" in text:
        messagebox.showwarning("Warning", f"No valid {label} link available for this entry.")
        return
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update() 
    print(f"Copied {label}: {text}")

def show_gui(data):
   
    root = tk.Tk()
    root.title("CVE Analysis Tool - NIST & GitHub")
    root.geometry("1100x600")

    # Layout Setup
    main_frame = ttk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=1)

    canvas = tk.Canvas(main_frame)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

    scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    table_frame = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=table_frame, anchor="nw")

    # Table Headers
    headers = ["CVE ID", "GHSA ID", "GH Score", "NIST Score", "Copy NIST", "Copy GHSA"]
    widths = [18, 18, 10, 10, 15, 15]
    for col, text in enumerate(headers):
        lbl = tk.Label(table_frame, text=text, font=('Arial', 10, 'bold'), borderwidth=1, relief="solid", width=widths[col], bg="#eeeeee")
        lbl.grid(row=0, column=col, sticky="nsew")

    # Data Rows
    for row_idx, (cve, ghsa, g_score, n_score, g_url, n_url) in enumerate(data, start=1):
        # Result Cells
        for col_idx, val in enumerate([cve, ghsa, g_score, n_score]):
            e = tk.Entry(table_frame, font=('Arial', 10))
            e.insert(0, str(val))
            e.config(state='readonly')
            e.grid(row=row_idx, column=col_idx, sticky="nsew", padx=1, pady=1)

        # Separate Link Buttons
        btn_nist = ttk.Button(table_frame, text="📋 NIST Link", command=lambda u=n_url: copy_to_clipboard(root, u, "NIST"))
        btn_nist.grid(row=row_idx, column=4, padx=5, pady=2)

        btn_ghsa = ttk.Button(table_frame, text="📋 GHSA Link", command=lambda u=g_url: copy_to_clipboard(root, u, "GHSA"))
        btn_ghsa.grid(row=row_idx, column=5, padx=5, pady=2)

    root.mainloop()

def start_process(url):
    scraper = cloudscraper.create_scraper()
    try:
        print(f"Scraping IDs from: {url}")
        response = scraper.get(url)
        if response.status_code != 200:
            messagebox.showerror("Error", f"Failed to load URL. Status: {response.status_code}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        cve_ids = sorted(list(set(l.text.strip() for l in links if "/cve/CVE-" in l['href'] and l.text.strip().startswith("CVE-"))))

        if not cve_ids:
            messagebox.showinfo("Empty", "No CVE IDs found on this page.")
            return

        print(f"Processing {len(cve_ids)} vulnerabilities. Please wait...")
        results = []
        for cve in cve_ids:
            ghsa_id, g_score, g_url = get_github_data(cve)
            n_score, n_url = get_nist_data(cve)
            results.append([cve, ghsa_id, g_score, n_score, g_url, n_url])
            # Delay to avoid GitHub API rate limits
            time.sleep(0.1) 
        
        show_gui(results)

    except Exception as e:
        messagebox.showerror("Error", f"Critical Error: {e}")

if __name__ == "__main__":
    user_url = input("Enter the CVEDetails URL: ").strip()
    if user_url.startswith("http"):
        start_process(user_url)
    else:
        print("Invalid URL.")
