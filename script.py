import cloudscraper
from bs4 import BeautifulSoup
import requests
import time
import tkinter as tk
from tkinter import ttk, messagebox


GITHUB_TOKEN = "YOUR_GITHUB_TOKEN_HERE" 

def get_nist_data(cve_id):
    """Fetches CVSS score and generates NIST URL."""
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    nist_web_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        
        time.sleep(0.6) 
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            if vulns:
                metrics = vulns[0]['cve'].get('metrics', {})
                for ver in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if ver in metrics:
                        return metrics[ver][0]['cvssData']['baseScore'], nist_web_url
        return "N/A", nist_web_url
    except:
        return "Error", nist_web_url

def get_github_data(cve_id):
    """Fetches GHSA details using Token Authentication."""
    api_url = f"https://api.github.com/advisories?cve_id={cve_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CVE-Scraper-V2"
    }
    
   
    if GITHUB_TOKEN and GITHUB_TOKEN != "YOUR_GITHUB_TOKEN_HERE":
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

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
            return "Not Found", "N/A", "N/A"
        elif response.status_code == 401:
            return "Bad Token", "N/A", "N/A"
        elif response.status_code == 403:
            return "Rate Limited", "N/A", "N/A"
        return f"Err {response.status_code}", "N/A", "N/A"
    except:
        return "Conn Error", "N/A", "N/A"

def copy_to_clipboard(root, text, label):
    """Copies text to clipboard."""
    if not text or text == "N/A" or "Not Found" in text:
        messagebox.showwarning("Warning", f"No {label} link available.")
        return
    root.clipboard_clear()
    root.clipboard_append(text)
    print(f"Copied {label}: {text}")

def show_gui(data):
    """GUI window with Token status and copy buttons."""
    root = tk.Tk()
    root.title("Advanced CVE & GHSA Tracker")
    root.geometry("1100x600")

    # Header Info
    status_text = "Authenticated" if GITHUB_TOKEN != "YOUR_GITHUB_TOKEN_HERE" else "Unauthenticated (Low Rate Limit)"
    lbl_status = tk.Label(root, text=f"GitHub Status: {status_text}", fg="blue" if "Auth" in status_text else "red")
    lbl_status.pack(pady=5)

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

    headers = ["CVE ID", "GHSA ID", "GH Score", "NIST Score", "NIST Link", "GitHub Link"]
    widths = [18, 18, 10, 10, 15, 15]
    for col, text in enumerate(headers):
        lbl = tk.Label(table_frame, text=text, font=('Arial', 10, 'bold'), borderwidth=1, relief="solid", width=widths[col], bg="#f4f4f4")
        lbl.grid(row=0, column=col, sticky="nsew")

    for row_idx, (cve, ghsa, g_score, n_score, g_url, n_url) in enumerate(data, start=1):
        for col_idx, val in enumerate([cve, ghsa, g_score, n_score]):
            e = tk.Entry(table_frame, font=('Arial', 10))
            e.insert(0, str(val))
            e.config(state='readonly')
            e.grid(row=row_idx, column=col_idx, sticky="nsew")

        btn_nist = ttk.Button(table_frame, text="Copy NIST", command=lambda u=n_url: copy_to_clipboard(root, u, "NIST"))
        btn_nist.grid(row=row_idx, column=4, padx=5, pady=2)

        btn_ghsa = ttk.Button(table_frame, text="Copy GHSA", command=lambda u=g_url: copy_to_clipboard(root, u, "GHSA"))
        btn_ghsa.grid(row=row_idx, column=5, padx=5, pady=2)

    root.mainloop()

def start_process(url):
    scraper = cloudscraper.create_scraper()
    try:
        print(f"Accessing: {url}")
        response = scraper.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        cve_ids = sorted(list(set(l.text.strip() for l in links if "/cve/CVE-" in l['href'] and l.text.strip().startswith("CVE-"))))

        if not cve_ids:
            messagebox.showinfo("Empty", "No CVEs found.")
            return

        print(f"Processing {len(cve_ids)} vulnerabilities...")
        results = []
        for cve in cve_ids:
            ghsa_id, g_score, g_url = get_github_data(cve)
            n_score, n_url = get_nist_data(cve)
            results.append([cve, ghsa_id, g_score, n_score, g_url, n_url])
           
            time.sleep(0.05) 
        
        show_gui(results)
    except Exception as e:
        messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    u = input("Enter CVEDetails URL: ").strip()
    if u.startswith("http"):
        start_process(u)
    else:
        print("Invalid URL.")
