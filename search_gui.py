
import tkinter as tk
from tkinter import messagebox, scrolledtext
import datetime
import webbrowser

SEARCH_INDEX = {
    "shodan": "https://www.shodan.io/search?query={}",
    "virustotal": "https://www.virustotal.com/gui/search/{}",
    "abuseipdb": "https://www.abuseipdb.com/check/{}",
    "greynoise": "https://viz.greynoise.io/ip/{}",
    "intelx": "https://intelx.io/?s={}",
    "exploitdb": "https://www.exploit-db.com/search?q={}",
    "pulsedive": "https://pulsedive.com/search/?q={}",
    "threatminer": "https://www.threatminer.org/search.php?q={}",
    "haveibeenpwned": "https://haveibeenpwned.com/unifiedsearch/{}",
    "dnsdumpster": "https://dnsdumpster.com/"
}

LOG_FILE = "search_log.txt"

def perform_search(term, selected_engines, log_output):
    if not term.strip():
        messagebox.showerror("Input Error", "Search term cannot be empty.")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_lines = [f"[{timestamp}] Search: '{term}'\n"]

    for engine in selected_engines:
        if engine in SEARCH_INDEX:
            url = SEARCH_INDEX[engine].format(term)
            log_lines.append(f"{engine}: {url}")
            webbrowser.open(url)
        else:
            log_lines.append(f"{engine}: [!] Engine not recognized")

    # Display and save logs
    log_output.delete("1.0", tk.END)
    log_output.insert(tk.END, "\n".join(log_lines))

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n\n")

def run_gui():
    root = tk.Tk()
    root.title("Cyber OSINT Search Engine (Clickable)")

    tk.Label(root, text="Enter Search Term:").pack(pady=(10, 0))
    search_term = tk.Entry(root, width=50)
    search_term.pack(pady=(0, 10))

    tk.Label(root, text="Select Search Engines:").pack()
    checks_frame = tk.Frame(root)
    checks_frame.pack()

    check_vars = {}
    for idx, engine in enumerate(SEARCH_INDEX.keys()):
        var = tk.BooleanVar()
        chk = tk.Checkbutton(checks_frame, text=engine, variable=var)
        chk.grid(row=idx//3, column=idx%3, sticky="w", padx=5, pady=2)
        check_vars[engine] = var

    output_box = scrolledtext.ScrolledText(root, width=80, height=15)
    output_box.pack(pady=10)

    def on_submit():
        term = search_term.get()
        selected = [k for k, v in check_vars.items() if v.get()]
        perform_search(term, selected, output_box)

    submit_btn = tk.Button(root, text="Run Search and Open URLs", command=on_submit)
    submit_btn.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    run_gui()
