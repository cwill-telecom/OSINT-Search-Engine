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

def search(term, engines):
    for engine in engines:
        if engine in SEARCH_INDEX:
            url = SEARCH_INDEX[engine].format(term)
            print(f"[+] Opening: {url}")
            webbrowser.open(url)
        else:
            print(f"[!] Engine '{engine}' not recognized.")

def list_engines():
    print("Available engines:")
    for engine in SEARCH_INDEX:
        print(f"- {engine}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cyber OSINT Search Engine")
    parser.add_argument("term", help="Search term (IP, hash, domain, etc.)")
    parser.add_argument("-e", "--engines", nargs="+", help="Search engines to use (space separated)")
    parser.add_argument("-l", "--list", action="store_true", help="List all available engines")

    args = parser.parse_args()

    if args.list:
        list_engines()
    elif args.term and args.engines:
        search(args.term, args.engines)
    else:
        print("⚠️ Usage: python cyber_search.py <term> -e shodan virustotal intelx")
        print("       Add -l to list available engines.")
