
# 🔍 Cyber OSINT Search Engine

This command-line tool allows cybersecurity analysts and OSINT researchers to quickly launch targeted searches across multiple cyber intelligence platforms. Just enter an IP, domain, hash, or keyword, and select the engines to query.

---

## 🚀 Features

- Supports fast lookups across top OSINT platforms
- Opens threat intelligence URLs directly in your default browser
- Supports IPs, domains, hashes, and email addresses
- Easily extendable for new engines

---

## 🔧 Supported Search Engines

| Engine        | Description                         |
|---------------|-------------------------------------|
| `shodan`      | Internet-connected devices          |
| `virustotal`  | File/hash/domain reputation         |
| `abuseipdb`   | Malicious IPs reporting             |
| `greynoise`   | Internet noise and background scan data |
| `intelx`      | Deep web, breached content, leaks   |
| `exploitdb`   | Public exploits and vulnerabilities |
| `pulsedive`   | Threat intelligence platform        |
| `threatminer` | Passive DNS, malware, and indicators|
| `haveibeenpwned` | Compromised credentials database |
| `dnsdumpster` | DNS recon and mapping tool          |

---

## 🛠️ Installation

No installation needed. Just clone or download the script and run it with Python 3:

```bash
python cyber_search.py <term> -e <engine1> <engine2> ...
```

---

## 📌 Usage Examples

### Search for a single IP in multiple engines:
```bash
python cyber_search.py 8.8.8.8 -e shodan abuseipdb greynoise
```

### Check if an email has been in a data breach:
```bash
python cyber_search.py someone@example.com -e haveibeenpwned intelx
```

### Search for a hash or domain in malware databases:
```bash
python cyber_search.py abcdef123456... -e virustotal threatminer
```

### List all supported engines:
```bash
python cyber_search.py anything -l
```

---

## 🧩 Easily Extendable

To add new engines, simply edit the `SEARCH_INDEX` dictionary in the script:

```python
"newengine": "https://new.engine/search?q={}",
```

---

## 📄 License

This project is open-source and free to use for education and research. Attribution appreciated.

---
