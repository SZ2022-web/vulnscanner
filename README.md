# Python + Nmap Vulnerability Scanner (Starter)

> **Ethical use only.** Scan **only** systems you own or have explicit permission to test.

## 1) Install Nmap (required)
- **Windows**: Download the latest Nmap installer from https://nmap.org/download and check the box to install **Npcap**.
- **macOS**: `brew install nmap`
- **Linux (Debian/Ubuntu)**: `sudo apt update && sudo apt install -y nmap`

Verify:
```bash
nmap -V
```

## 2) Set up Python environment
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## 3) Run quick scans (try the public test host first)
> The Nmap team allows testing against **scanme.nmap.org** (do not exceed a dozen scans/day).
```bash
python vulnscan.py scanme.nmap.org --profile quick
```

## 4) Run deeper scans
```bash
# Safe service/OS detection on custom ports
python vulnscan.py 192.168.1.0/24 -p 1-1024 --profile safe

# Aggressive scan (version, OS, scripts, traceroute)
python vulnscan.py scanme.nmap.org -p 1-2000 --profile aggressive

# Vulnerability NSE scripts
python vulnscan.py scanme.nmap.org -p 1-1024 --profile vuln
```

## 5) Outputs
Reports (CSV + JSON) are saved to the `reports/` folder with a timestamped filename.

## 6) Notes
- Some scans require admin privileges (root) for accurate results (e.g., SYN/OS detection).
- Long port ranges + `--profile aggressive` can take time.
- Use `--help` to see all options.

---

## Example Output
```
Host: 45.33.32.156 (scanme.nmap.org)
Open TCP Ports:
  22/tcp open  ssh     (OpenSSH 6.6.1p1)
  80/tcp open  http    (Apache httpd 2.4.7)
Saved: reports/scan_2025-09-23_21-00-00.csv
```

## License
MIT (for this starter). Nmap is licensed separately (see nmap.org).
