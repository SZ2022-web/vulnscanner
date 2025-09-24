#!/usr/bin/env python3
"""
vulnscan.py — Python wrapper around Nmap for educational use.

⚠️ Ethical use only: scan systems you own or have explicit permission to test.
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime

try:
    import nmap  # from python-nmap
except Exception as e:
    print("ERROR: python-nmap is not installed. Run: pip install -r requirements.txt", file=sys.stderr)
    raise


def build_nmap_args(profile: str, ports: str | None) -> str:
    base = []
    if profile == "quick":
        # Fast scan of top 100 ports
        base = ["-F", "-T4", "-sS", "-Pn"]
    elif profile == "safe":
        base = ["-sS", "-sV", "-O", "-T3", "-Pn"]
    elif profile == "aggressive":
        base = ["-A", "-T4", "-Pn"]
    elif profile == "vuln":
        base = ["-sV", "--script", "vuln", "-T3", "-Pn"]
    else:
        base = ["-sS", "-T3", "-Pn"]
    if ports:
        base += ["-p", ports]
    return " ".join(base)


def scan_targets(target: str, arguments: str) -> dict:
    scanner = nmap.PortScanner()
    # Note: nmap binary must be installed on the system
    scanner.scan(hosts=target, arguments=arguments)
    return scanner


def parse_results(scanner: "nmap.PortScanner") -> list[dict]:
    rows = []
    for host in scanner.all_hosts():
        # Handle hostname safely (string in most installs)
        try:
            hostnames = scanner[host].hostname() if hasattr(scanner[host], "hostname") else ""
            if isinstance(hostnames, list):  # rare case
                hostnames = ",".join([str(h) for h in hostnames])
        except Exception:
            hostnames = ""

        # TCP/UDP results
        for proto in ["tcp", "udp"]:
            if proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for p in sorted(ports):
                    entry = scanner[host][proto][p]
                    rows.append({
                        "host": host,
                        "hostname": hostnames,
                        "protocol": proto,
                        "port": p,
                        "state": entry.get("state", ""),
                        "name": entry.get("name", ""),
                        "product": entry.get("product", ""),
                        "version": entry.get("version", ""),
                        "extrainfo": entry.get("extrainfo", ""),
                        "cpe": ",".join(entry.get("cpe", [])) if isinstance(entry.get("cpe", []), list) else entry.get("cpe", ""),
                    })
    return rows


def save_reports(rows: list[dict], outdir: str) -> tuple[str, str]:
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_path = os.path.join(outdir, f"scan_{ts}.csv")
    json_path = os.path.join(outdir, f"scan_{ts}.json")

    # CSV
    if rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    else:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            f.write("no results\n")

    # JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    return csv_path, json_path


def main():
    parser = argparse.ArgumentParser(description="Python + Nmap vulnerability scanner (educational).")
    parser.add_argument("target", help="Target host, CIDR, or hostname (e.g., 192.168.1.0/24 or scanme.nmap.org)")
    parser.add_argument("-p", "--ports", help="Ports or ranges (e.g., 1-1024,80,443)", default=None)
    parser.add_argument("--profile", choices=["quick", "safe", "aggressive", "vuln"], default="quick",
                        help="Scan profile: quick | safe | aggressive | vuln")
    parser.add_argument("--outdir", default="reports", help="Output folder for CSV/JSON")
    args = parser.parse_args()

    nmap_args = build_nmap_args(args.profile, args.ports)
    print(f"[+] Running nmap with arguments: {nmap_args}")
    try:
        scanner = scan_targets(args.target, nmap_args)
    except Exception as e:
        print(f"ERROR running nmap: {e}", file=sys.stderr)
        sys.exit(2)

    # Print brief summary
    print("[+] Hosts found:", scanner.all_hosts())
    rows = parse_results(scanner)

    # Show a compact table to stdout
    if not rows:
        print("[!] No results parsed.")
    else:
        print("\nHost\tProto\tPort\tState\tService\tProduct Version")
        for r in rows[:50]:  # limit to first 50 lines for console
            pv = (r["product"] + " " + r["version"]).strip()
            print(f"{r['host']}\t{r['protocol']}\t{r['port']}\t{r['state']}\t{r['name']}\t{pv}")

    csv_path, json_path = save_reports(rows, args.outdir)
    print(f"\n[+] Reports saved:\n - {csv_path}\n - {json_path}")
    print("\nReminder: Only scan systems you own or have permission to test.")


if __name__ == "__main__":
    main()
