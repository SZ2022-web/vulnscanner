# VulnScanner 🔍  
Python + Nmap Vulnerability Scanner (Starter Project)

This tool is a Python wrapper around **Nmap**. It allows you to run different scanning profiles (quick, safe, aggressive, vuln) and export results into **CSV** and **JSON** formats.  

⚠️ **Ethical use only**: Scan only systems you own or have explicit permission to test.

---

## ✨ Features
- Profiles: `quick` | `safe` | `aggressive` | `vuln`
- Detects open ports, services, and versions
- Saves reports in **CSV** and **JSON**
- Easy to extend with new profiles
- Beginner-friendly starter project for security learning

---

## 1) Install Nmap (required)

- **Windows**: Download the latest Nmap installer from [nmap.org/download](https://nmap.org/download) and check the box to install **Npcap**.  
- **macOS**:  
  ```bash
  brew install nmap
