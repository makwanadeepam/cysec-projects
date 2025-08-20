# 🕵️ Python Port Sniffer

A lightweight port scanning tool inspired by **Nmap**, written in Python.
It supports multiple scanning techniques, banner grabbing, and simple OS detection.

---

## 🚀 Features

-   **Normal Connect Scan** – Checks open ports using standard TCP connect.
-   **Stealth SYN Scan (-sS)** – Uses raw packets (via `scapy`) to stealthily identify open ports without completing the handshake.
-   **Threaded Scanning** – Parallel scanning for speed (default: 100 threads).
-   **Banner Grabbing** – Attempts to fetch service banners from open ports.
-   **OS Detection (Basic)** – Guesses target OS based on TTL values.
-   **Common Ports Fast Scan** – Quickly scans the most popular service ports.
-   **Semantic Commands** – Inspired by Nmap’s syntax, but simplified.

---

## ⚡ Usage

```bash
# Normal full range scan
python mini_nmap.py scan host 127.0.0.1 ports 1-1000

# Stealth SYN scan (requires sudo/root)
sudo python mini_nmap.py stealth host 192.168.1.5 ports 1-1024

# Fast scan common ports
python mini_nmap.py fast host 10.0.0.10

# Banner grabbing
python mini_nmap.py banner host example.com ports 20-100

# OS Detection
python mini_nmap.py detect os host 192.168.1.1
```

---

## 🧩 Example Output

```bash
[*] Starting threaded SYN stealth scan on 192.168.1.10 ports 1-1024...
[+] Port 22 OPEN (SYN scan)
[+] Port 80 OPEN (SYN scan)
[+] Port 443 OPEN (SYN scan)

[+] 192.168.1.10 seems to be running Linux/Unix (TTL=64)
```

---

## 📌 Notes

-   A **basic port sniffer application** based on Nmap & its scripts in Python.
-   Made **for learning purposes only** – do not use on networks you don’t own or have permission to scan.
-   Might integrate **AI in the long-term** for smart target profiling.
-   Stealth scans require **root privileges** (because raw sockets).

---

## 🔧 Requirements

-   Python 3.8+
-   [Scapy](https://scapy.net/) (`pip install scapy`)

---

## 🏗️ Roadmap / Future Ideas

-   [ ] Use argparse or Typer for better command-line arg passing
-   [ ] Add input validation
-   [ ] Improve the OS detection logic to handle cases where port 80 is closed.
-   [ ] Add robust error handling for network-related exceptions
-   [ ] Add UDP scanning
-   [ ] Service version detection
-   [ ] Replace manual thread management with a thread pool for better performance and readability
-   [ ] Add verbose logging
-   [ ] Export results to JSON/HTML
-   [ ] Aggressive OS fingerprinting
-   [ ] AI-assisted vulnerability & penetration testing hints
