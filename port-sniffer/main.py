import sys
import socket
import threading
from scapy.all import IP, TCP, sr1, send

def stealth_scan_worker(host, port, results):
    pkt = IP(dst=host)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=0.5, verbose=0)
    if resp is None:
        return
    if resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN/ACK
            results.append(f"[+] Port {port} OPEN (SYN scan)")
            # Send RST to close connection stealthily
            rst_pkt = IP(dst=host)/TCP(dport=port, flags="R")
            send(rst_pkt, verbose=0)

def stealth_scan(host, port_range=(1,1024), threads=100):
    start_port, end_port = port_range
    results, workers = [], []

    print(f"[*] Starting threaded SYN stealth scan on {host} ports {start_port}-{end_port}...")

    for port in range(start_port, end_port+1):
        t = threading.Thread(target=stealth_scan_worker, args=(host, port, results))
        workers.append(t)
        t.start()

        if len(workers) >= threads:
            for w in workers:
                w.join()
            workers = []

    for w in workers:
        w.join()

    for r in sorted(results):
        print(r)

# -------- Normal Connect Scan (already threaded) --------
def scan_port(host, port, results, grab_banner=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = ""
            if grab_banner:
                try:
                    sock.send(b"Hello\r\n")
                    response = sock.recv(1024).decode(errors="ignore")
                    if response.strip():
                        banner = f" | Banner: {response.strip()[:50]}"
                except:
                    pass
            results.append(f"[+] Port {port} is OPEN {banner}")
        sock.close()
    except:
        pass

def run_scan(host, port_range=(1,1024), threads=100, grab_banner=False):
    threads_list, results = [], []
    start_port, end_port = port_range

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(host, port, results, grab_banner))
        threads_list.append(t)
        t.start()

        if len(threads_list) >= threads:
            for thread in threads_list:
                thread.join()
            threads_list = []

    for thread in threads_list:
        thread.join()

    for r in sorted(results):
        print(r)

# -------- OS Detection -------- #
def detect_os(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, 80))
        sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        sock.close()

        if ttl <= 64:
            print(f"[+] {host} seems to be running Linux/Unix (TTL={ttl})")
        elif ttl <= 128:
            print(f"[+] {host} seems to be running Windows (TTL={ttl})")
        else:
            print(f"[?] {host} OS unknown (TTL={ttl})")
    except Exception as e:
        print(f"[!] Could not detect OS: {e}")

# -------- Command Parser --------
def parse_command(args):
    if len(args) < 2:
        print("Usage examples:\n"
              "  python mini_nmap.py scan host 127.0.0.1 ports 1-1000\n"
              "  python mini_nmap.py detect http host example.com\n"
              "  python mini_nmap.py fast host 192.168.1.1\n"
              "  python mini_nmap.py detect os host 10.0.0.1\n"
              "  python mini_nmap.py banner host 192.168.1.5 ports 20-100\n"
              "  sudo python mini_nmap.py stealth host 192.168.1.5 ports 1-1024\n")
        return

    cmd = args[1]

    if cmd == "stealth":
        host, start, end = "127.0.0.1", 1, 1024
        if "host" in args:
            host = args[args.index("host") + 1]
        if "ports" in args:
            port_range = args[args.index("ports") + 1]
            if "-" in port_range:
                start, end = map(int, port_range.split("-"))
            else:
                start = end = int(port_range)
        stealth_scan(host, (start, end))

    elif cmd == "scan":
        host, start, end = "127.0.0.1", 1, 1024
        if "host" in args:
            host = args[args.index("host") + 1]
        if "ports" in args:
            port_range = args[args.index("ports") + 1]
            if "-" in port_range:
                start, end = map(int, port_range.split("-"))
            else:
                start = end = int(port_range)
        run_scan(host, (start, end))

    elif cmd == "detect":
        if args[2] == "os":
            host = "127.0.0.1"
            if "host" in args:
                host = args[args.index("host") + 1]
            detect_os(host)

    elif cmd == "banner":
        host, start, end = "127.0.0.1", 1, 1024
        if "host" in args:
            host = args[args.index("host") + 1]
        if "ports" in args:
            port_range = args[args.index("ports") + 1]
            if "-" in port_range:
                start, end = map(int, port_range.split("-"))
            else:
                start = end = int(port_range)
        run_scan(host, (start, end), grab_banner=True)

    elif cmd == "fast":
        host = "127.0.0.1"
        if "host" in args:
            host = args[args.index("host") + 1]
        common_ports = [21,22,25,53,80,110,135,139,143,443,
                        445,3306,5432,6379,8080,27017]
        for p in common_ports:
            run_scan(host, (p, p))

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    parse_command(sys.argv)
