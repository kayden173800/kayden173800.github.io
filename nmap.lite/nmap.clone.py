#!/usr/bin/env python3
"""
nmap_lite.py — A small TCP connect port scanner with simple banner grabbing,
concurrent worker threads, and JSON/CSV output.

Safe use: scan only hosts/networks you own or have explicit permission to test.
"""

import argparse
import socket
import json
import csv
import ipaddress
import sys
from queue import Queue, Empty
from threading import Thread, Lock
from datetime import datetime

VERSION = "0.1"

# Global lock for safe printing from threads
print_lock = Lock()

def parse_targets(target_str):
    """
    Accepts single IP (v4), hostname, or CIDR like 192.168.1.0/24
    Returns a list of strings (IP addresses).
    """
    targets = []
    # Try CIDR
    try:
        if "/" in target_str:
            net = ipaddress.ip_network(target_str, strict=False)
            for ip in net.hosts():
                targets.append(str(ip))
            return targets
        # Try single IP
        ip = ipaddress.ip_address(target_str)
        return [str(ip)]
    except ValueError:
        # Not an IP; treat as hostname (resolve)
        try:
            resolved = socket.gethostbyname_ex(target_str)[2]
            if not resolved:
                raise RuntimeError(f"Could not resolve hostname: {target_str}")
            return resolved
        except socket.gaierror:
            raise RuntimeError(f"Could not resolve hostname: {target_str}")

def banner_grab(sock, target, port, timeout):
    """
    Attempt to grab a banner. Many services send a banner on connect (FTP, SMTP, SSH).
    For HTTP we send a HEAD request. This is *simple* and non-intrusive, but still
    should only be used against authorized targets.
    """
    try:
        sock.settimeout(timeout)
        # Try to read passive banner first
        try:
            data = sock.recv(1024)
            if data:
                return data.decode(errors="replace").strip()
        except socket.timeout:
            pass
        except Exception:
            pass

        # Heuristic: if port 80 or 8080 or 8000, try an HTTP HEAD
        if port in (80, 8080, 8000, 8008, 5000):
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    return data.decode(errors="replace").strip()
            except Exception:
                pass

        # If nothing found, return empty string
        return ""
    except Exception:
        return ""

def worker(q, results, args):
    timeout = args.timeout
    while True:
        try:
            target, port = q.get_nowait()
        except Empty:
            return
        addr = (target, port)
        status = "closed"
        b = ""
        try:
            # Create a socket and attempt to connect (TCP connect scan).
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                try:
                    s.connect(addr)
                    status = "open"
                    # Attempt banner grabbing (non-intrusive)
                    b = banner_grab(s, target, port, timeout)
                except (socket.timeout, ConnectionRefusedError):
                    status = "closed"
                except Exception as e:
                    status = f"err:{type(e).__name__}"
        except Exception as e_outer:
            status = f"err:{type(e_outer).__name__}"

        # Thread-safe append
        with print_lock:
            results.append({
                "target": target,
                "port": port,
                "status": status,
                "banner": b,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            if args.verbose:
                print(f"[{target}:{port}] {status}" + (f" -- {b[:80]}" if b else ""))

        q.task_done()

def build_port_list(port_spec):
    """
    Accepts:
       - single port e.g. "22"
       - comma separated "22,80,443"
       - range "1-1024"
       - combined "22,80,1000-1010"
    Returns a sorted list of ints (unique).
    """
    ports = set()
    parts = [p.strip() for p in port_spec.split(",")]
    for part in parts:
        if "-" in part:
            low, high = part.split("-", 1)
            low_i = int(low)
            high_i = int(high)
            if low_i > high_i:
                low_i, high_i = high_i, low_i
            for p in range(low_i, high_i + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

def save_results_json(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

def save_results_csv(results, filename):
    if not results:
        return
    fieldnames = ["target", "port", "status", "banner", "timestamp"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

def main():
    parser = argparse.ArgumentParser(description="nmap_lite — simple TCP connect scanner")
    parser.add_argument("target", help="IP, CIDR (e.g. 192.168.1.0/24) or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan: single, comma-separated, ranges. Default: 1-1024")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of worker threads")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("-oJ", "--out-json", help="Write results to JSON file")
    parser.add_argument("-oC", "--out-csv", help="Write results to CSV file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print("nmap_lite version", VERSION)
        sys.exit(0)

    try:
        targets = parse_targets(args.target)
    except RuntimeError as e:
        print("ERROR:", e)
        sys.exit(1)

    ports = build_port_list(args.ports)
    if not ports:
        print("No valid ports specified.")
        sys.exit(1)

    # Create job queue
    q = Queue()
    results = []

    for t in targets:
        for p in ports:
            q.put((t, p))

    if args.verbose:
        print(f"Scanning {len(targets)} target(s) x {len(ports)} ports = {q.qsize()} checks")
        print(f"Threads: {args.threads}  Timeout: {args.timeout}s")

    workers = []
    for i in range(max(1, args.threads)):
        thr = Thread(target=worker, args=(q, results, args), daemon=True)
        thr.start()
        workers.append(thr)

    # Wait for queue to finish
    q.join()

    # Sort results for nicer output
    results_sorted = sorted(results, key=lambda r: (r["target"], r["port"]))

    # Print summary
    open_count = sum(1 for r in results_sorted if r["status"] == "open")
    print(f"\nScan complete: {len(results_sorted)} checks, {open_count} open ports found.")

    if args.out_json:
        save_results_json(results_sorted, args.out_json)
        print(f"Wrote JSON results to {args.out_json}")
    if args.out_csv:
        save_results_csv(results_sorted, args.out_csv)
        print(f"Wrote CSV results to {args.out_csv}")
    # If no outputs requested, print a short textual summary
    if not args.out_json and not args.out_csv:
        for r in results_sorted:
            if r["status"] == "open":
                banner = f" -- {r['banner'][:120]}" if r["banner"] else ""
                print(f"{r['target']}:{r['port']} OPEN{banner}")

if __name__ == "__main__":
    main()
