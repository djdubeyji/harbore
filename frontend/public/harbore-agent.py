#!/usr/bin/env python3
"""
harbore Asset Discovery Agent
=============================
Runs on the machine/network you want to inventory (your Mac, a laptop on the
office LAN, a jump host in a VPC) and writes a JSON file you then import into
harbore → Asset Discovery. It runs on the *host*, so it sees the real LAN — a
Docker container cannot (its bridge network can't cross into your Mac's LAN).

Requirements
------------
  1. nmap            macOS:  brew install nmap
                     Ubuntu: sudo apt-get install -y nmap
                     Windows: https://nmap.org/download.html
  2. python-nmap     pip install python-nmap

Usage
-----
  # auto-detect your subnet, thorough discovery, save to a file:
  sudo python3 harbore-agent.py --output scan_results.json

  # specific subnet:
  sudo python3 harbore-agent.py --subnet 192.168.1.0/24 --output scan_results.json

Then open harbore → Asset Discovery → Import and upload scan_results.json.

Note: run with sudo/Administrator so nmap can use ARP/raw packets (far more
accurate host discovery, incl. sleeping phones/IoT).
"""
import json
import sys
import socket
import argparse
from datetime import datetime, timezone


def local_ip_and_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip, f"{'.'.join(ip.split('.')[:3])}.0/24"
    except Exception:
        return None, None


def scan(subnet_arg=None, top_ports=100):
    try:
        import nmap
    except ImportError:
        print("ERROR: pip install python-nmap", file=sys.stderr)
        sys.exit(1)

    local_ip, auto_subnet = local_ip_and_subnet()
    subnet = subnet_arg or auto_subnet
    if not subnet:
        print("ERROR: could not determine a subnet; pass --subnet", file=sys.stderr)
        sys.exit(1)

    nm = nmap.PortScanner()
    print(f"[harbore] Discovering hosts on {subnet} (this can take a few minutes)...", file=sys.stderr)

    # Phase 1 — host discovery: ARP + ICMP echo/timestamp/netmask + TCP SYN
    nm.scan(hosts=subnet, arguments="-sn -PR -PE -PP -PM -PS22,80,443,445,3389")

    hosts = []
    for host in nm.all_hosts():
        addrs = nm[host].get("addresses", {})
        mac = addrs.get("mac")
        vendor = nm[host].get("vendor", {}).get(mac) if mac else None
        hosts.append({
            "ip_address": host,
            "hostname": nm[host].hostname() or None,
            "mac_address": mac,
            "vendor": vendor,
            "is_scanner": host == local_ip,
            "ports": [],
        })
        print(f"  found {host} - {nm[host].hostname() or 'unknown'}", file=sys.stderr)

    # Phase 2 — service/version detection on discovered hosts
    print(f"[harbore] Port scan on {len(hosts)} hosts (top {top_ports})...", file=sys.stderr)
    for h in hosts:
        try:
            nm.scan(hosts=h["ip_address"], arguments=f"-sV -T4 --top-ports {top_ports}")
            ip = h["ip_address"]
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto].keys():
                        info = nm[ip][proto][port]
                        if info.get("state") == "open":
                            h["ports"].append({
                                "port": port,
                                "protocol": proto,
                                "service": info.get("name", ""),
                                "product": info.get("product", ""),
                                "version": info.get("version", ""),
                            })
        except Exception:
            pass

    return {
        "scan_info": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subnet": subnet,
            "scanner_ip": local_ip,
            "total_hosts": len(hosts),
            "agent": "harbore-agent/1.0",
        },
        "hosts": hosts,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="harbore Asset Discovery Agent")
    ap.add_argument("--subnet", "-s", help="Subnet, e.g. 192.168.1.0/24 (default: auto-detect)")
    ap.add_argument("--output", "-o", help="Write JSON to this file (default: stdout)")
    ap.add_argument("--top-ports", type=int, default=100, help="Top N ports to scan (default 100)")
    args = ap.parse_args()

    result = scan(args.subnet, args.top_ports)
    out = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"\n[harbore] {result['scan_info']['total_hosts']} hosts saved to {args.output}", file=sys.stderr)
        print("[harbore] Import it in harbore → Asset Discovery → Import.", file=sys.stderr)
    else:
        print(out)
