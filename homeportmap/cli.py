"""Low-impact common-port inventory restricted to RFC1918 IPv4 networks."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import socket

PRIVATE_V4 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
# Fixed, small inventory set; TCP connect only, no banners or payloads.
PORTS = {22: "ssh", 53: "dns-tcp", 80: "http", 443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 3389: "rdp", 8080: "http-alt", 8443: "https-alt"}
MAX_WORKERS = 4
TIMEOUT_SECONDS = 0.35


def validate_network(cidr: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("provide a valid IPv4 CIDR, such as 192.168.1.0/24") from exc
    if not isinstance(network, ipaddress.IPv4Network) or not any(network.subnet_of(private) for private in PRIVATE_V4):
        raise ValueError("only RFC1918 private IPv4 networks are allowed")
    if network.prefixlen < 24:
        raise ValueError("network is too broad; use /24 or a smaller subnet")
    return network


def probe(address: str, port: int, timeout: float = TIMEOUT_SECONDS) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan(cidr: str) -> dict:
    network = validate_network(cidr)
    hosts = list(network.hosts())
    found: dict[str, list[dict]] = {str(host): [] for host in hosts}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(probe, str(host), port): (str(host), port)
            for host in hosts for port in PORTS
        }
        for future in as_completed(futures):
            host, port = futures[future]
            if future.result():
                found[host].append({"port": port, "service_hint": PORTS[port], "protocol": "tcp"})
    results = [
        {"address": host, "open_tcp_ports": sorted(ports, key=lambda x: x["port"])}
        for host, ports in found.items() if ports
    ]
    return {
        "network": str(network),
        "hosts_checked": len(hosts),
        "ports_checked_per_host": list(PORTS),
        "hosts_with_open_ports": len(results),
        "results": results,
        "scope": "TCP connect checks only; RFC1918 IPv4 /24 or smaller; max 4 concurrent checks; no banners, payloads, or exploit attempts.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory a small authorized private IPv4 home subnet.")
    parser.add_argument("cidr", help="authorized RFC1918 subnet, /24 or smaller (for example 192.168.1.0/24)")
    parser.add_argument("--confirm-authorized", action="store_true", help="confirm you own/administer this network or have permission")
    args = parser.parse_args()
    if not args.confirm_authorized:
        parser.error("confirm authorization with --confirm-authorized")
    try:
        result = scan(args.cidr)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
