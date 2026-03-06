#!/usr/bin/env python3
"""
network_scanner.py

A simple TCP network scanner for authorized systems only.

Features:
- Scan a single IP or CIDR subnet
- Scan configurable TCP ports
- Label common services
- Optional basic banner grabbing
- Hostname resolution
- CSV export
- Optional JSON export
- Progress indicator
- Scan timing statistics

Examples:
    python network_scanner.py 127.0.0.1
    python network_scanner.py 192.168.1.10 --ports 22,80,443
    python network_scanner.py 192.168.1.0/24 --banner --json results.json
"""

import argparse
import csv
import ipaddress
import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


DEFAULT_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 100

COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3389: "rdp",
    8080: "http-alt",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple TCP network scanner")
    parser.add_argument(
        "target",
        help="Target IP address or CIDR subnet (example: 192.168.1.10 or 192.168.1.0/24)",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated list of TCP ports to scan",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Socket timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Maximum number of worker threads (default: 100)",
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Attempt basic banner grabbing on open ports",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="scan_results.csv",
        help="CSV output filename (default: scan_results.csv)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        type=str,
        default=None,
        help="Optional JSON output filename",
    )
    return parser.parse_args()


def parse_ports(port_string: str) -> list[int]:
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port: {port}")
        ports.append(port)
    return sorted(set(ports))


def expand_targets(target: str) -> list[str]:
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(host) for host in network.hosts()]
        ip = ipaddress.ip_address(target)
        return [str(ip)]
    except ValueError as exc:
        raise ValueError(f"Invalid target '{target}': {exc}") from exc


def guess_service(port: int) -> str:
    return COMMON_SERVICES.get(port, "unknown")


def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in (80, 8080):
                request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode("utf-8", errors="ignore"))
            elif port == 443:
                return "TLS service detected (no plaintext banner)"

            data = sock.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
            return banner[:200] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, banner: bool) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))

            if result == 0:
                service = guess_service(port)
                banner_text = grab_banner(ip, port, timeout) if banner else ""
                return {
                    "ip": ip,
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner_text,
                }
    except (socket.gaierror, socket.timeout, OSError):
        pass

    return None


def scan_targets(
    targets: list[str],
    ports: list[int],
    timeout: float,
    workers: int,
    banner: bool,
) -> tuple[list[dict], dict]:
    results: list[dict] = []
    hostnames: dict[str, str] = {}

    total_tasks = len(targets) * len(ports)
    completed_tasks = 0
    lock = threading.Lock()

    def wrapped_scan(ip: str, port: int) -> dict | None:
        nonlocal completed_tasks
        result = scan_port(ip, port, timeout, banner)

        with lock:
            completed_tasks += 1
            print(f"\rProgress: {completed_tasks}/{total_tasks} port checks completed", end="", flush=True)

        return result

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(wrapped_scan, ip, port) for ip in targets for port in ports]

        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    print()

    for ip in targets:
        hostnames[ip] = resolve_hostname(ip)

    results.sort(key=lambda row: (ipaddress.ip_address(row["ip"]), row["port"]))
    return results, hostnames


def write_csv(results: list[dict], hostnames: dict[str, str], filename: str) -> None:
    fieldnames = ["ip", "hostname", "port", "status", "service", "banner"]

    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in results:
            writer.writerow({
                "ip": row["ip"],
                "hostname": hostnames.get(row["ip"], ""),
                "port": row["port"],
                "status": row["status"],
                "service": row["service"],
                "banner": row["banner"],
            })


def write_json(results: list[dict], hostnames: dict[str, str], filename: str) -> None:
    grouped: dict[str, dict] = {}

    for row in results:
        ip = row["ip"]
        if ip not in grouped:
            grouped[ip] = {
                "ip": ip,
                "hostname": hostnames.get(ip, ""),
                "open_ports": [],
            }

        grouped[ip]["open_ports"].append({
            "port": row["port"],
            "service": row["service"],
            "status": row["status"],
            "banner": row["banner"],
        })

    output_data = {
        "generated_at": datetime.now().isoformat(),
        "hosts": list(grouped.values()),
    }

    with open(filename, "w", encoding="utf-8") as jsonfile:
        json.dump(output_data, jsonfile, indent=2)


def print_results(results: list[dict], hostnames: dict[str, str]) -> None:
    if not results:
        print("No open ports found.")
        return

    current_ip = None

    for row in results:
        if row["ip"] != current_ip:
            current_ip = row["ip"]
            hostname = hostnames.get(current_ip, "")

            if hostname:
                print(f"\nHost: {current_ip} ({hostname})")
                print("-" * (8 + len(current_ip) + len(hostname)))
            else:
                print(f"\nHost: {current_ip}")
                print("-" * (6 + len(current_ip)))

        banner_suffix = f" | banner: {row['banner']}" if row["banner"] else ""
        print(
            f"  Port {row['port']:>5} | {row['status']:<4} | "
            f"{row['service']}{banner_suffix}"
        )


def print_stats(
    targets: list[str],
    ports: list[int],
    results: list[dict],
    start_time: float,
    end_time: float,
) -> None:
    duration = end_time - start_time
    unique_hosts_with_open_ports = len({row["ip"] for row in results})

    print("\nScan Summary")
    print("------------")
    print(f"Hosts scanned: {len(targets)}")
    print(f"Ports per host: {len(ports)}")
    print(f"Total port checks: {len(targets) * len(ports)}")
    print(f"Hosts with open ports: {unique_hosts_with_open_ports}")
    print(f"Open ports found: {len(results)}")
    print(f"Scan duration: {duration:.2f} seconds")


def main() -> None:
    args = parse_args()

    try:
        ports = parse_ports(args.ports)
        targets = expand_targets(args.target)
    except ValueError as exc:
        print(f"Error: {exc}")
        return

    print(f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Targets: {len(targets)} host(s)")
    print(f"Ports: {ports}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workers: {args.workers}")
    print(f"Banner grabbing: {'enabled' if args.banner else 'disabled'}")

    start_time = time.perf_counter()

    results, hostnames = scan_targets(
        targets=targets,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        banner=args.banner,
    )

    end_time = time.perf_counter()

    print_results(results, hostnames)
    print_stats(targets, ports, results, start_time, end_time)

    write_csv(results, hostnames, args.output)
    print(f"\nCSV results saved to: {args.output}")

    if args.json_output:
        write_json(results, hostnames, args.json_output)
        print(f"JSON results saved to: {args.json_output}")


if __name__ == "__main__":
    main()