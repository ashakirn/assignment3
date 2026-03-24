#!/usr/bin/env python3
"""
ping_scanner.py
---------------
Ping Scanner for Network Reconnaissance
Assignment: Cybersecurity & Ethical Hacking – Module 3
"""

import subprocess
import platform
import re
import sys


def build_ping_command(target: str, count: int = 4) -> list:
    """
    Build the OS-appropriate ping command.

    Args:
        target: Hostname or IP address to ping.
        count: Number of ICMP echo requests to send.

    Returns:
        A list of arguments suitable for subprocess.
    """
    os_type = platform.system().lower()

    if os_type == "windows":
        # Windows uses -n for count
        return ["ping", "-n", str(count), target]
    else:
        # Linux / macOS use -c for count
        return ["ping", "-c", str(count), target]

def ping_host(target: str, count: int = 4, timeout: int = 10) -> str:
    """
    Execute a ping command and return the raw stdout output.

    Args:
        target: Hostname or IP address.
        count: Number of ping packets.
        timeout: Seconds before giving up (handles unresponsive hosts).

    Returns:
        Raw string output from the ping command, or an error message.
    """
    command = build_ping_command(target, count)

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        # Combine stdout + stderr so we catch "host unreachable" messages too
        return result.stdout + result.stderr

    except subprocess.TimeoutExpired:
        return f"TIMEOUT: No response from {target} within {timeout}s."

    except FileNotFoundError:
        return "ERROR: 'ping' command not found on this system."

    except Exception as exc:
        return f"ERROR: {exc}"

def parse_ping_output(output: str) -> tuple:
    """
    Parse raw ping output to determine reachability and average RTT.

    Args:
        output: Raw string from ping_host().

    Returns:
        A tuple (status: str, avg_time: str).
        status – "Reachable" or "Unreachable"
        avg_time – e.g. "12.5 ms" or "N/A"
    """
    output_lower = output.lower()

    # Detect timeout / errors set by ping_host
    if output_lower.startswith("timeout:") or output_lower.startswith("error:"):
        return "Unreachable", "N/A"

    # Positive indicators that at least one packet got a reply
    reachable_patterns = ["bytes from", "reply from", "1 received", "time="]
    is_reachable = any(p in output_lower for p in reachable_patterns)

    if not is_reachable:
        return "Unreachable", "N/A"

    # Extract average RTT
    # Linux / macOS: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.100 ms"
    linux_match = re.search(
        r"min/avg/max(?:/mdev)?\s*=\s*[\d.]+/([\d.]+)/", output
    )

    # Windows: "Average = 12ms"
    windows_match = re.search(
        r"Average\s*=\s*([\d.]+)\s*ms", output, re.IGNORECASE
    )

    # Fallback: grab any "time=12 ms" value
    fallback_match = re.search(
        r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE
    )

    if linux_match:
        avg_time = f"{linux_match.group(1)} ms"
    elif windows_match:
        avg_time = f"{windows_match.group(1)} ms"
    elif fallback_match:
        avg_time = f"{fallback_match.group(1)} ms (single packet)"
    else:
        avg_time = "Unknown"

    return "Reachable", avg_time

def scan_single_host(target: str) -> dict:
    """
    Scan a single host and return a result dictionary.

    Args:
        target: Hostname or IP address.

    Returns:
        dict with keys: host, status, avg_time, raw_output
    """
    raw = ping_host(target)
    status, avg_time = parse_ping_output(raw)
    return {
        "host": target,
        "status": status,
        "avg_time": avg_time,
        "raw_output": raw
    }

def scan_multiple_hosts(targets: list) -> list:
    """
    Scan multiple hosts sequentially.

    Args:
        targets: List of hostnames / IP addresses.

    Returns:
        List of result dicts (same structure as scan_single_host).
    """
    results = []
    for target in targets:
        print(f" Scanning {target} ...", end=" ", flush=True)
        result = scan_single_host(target)
        print(f"{result['status']}")
        results.append(result)
    return results

# ---------------------------------------------------------------------------
# Display Helper
# ---------------------------------------------------------------------------

def print_results(results: list) -> None:
    """Print a formatted results table."""
    print("\n" + "=" * 55)
    print(f" {'HOST':<25} {'STATUS':<15} {'AVG RTT'}")
    print("=" * 55)
    for r in results:
        print(f" {r['host']:<25} {r['status']:<15} {r['avg_time']}")
    print("=" * 55)

    reachable = sum(1 for r in results if r["status"] == "Reachable")
    print(f"\n Summary: {reachable}/{len(results)} host(s) reachable.")

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 55)
    print(" PING SCANNER – Network Reconnaissance")
    print("=" * 55)
    print(f" Platform: {platform.system()} {platform.release()}")
    print(" NOTE: Only scan networks you own or have permission to scan.")
    print("=" * 55)

    # Ask user for scan mode
    print("\nScan mode:")
    print(" 1. Single host")
    print(" 2. Multiple hosts")

    while True:
        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice in ("1", "2"):
            break
        print(" Invalid choice. Please enter 1 or 2.")

    if choice == "1":
        target = input("Enter hostname or IP address: ").strip()
        if not target:
            print("ERROR: No target specified. Exiting.")
            sys.exit(1)
        targets = [target]
    else:
        raw_input_str = input(
            "Enter hostnames/IPs separated by commas\n"
            "(e.g. 127.0.0.1, google.com, 192.168.1.1): "
        ).strip()
        targets = [t.strip() for t in raw_input_str.split(",") if t.strip()]
        if not targets:
            print("ERROR: No targets specified. Exiting.")
            sys.exit(1)

    print(f"\nScanning {len(targets)} host(s) ...\n")
    results = scan_multiple_hosts(targets)
    print_results(results)

if __name__ == "__main__":
    main()
