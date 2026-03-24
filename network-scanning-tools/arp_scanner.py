#!/usr/bin/env python3
"""
arp_scanner.py
--------------
ARP Table Scanner for Network Reconnaissance
Assignment: Cybersecurity & Ethical Hacking – Module 3

"""

import subprocess
import platform
import re
import sys
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# ARP Table Retrieval
# ---------------------------------------------------------------------------

def get_arp_output() -> str:
    """
    Run the 'arp' command appropriate for the current OS and return
    its raw text output.
    """
    os_type = platform.system().lower()

    if os_type == "windows":
        # 'arp -a' works on Windows
        command = ["arp", "-a"]
    elif os_type in ("linux", "darwin"):
        # '-n' skips slow DNS reverse lookups; falls back to plain 'arp -a'
        command = ["arp", "-n"]
    else:
        command = ["arp", "-a"]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )

        if result.returncode != 0 and not result.stdout:
            # Some systems print to stderr on failure
            print(f"WARNING: arp command returned code {result.returncode}")
            print(result.stderr.strip())
        return result.stdout

    except FileNotFoundError:
        print("ERROR: 'arp' command not found.")
        print(" Linux: sudo apt install net-tools")
        print(" macOS: built-in (should be available)")
        print(" Windows: built-in")
        sys.exit(1)

    except subprocess.TimeoutExpired:
        print("ERROR: arp command timed out.")
        sys.exit(1)

    except Exception as exc:
        print(f"ERROR: Unexpected error running arp: {exc}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_arp_table(raw_output: str) -> list:
    """
    Parse raw ARP command output into a list of (ip, mac, interface) dicts.
    """
    entries = []

    # Linux: "192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0"
    linux_pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})"          # IP
        r".*?"
        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"  # MAC (colon-separated)
        r".*?"
        r"(\S+)\s*$",                        # Interface (last word)
        re.MULTILINE
    )

    # macOS / BSD: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
    macos_pattern = re.compile(
        r"\((\d{1,3}(?:\.\d{1,3}){3})\)"     # IP in ()
        r"\s+at\s+"
        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"  # MAC
        r"\s+on\s+(\S+)",                   # Interface
        re.MULTILINE
    )

    # Windows: " 192.168.1.1 aa-bb-cc-dd-ee-ff dynamic"
    windows_pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})"         # IP
        r"\s+"
        r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",  # MAC (hyphen-separated)
        re.MULTILINE
    )

    os_type = platform.system().lower()

    if os_type == "windows":
        for match in windows_pattern.finditer(raw_output):
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            entries.append({"ip": ip, "mac": mac, "interface": "N/A"})

    elif os_type == "darwin":
        for match in macos_pattern.finditer(raw_output):
            entries.append({
                "ip": match.group(1),
                "mac": match.group(2).upper(),
                "interface": match.group(3)
            })

    else:
        # Linux – try linux_pattern first, fall back to macos_pattern style
        matched = list(linux_pattern.finditer(raw_output))
        if matched:
            for match in matched:
                entries.append({
                    "ip": match.group(1),
                    "mac": match.group(2).upper(),
                    "interface": match.group(3)
                })
        else:
            for match in macos_pattern.finditer(raw_output):
                entries.append({
                    "ip": match.group(1),
                    "mac": match.group(2).upper(),
                    "interface": match.group(3)
                })

    # Deduplicate by IP (keep first occurrence)
    seen_ips = set()
    unique_entries = []
    for entry in entries:
        if entry["ip"] not in seen_ips:
            seen_ips.add(entry["ip"])
            unique_entries.append(entry)

    return unique_entries

# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_arp_table(entries: list) -> None:
    """Print a formatted ARP table to the console."""
    print("\n" + "=" * 60)
    print(" ARP TABLE – IP to MAC Address Mappings")
    print("=" * 60)

    if not entries:
        print(" No ARP entries found.")
        print(" Tip: Try pinging some hosts first to populate the cache.")
        print("=" * 60)
        return

    print(f" {'IP ADDRESS':<20} {'MAC ADDRESS':<20} {'INTERFACE'}")
    print("-" * 60)

    for entry in entries:
        print(f" {entry['ip']:<20} {entry['mac']:<20} {entry['interface']}")

    print("=" * 60)
    print(f" Total entries: {len(entries)}")
    print("=" * 60)

# ---------------------------------------------------------------------------
# Save to File
# ---------------------------------------------------------------------------

def save_results(entries: list, filename: str) -> None:
    """
    Save ARP table entries to a plain-text file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(filename, "w") as f:
            f.write(f"ARP Scan Results – {timestamp}\n")
            f.write("=" * 60 + "\n")
            f.write(f" {'IP ADDRESS':<20} {'MAC ADDRESS':<20} {'INTERFACE'}\n")
            f.write("-" * 60 + "\n")
            for entry in entries:
                f.write(
                    f" {entry['ip']:<20} {entry['mac']:<20} {entry['interface']}\n"
                )
            f.write("=" * 60 + "\n")
            f.write(f" Total entries: {len(entries)}\n")

        print(f"\n Results saved to: {os.path.abspath(filename)}")

    except OSError as exc:
        print(f"\n WARNING: Could not save file – {exc}")

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print(" ARP SCANNER – Network Reconnaissance")
    print("=" * 60)
    print(f" Platform : {platform.system()} {platform.release()}")
    print(" NOTE: Only scan networks you own or have permission to scan.")
    print("=" * 60)

    print("\nRetrieving ARP table from the operating system ...\n")
    raw_output = get_arp_output()

    entries = parse_arp_table(raw_output)
    print_arp_table(entries)

    # Optional: save to file
    save_choice = input("\nSave results to a file? (y/n): ").strip().lower()
    if save_choice == "y":
        default_name = f"arp_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filename = input(
            f"Enter filename (press Enter for '{default_name}'): "
        ).strip()
        if not filename:
            filename = default_name
        save_results(entries, filename)

if __name__ == "__main__":
    main()
