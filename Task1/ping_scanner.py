#!/usr/bin/env python3

"""
Ping Scanner – Cybersecurity Assignment

Simple tool to check if hosts are reachable using ping.
Also shows average response time.

"""

import subprocess
import platform
import re
import sys


# Build ping command depending on OS
def build_ping_command(target, count=4):

    os_type = platform.system().lower()

    if os_type == "windows":

        return ["ping","-n",str(count),target]

    else:

        return ["ping","-c",str(count),target]


# Run ping
def ping_host(target,count=4,timeout=10):

    cmd = build_ping_command(target,count)

    try:

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        return result.stdout + result.stderr

    except subprocess.TimeoutExpired:

        return "timeout"

    except:

        return "error"


# Extract info from ping output
def parse_ping_output(output):

    out = output.lower()

    if out.startswith("timeout") or out.startswith("error"):

        return "Unreachable","N/A"


    # check if any reply came
    check = ["reply from","bytes from","time="]

    reachable = False

    for c in check:

        if c in out:

            reachable = True
            break


    if not reachable:

        return "Unreachable","N/A"


    # linux style average
    linux = re.search(
        r"min/avg/max.*=\s*[\d.]+/([\d.]+)/",
        output
    )

    # windows style
    windows = re.search(
        r"Average\s*=\s*([\d.]+)",
        output,
        re.IGNORECASE
    )

    # fallback
    fallback = re.search(
        r"time[=<]([\d.]+)",
        output,
        re.IGNORECASE
    )


    if linux:

        avg = linux.group(1)+" ms"

    elif windows:

        avg = windows.group(1)+" ms"

    elif fallback:

        avg = fallback.group(1)+" ms"

    else:

        avg = "Unknown"


    return "Reachable",avg


# Scan one host
def scan_single_host(target):

    raw = ping_host(target)

    status,avg = parse_ping_output(raw)

    return {
        "host":target,
        "status":status,
        "avg":avg
    }


# Scan many hosts
def scan_multiple_hosts(targets):

    results = []

    for t in targets:

        print("Scanning",t,"...",end=" ")

        r = scan_single_host(t)

        print(r["status"])

        results.append(r)


    return results


# Show results
def print_results(results):

    print("\nResults\n")

    print("Host\t\tStatus\t\tAvg time")

    for r in results:

        print(
            r["host"],
            "\t",
            r["status"],
            "\t",
            r["avg"]
        )


    up = 0

    for r in results:

        if r["status"]=="Reachable":

            up+=1


    print("\nReachable:",up,"/",len(results))


def main():

    print("\nPing Scanner")

    print("System:",platform.system())

    print("\n1 Single host")

    print("2 Multiple hosts")


    while True:

        choice = input("Choice: ")

        if choice=="1" or choice=="2":

            break

        print("Enter 1 or 2")


    if choice=="1":

        target = input("Enter IP or hostname: ")

        if target=="":

            print("No target")
            sys.exit()

        targets=[target]


    else:

        data = input("Enter hosts separated by comma: ")

        targets=[]

        parts=data.split(",")

        for p in parts:

            p=p.strip()

            if p!="":

                targets.append(p)


        if len(targets)==0:

            print("No targets")
            sys.exit()


    print("\nStarting scan...\n")

    results=scan_multiple_hosts(targets)

    print_results(results)


if __name__=="__main__":

    main()
