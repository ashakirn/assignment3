#!/usr/bin/env python3

"""
ARP Scanner – Cybersecurity Assignment


"""

import subprocess
import platform
import re
import sys
import os
from datetime import datetime


# get arp output from system
def get_arp_output():

    os_type = platform.system().lower()

    if os_type=="windows":

        cmd=["arp","-a"]

    else:

        cmd=["arp","-n"]


    try:

        result=subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return result.stdout

    except:

        print("arp command not found")
        sys.exit()


# parse arp entries
def parse_arp_table(raw):

    entries=[]

    linux=re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3}).*?"
        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}).*?"
        r"(\S+)$",
        re.MULTILINE
    )


    mac=re.compile(
        r"\((\d{1,3}(?:\.\d{1,3}){3})\)"
        r"\s+at\s+"
        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
        r"\s+on\s+(\S+)",
        re.MULTILINE
    )


    win=re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3})"
        r"\s+"
        r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",
        re.MULTILINE
    )


    os_type=platform.system().lower()


    if os_type=="windows":

        for m in win.finditer(raw):

            ip=m.group(1)

            macaddr=m.group(2)

            macaddr=macaddr.replace("-",":")

            entries.append({
                "ip":ip,
                "mac":macaddr,
                "int":"N/A"
            })


    elif os_type=="darwin":

        for m in mac.finditer(raw):

            entries.append({

                "ip":m.group(1),

                "mac":m.group(2),

                "int":m.group(3)
            })


    else:

        found=list(linux.finditer(raw))

        if found:

            for m in found:

                entries.append({

                    "ip":m.group(1),

                    "mac":m.group(2),

                    "int":m.group(3)
                })


        else:

            for m in mac.finditer(raw):

                entries.append({

                    "ip":m.group(1),

                    "mac":m.group(2),

                    "int":m.group(3)
                })


    # remove duplicates
    seen=set()

    unique=[]

    for e in entries:

        if e["ip"] not in seen:

            seen.add(e["ip"])

            unique.append(e)


    return unique


# print table
def print_table(entries):

    print("\nARP Table\n")

    if len(entries)==0:

        print("No entries found")

        return


    print("IP\t\tMAC\t\tInterface")


    for e in entries:

        print(

            e["ip"],
            "\t",
            e["mac"],
            "\t",
            e["int"]
        )


    print("\nTotal:",len(entries))


# save results
def save_results(entries,file):

    try:

        f=open(file,"w")

        f.write("ARP Results\n\n")

        for e in entries:

            f.write(

                e["ip"]+" "+e["mac"]+" "+e["int"]+"\n"

            )

        f.close()

        print("Saved to",os.path.abspath(file))

    except:

        print("Could not save")


def main():

    print("\nARP Scanner")

    print("System:",platform.system())


    print("\nReading ARP table...\n")


    raw=get_arp_output()

    entries=parse_arp_table(raw)

    print_table(entries)


    s=input("\nSave results? y/n:")

    if s=="y":

        name="arp_"+datetime.now().strftime("%H%M%S")+".txt"

        file=input("Filename (Enter for default):")

        if file=="":

            file=name

        save_results(entries,file)


if __name__=="__main__":

    main()
