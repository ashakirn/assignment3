#!/usr/bin/env python3

"""
Simple Nmap Scanner
Cybersecurity Assignment – Module 3

This tool performs:
1. Host discovery
2. Port scanning
3. Service detection
4. OS detection

Note:
Nmap must be installed.
Install python-nmap using pip.
Author: Ashakirana V
"""

import sys
import platform
import subprocess
from datetime import datetime


# Check if nmap exists
def check_nmap_installed():

    try:
        result = subprocess.run(
            ["nmap","--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode == 0:
            return True

    except:
        return False

    return False


# Check python nmap library
def check_python_nmap():

    try:
        import nmap
        return True

    except:
        return False


# Host discovery scan
def scan_host_discovery(nm,target):

    print("\nStarting host discovery...")
    print("Target:",target)

    try:
        nm.scan(hosts=target,arguments="-sn")

    except Exception as e:
        print("Scan failed:",e)
        return


    hosts_up = []

    for h in nm.all_hosts():

        if nm[h].state()=="up":
            hosts_up.append(h)

        name = nm[h].hostname()

        if name=="":
            name="N/A"

        print(h,nm[h].state(),name)


    print("\nHosts up:",len(hosts_up))


# Port scanning
def scan_ports(nm,target,port_range="1-1000"):

    print("\nScanning ports...")
    print("Range:",port_range)

    try:

        nm.scan(
            hosts=target,
            ports=port_range,
            arguments="-sT"
        )

    except Exception as e:

        print("Error:",e)
        return


    print_ports(nm,target)


# Service detection
def scan_service_detection(nm,target):

    print("\nDetecting services...")

    try:

        nm.scan(
            hosts=target,
            ports="1-1000",
            arguments="-sV"
        )

    except Exception as e:

        print("Scan error:",e)
        return


    print_ports(nm,target,True)


# OS detection
def scan_os_detection(nm,target):

    print("\nTrying OS detection")

    try:

        nm.scan(
            hosts=target,
            arguments="-O"
        )

    except Exception as e:

        print("Run as admin/root")
        return


    for host in nm.all_hosts():

        print("\nHost:",host)

        matches = nm[host].get("osmatch",[])

        if len(matches)>0:

            print("Possible OS:")

            for m in matches[:3]:

                print(
                    m.get("name"),
                    m.get("accuracy")+"%"
                )

        else:

            print("OS not detected")


# Display ports
def print_ports(nm,target,version=False):

    if len(nm.all_hosts())==0:

        print("No host found")
        return


    for host in nm.all_hosts():

        print("\nHost:",host)

        for proto in nm[host].all_protocols():

            print("Protocol:",proto)

            ports=sorted(
                nm[host][proto].keys()
            )

            for port in ports:

                info=nm[host][proto][port]

                state=info['state']

                service=info['name']

                if version:

                    product=info.get('product','')

                    ver=info.get('version','')

                    print(
                        port,
                        state,
                        service,
                        product,
                        ver
                    )

                else:

                    print(
                        port,
                        state,
                        service
                    )


# Save output
def save_results(nm,scan_type,target):

    time=datetime.now().strftime("%Y%m%d_%H%M")

    file="scan_"+time+".txt"

    try:

        f=open(file,"w")

        f.write("Scan:"+scan_type+"\n")

        f.write("Target:"+target+"\n")

        f.write("\n")

        data=nm.get_nmap_last_output()

        if isinstance(data,bytes):

            data=data.decode()

        f.write(data)

        f.close()

        print("Saved:",file)

    except:

        print("Could not save file")


# Menu
def menu():

    print("\n--- Nmap Scanner ---")

    print("1 Host discovery")

    print("2 Port scan")

    print("3 Custom scan")

    print("4 Service detection")

    print("5 OS detection")

    print("6 Exit")


def get_target():

    while True:

        t=input("Enter target: ").strip()

        if t!="":
            return t

        print("Enter valid target")


def main():

    print("\nNmap Scanner")
    print("System:",platform.system())

    if not check_nmap_installed():

        print("Install nmap first")

        sys.exit()


    if not check_python_nmap():

        print("Install python-nmap")

        sys.exit()


    import nmap

    nm=nmap.PortScanner()


    while True:

        menu()

        choice=input("Choice: ")

        if choice=="6":

            print("Exiting")
            break


        target=get_target()


        if choice=="1":

            scan_host_discovery(nm,target)

            label="Host discovery"


        elif choice=="2":

            scan_ports(nm,target)

            label="Port scan"


        elif choice=="3":

            p=input("Ports:")

            if p=="":
                p="1-1000"

            scan_ports(nm,target,p)

            label="Custom"


        elif choice=="4":

            scan_service_detection(nm,target)

            label="Service"


        elif choice=="5":

            scan_os_detection(nm,target)

            label="OS"


        else:

            print("Wrong choice")
            continue


        s=input("Save? y/n:")

        if s=="y":

            save_results(nm,label,target)


        again=input("Again? y/n:")

        if again!="y":

            break


if __name__=="__main__":

    main()
