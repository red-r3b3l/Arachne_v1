#!/usr/bin/env python
import os
import socket
import subprocess
import sys
import urllib.request
from datetime import datetime

#TO-DO List

# 1. Add CURL / Download function
# 2. Add Shell Function
# 3. OS Fingerprinting?
# 4. Add options
# 5. Check IP Reputation

#setting up clearscreen function
clear = lambda: os.system('cls')
clear()

#set your targeted ports by scan type here
quickscan = int("21"),int("22"),int("23"),int("25"),int("53"),int("80"),int("110"),int("135"),int("443")
fullscan = int("2"),int("3"),int("4"),int("5"),int("7"),int("8"),int("9"),int("10"),int("11"),int("12"),int("13"),int("15"),int("16"),int("17"),int("18"),int("19"),int("20"),int("21"),int("22"),int("23"),int("25"),int("27"),int("30"),int("31"),int("34"),int("37"),int("39"),int("41"),int("42"),int("43"),int("44"),int("48"),int("49"),int("50"),int("51"),int("52"),int("53"),int("54"),int("57"),int("58"),int("59"),int("66"),int("67"),int("68"),int("69"),int("70"),int("73"),int("77"),int("79"),int("80"),int("82"),int("85"),int("86"),int("87"),int("88"),int("90"),int("96"),int("97"),int("98"),int("99"),int("101"),int("102"),int("103"),int("105"),int("106"),int("107"),int("109")

#creating empty list to store our open ports in
openports = []
vulns = []

def mainmenu():
    print("")
    print("-" * 71)
    print("                      ȺŘACĤŇE̺ v4.4")
    print("             Developed by MafiaSec Cybersecurity")
    print("                    www.mafiasec.net")
    print("-" * 71)
    print("")
    print("1. Port Scan")
    print("2. Vulnerability Report")
    print("3. Resolve Hostname")
    print("4. DNS Reverse Lookup (Domain from IP)")
#   print("5. Curl URL")
#   print("6. Options")
    print("")
    print("Please type the corresponding number and press enter.")
    print("\n")
    print("")
    promptfor = input()
    if promptfor == "1":
        portscan()
    if promptfor == "2":
        threatscan()
    if promptfor == "3":
        hostnameresolver()
    if promptfor == "4":
        dnsreverselookup()
    if promptfor == "5":
        urlretrieve()

def urlretrieve():
    clear()
    print("\n\n")
    print("-" * 71)
    remoteURL = input("Enter the internet address to retrieve file from: \n" + ("-" * 71) + "\n\n")
    urllib.request.urlretrieve(remoteURL, 'py.py')
    print("Check now.")

def dnsreverselookup():
    clear()
    print("\n\n")
    print("-" * 71)
    try:

        remoteDNSIP = input("Enter a remote IP to reverse DNS lookup: \n" + ("-" * 71) + "\n\n")
        print(socket.gethostbyaddr(remoteDNSIP.replace(" ", "")))
        print("\n\n")
        print("Press any key to return to the main menu.")
        i = input()
        if i == "":
            clear()
            mainmenu()
        else:
            clear()
            mainmenu()
    except socket.error:
        print("\n\n")
        print("Socket error.")
        print("\n\n")
        print("Press any key to return to the main menu.")
        i = input()
        if i == "":
            clear()
            mainmenu()
        else:
            clear()
            mainmenu()
    except socket.herror:
        print("\n\n")
        print("Host not found.")
        print("\n\n")
        print("Press any key to return to the main menu.")
        i = input()
        if i == "":
            clear()
            mainmenu()
        else:
            clear()
            mainmenu()
    except socket.gaierror:
        print("\n\n")
        print("Hostname could not be resolved.")
        print("\n\n")
        print("Press any key to return to the main menu.")
        i = input()
        if i == "":
            clear()
            mainmenu()
        else:
            clear()
            mainmenu()

def hostnameresolver():
    clear()
    print("\n\n")
    print("-" * 71)
    remoteServer = input("Enter a remote host to resolve: \n" + ("-" * 71) + "\n\n" )
    remoteServerIP = socket.gethostbyname(remoteServer.replace(" ", ""))
    clear()
    print("\n\n")
    print("IP Address: " + remoteServerIP)
    print("\n\n")
    print("Press any key to return to the main menu. \n")
    i = input()
    if i == "":
        clear()
        mainmenu()
    else:
        clear()
        mainmenu()

def threatscan():
    clear()
    print("\n\n")
    print("-" * 71)
    print("What type of scan would you like to run?")
    print("-" * 71)
    print("")
    print("1. Quick Scan")
    print("2. Full Scan")
    print("")
    print("Please type the corresponding number and press enter.")
    print("\n")
    print("")
    promptfor = input()
    if promptfor == "1":
        quickscanaskforhost()
    elif promptfor == "2":
        fullscanaskforhost()

def quickscanaskforhost():
    clear()
    print("\n")
    remoteServer = input("Enter a hostname or IP address to scan: \n\n")
    remoteServerIP = socket.gethostbyname(remoteServer.replace(" ", ""))
    clear()
    print("-" * 71  )
    print("Please wait, ȺŘACĤŇE is beginning quick threat scan >>>>>", remoteServerIP)
    print("-" * 71)
    print("")
    print("")
    try:
        for port in quickscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print("Port {}:                                                  Open".format(port))
                openports.append(port)
            else:
                print("Port {}:                                                 Closed".format(port))
            sock.close()
    except KeyboardInterrupt:
        print("Exit.")
        sys.exit()
    except socket.gaierror:
        print('Hostname could not be resolved.')
        sys.exit()
    except socket.error:
        print("Couldn't connect to server. Socket error.")
        sys.exit()
    print("")

    vulnreport()
    mainmenu()

def fullscanaskforhost():
    clear()
    print("\n")
    remoteServer = input("Enter a remote host to scan: \n\n")
    remoteServerIP = socket.gethostbyname(remoteServer.replace(" ", ""))
    clear()
    print("-" * 71)
    print("Please wait, ȺŘACĤŇE is beginning full threat scan >>>>>", remoteServerIP)
    print("-" * 71)
    print("")
    print("")
    try:
        for port in fullscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print("Port {}:                                                  Open ".format(port))
                openports.append(port)
            else:
                print("Port {}:                                                 Closed".format(port))
            sock.close()
    except KeyboardInterrupt:
        print("Exit.")
        sys.exit()
    except socket.gaierror:
        print('Hostname could not be resolved.')
        sys.exit()
    except socket.error:
        print("Couldn't connect to server. Socket error.")
        sys.exit()
    print("")
    print("")
    print(openports)
    print("\n\n")
    print("Press any key to proceed to the vulnerability report.")
    i = input()
    if i == "":
        clear()
        vulnreport()
    else:
        clear()
        vulnreport()

def vulnreport():
    if 8 in openports:
        vulns.append("Ping of Death (DDoS)")
    if 11 in openports:
        vulns.append("Unix TCP Process Check")
    if 21 in openports:
        vulns.append("THC-Hydra FTP Bruteforce")
        vulns.append("ftp_login (Metasploit)")
        vulns.append("ftp/anonymous (Metasploit)")
        vulns.append("ftp_version (Metasploit)")
        vulns.append("nmap ftp-brute")
    if 22 in openports:
        vulns.append("THC-Hydra SSH Bruteforce")
        vulns.append("ssh_login (Metasploit)")
        vulns.append("ssh_version 'Banner Grabbing' (Metasploit)")
        vulns.append("Netcat Shell/Reverse Shell")
    if 23 in openports:
        vulns.append("THC-Hydra Telnet Bruteforce")
        vulns.append("Telnet-Based RAT")
        vulns.append("SSH MITM (dsniff sshmitm)")
        vulns.append("telnet_login (Metasploit)")
        vulns.append("telnet_version (Metasploit)")
        vulns.append("IP Spoofed Login")
    if 25 in openports:
        vulns.append("smtp_enum (Metasploit)")
        vulns.append("smtp_version (Metasploit)")
        vulns.append("Telnet E-mail Spoofing")
        vulns.append("Phishing")
        vulns.append("Spam")
        vulns.append("E-mail Attachment Virus")
    if 53 in openports:
        vulns.append("DDoS of DNS")
        vulns.append("DNS Bruteforce")
        vulns.append("DNS Zone Transfer (AXFR)")
    if 69 in openports:
        vulns.append("TFTP Worm")
        vulns.append("FPipe Port Redirect")
        vulns.append("Netcat Shell/Reverse Shell")
    if 80 in openports:
        vulns.append("Slowloris DDoS")
        vulns.append("Cross Site Scripting (XSS)")
        vulns.append("Session/Cookie Hijacking")
        vulns.append("W3af")
        vulns.append("Nikto")
        vulns.append("THC-Hydra HTTP Bruteforce")
    if 110 in openports:
        vulns.append("pop3_version (Metasploit)")
        vulns.append("pop3_login (Metasploit)")
        vulns.append("libcurl pop3 Buffer Overflow (PoC)")
    if 135 in openports:
        vulns.append("Get Hostname from NetBIOS (nbname (Metasploit))")
        vulns.append("WinXP/Server 2003 ms03_026_dcom (Metasploit)")
        vulns.append("SMB Vulnerabilities")
    if 443 in openports:
        vulns.append("THC-Hydra HTTPS Bruteforce")
        vulns.append("Heartbleed OpenSSL Error")
    if 445 in openports:
        vulns.append("EternalBlue SMB Vulnerability")
        vulns.append("SMB Based Exploits")
    else:
        print("")
    clear()
    print("\n\n")
    print("-" * 71)
    print("The specified target may be vulnerable to the following:")
    print("-" * 71)
    print("\n")
    print(vulns)
    print("\n\n")
    print("Press any key to return to the main menu.")
    i = input()
    if i == "":
        clear()
        mainmenu()
    else:
        clear()
        mainmenu()


def portscan():
    clear()
    print("\n\n")
    print("-" * 71)
    print("What type of scan would you like to run?")
    print("-" * 71)
    print("")
    print("1. Quick Scan")
    print("2. Full Scan")
    print("")
    print("Please type the corresponding number and press enter.")
    print("\n")
    print("")
    promptfor = input()
    if promptfor == "1":
        portquickscanaskforhost()
    elif promptfor == "2":
        portfullscanaskforhost()


def portquickscanaskforhost():
    clear()
    print("\n")
    remoteServer = input("Enter a hostname or IP address to scan: \n\n")
    remoteServerIP = socket.gethostbyname(remoteServer.replace(" ", ""))
    clear()
    print("-" * 71)
    print("Please wait, ȺŘACĤŇE is beginning quick port scan >>>>>", remoteServerIP)
    print("-" * 71)
    print("")
    print("")
    try:
        for port in quickscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print("Port {}:                                                  Open ".format(port))
                openports.append(port)
            else:
                print("Port {}:                                                 Closed".format(port))
            sock.close()
    except KeyboardInterrupt:
        print("Exit.")
        sys.exit()
    except socket.gaierror:
        print('Hostname could not be resolved.')
        sys.exit()
    except socket.error:
        print("Couldn't connect to server. Socket error.")
        sys.exit()
    print("")
    portreport()
    #    vulnreport()
    mainmenu()


def portfullscanaskforhost():
    clear()
    print("\n")
    remoteServer = input("Enter a remote host to scan: \n\n")
    remoteServerIP = socket.gethostbyname(remoteServer.replace(" ", ""))
    clear()
    print("-" * 71)
    print("Please wait, ȺŘACĤŇE is beginning full port scan >>>>>", remoteServerIP)
    print("-" * 71)
    print("")
    print("")
    try:
        for port in fullscan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print("Port {}:                                                  Open ".format(port))
                openports.append(port)
            else:
                print("Port {}:                                                 Closed".format(port))
            sock.close()
    except KeyboardInterrupt:
        print("Exit.")
        sys.exit()
    except socket.gaierror:
        print('Hostname could not be resolved.')
        sys.exit()
    except socket.error:
        print("Couldn't connect to server. Socket error.")
        sys.exit()
    print("")
    print("")
    portreport()
    #    vulnreport()
    mainmenu()

def portreport():
    print("\n\n")
    print("-" * 71)
    print("The specified target has the following ports open:")
    print("-" * 71)
    print("\n")
    print(openports)
    print("\n\n")
    print("Press any key to return to the main menu.")
    i = input()
    if i == "":
        clear()
        mainmenu()
    else:
        clear()
        mainmenu()

mainmenu()



