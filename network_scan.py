#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Your Python code goes here
import socket
import nmap

# Enter the IP address you want to scan
ip_address = "192.168.1.1"

# Create a TCP socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set a timeout for the socket
sock.settimeout(2)

# Define a function to check if a port is open
def is_port_open(port):
    result = sock.connect_ex((ip_address, port))
    if result == 0:
        return True
    else:
        return False

# Define a function to scan for vulnerabilities using nmap
def scan_vulnerabilities():
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-sV')
    return scanner[ip_address]['tcp']

# Define a function to perform fingerprinting and OS detection using nmap
def scan_fingerprint():
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-O')
    return scanner[ip_address]['osmatch']

# Define a list of ports to scan
ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 
3389, 5432, 8080]

# Iterate through the list of ports and check if they are open
for port in ports:
    if is_port_open(port):
        print(f"Port {port} is open")

# Scan for vulnerabilities and print the results
vulnerabilities = scan_vulnerabilities()
for port, data in vulnerabilities.items():
    print(f"Port {port} is vulnerable to {data['name']} ({data['version']})")


# Perform fingerprinting and OS detection and print the results
fingerprint = scan_fingerprint()
for os in fingerprint:
    print(f"OS detected: {os['name']} ({os['accuracy']}%)")
for osclass in fingerprint[0]['osclass']:
    print(f"Classification: {osclass['type']} ({osclass['vendor']})")

