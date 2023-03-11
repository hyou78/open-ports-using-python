# open-ports-using-python
#this tool is used to find the open ports of the network using python 
import argparse
import nmap
from openvas_lib import VulnscanManager, VulnscanException
import xml.etree.ElementTree as ET

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sV')
    devices = {}
    for host in nm.all_hosts():
        os = nm[host]['osmatch'][0]['name'] if len(nm[host]['osmatch']) > 0 else 'Unknown'
        vendor = nm[host]['vendor'][0] if len(nm[host]['vendor']) > 0 else 'Unknown'
        devices[host] = {'os': os, 'vendor': vendor, 'ports': []}
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                service = nm[host]['tcp'][port]['name']
                devices[host]['ports'].append({'port': port, 'service': service})
    return devices

def scan_vulnerabilities(ip_address, username, password):
    try:
        manager = VulnscanManager(ip_address, username=username, password=password)
        manager.launch_scanner()
        report_id = manager.start_scan()
        report = manager.get_report(report_id)
        vulnerabilities = []
        root = ET.fromstring(report)
        for child in root.findall('.//result'):
            if child.findtext('severity') == 'High':
                vulnerability = {
                    'name': child.findtext('name'),
                    'description': child.findtext('description'),
                    'solution': child.findtext('solution')
                }
                vulnerabilities.append(vulnerability)
        return vulnerabilities
    except VulnscanException as e:
        print(e.msg)

def main():
    parser = argparse.ArgumentParser(description='Scan for open ports and vulnerabilities')
    parser.add_argument('ip_address', type=str, help='IP address or range to scan')
    parser.add_argument('-u', '--username', type=str, default='admin', help='Username for OpenVAS scanner (default: admin)')
    parser.add_argument('-p', '--password', type=str, default='password', help='Password for OpenVAS scanner (default: password)')
    args = parser.parse_args()

    devices = scan_ports(args.ip_address)
    for host, device in devices.items():
        print('IP address:', host)
        print('OS:', device['os'])
        print('Vendor:', device['vendor'])
        print('Open ports:')
        for port_info in device['ports']:
            print('- Port:', port_info['port'], 'Service:', port_info['service'])
        vulnerabilities = scan_vulnerabilities(host, args.username, args.password)
        print('Vulnerabilities:', vulnerabilities)
        print('---------------------------------------')

if __name__ == '__main__':
    main()
