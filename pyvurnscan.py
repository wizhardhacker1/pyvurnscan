import os
import webbrowser
from typing import TypedDict

import nmap


# Define a typed dictionary for the Nmap scan info
class NmapScanInfo(TypedDict):
    xmloutputversion: str
    style: str


# Ask for user input
subnet = input("Enter the subnet you want to scan (e.g. 192.168.1.0/24): ")

# Create a new Nmap scanner object
scanner = nmap.PortScanner()

# Perform the vulnerability scan on the specified subnet
# result = scanner.scan(subnet, arguments="--script vuln")
result = scanner.scan(subnet, arguments="--script vuln,smb-vuln-*,ssl-*")
# result = scanner.scan(subnet, arguments="--script vuln,http-vuln-*,ftp-vuln-*,ssh-vuln-*,smtp-vuln-*,dns-vuln-*")

# Get the raw Nmap output in XML format
xml_output = scanner.get_nmap_last_output()

# Create the XML report file
xml_report_file = f"nmap_scan_{subnet.replace('/', '-')}.xml"

with open(xml_report_file, "w") as f:
    f.write(xml_output)

# Perform XSLT transformation to generate HTML report
xslt_stylesheet = "/usr/share/nmap/nmap.xsl"  # Replace with path to XSLT stylesheet on your system
html_report_file = f"nmap_scan_{subnet.replace('/', '-')}.html"
os.system(f"xsltproc -o {html_report_file} {xslt_stylesheet} {xml_report_file}")

# Open the HTML report with the default web browser
webbrowser.open(f"file://{os.path.abspath(html_report_file)}")

# Print the results of the scan
print(f"Scan results saved to {os.path.abspath(html_report_file)}")
for host in result["scan"]:
    print(f"Vulnerabilities found for {host}:")
    if "tcp" in result["scan"][host]:
        for vuln in result["scan"][host]["tcp"]:
            if "script" in result["scan"][host]["tcp"][vuln]:
                script_output = result["scan"][host]["tcp"][vuln]["script"]
                if script_output and "output" in script_output:
                    vulnerability_name = script_output["output"].split(":")[0]
                else:
                    vulnerability_name = "N/A"
                print(f"  {vulnerability_name}")
    else:
        print("  No open TCP ports found")
