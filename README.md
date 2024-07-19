# Python Network Port Scanner
## Overview
**Port-Scanner** is a user-friendly tool for scanning network ports to detect open, closed, and filtered ports. This tool is written in Python and utilizes Nmap for scanning, Tkinter for the user interface, and ReportLab for exporting reports in PDF format. This port scanner allows users to specify the IP address and port range to scan and export scan results in PDF format.

## Features
- **User-friendly Interface:** Easy for users to input parameters and interact with the application.
- **Port Detection:** Identifies open, closed, and filtered ports.
- **Customizable Scanning:** Users can specify the IP address and port range to scan.
- **Export Results:** Export scan results in PDF format.

## Instructions
### Installation

To install the required libraries, run the following commands:

```bash
Install libraries
pip install python-nmap
pip install reportlab

Run the script:
python port_scanner_nmap.py
```

### Demonstration

As a demonstration, we scanned all 65,535 ports of the IP address 192.168.0.184 in Kali Linux and provided the scan results.

<img src="https://github.com/user-attachments/assets/72681465-778d-44b4-a282-229407025be1" alt="Results" width="600"/>
<img src="https://github.com/user-attachments/assets/f618f1c8-464a-4dbc-b366-bb45031b1ae1" alt="Results" width="600"/>
<img src="https://github.com/user-attachments/assets/7357339c-46c5-4c6c-a22a-655b998deec3" alt="Results" width="600"/>
<img src="https://github.com/user-attachments/assets/ee41142e-630a-4ea8-9a8e-ca15db566c87" alt="Results" width="600"/>
<img src="https://github.com/user-attachments/assets/4061e3ec-94c3-4b76-be28-c578e8ba4577" alt="Results" width="600"/>
<img src="https://github.com/user-attachments/assets/bd95e75e-002f-4fb7-91ad-2340cfbbde0f" alt="Results" width="600"/>
<img src="https://github.com/user-attachments/assets/4aeb165d-ef54-4744-8673-75c11e315499" alt="Results" width="600"/></br>
</br>
In Scan Port Result, open port will be marked in yellow.
</br>
<img src="https://github.com/user-attachments/assets/acbf32a4-9c66-4f67-8fa5-0632b1133e40" alt="Results" width="600"/>
