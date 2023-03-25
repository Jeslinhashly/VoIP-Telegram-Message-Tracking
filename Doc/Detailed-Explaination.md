# VoIP Forensics Tool

This is a tool for performing VoIP forensics on PCAP files. It can analyze packet captures, generate reports, and visualize data.

## Requirements

* Python 3
* tshark
* Wireshark

## Installation

1. Clone the repository
2. Install the required Python packages: `pip install -r requirements.txt`
3. Install Wireshark and tshark
4. Run the application: `python main.py`

## Usage

### Home Screen

The home screen displays three buttons:

* Analyze PCAP file: Allows you to select a PCAP file and start the analysis process.
* View Reports: Allows you to view previously generated reports.
* Exit: Exits the application.

### Analyze PCAP File

On this screen, you can select a PCAP file and specify a case ID. After selecting the file and entering the case ID, click the "Generate report" button to begin the analysis.

### View Reports

This screen displays a list of all previously generated reports. You can select a report and click the "View" button to view the report.

### Report Types

The following report types are available:

* TCP/UDP report: Displays the number of TCP and UDP packets in the capture file.
* VoIP Packet Composition report: Displays the composition of VoIP packets in the capture file.
* SIP packet data report: Displays information about each SIP packet in the capture file.
* Duration of the call report: Calculates the duration of each call in the capture file.

### Report Generation

After selecting the report types you want to generate, click the "Generate report" button. The tool will generate the selected reports and save them as PDF files in the `cache_files` directory. If multiple reports are generated, they will be merged into a single PDF file.

