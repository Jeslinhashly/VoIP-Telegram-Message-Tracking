# VoIP Packet Analysis Tool

This tool allows users to analyze VoIP packets from a PCAP file and generate reports in PDF format. The tool supports the analysis of TCP/UDP packet data, VoIP packet composition, SIP packet data, and the duration of the call.

## Getting Started

1. Clone the repository: `git clone https://github.com/example/voip-packet-analysis-tool.git`
2. Install the required Python packages: `pip3 install -r requirements.txt`
3. Run the tool: `python3 voip_packet_analysis_tool.py`

## Usage

### Home Page

Upon launching the tool, users will be presented with the Home page where they can specify the case ID and location of the PCAP file to analyze. They can then navigate to the relevant report generation pages.

### Report Generation Pages

There are four report generation pages:
- TCP/UDP Report
- VoIP Packet Composition Report
- SIP Packet Data Report
- Duration of the Call Report

Users can select which reports they want to generate by checking the checkboxes at the bottom of the page. Once the desired checkboxes are selected, users can click on the "Generate Report" button to generate the reports.

## Supported Platforms

This tool has been tested on Windows, macOS, and Linux. However, it should work on any platform that supports Python 3 and the required Python packages.

## Dependencies

- Python 3
- PyShark
- matplotlib
- pandas
- reportlab
- FPDF
- PyPDF2
- tkinter

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [PyShark](https://github.com/KimiNewt/pyshark) - a wrapper for the Wireshark CLI interface, used to parse PCAP files.
- [matplotlib](https://github.com/matplotlib/matplotlib) - a plotting library used to generate charts for the VoIP Packet Composition Report.
- [pandas](https://github.com/pandas-dev/pandas) - a library used to parse and manipulate data for the TCP/UDP Report.
- [reportlab](https://www.reportlab.com/) - a library used to generate PDF reports.
- [FPDF](https://pyfpdf.readthedocs.io/en/latest/) - a library used to generate PDF reports.
- [PyPDF2](https://pythonhosted.org/PyPDF2/) - a library used to merge PDF reports.
