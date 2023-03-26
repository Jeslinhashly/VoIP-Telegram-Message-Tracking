# VoIP-Message-Tracking

## Network Shark

The VoIP Telegram-Message-Tracking is a software application that allows users to extract relevant information from VoIP packets between two end devices and decode the relevant data. The packets can be used to extract useful information like the IP addresses of the clients, the VoIP server, their location, their ISP details, time and date of communication, and duration of communication.

## Getting Started

1. Clone the repository: `git clone https://github.com/jeslinhashly/voip-Message-Tracking.git`
2. Install the required Python packages: `pip3 install -r requirements.txt`
3. Run the tool: `python3 voip_packet_analysis_tool.py`
### Features

The software dynamically analyzes the packets using modules like pyshark after we upload the packet to it. An interface will be provided where users can upload a VoIP packet with the case number. This capture would be analyzed by using the python modules (pyshark) for deeper analysis. The analyzed data would be presented in a report format either graphically or analytically readable. Also, the analyzed data can be downloaded in a pdf format that embeds picharts.

### Usage

To use the VoIP Packet Analysis Tool, follow these steps:

- Upload a VoIP packet with the case number via the interface provided.
- The software will analyze the packet using pyshark modules and extract relevant information.
- The analyzed data will be presented in a report format that is either graphically or analytically readable.
- The analyzed data can be downloaded in a PDF format that embeds picharts.

### Report Generation Pages

- TCP/UDP Report
- VoIP Packet Composition Report
- SIP/RTP Packet Data Report
- Duration of the Call Report
- 




## Supported Platforms

This tool has been tested on Windows, macOS, and Linux. However, it should work on any platform that supports Python 3 and the required Python packages.

## Dependencies

- tkinter
- customtkinter
- PyPDF2
- pyshark
- matplotlib
- numpy
- fpdf
- pydub
- speech_recognition
- os
- PIL

## Acknowledgments

- [PyShark](https://github.com/KimiNewt/pyshark) - a wrapper for the Wireshark CLI interface, used to parse PCAP files.
- [matplotlib](https://github.com/matplotlib/matplotlib) - a plotting library used to generate charts for the VoIP Packet Composition Report.
- [FPDF](https://pyfpdf.readthedocs.io/en/latest/) - a library used to generate PDF reports.
- [PyPDF2](https://pythonhosted.org/PyPDF2/) - a library used to merge PDF reports.


### Conclusion
The VoIP Telegram-Message-Tracking is a powerful software application that allows users to extract relevant information from VoIP packets between two end devices. With its dynamic analysis and reporting features, users can gain insights into the IP addresses of the clients, the VoIP server, their location, their ISP details, time and date of communication, and duration of communication. If you are looking for a tool to help you analyze VoIP packets, the VoIP Packet Analysis Tool is an excellent choice.

<iframe width="560" height="315" src="https://www.youtube.com/embed/VIDEO_ID" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

