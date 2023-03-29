# VoIP-Message-Tracking

## Network Shark

The VoIP Telegram-Message-Tracking is a software application that allows users to extract relevant information from VoIP packets between two end devices and decode the relevant data. The packets can be used to extract useful information like the IP addresses of the clients, the VoIP server, their location, their ISP details, time and date of communication, and duration of communication.

## Demo video


[![Demo Video](https://img.youtube.com/vi/https://www.youtube.com/watch?v=iFQKB0MQ-dY/0.jpg)](https://youtu.be/M9Pn7CASCQw)




## Getting Started

1. Clone the repository: `git clone https://github.com/jeslinhashly/VOIP-Telegram-Message-Tracking.git`
2. Install the required Python packages: `pip3 install -r requirements.txt`
3. Run the tool: `python3 software.py`
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





## Supported Platforms

This tool has been tested on Windows, macOS, and Linux. However, it should work on any platform that supports Python 3 and the required Python packages.

## Dependencies

- secrets
- tkinter
- customtkinter
- PyPDF2
- pyshark
- matplotlib
- numpy
- fpdf
- os
- PIL
- tkintermapview
- Crypto
- base64
- ip2geotools
- geopy


## Acknowledgments

- [PyShark](https://pypi.org/project/pyshark/) - a wrapper for the Wireshark CLI interface, used to parse PCAP files.
- [matplotlib](https://matplotlib.org/) - a plotting library used to generate charts for the VoIP Packet Composition Report.
- [FPDF](https://pyfpdf.readthedocs.io/en/latest/) - a library used to generate PDF reports.
- [PyPDF2](https://pypi.org/project/PyPDF2/) - a library used to merge PDF reports.
- [Geopy](https://pypi.org/project/geopy/) - a Python client for several popular geocoding web services.
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - a  standard GUI library for Python.
- [Numpy](https://numpy.org/doc/stable/) - to perform a wide variety of mathematical operations on arrays


### Conclusion
The VoIP Telegram-Message-Tracking is a powerful software application that allows users to extract relevant information from VoIP packets between two end devices. With its dynamic analysis and reporting features, users can gain insights into the IP addresses of the clients, the VoIP server, their location, their ISP details, time and date of communication, and duration of communication. If you are looking for a tool to help you analyze VoIP packets, the VoIP Packet Analysis Tool is an excellent choice.

### Screen-Shots:
![Screenshot from 2023-03-29 00-19-51](https://user-images.githubusercontent.com/114294837/228341737-1f876a51-4afa-44a5-a095-d11ad91a7934.png)

![Screenshot from 2023-03-29 00-21-52](https://user-images.githubusercontent.com/114294837/228341821-7265c41a-5b1b-4d6b-ba8b-a11f0ae50dd8.png)

![Screenshot from 2023-03-29 00-26-16](https://user-images.githubusercontent.com/114294837/228341937-21891ec1-4826-4f05-bd0a-5de8009f3262.png)

![Screenshot from 2023-03-29 00-27-12](https://user-images.githubusercontent.com/114294837/228341959-aec73742-63ab-4e52-8743-41ad6b44696f.png)

![Screenshot from 2023-03-29 00-27-28](https://user-images.githubusercontent.com/114294837/228342052-f237b5fe-80cb-4c64-bb12-69931ddb4984.png)

![Screenshot from 2023-03-29 00-27-38](https://user-images.githubusercontent.com/114294837/228342072-d28ea93e-0593-4094-8369-9a30b10af5e0.png)
