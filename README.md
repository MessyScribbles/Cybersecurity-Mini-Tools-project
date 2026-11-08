# Cybersecurity Mini-Tools

A set of small, GUI-based security utilities for Windows, written in Python. Each tool covers one practical network or privacy task and runs from its own folder.

I built them as a student to practice what I learned in the Google Cybersecurity Foundations and CompTIA courses. They are learning projects, and feedback is welcome.

![Python](https://img.shields.io/badge/Python-3.7+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/Purpose-Educational-orange)

## Screenshots

<!-- Add one screenshot per tool in a screenshots/ folder, then uncomment: -->
<!-- ![ARP Device Scanner](screenshots/arp-scanner.png) -->
<!-- ![Chat Sniffer](screenshots/chat-sniffer.png) -->
<!-- ![File Shredder](screenshots/file-shredder.png) -->
<!-- ![WiFi Analyzer](screenshots/wifi-analyzer.png) -->

## Tools

| Tool | What it does |
| :--- | :--- |
| [ARP Device Scanner](#arp-device-scanner) | Finds devices on your local network |
| [Chat Sniffer](#chat-sniffer) | Displays chat messages sent over your local network |
| [File Shredder](#file-shredder) | Overwrites a file with random data, then deletes it |
| [WiFi Analyzer](#wifi-analyzer) | Lists nearby WiFi networks with signal and security details |

### ARP Device Scanner

Scans the local network with ARP requests and lists the devices that answer.

- Shows the IP and MAC address of each device
- Helps you spot unknown or unauthorized devices on your LAN

### Chat Sniffer

Captures and displays chat messages sent over the local network, for the protocols it supports.

- Shows captured chat traffic in a live view
- Intended for network analysis and learning how unencrypted traffic can be read

### File Shredder

Overwrites a file with random data several times, then deletes it.

- Choose 1 to 10 overwrite passes
- Removes the file after shredding

**Limitation:** overwriting is not a guaranteed wipe on SSDs, on drives with wear leveling, on journaling file systems, or on files synced to cloud storage or covered by backups and shadow copies. For sensitive data, use full-disk encryption or the drive's secure-erase feature.

### WiFi Analyzer

Scans nearby WiFi networks and compares them.

- Lists available networks
- Shows signal strength, channel and encryption type
- Displays graphs for easy comparison

## Requirements

- Windows
- Python 3.7 or newer
- Tkinter (included with the standard Python installer)
- Extra packages per tool: see the `requirements.txt` or the README inside each tool's folder

Some tools (network scanning and packet capture) may need to run from a terminal with administrator rights.

## Usage

1. Clone the repository and open the folder of the tool you want:
   ```bash
   git clone <repository-url>
   cd <repository-folder>/<tool-folder>
   ```
2. Install that tool's dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run it:
   ```bash
   python main.py
   ```
4. Follow the instructions in the window.

## Legal and ethical use

- These tools are for education and for testing systems you own or have written permission to test.
- Do not scan, capture traffic on, or analyze networks that you do not own or administer. Intercepting other people's communications is illegal in most countries.
- The author takes no responsibility for misuse.

## Roadmap

- [ ] Add a `requirements.txt` and short README to every tool folder
- [ ] Add screenshots for each tool
- [ ] Export scan results to CSV
- [ ] Add basic tests

## Author

GitHub:[https://github.com/MessyScribbles](url)

Feedback, issues and suggestions are welcome through GitHub issues.
