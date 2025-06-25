# ARP Device Scanner

A minimalistic Python/Tkinter tool to scan your local network for connected devices using ARP requests. It displays each device's IP address, MAC address, and vendor information in a clean, easy-to-read GUI.

---

## What does it do?

- **Scans your local subnet** for active devices using ARP (Address Resolution Protocol).
- **Displays**:  
  - IP address  
  - MAC address  
  - Vendor/manufacturer (e.g., Apple, Samsung, Intel)
- **Shows results in a minimalist, centered GUI** for easy viewing.

---

## How does it work?

- The app automatically detects your local subnet (e.g., `192.168.1.1/24`).
- When you click "Scan Network", it sends ARP requests to all IPs in the subnet.
- Devices that respond are listed with their IP, MAC, and vendor (using the `mac-vendor-lookup` package).
- The results are formatted in columns for clarity.

---

## Main Functions

- **get_local_ip()**  
  Detects your computer's local IP address for subnet calculation.

- **scan(ip_range)**  
  Sends ARP requests to the specified IP range and collects responses.

- **start_scan()**  
  Handles the scan button click: clears the text area, runs the scan, looks up vendors, and displays results in aligned columns.

---

## How to use

1. **Requirements**
   - Python 3.7+
   - [Scapy](https://scapy.net/) (`pip install scapy`)
   - [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/) (`pip install mac-vendor-lookup`)
   - Tkinter (usually included with Python)

2. **Run the app**
   - Open a terminal as Administrator (for best results on Windows).
   - Run:
     ```
     python Main.py
     ```
   - Click the **"Scan Network"** button to see all devices on your local subnet.

---

## Notes

- Only scans your local network (LAN).
- Results depend on devices responding to ARP (some may not respond if firewalled).
- Vendor info is based on MAC address and may not always indicate exact device type.
- For educational and personal use only.

---

## License

For educational and personal use only.
