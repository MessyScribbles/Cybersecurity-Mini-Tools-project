# ChatSniffer

**ChatSniffer** is a professional-grade TCP chat message analyzer with a modern, user-friendly interface.  
It allows you to select a network interface and port, then capture and display plain-text TCP chat messages in real time.  
Ideal for network analysis, educational purposes, and debugging simple chat applications.

---

## Features Summary

| Feature                   | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| Network Interface Select  | Choose which network device (adapter) to monitor                            |
| Port Filtering            | Only capture messages on the specified TCP port                             |
| Live Message Display      | See source IP, port, and message content as they're sent                    |
| Modern GUI                | Clean, accessible design with clear fonts and responsive controls           |
| Start/Stop Control        | Easily start or stop packet sniffing with a single button                   |
| Error Handling            | User-friendly error messages for invalid input or missing selections        |

---

## How to Use

### 1. Prerequisites

- **Python 3.7+** installed
- **Scapy** library installed:
    ```sh
    pip install scapy
    ```

### 2. Running with Python

1. Open a terminal in the `ChatSniffer` directory.
2. Run:
    ```sh
    python ChatSniffer.py
    ```
3. In the GUI:
    - Select your network interface from the dropdown.
    - Enter the TCP port used by your chat application (e.g., `12345`).
    - Click **Start Sniffing** to begin capturing messages.
    - Click **Stop Sniffing** to end the capture.

> **Note:**  
> - You may need to run as administrator for packet sniffing.
> - This tool works best with plain-text TCP chat protocols (e.g., simple Java chat apps).

---

### 3. Running with IntelliJ IDEA

If you prefer to use IntelliJ IDEA (with the Python plugin):

1. **Open IntelliJ IDEA** and select **Open**.
2. Navigate to your `ChatSniffer` folder and open it as a project.
3. Make sure the Python plugin is installed and a Python interpreter is configured.
4. In the Project view, right-click `ChatSniffer.py` and select **Run 'ChatSniffer'**.
5. The GUI will appear. Use it as described above.

---

## Example Use Case

Suppose you have a Java-based TCP chat application running on port `12345`.  
Start ChatSniffer, select your active network interface, enter `12345` as the port, and click **Start Sniffing**.  
All plain-text messages sent between clients on that port will appear in the table, along with the sender's IP and port.

---

## Disclaimer

For educational and authorized testing only.  
Do not use on networks you do not own or have permission to monitor.

---
