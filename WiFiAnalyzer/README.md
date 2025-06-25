# WiFiAnalyzer

**WiFiAnalyzer** is a modern, user-friendly tool for scanning, analyzing, and connecting to Wi-Fi networks on Windows.  
It displays detailed information about nearby networks, highlights security status, and allows you to connect or disconnect with ease.

---

## Features Summary

| Feature                | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| Wi-Fi Scanning         | Lists all nearby Wi-Fi networks with SSID, signal, channel, band, and BSSID |
| Security Analysis      | Clearly marks networks as SAFE or NOT SAFE based on encryption              |
| Connect/Disconnect     | Connect to or disconnect from any listed network directly from the GUI       |
| Password Prompt        | Secure dialog for entering Wi-Fi passwords                                  |
| Current Status Display | Shows your current Wi-Fi connection                                         |
| Modern GUI             | Clean, accessible design with clear fonts and responsive controls            |
| Error Handling         | User-friendly error messages and status updates                             |

---

## How to Use

### 1. Prerequisites

- **Windows OS** (uses `netsh` command)
- **Python 3.7+** installed

### 2. Running with Python

1. Open a terminal in the `WiFiAnalyzer` directory.
2. Run:
    ```sh
    python WifiAnalyzer.py
    ```
3. In the GUI:
    - Click **Scan Wi-Fi** to list available networks.
    - Click a network in the list to select it.
    - Click **Connect** to join (enter password if required).
    - Click **Disconnect** to leave the current network.
    - View your current connection at the top of the window.

> **Note:**  
> - You may need to run as administrator for some Wi-Fi operations.
> - This tool is designed for educational and diagnostic use on Windows.

---

### 3. Running with IntelliJ IDEA

If you prefer to use IntelliJ IDEA (with the Python plugin):

1. **Open IntelliJ IDEA** and select **Open**.
2. Navigate to your `WiFiAnalyzer` folder and open it as a project.
3. Make sure the Python plugin is installed and a Python interpreter is configured.
4. In the Project view, right-click `WifiAnalyzer.py` and select **Run 'WifiAnalyzer'**.
5. The GUI will appear. Use it as described above.

---

## Example Use Case

Suppose you want to check the security of nearby Wi-Fi networks and connect to the safest one.  
Start WiFiAnalyzer, click **Scan Wi-Fi**, review the list, select a network marked as **SAFE**, and click **Connect**.  
Enter the password if prompted. Your connection status will update at the top.

---

## Disclaimer

For educational and authorized testing only.  
Do not use on networks you do not own or have permission to access.

---
