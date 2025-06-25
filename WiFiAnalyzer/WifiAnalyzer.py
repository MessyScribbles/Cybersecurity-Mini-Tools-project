import subprocess
import tkinter as tk
from tkinter import simpledialog
import threading
import time

def get_current_wifi():
    try:
        output = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'interfaces'],
            shell=True, encoding='utf-8', errors='replace'
        )
        for line in output.splitlines():
            if "SSID" in line and "BSSID" not in line:
                ssid = line.split(":", 1)[1].strip()
                if ssid:
                    return ssid
        return "Not connected"
    except Exception:
        return "Unknown"

class CustomPasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, title, ssid):
        self.ssid = ssid
        self.password = None
        super().__init__(parent, title)

    def body(self, master):
        master.configure(bg="white")
        tk.Label(master, text=f"Enter password for '{self.ssid}':", font=("Segoe UI", 12, "bold"), bg="white", fg="#222").pack(padx=10, pady=(10, 5))
        self.entry = tk.Entry(master, show="*", font=("Segoe UI", 12), bg="white", fg="#222", borderwidth=0, highlightthickness=1, relief=tk.FLAT, width=30)
        self.entry.pack(padx=10, pady=(0, 10))
        self.entry.focus()
        return self.entry

    def apply(self):
        self.password = self.entry.get()

def show_centered_message(msg, color="#222"):
    for widget in center_message_frame.winfo_children():
        widget.destroy()
    label = tk.Label(center_message_frame, text=msg, font=("Segoe UI", 15, "bold"), fg=color, bg="white")
    label.pack(expand=True, padx=30, pady=20)
    center_message_frame.lift()
    center_message_frame.place(relx=0.5, rely=0.5, anchor="center")
    root.after(2000, lambda: center_message_frame.place_forget())

def scan_wifi():
    threading.Thread(target=scan_wifi_thread, daemon=True).start()

def scan_wifi_thread():
    global networks, selected_network_idx, loading
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END)
    status_label.config(text="Scanning for Wi-Fi networks...")
    loading = True
    animate_loading()
    try:
        output = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            shell=True, encoding='utf-8', errors='replace'
        )
        networks = parse_networks(output)
        text_area.delete(1.0, tk.END)
        if not networks:
            text_area.insert(tk.END, "No networks found.\n")
        # Wider header for better spacing
        header = f"{'No.':<5}{'SSID':<32}{'Signal':<10}{'Channel':<10}{'Band':<10}{'BSSID':<22}{'Status':<12}\n"
        text_area.insert(tk.END, header, "header")
        text_area.insert(tk.END, "-" * 110 + "\n", "header")
        for idx, net in enumerate(networks):
            ssid = net['ssid']
            signal = net.get('signal', '')
            channel = net.get('channel', '')
            band = net.get('band', '')
            bssid = net.get('bssid', '')
            if "Open" in net['security'] or "WEP" in net['security']:
                level = "NOT SAFE"
                tag = "not_safe"
            else:
                level = "SAFE"
                tag = "safe"
            # Insert each column, align and color only status
            text_area.insert(tk.END, f"{idx+1:<5}", "ssid_dark")
            text_area.insert(tk.END, f"{ssid:<32}", "ssid_dark")
            text_area.insert(tk.END, f"{signal:<10}", "ssid_dark")
            text_area.insert(tk.END, f"{channel:<10}", "ssid_dark")
            text_area.insert(tk.END, f"{band:<10}", "ssid_dark")
            text_area.insert(tk.END, f"{bssid:<22}", "ssid_dark")
            text_area.insert(tk.END, f"{level:<12}\n", tag)
        text_area.tag_configure("header", font=("Segoe UI", 12, "bold"), foreground="#0078D7", justify="center")
        text_area.tag_configure("ssid_dark", foreground="#222", font=("Segoe UI", 12), justify="center")
        text_area.tag_configure("safe", foreground="#27ae60", font=("Segoe UI", 12, "bold"), justify="center")
        text_area.tag_configure("not_safe", foreground="#e74c3c", font=("Segoe UI", 12, "bold"), justify="center")
        text_area.tag_configure("center", justify="center")
        text_area.tag_add("center", "1.0", tk.END)
        status_label.config(text=f"Found {len(networks)} networks. Click a network to select, then Connect.")
    except Exception as e:
        text_area.delete(1.0, tk.END)
        text_area.insert(tk.END, f"Error: {e}\n")
        status_label.config(text=f"Error: {e}")
    text_area.config(state=tk.DISABLED)
    selected_network_idx = None
    loading = False

def animate_loading():
    def animate():
        dots = 0
        while loading:
            status_label.config(text="Scanning for Wi-Fi networks" + "." * (dots % 4))
            dots += 1
            time.sleep(0.4)
    threading.Thread(target=animate, daemon=True).start()

def parse_networks(output):
    networks = []
    lines = output.splitlines()
    ssid, security, signal, channel, band, bssid = "", "", "", "", "", ""
    for i, line in enumerate(lines):
        if "SSID " in line and ":" in line and "BSSID" not in line:
            if ssid:  # Save previous
                networks.append({
                    'ssid': ssid, 'security': security, 'signal': signal,
                    'channel': channel, 'band': band, 'bssid': bssid
                })
            ssid = line.split(":", 1)[1].strip()
            security = signal = channel = band = bssid = ""
        elif "Authentication" in line:
            security = line.split(":", 1)[1].strip()
        elif "Signal" in line:
            signal = line.split(":", 1)[1].strip()
        elif "Channel" in line:
            channel = line.split(":", 1)[1].strip()
            try:
                ch = int(channel)
                band = "5GHz" if ch > 14 else "2.4GHz"
            except:
                band = ""
        elif "BSSID 1" in line:
            bssid = line.split(":", 1)[1].strip()
    # Add last network
    if ssid:
        networks.append({
            'ssid': ssid, 'security': security, 'signal': signal,
            'channel': channel, 'band': band, 'bssid': bssid
        })
    return networks

def on_text_click(event):
    global selected_network_idx
    index = text_area.index(f"@{event.x},{event.y}")
    line = int(index.split('.')[0]) - 3  # Adjust for header (2 lines)
    if 0 <= line < len(networks):
        selected_network_idx = line
        # Highlight the selected line
        text_area.config(state=tk.NORMAL)
        text_area.tag_remove("selected", "1.0", tk.END)
        text_area.tag_add("selected", f"{line+3}.0", f"{line+4}.0")
        text_area.tag_configure("selected", background="#0078D7", foreground="white")
        text_area.config(state=tk.DISABLED)

def connect_wifi():
    if selected_network_idx is None or selected_network_idx >= len(networks):
        show_centered_message("Please click a network in the list to select it.", "#e67e22")
        return
    ssid = networks[selected_network_idx]['ssid']
    security = networks[selected_network_idx]['security']
    if "Open" in security:
        password = None
    else:
        dialog = CustomPasswordDialog(root, "Wi-Fi Password", ssid)
        password = dialog.password
        if not password:
            show_centered_message("No password entered.", "#e74c3c")
            return
    connect_to_network(ssid, password)

def connect_to_network(ssid, password):
    profile = f"""
    <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <name>{ssid}</name>
        <SSIDConfig>
            <SSID>
                <name>{ssid}</name>
            </SSID>
        </SSIDConfig>
        <connectionType>ESS</connectionType>
        <connectionMode>auto</connectionMode>
        <MSM>
            <security>
                <authEncryption>
                    <authentication>{'open' if not password else 'WPA2PSK'}</authentication>
                    <encryption>{'none' if not password else 'AES'}</encryption>
                    <useOneX>false</useOneX>
                </authEncryption>
                {"<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>" + password + "</keyMaterial></sharedKey>" if password else ""}
            </security>
        </MSM>
    </WLANProfile>
    """
    with open("wifi_profile.xml", "w") as f:
        f.write(profile)
    try:
        subprocess.check_call(f'netsh wlan add profile filename="wifi_profile.xml"', shell=True)
        subprocess.check_call(f'netsh wlan connect name="{ssid}"', shell=True)
        show_centered_message(f"Attempted to connect to '{ssid}'.\nCheck your Wi-Fi icon for status.", "#27ae60")
        update_connected_label()
    except Exception as e:
        show_centered_message(f"Could not connect: {e}", "#e74c3c")

def disconnect_wifi():
    try:
        subprocess.check_call('netsh wlan disconnect', shell=True)
        show_centered_message("You have been disconnected from Wi-Fi.", "#e74c3c")
        update_connected_label()
    except Exception as e:
        show_centered_message(f"Could not disconnect: {e}", "#e74c3c")

def update_connected_label():
    current_ssid = get_current_wifi()
    connected_label.config(text=f"Currently connected: {current_ssid}")

# Tkinter UI
root = tk.Tk()
root.title("Wi-Fi Security Analyzer")
root.geometry("900x700")
root.resizable(False, False)
root.configure(bg="white")

frame = tk.Frame(root, bg="white")
frame.pack(expand=True, fill=tk.BOTH)

connected_label = tk.Label(
    frame,
    text=f"Currently connected: {get_current_wifi()}",
    bg="white",
    fg="#0078D7",
    font=("Segoe UI", 14, "bold")
)
connected_label.pack(pady=(18, 5))

status_label = tk.Label(
    frame,
    text="Click 'Scan Wi-Fi' to begin.",
    bg="white",
    fg="gray",
    font=("Segoe UI", 12)
)
status_label.pack(pady=(0, 10))

scan_button = tk.Button(
    frame,
    text="Scan Wi-Fi",
    command=scan_wifi,
    bg="#222",
    fg="white",
    font=("Segoe UI", 12, "bold"),
    relief=tk.FLAT,
    padx=20,
    pady=5,
    cursor="hand2"
)
scan_button.pack(pady=(0, 10))

text_area = tk.Text(
    frame,
    font=("Segoe UI", 12),
    width=110,
    height=18,
    bg="white",
    fg="#222",
    borderwidth=0,
    highlightthickness=1,
    relief=tk.FLAT,
    state=tk.NORMAL
)
text_area.pack(padx=20, pady=10)
text_area.config(state=tk.DISABLED)
text_area.bind("<Button-1>", on_text_click)

button_frame = tk.Frame(frame, bg="white")
button_frame.pack(pady=(0, 20))

connect_button = tk.Button(
    button_frame,
    text="Connect",
    command=connect_wifi,
    bg="#27ae60",  # Green
    fg="white",
    font=("Segoe UI", 12, "bold"),
    relief=tk.FLAT,
    padx=20,
    pady=5,
    cursor="hand2"
)
connect_button.pack(side=tk.LEFT, padx=10)

disconnect_button = tk.Button(
    button_frame,
    text="Disconnect",
    command=disconnect_wifi,
    bg="#e74c3c",  # Red
    fg="white",
    font=("Segoe UI", 12, "bold"),
    relief=tk.FLAT,
    padx=20,
    pady=5,
    cursor="hand2"
)
disconnect_button.pack(side=tk.LEFT, padx=10)

# Centered message frame for connection/disconnection replies
center_message_frame = tk.Frame(root, bg="white")
center_message_frame.place_forget()

networks = []
selected_network_idx = None
loading = False

root.mainloop()