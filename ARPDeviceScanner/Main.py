import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import socket
import tkinter as tk

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def scan(ip_range):
    arp = scapy.ARP(pdst=ip_range)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = scapy.srp(packet, timeout=2, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def start_scan():
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, f"Scanning {ip_range}...\n\n")
    devices = scan(ip_range)
    text_area.insert(tk.END, f"{'IP':<18}{'MAC Address':<22}Vendor\n")
    text_area.insert(tk.END, "-" * 60 + "\n")
    mac_lookup = MacLookup()
    for device in devices:
        try:
            vendor = mac_lookup.lookup(device['mac'])
        except Exception:
            vendor = "Unknown"
        text_area.insert(
            tk.END,
            f"{device['ip']:<18}{device['mac']:<22}{vendor}\n"
        )
    text_area.tag_configure("center", justify='center')
    text_area.tag_add("center", "1.0", "end")
    text_area.config(state=tk.DISABLED)

# Detect local subnet automatically
local_ip = get_local_ip()
ip_range = local_ip.rsplit('.', 1)[0] + '.1/24'

# Tkinter UI
root = tk.Tk()
root.title("ARP Device Scanner")
root.geometry("700x400")
root.resizable(False, False)
root.configure(bg="white")

center_frame = tk.Frame(root, bg="white")
center_frame.pack(expand=True)

status_label = tk.Label(center_frame, text=f"Detected subnet: {ip_range}", bg="white", fg="gray", font=("Consolas", 10))
status_label.pack(pady=(30, 10))

scan_button = tk.Button(center_frame, text="Scan Network", command=start_scan, bg="#222", fg="white", font=("Consolas", 12), relief=tk.FLAT, padx=20, pady=5, cursor="hand2")
scan_button.pack(pady=(0, 20))

text_area = tk.Text(center_frame, bg="white", fg="black", font=("Consolas", 10), borderwidth=0, highlightthickness=0, width=80, height=15)
text_area.pack(padx=10, pady=10)
text_area.config(state=tk.DISABLED)

root.mainloop()