import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, TCP, IP, get_if_list
import threading

BG_COLOR = "#f4f6fb"
HEADER_COLOR = "#1976d2"
FG_COLOR = "#222"
BTN_COLOR = "#1976d2"
BTN_TEXT = "#fff"
ENTRY_BG = "#fff"
ENTRY_FG = "#222"
FONT = ("Segoe UI", 11)
HEADER_FONT = ("Segoe UI", 18, "bold")

class ChatSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ChatSniffer - Network Message Analyzer")
        self.root.configure(bg=BG_COLOR)
        self.running = False

        # Header
        header = tk.Label(
            root, text="ChatSniffer - Network Message Analyzer",
            bg=BG_COLOR, fg=HEADER_COLOR, font=HEADER_FONT, pady=10
        )
        header.pack(fill=tk.X, padx=20, pady=(10, 0))

        # Frame for controls
        controls = tk.Frame(root, bg=BG_COLOR)
        controls.pack(fill=tk.X, padx=20, pady=10)

        # Interface selection
        tk.Label(controls, text="Network Interface:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(controls, textvariable=self.iface_var, font=FONT, width=30, state="readonly")
        self.iface_combo['values'] = get_if_list()
        self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(0, 20))

        # Port entry
        tk.Label(controls, text="Port:", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=2, sticky="w")
        self.port_entry = tk.Entry(controls, width=8, font=FONT, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG, relief=tk.GROOVE)
        self.port_entry.grid(row=0, column=3, padx=(0, 20))
        self.port_entry.insert(0, "12345")

        # Start/Stop button
        self.start_btn = tk.Button(
            controls, text="Start Sniffing", bg=BTN_COLOR, fg=BTN_TEXT, font=FONT,
            activebackground="#1565c0", activeforeground=BTN_TEXT, command=self.toggle_sniffing,
            relief=tk.FLAT, padx=16, pady=4, cursor="hand2"
        )
        self.start_btn.grid(row=0, column=4)

        # Treeview for results
        columns = ("ip", "port", "message")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=16)
        self.tree.heading("ip", text="Source IP")
        self.tree.heading("port", text="Port")
        self.tree.heading("message", text="Message")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("port", width=80, anchor="center")
        self.tree.column("message", width=500, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#fff", fieldbackground="#fff", foreground=FG_COLOR, rowheight=26, font=FONT)
        style.configure("Treeview.Heading", background=HEADER_COLOR, foreground="#fff", font=("Segoe UI", 11, "bold"))
        style.map("Treeview", background=[("selected", "#e3f2fd")], foreground=[("selected", "#1976d2")])

    def toggle_sniffing(self):
        if not self.running:
            try:
                port = int(self.port_entry.get())
                if port < 1 or port > 65535:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid Port", "Please enter a valid TCP port number (1-65535).")
                return
            iface = self.iface_var.get()
            if not iface:
                messagebox.showerror("No Interface", "Please select a network interface.")
                return
            self.running = True
            self.start_btn.config(text="Stop Sniffing")
            threading.Thread(target=self.sniff_packets, args=(port, iface), daemon=True).start()
        else:
            self.running = False
            self.start_btn.config(text="Start Sniffing")

    def sniff_packets(self, port, iface):
        def process_packet(pkt):
            if not self.running:
                return False  # Stop sniffing
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp = pkt[TCP]
                ip = pkt[IP]
                if tcp.dport == port or tcp.sport == port:
                    payload = bytes(tcp.payload)
                    try:
                        message = payload.decode("utf-8", errors="ignore").strip()
                        if message:
                            self.tree.insert("", "end", values=(ip.src, tcp.sport, message))
                    except Exception:
                        pass
        sniff(filter=f"tcp port {port}", prn=process_packet, store=0, stop_filter=lambda x: not self.running, iface=iface)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatSnifferApp(root)
    root.mainloop()
