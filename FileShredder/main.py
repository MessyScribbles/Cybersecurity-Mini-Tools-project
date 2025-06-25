import os
import tkinter as tk
from tkinter import filedialog, messagebox

BG_COLOR = "#181c20"
FG_COLOR = "#e0e6ed"
HEADER_COLOR = "#4fc3f7"
BTN_COLOR = "#23272e"
BTN_TEXT = "#e0e6ed"

def shred_file(path, passes=3):
    try:
        if not os.path.isfile(path):
            return False, "File does not exist."
        size = os.path.getsize(path)
        with open(path, "ba+", buffering=0) as f:
            for p in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
        os.remove(path)
        return True, "File shredded and deleted successfully."
    except Exception as e:
        return False, f"Error: {e}"

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def shred_action():
    path = file_entry.get()
    passes = passes_var.get()
    if not path:
        messagebox.showerror("Error", "Please select a file.")
        return
    try:
        passes = int(passes)
        if passes < 1 or passes > 10:
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "Passes must be a number between 1 and 10.")
        return
    ok, msg = shred_file(path, passes)
    if ok:
        messagebox.showinfo("Success", msg)
        file_entry.delete(0, tk.END)
    else:
        messagebox.showerror("Error", msg)

root = tk.Tk()
root.title("File Shredder")
root.geometry("600x250")
root.configure(bg=BG_COLOR)

frame = tk.Frame(root, bg=BG_COLOR)
frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

title_label = tk.Label(
    frame,
    text="Secure File Shredder",
    bg=BG_COLOR,
    fg=HEADER_COLOR,
    font=("Segoe UI", 16, "bold")
)
title_label.pack(pady=(0, 10))

desc_label = tk.Label(
    frame,
    text="Select a file to securely overwrite and delete. This process is irreversible.",
    bg=BG_COLOR,
    fg=FG_COLOR,
    font=("Segoe UI", 11)
)
desc_label.pack(pady=(0, 10))

file_frame = tk.Frame(frame, bg=BG_COLOR)
file_frame.pack(fill=tk.X, pady=(0, 10))

file_entry = tk.Entry(
    file_frame,
    font=("Segoe UI", 11),
    bg=BTN_COLOR,
    fg=FG_COLOR,
    width=40,
    borderwidth=0,
    highlightthickness=1,
    relief=tk.FLAT,
    insertbackground=FG_COLOR
)
file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

browse_btn = tk.Button(
    file_frame,
    text="Browse",
    command=select_file,
    bg=BTN_COLOR,
    fg=BTN_TEXT,
    font=("Segoe UI", 11, "bold"),
    relief=tk.FLAT,
    padx=10,
    pady=2,
    cursor="hand2"
)
browse_btn.pack(side=tk.LEFT)

passes_frame = tk.Frame(frame, bg=BG_COLOR)
passes_frame.pack(fill=tk.X, pady=(0, 10))

passes_label = tk.Label(
    passes_frame,
    text="Overwrite Passes (1-10):",
    bg=BG_COLOR,
    fg=FG_COLOR,
    font=("Segoe UI", 11)
)
passes_label.pack(side=tk.LEFT)

passes_var = tk.StringVar(value="3")
passes_entry = tk.Entry(
    passes_frame,
    textvariable=passes_var,
    font=("Segoe UI", 11),
    bg=BTN_COLOR,
    fg=FG_COLOR,
    width=5,
    borderwidth=0,
    highlightthickness=1,
    relief=tk.FLAT,
    insertbackground=FG_COLOR
)
passes_entry.pack(side=tk.LEFT, padx=(8, 0))

shred_btn = tk.Button(
    frame,
    text="Shred File",
    command=shred_action,
    bg="#e74c3c",
    fg=BTN_TEXT,
    font=("Segoe UI", 12, "bold"),
    relief=tk.FLAT,
    padx=20,
    pady=5,
    cursor="hand2",
    activebackground="#ff7b7b",
    activeforeground=BG_COLOR
)
shred_btn.pack(pady=(10, 0))

root.mainloop()