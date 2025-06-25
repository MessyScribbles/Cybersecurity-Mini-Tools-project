# File Shredder

A minimalistic, GUI-based tool for securely deleting files by overwriting their contents multiple times before removal. Built with Python and Tkinter, this utility is designed for users who want a simple, effective way to ensure sensitive files are permanently destroyed.

---

## Summary

- **Securely overwrites files** with random data for a user-specified number of passes (default: 3, configurable 1–10).
- **Deletes the file** after overwriting, making recovery extremely difficult.
- **Simple, modern GUI** for easy file selection and operation.
- **Irreversible process**: Once shredded, files cannot be recovered.

---

## Features

- Select any file via a file dialog.
- Choose the number of overwrite passes (1–10).
- One-click shredding with clear success/error messages.
- Modern, dark-themed interface.

---

## How it Works

1. **File Selection**: Use the "Browse" button to pick a file.
2. **Set Passes**: Enter the number of overwrite passes (default is 3).
3. **Shred**: Click "Shred File" to securely overwrite and delete the file.
4. **Confirmation**: Success or error messages are shown after the operation.

The core logic is implemented in the [`shred_file`](FileShredder/main.py) function in [FileShredder/main.py](FileShredder/main.py).

---

## Requirements

- Python 3.7+
- Tkinter (usually included with Python)

---

## Usage

1. Run the script:
    ```sh
    python main.py
    ```
2. Use the GUI to select a file and shred it.

---

## Disclaimer

- This tool is for educational and personal use only.
- Shredded files **cannot be recovered**. Use with caution!

---
