#config_decrypt.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import json

def decrypt_config(enc_path: str, key_path: str) -> dict:
    try:
        # Load AES key
        with open(key_path, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes (256 bits)")

        # Load encrypted config (IV + ciphertext)
        with open(enc_path, "rb") as f:
            blob = f.read()
        iv, ciphertext = blob[:16], blob[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        config = json.loads(decrypted)

        return config

    except Exception as e:
        print(f"[ERROR] Failed to decrypt config: {e}")
        return {}
