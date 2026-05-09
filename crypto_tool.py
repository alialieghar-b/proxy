#!/usr/bin/env python3
"""AES‑GCM encryption/decryption tool, key from ENCRYPTION_KEY env (hex)."""
import sys
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def main():
    key_hex = os.environ["ENCRYPTION_KEY"]
    key = bytes.fromhex(key_hex)
    aead = AESGCM(key)

    if len(sys.argv) != 2 or sys.argv[1] not in ("encrypt", "decrypt"):
        print("Usage: crypto_tool.py encrypt|decrypt", file=sys.stderr)
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "encrypt":
        data = sys.stdin.buffer.read()
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, data, None)
        sys.stdout.write(base64.b64encode(nonce + ct).decode())
    else:  # decrypt
        b64_in = sys.stdin.read().strip()
        raw = base64.b64decode(b64_in)
        nonce, ct = raw[:12], raw[12:]
        plain = aead.decrypt(nonce, ct, None)
        sys.stdout.buffer.write(plain)

if __name__ == "__main__":
    main()
