#!/usr/bin/env python3
"""
wallet_generator_and_backup.py
Generates a BIP39 mnemonic, derives an Ethereum private key and address,
and writes an encrypted JSON backup (AES-GCM) protected by a password.

This is for legitimate use only: generate and back up *your own* keys.
"""

import os
import json
import getpass
import base64
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Helper functions ----
def derive_key_from_password(password: bytes, salt: bytes, length=32):
    # Use scrypt to derive a symmetric key from password
    kdf = Scrypt(salt=salt, length=length, n=2**14, r=8, p=1)
    return kdf.derive(password)

def encrypt_json(obj: dict, password: str) -> dict:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    salt = os.urandom(16)
    key = derive_key_from_password(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return {
        "version": 1,
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }

def decrypt_json(enc: dict, password: str) -> dict:
    salt = base64.b64decode(enc["salt"])
    nonce = base64.b64decode(enc["nonce"])
    ct = base64.b64decode(enc["ciphertext"])
    key = derive_key_from_password(password.encode("utf-8"), salt)
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ct, None)
    return json.loads(data.decode("utf-8"))

# ---- Main flow ----
def main():
    print("=== Wallet generator & encrypted backup (Ethereum) ===")
    # Generate mnemonic (12 words)
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
    print("\nIMPORTANT: This script will display a mnemonic. Anyone who sees it can control your funds.")
    print("Store it securely (paper + hardware wallet recommended).")
    print("\nMnemonic (write this down, keep it offline):\n")
    print(mnemonic)
    print("\n---")

    # Derive seed and ETH account (BIP44 path m/44'/60'/0'/0/0)
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    acct = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    priv_key_hex = acct.PrivateKey().Raw().ToHex()
    address = acct.PublicKey().ToAddress()

    print(f"Derived Ethereum address: {address}")
    # Note: private key shown here — keep it secret
    print(f"Private key (hex): {priv_key_hex}")

    # Prepare JSON backup object (DO NOT share)
    backup_obj = {
        "mnemonic": str(mnemonic),
        "derivation": "m/44'/60'/0'/0/0",
        "address": address,
        "private_key_hex": priv_key_hex,
        "note": "Keep this encrypted. Anyone with mnemonic or private key can spend your funds."
    }

    # Ask for password to encrypt
    pw = getpass.getpass("Enter a strong password to encrypt the backup file: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("Passwords do not match. Exiting.")
        return

    enc = encrypt_json(backup_obj, pw)
    filename = f"wallet_backup_{address[2:10]}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(enc, f, indent=2)
    print(f"\nEncrypted backup saved to: {filename}")
    print("Store the file somewhere safe (offline). Do NOT share your password.\n")

    # Optionally demonstrate decryption (comment out in production)
    ans = input("Do you want to decrypt the file now to verify? (y/N) ").strip().lower()
    if ans == "y":
        pwv = getpass.getpass("Password to decrypt: ")
        try:
            recovered = decrypt_json(enc, pwv)
            print("\nRecovered decrypted data (for verification):")
            print(json.dumps(recovered, indent=2))
        except Exception as e:
            print("Failed to decrypt — wrong password or file corrupted.")

if __name__ == "__main__":
    main()
