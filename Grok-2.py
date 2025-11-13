#!/usr/bin/env python3
"""
Grok-2.py
A safe Bitcoin learning utility:
 - generate BIP39 mnemonic
 - derive addresses (legacy P2PKH, segwit P2WPKH bech32, and P2SH-P2WPKH)
 - lookup address balances via Blockstream public API

Requires:
    pip install bip-utils requests

Usage examples:
    python Grok-2.py --generate
    python Grok-2.py --mnemonic "abandon abandon ..." --derive 0 5
    python Grok-2.py --address bc1q... --balance
    python Grok-2.py --mnemonic "<mnemonic>" --derive 0 2 --show-priv
"""

import argparse
import sys
from typing import List, Tuple
import requests

# bip-utils imports
try:
    from bip_utils import (
        Bip39MnemonicGenerator, Bip39WordsNum, Bip39SeedGenerator,
        Bip44, Bip44Coins, Bip44Changes,
        Bip84, Bip84Coins,
        Bip49, Bip49Coins
    )
except Exception as e:
    print("Missing dependency bip-utils. Install with: pip install bip-utils")
    raise

# ---------- Helpers ----------

def generate_mnemonic(words: int = 12) -> str:
    if words == 12:
        num = Bip39WordsNum.WORDS_NUM_12
    elif words == 15:
        num = Bip39WordsNum.WORDS_NUM_15
    elif words == 18:
        num = Bip39WordsNum.WORDS_NUM_18
    elif words == 21:
        num = Bip39WordsNum.WORDS_NUM_21
    elif words == 24:
        num = Bip39WordsNum.WORDS_NUM_24
    else:
        raise ValueError("Unsupported word count. Choose from 12,15,18,21,24.")
    return Bip39MnemonicGenerator().FromWordsNumber(num)

def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    return Bip39SeedGenerator(mnemonic).Generate(passphrase)

def derive_address_bip44(seed: bytes, index: int) -> Tuple[str, str, str]:
    """BIP44 legacy P2PKH (m/44'/0'/0'/0/index)"""
    bip44_mst = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    addr_obj = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
    addr = addr_obj.PublicKey().ToAddress()
    wif = addr_obj.PrivateKey().ToWif()
    pub = addr_obj.PublicKey().RawCompressed().ToHex()
    return addr, pub, wif

def derive_address_bip84(seed: bytes, index: int) -> Tuple[str, str, str]:
    """BIP84 native segwit bech32 (m/84'/0'/0'/0/index)"""
    bip84_mst = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
    addr_obj = bip84_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
    addr = addr_obj.PublicKey().ToAddress()
    wif = addr_obj.PrivateKey().ToWif()
    pub = addr_obj.PublicKey().RawCompressed().ToHex()
    return addr, pub, wif

def derive_address_bip49(seed: bytes, index: int) -> Tuple[str, str, str]:
    """BIP49 P2SH-wrapped segwit (m/49'/0'/0'/0/index)"""
    bip49_mst = Bip49.FromSeed(seed, Bip49Coins.BITCOIN)
    addr_obj = bip49_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
    addr = addr_obj.PublicKey().ToAddress()
    wif = addr_obj.PrivateKey().ToWif()
    pub = addr_obj.PublicKey().RawCompressed().ToHex()
    return addr, pub, wif

# ---------- Blockchain queries (readonly) ----------

BLOCKSTREAM_API = "https://blockstream.info/api"

def get_address_balance_blockstream(address: str) -> dict:
    """
    Returns confirmed and pending balances in satoshis and BTC.
    """
    url = f"{BLOCKSTREAM_API}/address/{address}"
    resp = requests.get(url, timeout=12)
    resp.raise_for_status()
    data = resp.json()
    chain = data.get("chain_stats", {})
    mempool = data.get("mempool_stats", {})
    confirmed_received = chain.get("funded_txo_sum", 0)
    confirmed_spent = chain.get("spent_txo_sum", 0)
    mem_received = mempool.get("funded_txo_sum", 0)
    mem_spent = mempool.get("spent_txo_sum", 0)

    confirmed_sats = confirmed_received - confirmed_spent
    pending_sats = (confirmed_received + mem_received) - (confirmed_spent + mem_spent)
    return {
        "confirmed_sats": confirmed_sats,
        "pending_sats": pending_sats,
        "confirmed_btc": confirmed_sats / 1e8,
        "pending_btc": pending_sats / 1e8
    }

# ---------- CLI and orchestration ----------

def derive_batch(seed: bytes, start: int, count: int, show_priv: bool = False) -> List[dict]:
    rows = []
    for i in range(start, start + count):
        legacy_addr, legacy_pub, legacy_wif = derive_address_bip44(seed, i)
        bech32_addr, bech32_pub, bech32_wif = derive_address_bip84(seed, i)
        p2sh_addr, p2sh_pub, p2sh_wif = derive_address_bip49(seed, i)
        row = {
            "index": i,
            "legacy_p2pkh": legacy_addr,
            "bech32_p2wpkh": bech32_addr,
            "p2sh_p2wpkh": p2sh_addr
        }
        if show_priv:
            row.update({
                "legacy_wif": legacy_wif,
                "bech32_wif": bech32_wif,
                "p2sh_wif": p2sh_wif,
            })
        rows.append(row)
    return rows

def main():
    parser = argparse.ArgumentParser(description="Grok-2.py — Bitcoin learning toolkit")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="Generate a new 12-word mnemonic")
    group.add_argument("--mnemonic", type=str, help="Supply an existing mnemonic (quoted)")
    group.add_argument("--address", type=str, help="Supply an address for balance lookup")

    parser.add_argument("--words", type=int, choices=[12,15,18,21,24], default=12, help="Mnemonic word count for --generate")
    parser.add_argument("--derive", nargs=2, metavar=('START','COUNT'), type=int, help="Derive addresses: start index and count")
    parser.add_argument("--passphrase", type=str, default="", help="BIP39 passphrase (optional)")
    parser.add_argument("--show-priv", action="store_true", help="Show private keys (WIF) in output — warning: secrets!")
    parser.add_argument("--balance", action="store_true", help="Check balance for --address or derived addresses (if used with --mnemonic and --derive)")

    args = parser.parse_args()

    if args.generate:
        mnemonic = generate_mnemonic(args.words)
        print("\n=== NEW MNEMONIC (KEEP THIS SECRET) ===")
        print(mnemonic)
        print("======================================")
        print("You can use this with --mnemonic '...'\n")
        return

    if args.address:
        # single address balance lookup
        try:
            bal = get_address_balance_blockstream(args.address)
            print(f"Address: {args.address}")
            print(f"Confirmed: {bal['confirmed_btc']} BTC ({bal['confirmed_sats']} sats)")
            print(f"Pending(including mempool): {bal['pending_btc']} BTC ({bal['pending_sats']} sats)")
        except Exception as e:
            print("Error fetching balance:", e)
        return

    # must be mnemonic path if we reach here
    mnemonic = args.mnemonic.strip()
    if not mnemonic:
        print("No mnemonic provided.")
        return

    # warning
    print("WARNING: Anyone with your mnemonic can spend your funds. Don't paste real mnemonics on untrusted machines.")
    seed = seed_from_mnemonic(mnemonic, args.passphrase)

    if args.derive:
        start, count = args.derive
        if count <= 0 or count > 1000:
            print("Count should be between 1 and 1000.")
            return
        rows = derive_batch(seed, start, count, show_priv=args.show_priv)
        for r in rows:
            print("\nIndex:", r["index"])
            print("  P2PKH (legacy)        :", r["legacy_p2pkh"])
            print("  P2WPKH (bech32)       :", r["bech32_p2wpkh"])
            print("  P2SH-P2WPKH (wrapped) :", r["p2sh_p2wpkh"])
            if args.show_priv:
                print("    WIF legacy:", r.get("legacy_wif"))
                print("    WIF bech32:", r.get("bech32_wif"))
                print("    WIF p2sh:", r.get("p2sh_wif"))
            if args.balance:
                # check balances for each address (may be slow for many addresses)
                for label in ("legacy_p2pkh", "bech32_p2wpkh", "p2sh_p2wpkh"):
                    addr = r[label]
                    try:
                        b = get_address_balance_blockstream(addr)
                        print(f"    Balance {label}: {b['confirmed_btc']} BTC (confirmed), {b['pending_btc']} BTC (including mempool)")
                    except Exception as e:
                        print(f"    Balance {label}: error ->", e)
        return

    # If we get here, nothing else to do
    parser.print_help()

if __name__ == "__main__":
    main()
