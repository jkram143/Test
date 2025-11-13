#!/usr/bin/env python3
"""
crypto_spectre_bnb.py
Derive BSC (Ethereum-format) addresses from a BIP39 mnemonic and optionally check balances via BSC RPC.

WARNING: keep your mnemonic/private keys secret. Run locally.
"""

import argparse
import csv
import sys
from decimal import Decimal

from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from web3 import Web3
import pandas as pd

# --- Helpers for derivation ---
def derive_eth_addresses(mnemonic: str, passphrase: str = "", count: int = 10, account: int = 0, change: int = 0):
    """
    Derive `count` Ethereum/BSC addresses and private keys from mnemonic using BIP44.
    Returns list of dicts: [{index, path, address, private_key_hex}, ...]
    """
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    results = []
    for i in range(count):
        addr_obj = bip44_mst.Purpose().Coin().Account(account).Change(Bip44Changes.CHAIN_EXT if change == 0 else Bip44Changes.CHAIN_INT).AddressIndex(i)
        priv = addr_obj.PrivateKey().Raw().ToHex()
        addr = addr_obj.PublicKey().ToAddress()  # returns 0x...
        path = f"m/44'/60'/{account}'/{change}/{i}"
        results.append({
            "index": i,
            "derivation_path": path,
            "address": Web3.toChecksumAddress(addr),
            "private_key": "0x" + priv
        })
    return results

# --- Web3 / balance checks ---
def connect_bsc(rpc_url: str = "https://bsc-dataseed.binance.org/"):
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
    if not w3.isConnected():
        raise ConnectionError(f"Failed to connect to BSC RPC {rpc_url}")
    return w3

def get_bnb_balance(w3: Web3, address: str) -> Decimal:
    wei = w3.eth.get_balance(address)
    return Decimal(w3.fromWei(wei, "ether"))

# ERC-20 balance: requires token contract address + standard ABI fragment
ERC20_ABI_FRAGMENT = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
]

def get_erc20_balance(w3: Web3, token_addr: str, wallet_addr: str):
    contract = w3.eth.contract(address=Web3.toChecksumAddress(token_addr), abi=ERC20_ABI_FRAGMENT)
    try:
        raw = contract.functions.balanceOf(Web3.toChecksumAddress(wallet_addr)).call()
        decimals = contract.functions.decimals().call()
        symbol = contract.functions.symbol().call()
        human = Decimal(raw) / (Decimal(10) ** decimals)
        return {"raw": raw, "human": human, "decimals": decimals, "symbol": symbol}
    except Exception as e:
        return {"error": str(e)}

# --- CLI / main ---
def main():
    parser = argparse.ArgumentParser(description="Derive BSC addresses from a BIP39 mnemonic and optionally check balances.")
    parser.add_argument("--mnemonic", "-m", required=True, help="BIP39 mnemonic (12/24 words). For safety, run locally and don't paste into public machines.")
    parser.add_argument("--passphrase", "-p", default="", help="Optional BIP39 passphrase (aka 25th word).")
    parser.add_argument("--count", "-n", type=int, default=10, help="Number of addresses to derive (default 10).")
    parser.add_argument("--start", type=int, default=0, help="Start index (default 0).")
    parser.add_argument("--rpc", default="https://bsc-dataseed.binance.org/", help="BSC RPC URL (default public).")
    parser.add_argument("--check-balances", action="store_true", help="Query BNB balance for derived addresses using the RPC.")
    parser.add_argument("--tokens", nargs="*", help="List of ERC20 token contract addresses to check (optional).")
    parser.add_argument("--out-csv", help="Write results to CSV file (path).")
    args = parser.parse_args()

    # Safety confirmation (requires user to accept)
    print("WARNING: This script will display private keys. Keep them secret.")
    confirm = input("Type 'I UNDERSTAND' to continue: ").strip()
    if confirm != "I UNDERSTAND":
        print("Aborted by user.")
        sys.exit(1)

    # Derive addresses
    derived = derive_eth_addresses(args.mnemonic, args.passphrase, count=args.count + args.start, account=0, change=0)
    # slice to requested start..start+count-1
    derived = [d for d in derived if d["index"] >= args.start][: args.count]

    # Optionally connect to BSC
    w3 = None
    if args.check_balances or args.tokens:
        try:
            w3 = connect_bsc(args.rpc)
            print(f"Connected to BSC node: {args.rpc}")
        except Exception as e:
            print(f"Failed to connect to RPC: {e}")
            w3 = None

    rows = []
    for info in derived:
        row = {
            "index": info["index"],
            "derivation_path": info["derivation_path"],
            "address": info["address"],
            "private_key": info["private_key"],
        }
        if w3 is not None and args.check_balances:
            try:
                row["bnb_balance"] = str(get_bnb_balance(w3, info["address"]))
            except Exception as e:
                row["bnb_balance"] = f"error: {e}"
        if w3 is not None and args.tokens:
            tokens_out = {}
            for taddr in args.tokens:
                taddr = taddr.strip()
                if not taddr:
                    continue
                try:
                    bal = get_erc20_balance(w3, taddr, info["address"])
                except Exception as e:
                    bal = {"error": str(e)}
                tokens_out[taddr] = bal
            row["tokens"] = tokens_out
        rows.append(row)
        # Print summary to console
        print("----")
        print(f"Index: {row['index']}  Path: {row['derivation_path']}")
        print(f"Address: {row['address']}")
        print(f"Private key: {row['private_key']}")
        if "bnb_balance" in row:
            print(f"BNB balance: {row['bnb_balance']}")
        if "tokens" in row and row["tokens"]:
            for t, b in row["tokens"].items():
                if "error" in b:
                    print(f"Token {t}: error: {b['error']}")
                else:
                    print(f"Token {b.get('symbol','?')} ({t}): {b['human']} (raw: {b['raw']})")

    # Save CSV if requested (private keys included — keep file safe)
    if args.out_csv:
        df_rows = []
        for r in rows:
            dr = r.copy()
            # Serialize tokens as string if present
            if "tokens" in dr:
                dr["tokens"] = str(dr["tokens"])
            df_rows.append(dr)
        df = pd.DataFrame(df_rows)
        df.to_csv(args.out_csv, index=False)
        print(f"Saved CSV to {args.out_csv}")

if __name__ == "__main__":
    main()
