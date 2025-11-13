#!/usr/bin/env python3
"""
Metamash wallet addresses.py
Read-only scanner for Ethereum (MetaMask) addresses.

Features:
- Read addresses (one per line) from a text file.
- Get ETH balance using Web3 provider (preferred) or Etherscan API fallback.
- Optional: check ERC-20 token balances for a given token contract address.
- Output CSV or JSON report.
- NEVER handles private keys or seeds.

Usage examples:
  python3 "Metamash wallet addresses.py" addresses.txt -o report.csv --provider rpc --rpc-url https://mainnet.infura.io/v3/YOUR_KEY
  python3 "Metamash wallet addresses.py" addresses.txt -o report.json --format json --provider etherscan --etherscan-key YOUR_KEY
  python3 "Metamash wallet addresses.py" addresses.txt --token 0x6B175474E89094C44Da98b954EedeAC495271d0F  # DAI token contract
"""

import argparse
import csv
import json
import sys
import time
from typing import List, Optional, Dict, Any

# web3 for JSON-RPC queries
try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except Exception:
    WEB3_AVAILABLE = False

import requests

ETHERSCAN_BALANCE_URL = "https://api.etherscan.io/api"
DEFAULT_TIMEOUT = 15

def read_addresses(path: str) -> List[str]:
    addrs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            addrs.append(s)
    return addrs

def wei_to_eth(wei: int) -> float:
    return wei / 1e18

def get_eth_balance_rpc(w3: 'Web3', address: str) -> Optional[int]:
    try:
        balance = w3.eth.get_balance(address)
        return int(balance)
    except Exception as e:
        # fail gracefully
        return None

def get_token_balance_rpc(w3: 'Web3', address: str, token_contract: str) -> Optional[int]:
    """Call ERC20 balanceOf via web3 (returns raw token units)."""
    try:
        abi = [
            {"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
            {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
            {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"}
        ]
        contract = w3.eth.contract(address=Web3.toChecksumAddress(token_contract), abi=abi)
        bal = contract.functions.balanceOf(Web3.toChecksumAddress(address)).call()
        return int(bal)
    except Exception:
        return None

def get_eth_balance_etherscan(address: str, api_key: Optional[str]) -> Optional[int]:
    params = {
        "module": "account",
        "action": "balance",
        "address": address,
        "tag": "latest",
    }
    if api_key:
        params["apikey"] = api_key
    try:
        r = requests.get(ETHERSCAN_BALANCE_URL, params=params, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        j = r.json()
        if j.get("status") == "1" or j.get("result") is not None:
            return int(j.get("result", 0))
        # Etherscan returns status=0 for 0 balance sometimes; still parse result
        return int(j.get("result", 0))
    except Exception:
        return None

def get_token_balance_etherscan(address: str, token_contract: str, api_key: Optional[str]) -> Optional[int]:
    # uses tokenbalance action (requires api key for some rate-limits)
    params = {
        "module": "account",
        "action": "tokenbalance",
        "contractaddress": token_contract,
        "address": address,
        "tag": "latest",
    }
    if api_key:
        params["apikey"] = api_key
    try:
        r = requests.get(ETHERSCAN_BALANCE_URL, params=params, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        j = r.json()
        return int(j.get("result", 0))
    except Exception:
        return None

def save_csv(rows: List[Dict[str, Any]], path: str):
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def save_json(rows: List[Dict[str, Any]], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

def parse_args():
    p = argparse.ArgumentParser(description="Metamash wallet addresses - read-only ETH address scanner")
    p.add_argument("input", help="Text file with one Ethereum address per line")
    p.add_argument("-o", "--output", default="eth_report.csv", help="Output path")
    p.add_argument("--format", choices=["csv","json"], default="csv", help="Output format")
    p.add_argument("--provider", choices=["rpc","etherscan"], default="rpc", help="Primary provider (rpc uses web3.py)")
    p.add_argument("--rpc-url", default=None, help="JSON-RPC URL (Infura/Alchemy/local node). Example: https://mainnet.infura.io/v3/YOUR_KEY")
    p.add_argument("--etherscan-key", default=None, help="Etherscan API key (optional)")
    p.add_argument("--token", default=None, help="Optional ERC-20 token contract address to query token balances")
    return p.parse_args()

def main():
    args = parse_args()
    addrs = read_addresses(args.input)
    if not addrs:
        print("No addresses found", file=sys.stderr)
        sys.exit(1)

    results = []
    w3 = None
    if args.provider == "rpc":
        if not WEB3_AVAILABLE:
            print("web3.py not installed. Install with: pip install web3", file=sys.stderr)
            # fall back to etherscan provider
            args.provider = "etherscan"
        else:
            if not args.rpc_url:
                print("RPC provider selected but --rpc-url not provided. Falling back to Etherscan.", file=sys.stderr)
                args.provider = "etherscan"
            else:
                w3 = Web3(Web3.HTTPProvider(args.rpc_url, request_kwargs={"timeout": DEFAULT_TIMEOUT}))
                if not w3.isConnected():
                    print("Warning: web3 RPC not reachable. Falling back to Etherscan.", file=sys.stderr)
                    args.provider = "etherscan"
                    w3 = None

    for a in addrs:
        row = {"address": a, "eth_balance_wei": None, "eth_balance": None}
        # Try provider
        bal_wei = None
        if args.provider == "rpc" and w3:
            try:
                bal_wei = get_eth_balance_rpc(w3, Web3.toChecksumAddress(a))
            except Exception:
                bal_wei = None
        if bal_wei is None and args.provider != "rpc":
            # use etherscan
            bal_wei = get_eth_balance_etherscan(a, args.etherscan_key)

        # If still None and we used rpc earlier but failed, try etherscan fallback
        if bal_wei is None and args.provider == "rpc":
            bal_wei = get_eth_balance_etherscan(a, args.etherscan_key)

        if bal_wei is None:
            row["eth_balance_wei"] = ""
            row["eth_balance"] = ""
        else:
            row["eth_balance_wei"] = int(bal_wei)
            row["eth_balance"] = float(wei_to_eth(int(bal_wei)))

        # Optionally token balance
        if args.token:
            token_bal = None
            if args.provider == "rpc" and w3:
                token_bal = get_token_balance_rpc(w3, a, args.token)
            if token_bal is None:
                token_bal = get_token_balance_etherscan(a, args.token, args.etherscan_key)
            row["token_contract"] = args.token
            row["token_balance_raw"] = token_bal if token_bal is not None else ""
        results.append(row)
        # polite pause to avoid hammering free providers
        time.sleep(0.12)

    # Save
    if args.format == "json":
        save_json(results, args.output)
    else:
        save_csv(results, args.output)

    total_eth = sum(r["eth_balance"] or 0 for r in results)
    nonzero = len([r for r in results if r.get("eth_balance") and r.get("eth_balance") > 0])
    print(f"Done. Addresses scanned: {len(results)}. Nonzero addresses: {nonzero}. Total ETH: {total_eth:.18f}")
    print(f"Report written to: {args.output}")

if __name__ == "__main__":
    main()
