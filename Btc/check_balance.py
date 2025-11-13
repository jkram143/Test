# save as check_balance.py
# No special libs required (uses requests). Install: pip install requests

import requests

def satoshi_to_btc(sats):
    return sats / 100_000_000

def get_address_balance(address):
    # Blockstream API: https://blockstream.info/api/
    base = "https://blockstream.info/api"
    # total received - total spent = confirmed balance
    resp = requests.get(f"{base}/address/{address}")
    resp.raise_for_status()
    data = resp.json()
    # data includes chain_stats and mempool_stats
    chain = data.get("chain_stats", {})
    mempool = data.get("mempool_stats", {})
    confirmed_received = chain.get("funded_txo_sum", 0)
    confirmed_spent = chain.get("spent_txo_sum", 0)
    mem_received = mempool.get("funded_txo_sum", 0)
    mem_spent = mempool.get("spent_txo_sum", 0)
    confirmed_balance = confirmed_received - confirmed_spent
    pending_balance = (confirmed_received + mem_received) - (confirmed_spent + mem_spent)
    return {
        "confirmed_sats": confirmed_balance,
        "pending_sats": pending_balance,
        "confirmed_btc": satoshi_to_btc(confirmed_balance),
        "pending_btc": satoshi_to_btc(pending_balance),
    }

if __name__ == "__main__":
    addr = input("Enter Bitcoin address: ").strip()
    try:
        bal = get_address_balance(addr)
        print("Confirmed balance:", bal["confirmed_btc"], "BTC (", bal["confirmed_sats"], "sats )")
        print("Including mempool (pending):", bal["pending_btc"], "BTC (", bal["pending_sats"], "sats )")
    except Exception as e:
        print("Error:", e)
