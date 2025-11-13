# save as generate_btc_address.py
# Install: pip install bip-utils

from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip39WordsNum, Bip44, Bip44Coins, Bip44Changes

# 1. Create a new 12-word mnemonic
mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
print("Mnemonic:", mnemonic)

# 2. Make seed from mnemonic (no passphrase)
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# 3. Use BIP44 for Bitcoin (derivation m/44'/0'/0'/0/0)
bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
acct = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

print("Derivation path: m/44'/0'/0'/0/0")
print("Address (P2PKH):", acct.PublicKey().ToAddress())
print("Public key (hex):", acct.PublicKey().RawCompressed().ToHex())
print("Private key (WIF):", acct.PrivateKey().ToWif())

# IMPORTANT: never share the mnemonic or private key for real funds.
