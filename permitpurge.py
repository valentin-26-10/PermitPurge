#!/usr/bin/env python3
"""
PermitPurge — find & defuse unlimited ERC20/Permit2 approvals.

Usage examples:
  python permitpurge.py 0xYourAddress
  RPC_URL="https://mainnet.infura.io/v3/<KEY>" python permitpurge.py 0xYourAddress --csv out.csv
"""

import os
import sys
import json
import argparse
from decimal import Decimal
from typing import Dict, List, Tuple, Optional

from web3 import Web3
from web3.middleware import geth_poa_middleware
from tabulate import tabulate

ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name":"","type":"uint8"}], "type":"function"},
    {"constant": True, "inputs": [], "name": "symbol",   "outputs": [{"name":"","type":"string"}], "type":"function"},
    {"constant": True, "inputs": [{"name":"owner","type":"address"},{"name":"spender","type":"address"}],
     "name": "allowance", "outputs": [{"name":"","type":"uint256"}], "type":"function"},
    {"constant": False, "inputs": [{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],
     "name": "approve", "outputs": [{"name":"","type":"bool"}], "type":"function"},
]

# Permit2: https://github.com/Uniswap/permit2
# function allowance(address user, address token, address spender) returns (uint160 amount, uint48 expiration, uint48 nonce)
PERMIT2_ALLOWANCE_SELECTOR = Web3.keccak(text="allowance(address,address,address)")[:4]
# function approve(address token, address spender, uint160 amount, uint48 expiration)
PERMIT2_APPROVE_SELECTOR = Web3.keccak(text="approve(address,address,uint160,uint48)")[:4]
# function lockdown(address[] tokens, address spender)
PERMIT2_LOCKDOWN_SELECTOR = Web3.keccak(text="lockdown(address[],address)")[:4]

UINT256_MAX = (1 << 256) - 1
UNLIMITED_THRESHOLD = UINT256_MAX - 10**18  # считать "почти максимум" как unlimited

# Ключевые «спендеры», которые чаще всего получают бесконечные approvals.
KNOWN_SPENDERS = {
    "Uniswap V2 Router": Web3.to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
    "Uniswap V3 Router": Web3.to_checksum_address("0xE592427A0AEce92De3Edee1F18E0157C05861564"),
    "Uniswap Permit2":   Web3.to_checksum_address("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
    "1inch Router":      Web3.to_checksum_address("0x1111111254EEB25477B68fb85Ed929f73A960582"),
    "0x Exchange":       Web3.to_checksum_address("0xDef1C0ded9bec7F1a1670819833240f027b25EfF"),
    "OpenSea Seaport":   Web3.to_checksum_address("0x00000000006c3852cbEf3e08E8dF289169EdE581"),
    "Blur Exchange":     Web3.to_checksum_address("0x000000000000Ad05Ccc4F10045630fb830B95127"),
    "Sushi Router":      Web3.to_checksum_address("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"),
}

# Ethereum mainnet (по умолчанию)
DEFAULT_RPC = os.getenv("RPC_URL", "https://cloudflare-eth.com")
ETHERSCAN_TX_URL = "https://etherscan.io/address/{addr}#writeContract"
ETHERSCAN_TOKEN_URL = "https://etherscan.io/token/{token}?a={owner}"

def ensure_w3(rpc: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 20}))
    # Если вдруг side-chain — автоматически переживём POA
    try:
        chain_id = w3.eth.chain_id
        if chain_id in (56, 97, 137, 250, 42161, 10, 8453):
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    except Exception:
        pass
    if not w3.is_connected():
        raise RuntimeError(f"Cannot connect RPC: {rpc}")
    return w3

def checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)

def safe_call_symbol_decimals(w3: Web3, token: str) -> Tuple[str, int]:
    c = w3.eth.contract(address=token, abi=ERC20_ABI)
    symbol, decimals = "?", 18
    try:
        symbol = c.functions.symbol().call()
    except Exception:
        # некоторые токены возвращают bytes32 для symbol/name — пропустим
        symbol = "<?>"
    try:
        decimals = c.functions.decimals().call()
    except Exception:
        decimals = 18
    return symbol, int(decimals)

def allowance_of(w3: Web3, token: str, owner: str, spender: str) -> int:
    c = w3.eth.contract(address=token, abi=ERC20_ABI)
    return int(c.functions.allowance(owner, spender).call())

def encode_erc20_approve(spender: str, amount: int) -> str:
    method_sig = Web3.keccak(text="approve(address,uint256)")[:4]
    data = method_sig + Web3.to_bytes(hexstr=spender.rjust(64, '0')) + amount.to_bytes(32, 'big')
    return "0x" + data.hex()

def encode_permit2_approve(token: str, spender: str, amount160: int = 0, expiration: int = 0) -> str:
    # approve(address token, address spender, uint160 amount, uint48 expiration)
    data = PERMIT2_APPROVE_SELECTOR
    data += Web3.to_bytes(hexstr=token.rjust(64, '0'))
    data += Web3.to_bytes(hexstr=spender.rjust(64, '0'))
    data += amount160.to_bytes(20, 'big')       # uint160 -> 20 bytes
    data += expiration.to_bytes(6, 'big')       # uint48  -> 6 bytes
    return "0x" + data.hex()

def encode_permit2_lockdown(tokens: List[str], spender: str) -> str:
    # lockdown(address[] tokens, address spender) — простая статическая сборка:
    # В целях наглядности делаем минимальную ABI-энкодацию руками (без eth_abi).
    # selector + offset + array length + items + spender
    from eth_abi import encode as abi_encode  # маленькая зависимость, зато правильно
    args = [tokens, spender]
    return "0x" + (PERMIT2_LOCKDOWN_SELECTOR + abi_encode(["address[]", "address"], args)).hex()

def permit2_allowance(w3: Web3, user: str, token: str, spender: str) -> Tuple[int, int, int]:
    """
    Возвращает (amount(uint160), expiration(uint48), nonce(uint48)) из Permit2.allowance
    """
    call_data = PERMIT2_ALLOWANCE_SELECTOR \
                + Web3.to_bytes(hexstr=user.rjust(64, '0')) \
                + Web3.to_bytes(hexstr=token.rjust(64, '0')) \
                + Web3.to_bytes(hexstr=spender.rjust(64, '0'))
    try:
        res = w3.eth.call({"to": KNOWN_SPENDERS["Uniswap Permit2"], "data": call_data})
        # decode as (uint160, uint48, uint48)
        raw = res.rjust(32*3, b'\x00')
        amount = int.from_bytes(raw[0:32], 'big') & ((1<<160)-1)
        expiration = int.from_bytes(raw[32:64], 'big') & ((1<<48)-1)
        nonce = int.from_bytes(raw[64:96], 'big') & ((1<<48)-1)
        return amount, expiration, nonce
    except Exception:
        return 0, 0, 0

def human_amount(val: int, decimals: int) -> str:
    q = Decimal(val) / (Decimal(10) ** decimals)
    # компактный вид
    return f"{q.normalize():,}".replace(",", " ")

def fetch_candidate_tokens(w3: Web3, owner: str, lookback_blocks: int = 250_000) -> List[str]:
    """
    Находит токены, где в истории были Approval'ы владельца — чтобы опросить их allowance сейчас.
    Это быстрый эвристический скан без внешних индексеров.
    """
    topic_approval = Web3.keccak(text="Approval(address,address,uint256)").hex()
    tokens: set = set()
    latest = w3.eth.block_number
    start = max(1, latest - lookback_blocks)

    for name, spender in KNOWN_SPENDERS.items():
        try:
            logs = w3.eth.get_logs({
                "fromBlock": hex(start),
                "toBlock": hex(latest),
                "topics": [
                    topic_approval,
                    Web3.to_hex(Web3.to_bytes(hexstr=owner.rjust(64, '0'))),  # owner
                    Web3.to_hex(Web3.to_bytes(hexstr=spender.rjust(64, '0'))),# spender
                ]
            })
            for lg in logs:
                tokens.add(lg["address"])
        except Exception:
            # если RPC не даёт много логов — просто продолжаем
            continue
    return [Web3.to_checksum_address(t) for t in tokens]

def score_risk(is_unlimited: bool, via_permit2: bool, expiration: int) -> str:
    if is_unlimited and via_permit2 and (expiration == 0 or expiration > 10**8):
        return "CRITICAL"
    if is_unlimited and not via_permit2:
        return "HIGH"
    if via_permit2 and expiration > 0:
        return "MEDIUM"
    return "LOW"

def main():
    parser = argparse.ArgumentParser(description="PermitPurge — detect & defuse unlimited approvals.")
    parser.add_argument("owner", help="Wallet address to scan (0x...)")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help="RPC URL (env RPC_URL has priority)")
    parser.add_argument("--csv", default=None, help="Save table to CSV file")
    parser.add_argument("--json", default="revoke_plan.json", help="Save raw revoke plan to JSON")
    parser.add_argument("--lookback", type=int, default=250_000, help="Blocks to scan for Approval events")
    args = parser.parse_args()

    owner = checksum(args.owner)
    rpc = os.getenv("RPC_URL", args.rpc)
    w3 = ensure_w3(rpc)

    print(f"🔍 Scanning {owner} on chain_id={w3.eth.chain_id} via {rpc}")

    tokens = fetch_candidate_tokens(w3, owner, args.lookback)
    if not tokens:
        print("No candidate tokens from logs — you can add tokens manually via --tokens later.")
        print("Done.")
        return

    rows = []
    revoke_plan = []
    for token in tokens:
        symbol, decimals = safe_call_symbol_decimals(w3, token)
        for label, spender in KNOWN_SPENDERS.items():
            # ERC20 allowance
            try:
                erc20_allow = allowance_of(w3, token, owner, spender)
            except Exception:
                erc20_allow = 0

            # Permit2 virtual allowance
            p2_amount, p2_exp, _ = (0, 0, 0)
            via_permit2 = (label != "Uniswap Permit2")
            if label != "Uniswap Permit2":
                p2_amount, p2_exp, _ = permit2_allowance(w3, owner, token, spender)

            # Считаем unlimited, если явно UINT256_MAX ~ иль около
            unlimited = erc20_allow >= UNLIMITED_THRESHOLD
            unlimited_p2 = p2_amount >= (1<<160) - 1  # максимум для uint160

            if erc20_allow > 0 or p2_amount > 0:
                risk = score_risk(unlimited or unlimited_p2, via_permit2, p2_exp)
                rows.append([
                    token,
                    symbol,
                    label,
                    "YES" if unlimited or unlimited_p2 else "—",
                    human_amount(erc20_allow, decimals) if erc20_allow > 0 else "0",
                    p2_amount if p2_amount > 0 else 0,
                    p2_exp if p2_exp > 0 else "—",
                    risk
                ])

                # План ревокации
                if erc20_allow > 0:
                    revoke_plan.append({
                        "type": "erc20_approve_zero",
                        "token": token,
                        "spender": spender,
                        "contract_write_hint": ETHERSCAN_TOKEN_URL.format(token=token, owner=owner),
                        "to": token,
                        "data": encode_erc20_approve(spender[2:].lower(), 0),
                        "value": "0x0"
                    })
                if p2_amount > 0:
                    # два варианта: approve(...,0,0) или lockdown
                    revoke_plan.append({
                        "type": "permit2_approve_zero",
                        "permit2": KNOWN_SPENDERS["Uniswap Permit2"],
                        "token": token,
                        "spender": spender,
                        "to": KNOWN_SPENDERS["Uniswap Permit2"],
                        "data": encode_permit2_approve(token[2:].lower(), spender[2:].lower(), 0, 0),
                        "value": "0x0"
                    })
                    revoke_plan.append({
                        "type": "permit2_lockdown_batch",
                        "permit2": KNOWN_SPENDERS["Uniswap Permit2"],
                        "tokens": [token],
                        "spender": spender,
                        "to": KNOWN_SPENDERS["Uniswap Permit2"],
                        "data": encode_permit2_lockdown([token], spender),
                        "value": "0x0"
                    })

    if not rows:
        print("✅ No active approvals found for known spenders in the scanned range.")
        return

    headers = ["Token", "Sym", "Spender", "Unlimited?", "ERC20 Allow", "Permit2 Amt", "P2 Exp", "Risk"]
    print()
    print(tabulate(rows, headers=headers, tablefmt="github"))

    if args.csv:
        import csv
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in rows:
                writer.writerow(r)
        print(f"\nSaved CSV -> {args.csv}")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(revoke_plan, f, indent=2)
    print(f"🧯 Revoke plan saved -> {args.json}")

    # Подсказки по ручному действию
    print("\nHow to revoke safely:")
    print("  • For classic ERC20: call approve(spender, 0) on the token.")
    print("  • For Permit2: either approve(token, spender, 0, 0) or lockdown([token], spender).")
    print("\nConvenience links per token are in Etherscan hint fields of revoke_plan.json.")
    print("⚠️ Always simulate and verify on a small gas price before sending main txs.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(__doc__)
        sys.exit(0)
    main()
