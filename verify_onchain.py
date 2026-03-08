"""
Verify a proof on-chain using the deployed Solidity verifier

Usage:
    python verify_onchain.py model1 --contract 0xYourContractAddress --rpc-url https://rpc-url
"""

import sys
import json
import argparse
from pathlib import Path

from web3 import Web3

from common import artifact_paths

VERIFIER_ABI = [
    {
        "inputs": [
            {"name": "proof", "type": "bytes"},
            {"name": "instances", "type": "uint256[]"},
        ],
        "name": "verifyProof",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
]


def parse_args():
    parser = argparse.ArgumentParser(description="Verify a proof on-chain")
    parser.add_argument("model", help="Model name (matches models/<name>.py)")
    parser.add_argument("--contract", required=True, help="Deployed verifier contract address")
    parser.add_argument("--rpc-url", required=True, help="RPC URL of the chain")
    return parser.parse_args()


def main():
    args = parse_args()
    paths = artifact_paths(args.model)

    proof_path = Path(paths["proof"])
    if not proof_path.exists():
        print(f"Error: proof not found at {proof_path}")
        print(f"Run `python prove.py {args.model} --input <input.json>` first.")
        sys.exit(1)

    with open(proof_path) as f:
        proof_data = json.load(f)

    # proof bytes from hex
    proof_bytes = bytes.fromhex(proof_data["hex_proof"].removeprefix("0x"))

    # instances: convert little-endian hex strings to uint256
    instances = []
    for hex_str in proof_data["instances"][0]:
        value = int.from_bytes(bytes.fromhex(hex_str), byteorder="little")
        instances.append(value)

    # Connect and call
    w3 = Web3(Web3.HTTPProvider(args.rpc_url))
    if not w3.is_connected():
        print(f"Error: cannot connect to {args.rpc_url}")
        sys.exit(1)

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(args.contract),
        abi=VERIFIER_ABI,
    )

    print(f"Verifying proof for {args.model} on-chain...")
    print(f"  Contract: {args.contract}")
    print(f"  Instances: {len(instances)} values")

    try:
        result = contract.functions.verifyProof(proof_bytes, instances).call()
    except Exception as e:
        print(f"Verification failed: {e}")
        sys.exit(1)

    if result:
        print("Proof VERIFIED on-chain.")
    else:
        print("Proof FAILED on-chain verification.")

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
