"""
Verify an existing ZK proof for a model

Usage:
    python verify.py model1
"""

import sys
import argparse
from pathlib import Path

import ezkl

from common import artifact_paths


def parse_args():
    parser = argparse.ArgumentParser(description="Verify a ZK proof for a model")
    parser.add_argument("model", help="Model name (matches models/<name>.py)")
    return parser.parse_args()


def main():
    args = parse_args()
    paths = artifact_paths(args.model)

    # Check that required files exist
    required = ["proof", "settings", "vk"]
    for key in required:
        if not Path(paths[key]).exists():
            print(f"Error: {key} not found at {paths[key]}")
            print(f"Run `python prove.py {args.model}` first.")
            sys.exit(1)

    print(f"Verifying proof for {args.model}...")
    try:
        result = ezkl.verify(paths["proof"], paths["settings"], paths["vk"])
    except RuntimeError:
        result = False

    if result:
        print("Proof VERIFIED successfully.")
    else:
        print("Proof FAILED verification.")

    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()
