"""
Generate a ZK proof for a model

Runs the full EZKL setup if artifacts don't exist yet, then generates
a witness and proof. Reuses existing setup (keys, SRS) when possible.

Usage:
    python prove.py model1 --input data.json
"""

import sys
import shutil
import asyncio
import argparse
from pathlib import Path

import ezkl

from common import export_model, artifact_paths


def parse_args():
    parser = argparse.ArgumentParser(description="Generate a ZK proof for a model")
    parser.add_argument("model", help="Model name (matches models/<name>.py)")
    parser.add_argument(
        "--input", dest="input_file", required=True,
        help="Path to input JSON file (e.g. {\"input_data\": [[1.0, 2.0, 3.0, 4.0]]})",
    )
    return parser.parse_args()


async def setup_model(model_name: str, paths: dict[str, str]):
    """Run the full EZKL setup pipeline (export, settings, compile, keygen)."""
    out_dir = Path(paths["dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Setting up model (first run)...")

    # Export model to ONNX + generate default input
    export_model(model_name, out_dir)

    # Generate and calibrate settings
    ezkl.gen_settings(paths["onnx"], paths["settings"])
    ezkl.calibrate_settings(
        paths["input"], paths["onnx"], paths["settings"], "resources"
    )

    # Compile circuit
    ezkl.compile_circuit(paths["onnx"], paths["compiled"], paths["settings"])

    # Download SRS
    await ezkl.get_srs(paths["settings"], srs_path=paths["srs"])

    # Generate proving and verification keys
    ezkl.setup(paths["compiled"], paths["vk"], paths["pk"], srs_path=paths["srs"])

    print("Setup complete.")


async def main():
    args = parse_args()
    paths = artifact_paths(args.model)
    out_dir = Path(paths["dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy input file into artifacts directory
    src = Path(args.input_file)
    if not src.exists():
        print(f"Error: input file not found: {src}")
        sys.exit(1)
    shutil.copy(src, paths["input"])
    print(f"Using input: {src}")

    # Run setup if keys don't exist yet
    if not Path(paths["pk"]).exists():
        await setup_model(args.model, paths)
    else:
        print(f"Reusing existing setup from {out_dir}")
        
    sol_path = str(Path(paths["dir"]) / "verifier.sol")
    print(f"Generating Solidity verifier for {args.model}...")
    ezkl.create_evm_verifier(paths["vk"], paths["settings"], sol_path)
    print(f"Verifier contract saved to {sol_path}")

    # Generate witness
    print("Generating witness...")
    ezkl.gen_witness(paths["input"], paths["compiled"], paths["witness"])

    # Generate proof
    print("Generating proof...")
    ezkl.prove(
        paths["witness"], paths["compiled"], paths["pk"], paths["proof"],
        srs_path=paths["srs"],
    )

    print(f"Proof saved to {paths['proof']}")
    print("Done. Run `python verify.py {0}` to verify.".format(args.model))


if __name__ == "__main__":
    asyncio.run(main())
