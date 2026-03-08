"""
EZKL Benchmarking Pipeline

Usage:
    python run_benchmark.py model1          # Run benchmark for one model
    python run_benchmark.py model1 model2   # Run multiple models
    python run_benchmark.py --all           # Run all models in models/
"""

import sys
import time
import asyncio
import csv
import shutil
from pathlib import Path

import ezkl

from common import ROOT, MODELS_DIR, RESULTS_DIR, ARTIFACTS_DIR, export_model, artifact_paths


async def run_ezkl_pipeline(model_name: str) -> dict:
    """Run the full EZKL pipeline for a model, return timing dict"""
    out_dir = Path(ARTIFACTS_DIR / model_name)
    out_dir.mkdir(parents=True, exist_ok=True)

    p = artifact_paths(model_name)
    timings = {"model": model_name}

    # Export model + copy input from inputs/<model_name>/
    t0 = time.time()
    export_model(model_name, out_dir)
    input_dir = ROOT / "inputs" / model_name
    input_files = sorted(input_dir.glob("*.json")) if input_dir.exists() else []
    if not input_files:
        print(f"Error: no input files found in {input_dir}")
        sys.exit(1)
    shutil.copy(input_files[0], p["input"])
    print(f"  Using input: {input_files[0].name}")
    timings["export_s"] = time.time() - t0

    # Generate settings
    t0 = time.time()
    ezkl.gen_settings(p["onnx"], p["settings"])
    timings["gen_settings_s"] = time.time() - t0

    # Calibrate settings
    t0 = time.time()
    ezkl.calibrate_settings(p["input"], p["onnx"], p["settings"], "resources")
    timings["calibrate_s"] = time.time() - t0

    # Compile circuit
    t0 = time.time()
    ezkl.compile_circuit(p["onnx"], p["compiled"], p["settings"])
    timings["compile_s"] = time.time() - t0

    # Get SRS (async)
    t0 = time.time()
    await ezkl.get_srs(p["settings"], srs_path=p["srs"])
    timings["get_srs_s"] = time.time() - t0

    # Setup (keygen)
    t0 = time.time()
    ezkl.setup(p["compiled"], p["vk"], p["pk"], srs_path=p["srs"])
    timings["setup_s"] = time.time() - t0

    # Generate witness
    t0 = time.time()
    ezkl.gen_witness(p["input"], p["compiled"], p["witness"])
    timings["witness_s"] = time.time() - t0

    # Generate proof
    t0 = time.time()
    ezkl.prove(p["witness"], p["compiled"], p["pk"], p["proof"], srs_path=p["srs"])
    timings["prove_s"] = time.time() - t0

    # Verify proof
    t0 = time.time()
    result = ezkl.verify(p["proof"], p["settings"], p["vk"])
    timings["verify_s"] = time.time() - t0
    timings["verified"] = result

    return timings


def save_results(all_timings: list[dict]):
    """Append benchmark results to a CSV file"""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "benchmarks.csv"

    file_exists = csv_path.exists()
    fieldnames = list(all_timings[0].keys())

    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerows(all_timings)

    print(f"\nResults saved to {csv_path}")


def get_all_model_names() -> list[str]:
    """Find all model files in models/ directory"""
    return sorted(
        p.stem for p in MODELS_DIR.glob("*.py") if p.stem != "__init__"
    )


async def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if "--all" in sys.argv:
        model_names = get_all_model_names()
    else:
        model_names = sys.argv[1:]

    print(f"Benchmarking models: {model_names}")
    all_timings = []

    for name in model_names:
        print(f"\n{'=' * 60}")
        print(f"  Running: {name}")
        print(f"{'=' * 60}")
        timings = await run_ezkl_pipeline(name)
        all_timings.append(timings)

        for k, v in timings.items():
            if k not in ("model", "verified"):
                print(f"  {k:20s}: {v:.3f}s")
        print(f"  {'verified':20s}: {timings['verified']}")

    save_results(all_timings)


if __name__ == "__main__":
    asyncio.run(main())
