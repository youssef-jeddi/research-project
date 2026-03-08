"""Shared constants and utils"""

import sys
import importlib.util
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parent
ARTIFACTS_DIR = ROOT / "artifacts"
RESULTS_DIR = ROOT / "results"
MODELS_DIR = ROOT / "models"


def load_model_module(model_name: str):
    """import models/<model_name>.py and return the module"""
    model_path = MODELS_DIR / f"{model_name}.py"
    if not model_path.exists():
        print(f"Error: model file not found: {model_path}")
        sys.exit(1)
    spec = importlib.util.spec_from_file_location(
        f"models.{model_name}", model_path
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def export_model(model_name: str, out_dir: Path):
    """Instantiate model and export ONNX to out_dir."""
    mod = load_model_module(model_name)
    model = mod.Model()
    model.eval()

    # Zeros tensor just for ONNX tracing (values don't matter)
    dummy_input = torch.zeros(*mod.INPUT_SHAPE)

    onnx_path = out_dir / "model.onnx"
    torch.onnx.export(
        model,
        dummy_input,
        str(onnx_path),
        input_names=["input"],
        output_names=["output"],
        opset_version=11,
        dynamo=False,
    )

    print(f"  Exported {mod.DESCRIPTION}")


def artifact_paths(model_name: str) -> dict[str, str]:
    """Return a dict of all artifact paths for a given model"""
    out_dir = ARTIFACTS_DIR / model_name
    return {
        "dir": str(out_dir),
        "onnx": str(out_dir / "model.onnx"),
        "input": str(out_dir / "input.json"),
        "settings": str(out_dir / "settings.json"),
        "compiled": str(out_dir / "compiled_model.ezkl"),
        "srs": str(out_dir / "kzg.srs"),
        "vk": str(out_dir / "vk.key"),
        "pk": str(out_dir / "pk.key"),
        "witness": str(out_dir / "witness.json"),
        "proof": str(out_dir / "proof.json"),
    }
