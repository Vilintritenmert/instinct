#!/usr/bin/env python3
"""Test fixture: saves an image returned by an API as base64 (never executed by tests)."""
import base64
import os
from pathlib import Path


def save(image_b64: str, out_path: Path) -> None:
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set")
    out_path.write_bytes(base64.b64decode(image_b64))
