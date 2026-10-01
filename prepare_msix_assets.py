"""Resize the already-created icon for the Windows package manifest."""

from pathlib import Path

from PIL import Image


root = Path(__file__).resolve().parent
source = Image.open(root / "assets" / "icon.png").convert("RGBA")
target = root / "build" / "msix-stage" / "Assets"
target.mkdir(parents=True, exist_ok=True)
for size, name in (
    (50, "StoreLogo.png"),
    (150, "Square150x150Logo.png"),
    (44, "Square44x44Logo.png"),
):
    source.resize((size, size), Image.Resampling.LANCZOS).save(target / name)
