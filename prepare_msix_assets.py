"""Resize the already-created icon for the Windows package manifest."""

from pathlib import Path

from PIL import Image


root = Path(__file__).resolve().parent
source = Image.open(root / "assets" / "icon.png").convert("RGBA")
for size, name in ((1080, "store-box-1080.png"), (300, "store-icon-300.png")):
    source.resize((size, size), Image.Resampling.LANCZOS).save(root / "assets" / name)
target = root / "build" / "msix-stage" / "Assets"
target.mkdir(parents=True, exist_ok=True)
for size, name in (
    (50, "StoreLogo.png"),
    (150, "Square150x150Logo.png"),
    (44, "Square44x44Logo.png"),
):
    source.resize((size, size), Image.Resampling.LANCZOS).save(target / name)
