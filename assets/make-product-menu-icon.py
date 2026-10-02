"""Draw the monochrome product-menu mark from the app's waveform and graph."""

from pathlib import Path

from PIL import Image, ImageDraw


SCALE = 4
SIZE = 128
INK = (255, 255, 255, 255)


def point(value):
    return round(value * SCALE)


def round_line(draw, start, end, width):
    draw.line((*map(point, start), *map(point, end)), fill=INK, width=point(width))
    radius = point(width / 2)
    for x, y in (start, end):
        cx, cy = point(x), point(y)
        draw.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=INK)


image = Image.new("RGBA", (point(SIZE), point(SIZE)), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)

# The rounded app tile, the audio waveform, and a diagnostic trend are the
# three recognizable parts of the full-color application icon.
draw.rounded_rectangle(
    (point(13), point(13), point(115), point(115)),
    radius=point(24),
    outline=INK,
    width=point(10),
)

for x, top, bottom in (
    (35, 49, 62),
    (50, 41, 70),
    (65, 34, 77),
    (80, 41, 70),
    (95, 49, 62),
):
    round_line(draw, (x, top), (x, bottom), 10)

trend = [(29, 96), (43, 84), (58, 97), (74, 84), (90, 95), (104, 82)]
for start, end in zip(trend, trend[1:]):
    round_line(draw, start, end, 9)

output = Path(__file__).resolve().parents[1] / "site" / "assets" / "product-menu-icon.png"
image.resize((SIZE, SIZE), Image.Resampling.LANCZOS).save(output, optimize=True)
print(output)
