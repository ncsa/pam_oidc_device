#!/usr/bin/env python3
"""Rasterize pam_oidc_device terminal QR art into a grayscale PNG for
independent scanner verification (zbarimg in CI; phone cameras manually).

Input is the module-matrix text produced by src/qr.c (qr_render_matrix) at any
integer scale 1-3, quiet zone included, NO instruction header:

  - UTF-8 style: one character per module column; each text line covers TWO
    module rows via half-block glyphs (U+2588 both dark, U+2580 top dark,
    U+2584 bottom dark), exactly as a monospace terminal renders them.
    QR_STYLE_ASCII and QR_STYLE_UTF8 both have their lines repeated
    `scale` times vertically by the renderer, which this tool detects from
    the quiet-zone width (4 modules * scale light lines) and downsamples.
  - ASCII style: one dark block character per dark module. The glyph shape
    is irrelevant to a barcode scanner — cell occupancy is what matters —
    so every dark cell is rasterized as a solid square.

The ISO/IEC 18004 quiet zone (4 light modules on every side) must be present
in the input; a violation (e.g. a prompt header line above the symbol) is an
error, so a wrong input can never silently produce an undecodable image.

Usage:  art2png.py ART_FILE OUT_FILE [PX_PER_MODULE]
        (OUT_FILE's extension selects P5 PGM when it ends in ".pgm" and a
        minimal grayscale PNG otherwise; PX_PER_MODULE is the output pixel
        size per module, default 3)
Exit:   0 success, 2 usage/parse error.  Pure standard library (struct/zlib).

Note:  the machine-scanned leg uses P5 PGM, not PNG: it is spec-trivial
(header + raw bytes, no zlib/chunk/CRC machinery) and reads cleanly through
every zbarimg image backend (ImageMagick's native PGM coder or libzbar's
built-in PPM/PGM decoders).  PNG output remains available (any other output
extension) for human/phone-camera use, where arbitrary decoders render it.
"""

import struct
import sys
import zlib

# Half-block glyphs used by src/qr.c for QR_STYLE_UTF8: char -> (top, bottom).
GLYPHS = {"\u2588": (1, 1), "\u2580": (1, 0), "\u2584": (0, 1)}

# Must match QR_QUIET_ZONE in include/pam_oidc_device.h.
QUIET_ZONE = 4

BLACK = 0
WHITE = 255


def _downsample(grid, rs, cs):
    """Collapse an rs x cs repeated block grid to its unique cell, requiring
    every block to be uniform (the renderer always emits uniform blocks)."""
    rows = len(grid)
    cols = len(grid[0])
    if rows % rs != 0 or cols % cs != 0:
        raise ValueError(f"art dimensions {cols}x{rows} are not multiples of the "
                         f"detected scale ({cs}x{rs} repetition)")
    out = [[0] * (cols // cs) for _ in range(rows // rs)]
    for r in range(rows // rs):
        for c in range(cols // cs):
            cell = 0
            for dy in range(rs):
                for dx in range(cs):
                    if grid[r * rs + dy][c * cs + dx]:
                        cell = 1
            out[r][c] = cell
    return out


def parse_art(text):
    """Return a square 2-D module grid [[0/1]...] (module rows of module cols)."""
    lines = [ln.rstrip("\n") for ln in text.splitlines()]
    # NOTE: the trailing all-space lines are the BOTTOM quiet zone — do NOT
    # strip them. A stray extra blank line makes the grid non-square and is
    # reported as an error, which is the desired behavior.
    if not lines:
        raise ValueError("empty art input")
    width = max(len(ln) for ln in lines)
    lines = [ln.ljust(width) for ln in lines]

    is_utf8 = any(ch in GLYPHS for ln in lines for ch in ln)
    if is_utf8:
        # UTF-8 style: no vertical repetition — each text line covers TWO module
        # rows (half-block glyphs); scale repeats every glyph horizontally.
        # Detect the horizontal scale from the leading-space run on the first
        # glyph line: the quiet zone is exactly 4 modules wide.
        first = next(ln for ln in lines if ln.strip())
        lead = len(first) - len(first.lstrip(" \t"))
        if lead < QUIET_ZONE or lead % QUIET_ZONE != 0 or lead // QUIET_ZONE > 3:
            raise ValueError(
                f"unexpected leading-space run {lead} (quiet zone must be 4*scale)")
        scale = lead // QUIET_ZONE
        for ln in lines:
            for ch in ln:
                if ch in (" ", "\t"):
                    continue
                if ch not in GLYPHS:
                    raise ValueError(f"unexpected glyph {ch!r} in UTF-8 art")
        # Packed module rows (last pair contributes only its top row).
        mod_rows = 2 * len(lines) - 1
        grid = [[0] * width for _ in range(mod_rows)]
        for y, ln in enumerate(lines):
            for x, ch in enumerate(ln):
                if ch in (" ", "\t"):
                    continue
                top, bottom = GLYPHS[ch]
                if top:
                    grid[2 * y][x] = 1
                if bottom and 2 * y + 1 < mod_rows:
                    grid[2 * y + 1][x] = 1
        modules = _downsample(grid, 1, scale)
    else:
        # ASCII style: one dark block character per dark module; the renderer
        # repeats every line `scale` times vertically, so the top light border
        # is exactly QUIET_ZONE * scale lines.
        top_light = 0
        for ln in lines:
            if ln.strip():
                break
            top_light += 1
        if top_light < QUIET_ZONE or top_light % QUIET_ZONE != 0:
            raise ValueError(
                "quiet zone violated (top border must be 4*scale light lines) — "
                "did you pass art with a prompt header or without the quiet zone?")
        scale = top_light // QUIET_ZONE
        if scale > 3:
            raise ValueError(f"implausible detected scale {scale}")
        grid = [[0] * width for _ in range(len(lines))]
        for y, ln in enumerate(lines):
            for x, ch in enumerate(ln):
                if ch not in (" ", "\t"):
                    grid[y][x] = 1
        modules = _downsample(grid, scale, scale)

    # Quiet-zone guard at module resolution: the outer 4 rows/columns light.
    mod_rows = len(modules)
    mod_cols = len(modules[0])
    for r in range(mod_rows):
        for c in range(mod_cols):
            in_border = r < QUIET_ZONE or r >= mod_rows - QUIET_ZONE \
                or c < QUIET_ZONE or c >= mod_cols - QUIET_ZONE
            if in_border and modules[r][c]:
                raise ValueError(
                    "quiet zone violated (dark module in the border) — did you "
                    "pass art with a prompt header or without the quiet zone?")
    if mod_rows != mod_cols:
        raise ValueError(f"module grid is not square ({mod_rows}x{mod_cols})")
    return modules, is_utf8


def write_png(path, width, height, pixel_rows):
    """Write a minimal 8-bit grayscale PNG (no third-party packages needed)."""

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + bytes(row) for row in pixel_rows)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def write_pgm(path, width, height, pixel_rows):
    """Write a minimal binary P5 PGM image (header + raw bytes, no encoding)."""
    header = f"P5\n{width} {height}\n255\n"
    with open(path, "wb") as fh:
        fh.write(header.encode("ascii"))
        fh.write(b"".join(pixel_rows))


def main(argv):
    if len(argv) not in (4, 5):
        print(__doc__, file=sys.stderr)
        return 2
    art_path, img_path = argv[1], argv[2]
    px_per_module = int(argv[3]) if len(argv) == 5 else 3
    if px_per_module < 1:
        print("error: PX_PER_MODULE must be >= 1", file=sys.stderr)
        return 2

    with open(art_path, "r", encoding="utf-8") as fh:
        try:
            grid, is_utf8 = parse_art(fh.read())
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    mod_rows = len(grid)
    mod_cols = len(grid[0])
    pixel_rows = []
    for row in grid:
        pixel = bytearray()
        for cell in row:
            pixel.extend([BLACK if cell else WHITE] * px_per_module)
        # A module row spans px_per_module pixel rows: repeat the expanded row
        # vertically as well (horizontal expansion happens in the inner loop).
        pixel_rows.extend([bytes(pixel)] * px_per_module)
    if img_path.endswith(".pgm"):
        write_pgm(img_path, mod_cols * px_per_module, mod_rows * px_per_module, pixel_rows)
        fmt = "P5 PGM"
    else:
        write_png(img_path, mod_cols * px_per_module, mod_rows * px_per_module, pixel_rows)
        fmt = "PNG"
    print(f"{img_path}: {mod_cols * px_per_module}x{mod_rows * px_per_module} px "
          f"({mod_cols}x{mod_rows} modules, {'UTF-8' if is_utf8 else 'ASCII'} art, "
          f"{px_per_module} px/module, {fmt})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
