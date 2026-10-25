#!/usr/bin/env python3
"""Turn Natural Earth land (world-atlas land-50m.json) into the dot grid behind the travel map.

The output is public and holds no private data: one bit per 0.25-degree cell, set when
the cell is mostly land.

Usage: python3 tools/make_map.py path/to/land-50m.json docs/assets/land.json
"""
import base64
import json
import sys

from PIL import Image, ImageDraw

STEP = 0.25         # degrees per dot
OVERSAMPLE = 4      # raster pixels per cell edge
THRESHOLD = 0.3     # share of a cell that must be land
LAT_MAX, LAT_MIN = 84, -60  # skip most of Antarctica and the Arctic ice


def decode_arcs(topo):
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    arcs = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sx + tx, y * sy + ty))
        arcs.append(pts)
    return arcs


def ring(arcs, idx):
    pts = []
    for i in idx:
        a = arcs[i] if i >= 0 else arcs[~i][::-1]
        pts.extend(a if not pts else a[1:])
    return pts


def unwrap(pts):
    """Keep a ring continuous where it crosses the antimeridian."""
    out = []
    shift = 0
    for i, (x, y) in enumerate(pts):
        if i and x + shift - out[-1][0] > 180:
            shift -= 360
        elif i and x + shift - out[-1][0] < -180:
            shift += 360
        out.append((x + shift, y))
    return out


def polygons(topo):
    arcs = decode_arcs(topo)
    obj = topo["objects"]["land"]
    geoms = obj["geometries"] if obj["type"] == "GeometryCollection" else [obj]
    for g in geoms:
        polys = g["arcs"] if g["type"] == "MultiPolygon" else [g["arcs"]]
        for poly in polys:
            yield [ring(arcs, r) for r in poly]


def main(src, dst):
    topo = json.load(open(src))
    cols = int(360 / STEP)
    rows = int((LAT_MAX - LAT_MIN) / STEP)
    px = 1 / (STEP / OVERSAMPLE)  # raster pixels per degree
    W, H = cols * OVERSAMPLE, rows * OVERSAMPLE
    img = Image.new("L", (W, H), 0)
    draw = ImageDraw.Draw(img)
    to_px = lambda p: ((p[0] + 180) * px, (LAT_MAX - p[1]) * px)
    for rings in polygons(topo):
        rings = [unwrap(r) for r in rings if len(r) > 2]
        if not rings:
            continue
        for off in (-360, 0, 360):  # a ring that was unwrapped past +-180 is drawn again on the other side
            shifted = [[(x + off, y) for x, y in r] for r in rings]
            draw.polygon([to_px(p) for p in shifted[0]], fill=255)
            for h in shifted[1:]:
                draw.polygon([to_px(p) for p in h], fill=0)
    small = img.resize((cols, rows), Image.BOX)
    bits = bytearray((cols * rows + 7) // 8)
    count = 0
    for i, v in enumerate((small.get_flattened_data() if hasattr(small, "get_flattened_data") else small.getdata())):
        if v >= THRESHOLD * 255:
            bits[i >> 3] |= 1 << (i & 7)
            count += 1
    out = {"step": STEP, "cols": cols, "rows": rows, "lon0": -180, "lat0": LAT_MAX,
           "bits": base64.b64encode(bytes(bits)).decode()}
    with open(dst, "w") as f:
        json.dump(out, f, separators=(",", ":"))
    print(f"{count} land dots, {len(out['bits'])} bytes")


if __name__ == "__main__":
    main(*sys.argv[1:3])
