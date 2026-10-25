#!/usr/bin/env python3
"""Build the encrypted love site.

Reads a folder of photos/videos plus a private story.json, and writes
docs/vault/: a public meta.json (salt, KDF settings, lock-screen text)
and AES-GCM encrypted blobs for the story manifest and every image.
Nothing private (names, captions, photos, dates) is written in plain text.

Usage:
  python3 tools/build.py --photos PHOTOS_DIR --story story.json \
      --state private/state.json --out docs [--password-file FILE]

The password is read from --password-file, $LOVE_PASSWORD, or a prompt.
The private state file keeps salt, key check and source->blob ids so a
rebuild only encrypts new photos and the git history stays small.
"""
import argparse
import base64
import datetime as dt
import getpass
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

from PIL import Image, ImageOps
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import pillow_heif

    pillow_heif.register_heif_opener()
except ImportError:  # HEIC files will be skipped with a warning
    pillow_heif = None

KDF_ITER = 600_000
SIZES = {"s": (960, 76), "l": (2048, 82)}  # long edge, WebP quality
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif", ".tif", ".tiff"}
VIDEO_EXT = {".mov", ".mp4", ".m4v"}
MANIFEST_VERSION = 1


def log(*a):
    print(*a, file=sys.stderr)


# ---------- crypto ----------

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    pw = unicodedata.normalize("NFC", password.strip()).encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(pw)


def seal(key: bytes, data: bytes) -> bytes:
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, data, None)


def key_check(key: bytes) -> str:
    return hashlib.sha256(b"love-site-key-check" + key).hexdigest()


# ---------- metadata ----------

def exif_info(img: Image.Image):
    """Return (datetime or None, (lat, lon) or None, camera model or "")."""
    try:
        ex = img.getexif()
    except Exception:
        return None, None, ""
    when = None
    try:
        sub = ex.get_ifd(0x8769)
        raw = sub.get(0x9003) or sub.get(0x9004) or ex.get(0x0132)
        if raw:
            when = dt.datetime.strptime(str(raw).strip("\x00").strip()[:19], "%Y:%m:%d %H:%M:%S")
    except Exception:
        when = None
    where = None
    try:
        g = ex.get_ifd(0x8825)
        if g.get(2) and g.get(4):
            deg = lambda v: float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
            lat = deg(g[2]) * (-1 if g.get(1) == "S" else 1)
            lon = deg(g[4]) * (-1 if g.get(3) == "W" else 1)
            where = (round(lat, 3), round(lon, 3))
    except Exception:
        where = None
    model = str(ex.get(0x0110) or "").strip("\x00").strip()
    return when, where, model


def video_info(path: Path):
    """Return (datetime or None, duration seconds, width, height, (lat, lon) or None)."""
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(path)],
            capture_output=True, text=True, check=True,
        ).stdout
        info = json.loads(out)
    except Exception:
        return None, 0, 0, 0, None
    tags = {k.lower(): v for k, v in (info.get("format", {}).get("tags") or {}).items()}
    raw = tags.get("com.apple.quicktime.creationdate") or tags.get("creation_time")
    when = None
    if raw:
        try:
            when = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if when.tzinfo and "com.apple.quicktime.creationdate" not in tags:
                when = when.astimezone()  # UTC creation_time -> local clock
            when = when.replace(tzinfo=None)
        except ValueError:
            when = None
    dur = float(info.get("format", {}).get("duration") or 0)
    w = h = 0
    rot = 0
    for s in info.get("streams", []):
        if s.get("codec_type") == "video":
            w, h = s.get("width", 0), s.get("height", 0)
            rot = int((s.get("tags") or {}).get("rotate", 0) or 0)
            for sd in s.get("side_data_list", []) or []:
                if "rotation" in sd:
                    rot = int(sd["rotation"])
            break
    if abs(rot) in (90, 270):
        w, h = h, w
    where = None
    iso = tags.get("com.apple.quicktime.location.iso6709") or tags.get("location")
    if iso:
        import re

        m = re.match(r"([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)", iso)
        if m:
            where = (round(float(m.group(1)), 3), round(float(m.group(2)), 3))
    return when, dur, w, h, where


def file_time(path: Path) -> dt.datetime:
    st = path.stat()
    ts = getattr(st, "st_birthtime", None) or st.st_mtime
    return dt.datetime.fromtimestamp(ts)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- image / video encoding ----------

def encode_sizes(img: Image.Image):
    img = ImageOps.exif_transpose(img)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.getbands() else "RGB")
    out = {}
    for name, (edge, q) in SIZES.items():
        im = img.copy()
        im.thumbnail((edge, edge), Image.LANCZOS)
        buf = io.BytesIO()
        # Saving without exif=... drops every metadata block (GPS, device, time).
        im.save(buf, "WEBP", quality=q, method=5)
        out[name] = (buf.getvalue(), im.size)
    return out


def average_color(img: Image.Image) -> str:
    im = ImageOps.exif_transpose(img).convert("RGB").resize((1, 1), Image.BILINEAR)
    r, g, b = im.getpixel((0, 0))
    return f"#{r:02x}{g:02x}{b:02x}"


def transcode_video(src: Path, tmpdir: Path):
    dst = tmpdir / (src.stem + ".mp4")
    poster = tmpdir / (src.stem + ".jpg")
    subprocess.run(
        ["ffmpeg", "-y", "-v", "error", "-i", str(src),
         "-map_metadata", "-1", "-map", "0:v:0", "-map", "0:a:0?",
         "-vf", "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(1280,ih))'",
         "-c:v", "libx264", "-preset", "slow", "-crf", "27", "-pix_fmt", "yuv420p",
         "-c:a", "aac", "-b:a", "96k", "-movflags", "+faststart", str(dst)],
        check=True,
    )
    subprocess.run(
        ["ffmpeg", "-y", "-v", "error", "-ss", "0.3", "-i", str(dst), "-frames:v", "1", "-q:v", "3", str(poster)],
        check=True,
    )
    return dst, poster


# ---------- Chinese font subsets ----------

PUNCT = "，。！？：；、“”‘’（）《》…—·～「」『』【】"


def load_font_table(font_dir: Path):
    """Map each WenKai chunk file to its unicode ranges, from the package CSS."""
    import re

    css = (font_dir / "lxgwwenkaigbscreen.css").read_text("utf-8")
    table = []
    for fname, rng in re.findall(r"src: url\('\./files/([^']+)'\).*?unicode-range: ([^\n}]+)", css, re.S):
        spans = []
        for part in rng.split(","):
            part = part.strip().upper().replace("U+", "")
            a, _, b = part.partition("-")
            spans.append((int(a, 16), int(b or a, 16)))
        table.append((font_dir / "files" / fname, spans))
    return table


def subset_font(table, text: str) -> bytes:
    """One woff2 holding only the glyphs needed for `text`, merged from the chunk files."""
    from fontTools import subset
    from fontTools.merge import Merger
    from fontTools.ttLib import TTFont

    need = {}
    for cp in sorted(set(map(ord, text + PUNCT + "".join(map(chr, range(0x20, 0x7F)))))):
        for path, spans in table:
            if any(a <= cp <= b for a, b in spans):
                need.setdefault(path, set()).add(cp)
                break
    parts = []
    for path, cps in need.items():
        font = TTFont(path)
        opts = subset.Options()
        opts.layout_features = ["*"]
        opts.notdef_outline = True
        sub = subset.Subsetter(opts)
        sub.populate(unicodes=cps)
        sub.subset(font)
        font.flavor = None
        buf = io.BytesIO()
        font.save(buf)
        buf.seek(0)
        parts.append(buf)
    merged = Merger().merge(parts) if len(parts) > 1 else TTFont(parts[0])
    merged.flavor = "woff2"
    out = io.BytesIO()
    merged.save(out)
    return out.getvalue()


# ---------- special days ----------

def expand_day(day):
    """A lunar birthday moves every year, so list its solar dates for the years ahead."""
    if "lunar" not in day:
        return day
    from lunardate import LunarDate

    month, dd = map(int, day["lunar"].split("-"))
    this_year = dt.date.today().year
    dates = []
    for y in range(this_year - 2, this_year + 40):
        try:
            solar = LunarDate(y, month, dd).to_solar_date()
        except ValueError:  # day 30 missing in a short month
            solar = LunarDate(y, month, dd - 1).to_solar_date()
        item = {"d": solar.isoformat()}
        if day.get("born"):
            item["age"] = y - int(day["born"])
        dates.append(item)
    out = {k: v for k, v in day.items() if k not in ("lunar", "born")}
    out["dates"] = dates
    return out


# ---------- places ----------

def km_between(a, b):
    import math

    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


def assign_places(media, places, place_of, hours=6):
    """Give each photo a place index. GPS decides first; a photo without GPS taken within a few
    hours of one that has a place (an underwater camera, a saved copy) joins that place.
    Only place names and city-level centres reach the site, never a photo's own coordinates."""
    if not places:
        return []
    for m in media:
        m.pop("place", None)
        if m["name"] in place_of:
            names = [p["name"] for p in places]
            if place_of[m["name"]] in names:
                m["place"] = names.index(place_of[m["name"]])
            continue
        if m.get("gps"):
            best = min(range(len(places)), key=lambda i: km_between(m["gps"], (places[i]["lat"], places[i]["lon"])))
            if km_between(m["gps"], (places[best]["lat"], places[best]["lon"])) <= places[best].get("km", 50):
                m["place"] = best
    timed = [(dt.datetime.fromisoformat(m["date"]), m["place"]) for m in media
             if "place" in m and m["dq"] != "unknown" and "T" in m["date"]]
    for m in media:
        if "place" in m or m.get("gps") or m["dq"] == "unknown" or "T" not in m["date"] or m["name"] in place_of:
            continue
        t = dt.datetime.fromisoformat(m["date"])
        near = min(timed, key=lambda x: abs(x[0] - t), default=None)
        if near and abs(near[0] - t) <= dt.timedelta(hours=hours):
            m["place"] = near[1]
    used = sorted({m["place"] for m in media if "place" in m})
    remap = {old: new for new, old in enumerate(used)}
    for m in media:
        if "place" in m:
            m["place"] = remap[m["place"]]
    return [{"name": places[i]["name"], "en": places[i].get("en", ""),
             "lat": round(places[i]["lat"], 2), "lon": round(places[i]["lon"], 2)} for i in used]


# ---------- cover mosaic ----------

MOSAIC_TILES, MOSAIC_COLS, MOSAIC_EDGE = 60, 8, 96  # the opening heart has 60 cells


def square_tile(path: Path, edge: int) -> Image.Image:
    with Image.open(path) as im:
        im.draft("RGB", (edge * 4, edge * 4))
        im = ImageOps.exif_transpose(im).convert("RGB")
    w, h = im.size
    s = min(w, h)
    left = (w - s) // 2
    top = int((h - s) * 0.3)  # portraits: keep the upper part, where faces usually are
    return im.crop((left, top, left + s, top + s)).resize((edge, edge), Image.LANCZOS)


def build_mosaic(media, sources, favorites, state, key, vault):
    """One small encrypted sprite of square thumbnails, so the opening heart needs a single request."""
    photos = [m for m in media if m["type"] == "photo" and m["digest"] in sources]
    if len(photos) < 8:
        return None
    fav = set(favorites)
    pool = [m for m in photos if m["name"] in fav] or photos
    if len(pool) < MOSAIC_TILES:
        rest = [m for m in photos if m not in pool]
        need = min(len(rest), MOSAIC_TILES - len(pool))
        pool = pool + [rest[int(i * len(rest) / need)] for i in range(need)] if need else pool
    if len(pool) > MOSAIC_TILES:
        pool = [pool[int(i * len(pool) / MOSAIC_TILES)] for i in range(MOSAIC_TILES)]
    pool.sort(key=lambda m: m["date"])
    digest = hashlib.sha256((f"v1-{MOSAIC_EDGE}" + "".join(m["digest"] for m in pool)).encode()).hexdigest()
    cached = state.get("mosaic")
    if not cached or cached["hash"] != digest or not (vault / f"{cached['id']}.bin").exists():
        rows = (len(pool) + MOSAIC_COLS - 1) // MOSAIC_COLS
        sheet = Image.new("RGB", (MOSAIC_COLS * MOSAIC_EDGE, rows * MOSAIC_EDGE), (20, 14, 22))
        for i, m in enumerate(pool):
            sheet.paste(square_tile(sources[m["digest"]], MOSAIC_EDGE),
                        ((i % MOSAIC_COLS) * MOSAIC_EDGE, (i // MOSAIC_COLS) * MOSAIC_EDGE))
        buf = io.BytesIO()
        sheet.save(buf, "WEBP", quality=74, method=5)
        cached = {"hash": digest, "id": secrets.token_hex(8)}
        (vault / f"{cached['id']}.bin").write_bytes(seal(key, buf.getvalue()))
        state["mosaic"] = cached
    return {"id": cached["id"], "n": len(pool), "cols": MOSAIC_COLS, "edge": MOSAIC_EDGE,
            "ids": [m["s"] for m in pool]}


# ---------- main ----------

def load_json(path: Path, default):
    if path and path.exists():
        return json.loads(path.read_text("utf-8"))
    return default


def get_password(args) -> str:
    if args.password_file:
        return Path(args.password_file).read_text("utf-8").strip()
    if os.environ.get("LOVE_PASSWORD"):
        return os.environ["LOVE_PASSWORD"]
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Again: "):
        sys.exit("Passwords differ.")
    return pw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--photos", required=True, type=Path)
    ap.add_argument("--story", required=True, type=Path)
    ap.add_argument("--state", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--password-file")
    ap.add_argument("--key-file", type=Path, help="private file keeping the derived key, so rebuilds need no password")
    ap.add_argument("--rekey", action="store_true", help="new salt; re-encrypt everything")
    ap.add_argument("--max-video-seconds", type=float, default=90)
    ap.add_argument("--zh-font", type=Path, help="lxgw-wenkai-screen-webfont package dir")
    args = ap.parse_args()

    story = load_json(args.story, {})
    state = load_json(args.state, {})
    saved_key = load_json(args.key_file, None) if args.key_file else None

    if args.rekey or "salt" not in state:
        state = {"salt": base64.b64encode(secrets.token_bytes(16)).decode(), "iter": KDF_ITER, "media": {}}
        saved_key = None
    if saved_key and saved_key.get("salt") == state["salt"] and not (args.password_file or os.environ.get("LOVE_PASSWORD")):
        key = base64.b64decode(saved_key["key"])
    else:
        key = derive_key(get_password(args), base64.b64decode(state["salt"]), state["iter"])
        if args.key_file:
            args.key_file.parent.mkdir(parents=True, exist_ok=True)
            args.key_file.write_text(json.dumps({"salt": state["salt"], "key": base64.b64encode(key).decode()}), "utf-8")
    if state.get("check") and state["check"] != key_check(key):
        sys.exit("Password differs from the one this vault was built with. Use --rekey to change it.")
    state["check"] = key_check(key)

    vault = args.out / "vault"
    vault.mkdir(parents=True, exist_ok=True)

    exclude = set(story.get("exclude", []))
    files = sorted(p for p in args.photos.rglob("*") if p.is_file() and not p.name.startswith("."))
    stems_with_still = {p.stem.lower() for p in files if p.suffix.lower() in IMAGE_EXT}

    media = []
    sources = {}
    seen = set()
    used_blobs = {"m"}
    tmp = Path(tempfile.mkdtemp(prefix="love-build-"))
    try:
        for p in files:
            ext = p.suffix.lower()
            if p.name in exclude or (ext not in IMAGE_EXT and ext not in VIDEO_EXT):
                continue
            if ext in VIDEO_EXT and p.stem.lower() in stems_with_still:
                continue  # motion half of a Live Photo; the still is enough
            if ext in {".heic", ".heif"} and pillow_heif is None:
                log("skip (no HEIC support):", p.name)
                continue
            digest = sha256_file(p)
            if digest in seen:
                log("duplicate:", p.name)
                continue
            seen.add(digest)
            entry = state["media"].get(digest)
            have = entry and all((vault / f"{entry[k]}.bin").exists() for k in ("s", "l", "v") if k in entry)
            if not have:
                entry = {"name": p.name}
                if ext in VIDEO_EXT:
                    when, dur, w, h, where = video_info(p)
                    if dur > args.max_video_seconds:
                        log(f"skip video longer than {args.max_video_seconds:.0f}s:", p.name)
                        continue
                    mp4, poster = transcode_video(p, tmp)
                    with Image.open(poster) as im:
                        sizes = encode_sizes(im)
                        entry["c"] = average_color(im)
                    entry["v"] = secrets.token_hex(8)
                    (vault / f"{entry['v']}.bin").write_bytes(seal(key, mp4.read_bytes()))
                    entry["dur"] = round(dur, 1)
                    entry["type"] = "video"
                    model = "video"
                else:
                    with Image.open(p) as im:
                        when, where, model = exif_info(im)
                        sizes = encode_sizes(im)
                        entry["c"] = average_color(im)
                    entry["type"] = "photo"
                    # Screenshots and app re-saves stamp the save time and drop the camera model.
                    if when and not model and abs((dt.datetime.now() - when).days) < 3:
                        when = None
                for k, (data, size) in sizes.items():
                    entry[k] = secrets.token_hex(8)
                    (vault / f"{entry[k]}.bin").write_bytes(seal(key, data))
                entry["w"], entry["h"] = sizes["l"][1]
                entry["dq"] = "exif" if when else "unknown"
                entry["date"] = (when or file_time(p)).isoformat(timespec="seconds")
                if where:
                    entry["gps"] = where  # private state only; never written to the site
                state["media"][digest] = entry
                log("added:", p.name, entry["date"])
            entry["name"] = p.name
            sources[digest] = p
            media.append({**entry, "digest": digest})  # a copy, so date overrides never leak into the state
            used_blobs.update(entry[k] for k in ("s", "l", "v") if k in entry)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Date overrides from story.json win over EXIF.
    dates = story.get("dates", {})
    for m in media:
        if m["name"] in dates:
            d = dates[m["name"]]
            # "~2024-05-04" marks a date worked out from file times or neighbours, not read from the photo.
            m["dq"] = "approx" if d.startswith("~") else "manual"
            m["date"] = d.lstrip("~")
    media.sort(key=lambda m: m["date"])
    unknown = [m["name"] for m in media if m["dq"] == "unknown"]
    if unknown:
        log(f"{len(unknown)} without a real shooting date (add them under \"dates\"):", ", ".join(unknown))

    by_name = {m["name"]: m for m in media}
    captions = story.get("captions", {})
    places = assign_places(media, story.get("places", []), story.get("placeOf", {}))

    def ref(name):
        return by_name[name]["s"] if name in by_name else None

    manifest = {
        "v": MANIFEST_VERSION,
        "built": dt.datetime.now().isoformat(timespec="seconds"),
        "names": story.get("names", ["", ""]),
        "since": story.get("since"),
        "tagline": story.get("tagline", ""),
        "cover": ref(story.get("cover")) or (media[0]["s"] if media else None),
        "chapters": story.get("chapters", {}),
        "milestones": [
            {**ms, "photo": ref(ms.get("photo"))} for ms in story.get("milestones", [])
        ],
        "letter": story.get("letter"),
        "days": [expand_day(d) for d in story.get("days", [])],
        "hero": [by_name[n]["s"] for n in story.get("hero", []) if n in by_name],
        "places": places,
        "media": [
            {
                "id": m["s"], "l": m["l"], "v": m.get("v"), "type": m["type"],
                "w": m["w"], "h": m["h"], "c": m["c"], "date": m["date"], "dq": m["dq"],
                "dur": m.get("dur"), "cap": captions.get(m["name"], ""),
                "fav": m["name"] in set(story.get("favorites", [])),
                "p": m.get("place"),
            }
            for m in media
        ],
    }
    mosaic = build_mosaic(media, sources, story.get("favorites", []), state, key, vault)
    if mosaic:
        manifest["mosaic"] = mosaic
        used_blobs.add(mosaic["id"])
    lock = story.get("lock", {})
    if args.zh_font:
        table = load_font_table(args.zh_font)
        ui_text = "".join(
            (args.out / f).read_text("utf-8") for f in ("index.html", "assets/love.js")
        ) + "".join(str(v) for v in lock.values())
        (args.out / "assets/fonts/ui-kai.woff2").write_bytes(subset_font(table, ui_text))
        story_text = ui_text + json.dumps(manifest, ensure_ascii=False)
        chars = "".join(sorted(set(story_text)))
        font_hash = hashlib.sha256(chars.encode()).hexdigest()
        font = state.get("font")
        if not font or font["hash"] != font_hash or not (vault / f"{font['id']}.bin").exists():
            font = {"hash": font_hash, "id": secrets.token_hex(8)}
            (vault / f"{font['id']}.bin").write_bytes(seal(key, subset_font(table, chars)))
            state["font"] = font
        manifest["font"] = font["id"]
        used_blobs.add(font["id"])
    (vault / "m.bin").write_bytes(seal(key, json.dumps(manifest, ensure_ascii=False).encode()))

    meta = {
        "v": 1,
        "kdf": "PBKDF2-SHA256",
        "iter": state["iter"],
        "salt": state["salt"],
        "title": lock.get("title", "Our Story"),
        "subtitle": lock.get("subtitle", "只属于我们两个人的地方"),
        "hint": lock.get("hint", ""),
    }
    (vault / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n", "utf-8")

    # Drop blobs that no longer belong to any photo (removed or excluded).
    stale = [f for f in vault.glob("*.bin") if f.stem not in used_blobs]
    for f in stale:
        f.unlink()

    args.state.parent.mkdir(parents=True, exist_ok=True)
    args.state.write_text(json.dumps(state, ensure_ascii=False, indent=1), "utf-8")
    total = sum(f.stat().st_size for f in vault.glob("*.bin"))
    log(f"done: {len(media)} items, {total / 1e6:.1f} MB encrypted, removed {len(stale)} stale blobs")


if __name__ == "__main__":
    main()
