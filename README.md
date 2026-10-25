# Our Story

A private, password-locked story site for two people. The site is `docs/`; GitHub Pages serves it from the `gh-pages` branch, which is `docs/` split out with `git subtree split --prefix docs -b gh-pages`.

Everything personal (names, dates, captions, the letter, every photo and video, and the Chinese font subset) is encrypted with AES-256-GCM before it is committed. The key comes from the password through PBKDF2-SHA256 (600,000 rounds) and is derived in the visitor's browser; the password itself is never stored in this repository. Photos are re-encoded as WebP, which drops all metadata, including GPS location.

## Layout

- `docs/index.html`, `docs/assets/` – the page, styles, script and public fonts
- `docs/vault/meta.json` – public lock-screen text and KDF salt
- `docs/vault/*.bin` – encrypted manifest (`m.bin`) and media
- `tools/build.py` – builds the vault from a photo folder and a private `story.json`
- `tools/make_map.py` – turns Natural Earth land (npm `world-atlas`, `land-50m.json`) into `docs/assets/land.json`, the dot grid behind the travel map
- `story.example.json` – the shape of `story.json` (the real one is kept out of this repo). `hero` lists the slideshow photos, `places` names the spots photo GPS is matched to (only names and city-level centres reach the site), and a date starting with `~` marks a guessed date, shown to the month only.

## Build

```sh
pip install pillow pillow-heif cryptography fonttools brotli
python3 tools/build.py --photos PHOTOS --story story.json --state private/state.json \
    --out docs --zh-font path/to/lxgw-wenkai-screen-webfont
```

The password is read from `--password-file`, `$LOVE_PASSWORD`, or a prompt. `state.json` remembers which photos were already encrypted, so later builds only add new ones.
