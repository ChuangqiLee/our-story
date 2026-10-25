# Our Story

A private, password-locked story site for two people, served by GitHub Pages from `docs/`.

Everything personal (names, dates, captions, the letter, every photo and video, and the Chinese font subset) is encrypted with AES-256-GCM before it is committed. The key comes from the password through PBKDF2-SHA256 (600,000 rounds) and is derived in the visitor's browser; the password itself is never stored in this repository. Photos are re-encoded as WebP, which drops all metadata, including GPS location.

## Layout

- `docs/index.html`, `docs/assets/` – the page, styles, script and public fonts
- `docs/vault/meta.json` – public lock-screen text and KDF salt
- `docs/vault/*.bin` – encrypted manifest (`m.bin`) and media
- `tools/build.py` – builds the vault from a photo folder and a private `story.json`
- `story.example.json` – the shape of `story.json` (the real one is kept out of this repo)

## Build

```sh
pip install pillow pillow-heif cryptography fonttools brotli
python3 tools/build.py --photos PHOTOS --story story.json --state private/state.json \
    --out docs --zh-font path/to/lxgw-wenkai-screen-webfont
```

The password is read from `--password-file`, `$LOVE_PASSWORD`, or a prompt. `state.json` remembers which photos were already encrypted, so later builds only add new ones.
