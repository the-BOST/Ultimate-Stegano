"""Image steganography analysis: EXIF, LSB, bit-planes, filters, steghide."""

from __future__ import annotations

import os

import numpy as np

from . import utils

try:
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = None
    _HAVE_PIL = True
except Exception:  # pragma: no cover
    _HAVE_PIL = False


# ---------------------------------------------------------------------------
# metadata
# ---------------------------------------------------------------------------
def analyze_metadata(filepath: str, outdir: str, flag_rx) -> list[dict]:
    findings: list[dict] = []
    report: list[str] = []

    if utils.have_tool("exiftool"):
        rc, out, _ = utils.run(["exiftool", "-a", "-u", "-g1", filepath])
        if out:
            report.append("=== exiftool ===\n" + out)
    else:
        try:
            import exifread
            with open(filepath, "rb") as fh:
                tags = exifread.process_file(fh, details=True)
            report.append("=== exifread ===")
            for k, v in tags.items():
                report.append(f"{k}: {v}")
        except Exception as exc:
            report.append(f"(exif read failed: {exc})")

    text = "\n".join(report)
    if text.strip():
        path = os.path.join(outdir, "EXIF.txt")
        utils.write_text(path, text)
        utils.log_info("Metadata written -> EXIF.txt")
        flags = utils.find_flags(text, flag_rx)
        susp = [ln for ln in report
                if any(s in ln for s in ("UserComment", "Comment",
                                         "MakerNote", "XPComment",
                                         "ImageDescription"))]
        if flags:
            for f in flags:
                utils.log_hit(f"flag in metadata: {f}")
            findings.append({
                "category": "Metadata flag",
                "detail": "Flag found in EXIF/metadata",
                "confidence": "high", "flags": flags,
                "artifacts": ["EXIF.txt"],
            })
        elif susp:
            findings.append({
                "category": "Suspicious metadata field",
                "detail": f"{len(susp)} comment/maker field(s) present",
                "confidence": "low", "flags": [],
                "artifacts": ["EXIF.txt"],
            })
    return findings


# ---------------------------------------------------------------------------
# LSB extraction + bit planes
# ---------------------------------------------------------------------------
def _load_rgb(filepath: str):
    img = Image.open(filepath)
    mode = img.mode
    if mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA" if "A" in mode else "RGB")
    return img


def analyze_lsb(filepath: str, outdir: str, flag_rx) -> list[dict]:
    findings: list[dict] = []
    if not _HAVE_PIL:
        return findings
    try:
        img = _load_rgb(filepath)
    except Exception as exc:
        utils.log_warn(f"cannot open image for LSB: {exc}")
        return findings

    arr = np.asarray(img)
    if arr.ndim == 2:
        arr = arr[:, :, None]
    h, w = arr.shape[:2]
    channels = arr.shape[2]
    names = "RGBA"[:channels] if channels <= 4 else [str(i) for i in range(channels)]

    bit_dir = utils.ensure_dir(os.path.join(outdir, "bitplanes"))
    lsb_dir = utils.ensure_dir(os.path.join(outdir, "lsb"))

    # bit-plane images + LSB bitstreams per channel
    for ci in range(channels):
        chan = arr[:, :, ci]
        for bit in range(8):
            plane = ((chan >> bit) & 1) * 255
            Image.fromarray(plane.astype(np.uint8)).save(
                os.path.join(bit_dir, f"{names[ci]}_{bit}.png"))

        # pack LSBs (bit 0) row-major into bytes
        bits = (chan & 1).flatten()
        nbytes = len(bits) // 8
        packed = np.packbits(bits[: nbytes * 8]).tobytes()
        raw_path = os.path.join(lsb_dir, f"lsb_{names[ci]}.bin")
        with open(raw_path, "wb") as fh:
            fh.write(packed)

        from .binary_analyzer import extract_strings
        s = "\n".join(extract_strings(packed, 4))
        if s:
            utils.write_text(os.path.join(lsb_dir, f"lsb_{names[ci]}_strings.txt"), s)
            flags = utils.find_flags(s, flag_rx)
            if flags:
                for f in flags:
                    utils.log_hit(f"flag in LSB channel {names[ci]}: {f}")
                findings.append({
                    "category": "LSB steganography",
                    "detail": f"Flag recovered from channel {names[ci]} LSB plane",
                    "confidence": "high", "flags": flags,
                    "artifacts": [os.path.relpath(raw_path, outdir)],
                })

    utils.log_info(f"Bit-planes ({channels}×8) + LSB bitstreams written")

    # stegano library (LSB text hidden by common CTF tools)
    try:
        from stegano import lsb
        msg = lsb.reveal(filepath)
        if msg:
            utils.log_hit(f"stegano.lsb hidden message: {msg[:80]}")
            findings.append({
                "category": "LSB steganography (stegano)",
                "detail": f"Hidden message: {msg[:120]}",
                "confidence": "high",
                "flags": utils.find_flags(msg, flag_rx) or [msg[:120]],
                "artifacts": [],
            })
    except Exception:
        pass  # not every PNG carries a stegano payload

    # chi-square-ish LSB randomness check on first channel
    chan0 = arr[:, :, 0].flatten()
    ones = int((chan0 & 1).sum())
    ratio = ones / len(chan0)
    if 0.49 < ratio < 0.51 and channels and h * w > 4096:
        findings.append({
            "category": "LSB randomness",
            "detail": f"LSB set-ratio {ratio:.4f} ≈ 0.5 — consistent with "
                      f"hidden data (vs natural image bias)",
            "confidence": "low", "flags": [], "artifacts": [],
        })
    return findings


# ---------------------------------------------------------------------------
# StegSolve-like filters
# ---------------------------------------------------------------------------
def analyze_filters(filepath: str, outdir: str) -> list[dict]:
    if not _HAVE_PIL:
        return []
    try:
        img = _load_rgb(filepath).convert("RGB")
    except Exception:
        return []
    arr = np.asarray(img)
    fdir = utils.ensure_dir(os.path.join(outdir, "filters"))

    # per-channel isolation
    for ci, name in enumerate("RGB"):
        iso = np.zeros_like(arr)
        iso[:, :, ci] = arr[:, :, ci]
        Image.fromarray(iso).save(os.path.join(fdir, f"plane_{name}.png"))

    # bit-level amplification (LSB×255), inversion, XOR 0xFF
    Image.fromarray(((arr & 1) * 255).astype(np.uint8)).save(
        os.path.join(fdir, "lsb_amplified.png"))
    Image.fromarray((255 - arr).astype(np.uint8)).save(
        os.path.join(fdir, "inverted.png"))
    Image.fromarray((arr ^ 0xFF).astype(np.uint8)).save(
        os.path.join(fdir, "xor_ff.png"))
    # gray + histogram-ish equalize via simple stretch
    gray = np.asarray(_load_rgb(filepath).convert("L"))
    lo, hi = gray.min(), gray.max()
    if hi > lo:
        stretched = ((gray - lo) * (255.0 / (hi - lo))).astype(np.uint8)
        Image.fromarray(stretched).save(os.path.join(fdir, "contrast_stretch.png"))

    utils.log_info("StegSolve-like filter set written -> filters/")
    return [{
        "category": "Visual filters",
        "detail": "Color-plane / XOR / inversion / LSB-amplified renders "
                  "generated for manual inspection",
        "confidence": "low", "flags": [],
        "artifacts": ["filters/"],
    }]


# ---------------------------------------------------------------------------
# steghide / zsteg / outguess
# ---------------------------------------------------------------------------
def _steghide_record(payload: bytes, pw: str, out_file: str,
                     outdir: str, ctx) -> dict:
    text = payload.decode("latin-1", "replace")
    flags = utils.find_flags(text, ctx.get("flag_rx"))
    utils.log_hit(f"steghide extracted with password {pw!r} "
                  f"({utils.human_size(len(payload))})")
    return {
        "category": "steghide payload",
        "detail": f"Extracted {utils.human_size(len(payload))} with "
                  f"password '{pw or '(empty)'}'",
        "confidence": "high", "flags": flags,
        "artifacts": [os.path.relpath(out_file, outdir)],
    }


def analyze_steghide(filepath: str, outdir: str, ctx) -> list[dict]:
    import itertools
    findings: list[dict] = []
    ext = ctx.get("ext", "")
    if ext not in ("jpg", "jpeg", "bmp", "wav", "au"):
        return findings  # steghide only supports these carriers
    if not utils.have_tool("steghide"):
        utils.log_warn("steghide not installed — skipping")
        return findings

    extract_dir = utils.ensure_dir(os.path.join(outdir, "steghide"))
    out_file = os.path.join(extract_dir, "steghide_out.bin")

    # Fast path: stegseek rips through rockyou in seconds (C, multithreaded).
    if ctx.get("brute") and ctx.get("rockyou") and utils.have_tool("stegseek"):
        utils.log_info("stegseek + rockyou.txt (fast steghide cracking)…")
        rc, out, err = utils.run(
            ["stegseek", "--crack", filepath, ctx["rockyou"], out_file],
            timeout=ctx.get("photorec_timeout", 600))
        if os.path.exists(out_file) and os.path.getsize(out_file):
            with open(out_file, "rb") as fh:
                payload = fh.read()
            pw = ""
            for line in (out + err).splitlines():
                if "passphrase" in line.lower():
                    pw = line.split('"')[1] if '"' in line else line
            findings.append(_steghide_record(payload, pw, out_file, outdir, ctx))
            return findings

    # Portable path: spawn steghide per password. rockyou is huge, so the cap
    # matters; empty password is tried first (very common in CTFs).
    log: list[str] = []
    cap = ctx.get("max_pw", 2000)
    candidates = itertools.chain([""], utils.password_candidates(ctx))
    tried = 0
    if ctx.get("brute"):
        utils.log_warn("steghide brute via rockyou is slow without stegseek — "
                       f"capped at {cap}; install stegseek for full runs")
    bar = utils.ProgressBar(min(cap + 1, utils.candidate_total(ctx) + 1),
                            "steghide brute")
    for pw in itertools.islice(candidates, cap + 1):
        tried += 1
        bar.update()
        rc, out, err = utils.run(
            ["steghide", "extract", "-sf", filepath, "-p", pw,
             "-xf", out_file, "-f"], timeout=30)
        log.append(f"pw={pw!r} rc={rc} {err.strip()[:80]}")
        if rc == 0 and os.path.exists(out_file) and os.path.getsize(out_file):
            bar.finish()
            findings.append(_steghide_record(payload=open(out_file, "rb").read(),
                                             pw=pw, out_file=out_file,
                                             outdir=outdir, ctx=ctx))
            break
    bar.finish()
    utils.write_text(os.path.join(extract_dir, "attempts.log"), "\n".join(log))

    if not findings:
        # Advisory: these carriers *can* hold steghide data; flag the chance.
        findings.append({
            "category": "Possible steghide payload",
            "detail": f"{ext.upper()} is a steghide carrier; no payload found "
                      f"after {tried} password(s). Retry with --brute "
                      f"(rockyou.txt) and/or install stegseek.",
            "confidence": "low", "flags": [], "artifacts": [],
        })
    return findings


def analyze_zsteg(filepath: str, outdir: str, ctx) -> list[dict]:
    if ctx.get("ext") not in ("png", "bmp"):
        return []
    if not utils.have_tool("zsteg"):
        utils.log_warn("zsteg not installed — relying on native LSB pass")
        return []
    rc, out, _ = utils.run(["zsteg", "-a", filepath], timeout=120)
    if not out:
        return []
    utils.write_text(os.path.join(outdir, "zsteg.txt"), out)
    flags = utils.find_flags(out, ctx.get("flag_rx"))
    if flags:
        for f in flags:
            utils.log_hit(f"zsteg flag: {f}")
        return [{
            "category": "zsteg", "detail": "Flag found by zsteg",
            "confidence": "high", "flags": flags, "artifacts": ["zsteg.txt"],
        }]
    return [{
        "category": "zsteg", "detail": "zsteg output captured",
        "confidence": "low", "flags": [], "artifacts": ["zsteg.txt"],
    }]


# ---------------------------------------------------------------------------
# dispatcher entry
# ---------------------------------------------------------------------------
def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    flag_rx = ctx.get("flag_rx")
    findings: list[dict] = []
    findings += analyze_metadata(filepath, outdir, flag_rx)
    findings += analyze_lsb(filepath, outdir, flag_rx)
    findings += analyze_filters(filepath, outdir)
    findings += analyze_zsteg(filepath, outdir, ctx)
    findings += analyze_steghide(filepath, outdir, ctx)
    return findings
