"""Generic binary analysis: strings, entropy, encodings, file carving.

Every finding is a dict:
    {"category": str, "detail": str, "confidence": "low|medium|high",
     "flags": [str, ...], "artifacts": [relpath, ...]}
"""

from __future__ import annotations

import base64
import binascii
import codecs
import os
import re

from . import utils
from .utils import C, _c


# ---------------------------------------------------------------------------
# strings extraction
# ---------------------------------------------------------------------------
def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """ASCII + UTF-16LE printable runs, like `strings -a -e {s,l}`."""
    out: list[str] = []
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("ascii", "replace"))
    # UTF-16LE (common in Windows artefacts)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        out.append(m.group().decode("utf-16-le", "replace"))
    return out


def analyze_strings(data: bytes, outdir: str, flag_rx) -> list[dict]:
    findings: list[dict] = []
    strings = extract_strings(data)
    joined = "\n".join(strings)
    path = os.path.join(outdir, "strings.txt")
    utils.write_text(path, joined)
    utils.log_info(f"Extracted {len(strings)} strings -> strings.txt")

    flags = utils.find_flags(joined, flag_rx)
    if flags:
        for f in flags:
            utils.log_hit(f"flag-like string: {f}")
        findings.append({
            "category": "Strings / flag pattern",
            "detail": f"{len(flags)} flag-like token(s) in raw strings",
            "confidence": "high",
            "flags": flags,
            "artifacts": [os.path.relpath(path, outdir)],
        })

    # interesting keywords
    kw = re.findall(
        r"(?i)\b(password|passwd|secret|private[_ ]?key|BEGIN [A-Z ]*PRIVATE|"
        r"ssh-rsa|xoxb-|AKIA[0-9A-Z]{16})\b[^\n]{0,60}",
        joined,
    )
    if kw:
        findings.append({
            "category": "Sensitive keyword",
            "detail": f"{len(kw)} credential/secret keyword hit(s) in strings",
            "confidence": "medium",
            "flags": [],
            "artifacts": [os.path.relpath(path, outdir)],
        })
    return findings


# ---------------------------------------------------------------------------
# alternative encodings
# ---------------------------------------------------------------------------
def _try_decode(blob: str) -> bytes | None:
    blob = blob.strip()
    try:
        raw = base64.b64decode(blob, validate=True)
        if raw and _mostly_printable(raw):
            return raw
    except (binascii.Error, ValueError):
        pass
    return None


def _mostly_printable(data: bytes, ratio: float = 0.85) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (9, 10, 13))
    return printable / len(data) >= ratio


def analyze_encodings(data: bytes, outdir: str, flag_rx) -> list[dict]:
    """Hunt base64 / hex / rot13 encoded flags inside the file's text."""
    findings: list[dict] = []
    text = data.decode("latin-1", "replace")
    report: list[str] = []

    # base64 blobs
    for m in re.finditer(r"(?:[A-Za-z0-9+/]{16,}={0,2})", text):
        decoded = _try_decode(m.group())
        if not decoded:
            continue
        dec_text = decoded.decode("latin-1", "replace")
        flags = utils.find_flags(dec_text, flag_rx, generic=False)
        if flags:
            for f in flags:
                utils.log_hit(f"base64-decoded flag: {f}")
            report.append(f"[base64] {m.group()[:40]}... -> {dec_text[:120]}")
            findings.append({
                "category": "Encoded flag (base64)",
                "detail": "Flag recovered after base64 decode",
                "confidence": "high",
                "flags": flags,
                "artifacts": [],
            })

    # rot13 whole-text pass
    rot = codecs.decode(text, "rot_13")
    flags = utils.find_flags(rot, flag_rx, generic=False)
    if flags:
        for f in flags:
            utils.log_hit(f"rot13-decoded flag: {f}")
        report.append("[rot13] flags: " + ", ".join(flags))
        findings.append({
            "category": "Encoded flag (rot13)",
            "detail": "Flag recovered after ROT13",
            "confidence": "high",
            "flags": flags,
            "artifacts": [],
        })

    # hex blobs
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){8,}", text):
        try:
            decoded = bytes.fromhex(m.group())
        except ValueError:
            continue
        dec_text = decoded.decode("latin-1", "replace")
        flags = utils.find_flags(dec_text, flag_rx, generic=False)
        if flags:
            for f in flags:
                utils.log_hit(f"hex-decoded flag: {f}")
            report.append(f"[hex] {m.group()[:40]}... -> {dec_text[:120]}")
            findings.append({
                "category": "Encoded flag (hex)",
                "detail": "Flag recovered after hex decode",
                "confidence": "high",
                "flags": flags,
                "artifacts": [],
            })

    if report:
        utils.write_text(os.path.join(outdir, "encodings.txt"), "\n".join(report))
    return findings


# ---------------------------------------------------------------------------
# entropy
# ---------------------------------------------------------------------------
def analyze_entropy(data: bytes, outdir: str) -> list[dict]:
    findings: list[dict] = []
    overall = utils.shannon_entropy(data)
    lines = [f"File size : {utils.human_size(len(data))} ({len(data)} bytes)",
             f"Overall entropy : {overall:.4f} bits/byte"]

    # windowed entropy to spot embedded compressed/encrypted regions
    win = 4096
    windows = []
    for i in range(0, len(data), win):
        chunk = data[i:i + win]
        if len(chunk) >= 256:
            windows.append((i, utils.shannon_entropy(chunk)))
    high = [(off, e) for off, e in windows if e > 7.8]
    lines.append(f"High-entropy windows (>7.8): {len(high)} / {len(windows)}")
    for off, e in high[:30]:
        lines.append(f"  offset 0x{off:08x}  entropy {e:.3f}")

    utils.write_text(os.path.join(outdir, "entropy_report.txt"), "\n".join(lines))
    utils.log_info(f"Overall entropy {overall:.3f} bits/byte")

    if overall > 7.5:
        findings.append({
            "category": "High entropy",
            "detail": f"Whole-file entropy {overall:.3f} — likely "
                      f"compressed/encrypted payload present",
            "confidence": "medium",
            "flags": [],
            "artifacts": ["entropy_report.txt"],
        })
    return findings


# ---------------------------------------------------------------------------
# file carving (binwalk if present, plus a native signature scan)
# ---------------------------------------------------------------------------
def _native_carve(data: bytes, outdir: str, source_ext: str) -> list[str]:
    """Carve only footer-delimited embedded files, plus validated ZIPs.

    Each signature here has a real end marker (or a validator), so a spurious
    header match in high-entropy data cannot carve the whole file to EOF — the
    footerless 2-byte signatures (BM/MZ/RIFF/…) that caused runaway gigabyte
    carves are intentionally NOT carved, only detected.
    """
    carved: list[str] = []
    extract_dir = utils.ensure_dir(os.path.join(outdir, "extracted_files"))
    host = {"jpeg": "jpg", "tif": "tiff"}.get(source_ext, source_ext)

    def _write(ext: str, idx: int, blob: bytes) -> bool:
        out = os.path.join(extract_dir, f"{ext}_0x{idx:x}.{ext}")
        with open(out, "wb") as fh:
            fh.write(blob)
        carved.append(os.path.relpath(out, outdir))
        utils.log_ok(f"Carved embedded {ext} at offset 0x{idx:x} "
                     f"({utils.human_size(len(blob))})")
        return len(carved) >= utils.CARVE_MAX_FILES

    # 1) footer-delimited formats (PNG/JPG/GIF/PDF)
    for header, footer, ext in utils.CARVE_SIGNATURES:
        if ext == host:
            continue  # host's own structure, not a hidden file
        start = 1     # skip the host header at offset 0
        while True:
            idx = data.find(header, start)
            if idx <= 0:
                break
            fidx = data.find(footer, idx + len(header))
            if fidx == -1:
                break  # no closing footer -> not a complete embedded file
            end = fidx + len(footer)
            blob = data[idx:end]
            # advance past this match regardless, so we never loop forever
            start = end
            if len(blob) < 32 or len(blob) > utils.CARVE_MAX_BLOB:
                continue
            if _write(ext, idx, blob):
                return carved

    # 2) ZIP: validate each candidate slice with zipfile before writing, so
    # random "PK\x03\x04" hits in binary data are rejected instead of dumped.
    if host not in ("zip", "jar", "apk"):
        carved.extend(_carve_zips(data, extract_dir, outdir,
                                  utils.CARVE_MAX_FILES - len(carved)))
    return carved


def _carve_zips(data: bytes, extract_dir: str, outdir: str,
                budget: int) -> list[str]:
    import io
    import zipfile
    out: list[str] = []
    if budget <= 0:
        return out
    start = 1
    while True:
        idx = data.find(b"PK\x03\x04", start)
        if idx <= 0:
            break
        start = idx + 4
        slice_ = data[idx:]
        if len(slice_) < 64 or len(slice_) > utils.CARVE_MAX_BLOB:
            continue
        try:
            zf = zipfile.ZipFile(io.BytesIO(slice_))
            names = zf.namelist()
            if not names:
                continue
        except Exception:
            continue  # spurious PK match, not a real zip
        p = os.path.join(extract_dir, f"zip_0x{idx:x}.zip")
        with open(p, "wb") as fh:
            fh.write(slice_)
        out.append(os.path.relpath(p, outdir))
        utils.log_ok(f"Carved embedded zip at offset 0x{idx:x} "
                     f"({len(names)} entrie(s), {utils.human_size(len(slice_))})")
        if len(out) >= budget:
            break
    return out


def analyze_carving(data: bytes, filepath: str, outdir: str,
                    source_ext: str, ctx: dict) -> list[dict]:
    findings: list[dict] = []

    # binwalk (external) for a professional signature map
    if utils.have_tool("binwalk"):
        rc, out, err = utils.run(["binwalk", filepath], timeout=120)
        if rc == 0 and out:
            utils.write_text(os.path.join(outdir, "binwalk.txt"), out)
            # count non-header signatures
            sig_lines = [ln for ln in out.splitlines()
                         if re.match(r"^\d+\s+0x", ln)]
            if len(sig_lines) > 1:
                utils.log_info(f"binwalk mapped {len(sig_lines)} signatures")
    else:
        utils.log_warn("binwalk not installed — using native carver only")

    carved = _native_carve(data, outdir, source_ext)
    if carved:
        findings.append({
            "category": "Embedded file (carving)",
            "detail": f"{len(carved)} embedded file(s) carved from the host",
            "confidence": "high",
            "flags": [],
            "artifacts": carved,
        })
        # recurse into carved archives (they are often password-protected)
        findings += _recurse_carved_archives(carved, outdir, ctx)
    return findings


def _recurse_carved_archives(carved: list[str], outdir: str,
                             ctx: dict) -> list[dict]:
    """If a carved file is itself an archive, extract/brute it in turn."""
    from . import archive_analyzer
    findings: list[dict] = []
    for rel in carved:
        if not rel.lower().endswith((".zip", ".7z", ".rar")):
            continue
        full = os.path.join(outdir, rel)
        sub = utils.ensure_dir(os.path.join(outdir, "carved_" +
                               os.path.basename(rel)))
        sctx = dict(ctx)
        sctx["ext"] = rel.rsplit(".", 1)[-1].lower()
        try:
            findings += archive_analyzer.analyze(full, sub, sctx)
        except Exception as exc:
            utils.log_warn(f"carved archive analysis failed: {exc}")
    return findings


# ---------------------------------------------------------------------------
# PhotoRec recovery — only for file types that make sense (disk/raw images)
# ---------------------------------------------------------------------------
PHOTOREC_EXTS = {
    "dd", "img", "raw", "iso", "dmp", "mem", "bin", "vmdk", "vhd", "vhdx",
    "qcow2", "e01", "001", "vdi", "sparseimage",
}
_PHOTOREC_FILE_KW = (
    "filesystem", "boot sector", "disk image", "partition", "dos/mbr",
    "ext2", "ext3", "ext4", "fat ", "ntfs", "iso 9660", "swap", "squashfs",
    "master boot record", "sqlite",
)


def _photorec_appropriate(filepath: str, ext: str) -> bool:
    if ext in PHOTOREC_EXTS:
        return True
    rc, out, _ = utils.run(["file", "-b", filepath], timeout=20)
    low = out.lower()
    return any(kw in low for kw in _PHOTOREC_FILE_KW)


def analyze_photorec(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    if not utils.have_tool("photorec"):
        if ctx.get("photorec"):
            utils.log_warn("photorec requested but not installed")
        return []
    ext = ctx.get("ext", "")
    forced = ctx.get("photorec")
    if not forced and not _photorec_appropriate(filepath, ext):
        return []  # wrong file type — skip silently (as requested)

    recup = utils.ensure_dir(os.path.join(outdir, "photorec"))
    dest = os.path.join(recup, "recup")
    utils.log_info("Running PhotoRec recovery (disk/raw image detected)…")
    # Enable EVERY file family (default only carves a subset) and search the
    # whole image so nothing is missed. "partition_none" = carve the raw image
    # regardless of any partition table. keep_corrupted_file keeps partial hits.
    photorec_cmd = ("partition_none,options,keep_corrupted_file,"
                    "fileopt,everything,enable,search")
    rc, out, err = utils.run(
        ["photorec", "/log", "/d", dest, "/cmd", filepath, photorec_cmd],
        timeout=ctx.get("photorec_timeout", 1800))
    if ("Unknown" in (out + err) or "Usage" in (out + err)) and rc != 0:
        # older/newer PhotoRec syntax fallback
        utils.log_warn("PhotoRec rejected the full command — retrying minimal")
        utils.run(["photorec", "/log", "/d", dest, "/cmd", filepath,
                   "partition_none,fileopt,everything,enable,search"],
                  timeout=ctx.get("photorec_timeout", 1800))
    # PhotoRec creates dest.1, dest.2, … ; gather what it recovered
    recovered: list[str] = []
    for d in os.listdir(recup):
        full = os.path.join(recup, d)
        if os.path.isdir(full):
            for root, _dd, files in os.walk(full):
                for name in files:
                    if name.lower() == "report.xml":
                        continue
                    recovered.append(os.path.relpath(
                        os.path.join(root, name), outdir))
    if recovered:
        recovered.sort()
        utils.log_ok(f"PhotoRec recovered {len(recovered)} file(s) "
                     f"-> {os.path.relpath(recup, outdir)}/")
        findings = [{
            "category": "PhotoRec recovery",
            "detail": f"{len(recovered)} file(s) recovered from raw/disk image"
                      + (f" (showing first 200)" if len(recovered) > 200 else ""),
            "confidence": "high", "flags": [], "artifacts": recovered[:200],
        }]
        # scan recovered files for flags
        from . import archive_analyzer
        findings += archive_analyzer._scan_extracted(recup, outdir, ctx)
        return findings
    utils.log_info("PhotoRec found nothing recoverable")
    return []


# ---------------------------------------------------------------------------
# entry point used by the dispatcher for any file
# ---------------------------------------------------------------------------
def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    with open(filepath, "rb") as fh:
        data = fh.read()
    flag_rx = ctx.get("flag_rx")
    findings: list[dict] = []
    findings += analyze_strings(data, outdir, flag_rx)
    findings += analyze_encodings(data, outdir, flag_rx)
    findings += analyze_entropy(data, outdir)
    findings += analyze_carving(data, filepath, outdir, ctx.get("ext", ""), ctx)

    # Treat ANY file as a possible ZIP (polyglot / appended archive). Skip when
    # the dispatcher already handles it as a first-class archive.
    if ctx.get("category") != "archive":
        from . import archive_analyzer
        try:
            findings += archive_analyzer.try_as_zip(filepath, outdir, ctx)
        except Exception as exc:
            utils.log_warn(f"polyglot-zip check failed: {exc}")

    # PhotoRec only when the file type warrants it (or --photorec forces it).
    findings += analyze_photorec(filepath, outdir, ctx)
    return findings
