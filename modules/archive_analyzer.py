"""Archive analysis: listing, password brute force, hidden-file extraction."""

from __future__ import annotations

import itertools
import os
import zipfile

from . import utils


def _password_iter(ctx):
    """Capped stream of password guesses (word.txt + rockyou in --brute)."""
    return itertools.islice(utils.password_candidates(ctx),
                            ctx.get("max_pw", 2000))


def _brute_zip(filepath: str, outdir: str, ctx) -> list[dict]:
    findings: list[dict] = []
    try:
        zf = zipfile.ZipFile(filepath)
    except Exception as exc:
        utils.log_warn(f"not a readable zip: {exc}")
        return findings

    encrypted = any(info.flag_bits & 0x1 for info in zf.infolist())
    edir = utils.ensure_dir(os.path.join(outdir, "extracted"))

    if not encrypted:
        try:
            zf.extractall(edir)
            names = zf.namelist()
            utils.log_ok(f"ZIP extracted {len(names)} entrie(s)")
            findings.append({
                "category": "ZIP contents",
                "detail": f"{len(names)} file(s) extracted (no password)",
                "confidence": "medium", "flags": [],
                "artifacts": [os.path.relpath(edir, outdir)]})
            findings += _scan_extracted(edir, outdir, ctx)
        except Exception as exc:
            utils.log_warn(f"extract failed: {exc}")
        return findings

    # encrypted -> brute force
    mode = "rockyou.txt" if ctx.get("brute") else "word.txt"
    utils.log_warn(f"Encrypted ZIP detected — brute forcing with {mode} "
                   f"(cap {ctx.get('max_pw', 2000)})")

    # Prefer fcrackzip with rockyou when present (fast, native C)
    wl = ctx.get("rockyou") if ctx.get("brute") else ctx.get("wordlist_path")
    if utils.have_tool("fcrackzip") and wl:
        rc, out, _ = utils.run(
            ["fcrackzip", "-v", "-u", "-D", "-p", wl, filepath], timeout=600)
        if "PASSWORD FOUND" in out:
            utils.write_text(os.path.join(outdir, "fcrackzip.txt"), out)
            utils.log_hit(f"fcrackzip: {out.strip().splitlines()[-1]}")

    # pyzipper handles both legacy ZipCrypto and WinZip AES; stdlib only the
    # former, so prefer pyzipper when it is installed.
    opener = zipfile.ZipFile
    try:
        import pyzipper
        opener = pyzipper.AESZipFile
    except Exception:
        pass

    tried = 0
    bar = utils.ProgressBar(utils.candidate_total(ctx), "ZIP brute")
    for pw in _password_iter(ctx):
        tried += 1
        bar.update()
        try:
            with opener(filepath) as z:
                z.extractall(edir, pwd=pw.encode())
                names = z.namelist()
            bar.finish()
            utils.log_hit(f"ZIP password found: {pw!r}")
            findings.append({
                "category": "ZIP password cracked",
                "detail": f"Password '{pw}' — {len(names)} file(s) extracted",
                "confidence": "high", "flags": [],
                "artifacts": [os.path.relpath(edir, outdir)]})
            # scan extracted files for flags right away
            findings += _scan_extracted(edir, outdir, ctx)
            return findings
        except (RuntimeError, zipfile.BadZipFile, ValueError):
            continue
        except Exception:
            continue
    bar.finish()
    utils.log_warn(f"ZIP password not found after {tried} attempt(s)"
                   + ("" if ctx.get("brute") else " — retry with --brute for rockyou.txt"))
    findings.append({
        "category": "Password-protected ZIP",
        "detail": f"Encrypted archive; {tried} password(s) tried without "
                  f"success. Run with --brute to use rockyou.txt.",
        "confidence": "medium", "flags": [], "artifacts": []})
    return findings


def _scan_extracted(edir: str, outdir: str, ctx) -> list[dict]:
    """Grep freshly extracted files for flag patterns."""
    findings: list[dict] = []
    flag_rx = ctx.get("flag_rx")
    for root, _d, files in os.walk(edir):
        for name in files:
            try:
                with open(os.path.join(root, name), "rb") as fh:
                    text = fh.read(1 << 20).decode("latin-1", "replace")
            except OSError:
                continue
            flags = utils.find_flags(text, flag_rx)
            if flags:
                for f in flags:
                    utils.log_hit(f"flag in extracted {name}: {f}")
                findings.append({
                    "category": "Flag in extracted file",
                    "detail": f"flag inside {name}", "confidence": "high",
                    "flags": flags,
                    "artifacts": [os.path.relpath(os.path.join(root, name), outdir)]})
    return findings


def _extract_7z(filepath: str, outdir: str, ctx) -> list[dict]:
    findings: list[dict] = []
    edir = utils.ensure_dir(os.path.join(outdir, "extracted"))
    # empty password first, then the capped candidate stream
    passwords = itertools.chain([""], _password_iter(ctx))
    bar = utils.ProgressBar(utils.candidate_total(ctx) + 1, "7z brute")
    try:
        import py7zr
        for pw in passwords:
            bar.update()
            try:
                with py7zr.SevenZipFile(filepath, mode="r",
                                        password=pw or None) as z:
                    z.extractall(edir)
                bar.finish()
                tag = f"password '{pw}'" if pw else "no password"
                utils.log_ok(f"7z extracted ({tag})")
                if pw:
                    utils.log_hit(f"7z password found: {pw!r}")
                findings.append({
                    "category": "7z contents",
                    "detail": f"extracted with {tag}",
                    "confidence": "high" if pw else "medium", "flags": [],
                    "artifacts": [os.path.relpath(edir, outdir)]})
                findings += _scan_extracted(edir, outdir, ctx)
                return findings
            except Exception:
                continue
    except Exception:
        pass
    bar.finish()
    # fallback to system 7z
    if utils.have_tool("7z"):
        for pw in itertools.chain([""], _password_iter(ctx)):
            rc, out, _ = utils.run(
                ["7z", "x", "-y", f"-o{edir}", f"-p{pw}", filepath], timeout=120)
            if rc == 0:
                tag = f"password '{pw}'" if pw else "no password"
                utils.log_ok(f"7z extracted ({tag})")
                findings.append({
                    "category": "7z contents", "detail": f"extracted with {tag}",
                    "confidence": "high" if pw else "medium", "flags": [],
                    "artifacts": [os.path.relpath(edir, outdir)]})
                findings += _scan_extracted(edir, outdir, ctx)
                return findings
    utils.log_warn("7z extraction failed (wrong password?)")
    findings.append({
        "category": "Password-protected 7z",
        "detail": "Encrypted 7z; no password matched. Run with --brute.",
        "confidence": "medium", "flags": [], "artifacts": []})
    return findings


def try_as_zip(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    """Attempt ZIP extraction on ANY file, regardless of its apparent type.

    Python's zipfile locates the central directory from the end of the file,
    so this transparently handles polyglots — e.g. a ZIP concatenated after a
    PNG/JPEG, which `unzip image.png` would also crack open.
    """
    if not zipfile.is_zipfile(filepath):
        return []
    utils.log_info("File is also a valid ZIP (polyglot/appended archive) — "
                   "extracting")
    zdir = utils.ensure_dir(os.path.join(outdir, "as_zip"))
    findings = _brute_zip(filepath, zdir, ctx)
    for f in findings:
        if f["category"] in ("ZIP contents", "ZIP password cracked"):
            f["category"] = "Hidden ZIP (polyglot)"
    return findings


def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    ext = ctx.get("ext", "")
    if ext == "zip":
        return _brute_zip(filepath, outdir, ctx)
    if ext == "7z":
        return _extract_7z(filepath, outdir, ctx)
    if ext in ("rar",):
        if utils.have_tool("unrar"):
            edir = utils.ensure_dir(os.path.join(outdir, "extracted"))
            findings: list[dict] = []
            for pw in itertools.chain([""], _password_iter(ctx)):
                rc, out, _ = utils.run(
                    ["unrar", "x", "-y", f"-p{pw or '-'}", filepath, edir + "/"],
                    timeout=120)
                if rc == 0:
                    tag = f"password '{pw}'" if pw else "no password"
                    utils.log_ok(f"RAR extracted ({tag})")
                    if pw:
                        utils.log_hit(f"RAR password found: {pw!r}")
                    findings.append({"category": "RAR contents",
                                     "detail": f"extracted with {tag}",
                                     "confidence": "high" if pw else "medium",
                                     "flags": [], "artifacts": ["extracted"]})
                    findings += _scan_extracted(edir, outdir, ctx)
                    return findings
            utils.log_warn("RAR extraction failed (wrong password?)")
            return findings
        utils.log_warn("unrar not installed — skipping RAR extraction")
    return []
