"""PDF analysis: metadata, text, embedded files, object streams."""

from __future__ import annotations

import os

from . import utils


def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    findings: list[dict] = []
    flag_rx = ctx.get("flag_rx")

    # extracted text
    text = ""
    if utils.have_tool("pdftotext"):
        rc, out, _ = utils.run(["pdftotext", "-layout", filepath, "-"])
        text = out
    if not text:
        try:
            from pypdf import PdfReader
            reader = PdfReader(filepath)
            text = "\n".join((pg.extract_text() or "") for pg in reader.pages)
        except Exception:
            pass
    if text:
        utils.write_text(os.path.join(outdir, "text.txt"), text)
        flags = utils.find_flags(text, flag_rx)
        if flags:
            for f in flags:
                utils.log_hit(f"flag in PDF text: {f}")
            findings.append({
                "category": "PDF text flag", "detail": "flag in page text",
                "confidence": "high", "flags": flags, "artifacts": ["text.txt"]})

    # metadata + embedded files via pypdf
    try:
        from pypdf import PdfReader
        reader = PdfReader(filepath)
        meta = reader.metadata or {}
        meta_txt = "\n".join(f"{k}: {v}" for k, v in meta.items())
        if meta_txt:
            utils.write_text(os.path.join(outdir, "metadata.txt"), meta_txt)
            mflags = utils.find_flags(meta_txt, flag_rx)
            if mflags:
                for f in mflags:
                    utils.log_hit(f"flag in PDF metadata: {f}")
                findings.append({
                    "category": "PDF metadata flag", "detail": "flag in info dict",
                    "confidence": "high", "flags": mflags,
                    "artifacts": ["metadata.txt"]})

        # embedded / attached files
        try:
            attachments = reader.attachments  # dict name -> [bytes]
        except Exception:
            attachments = {}
        if attachments:
            edir = utils.ensure_dir(os.path.join(outdir, "embedded"))
            arts = []
            for name, contents in attachments.items():
                data = contents[0] if isinstance(contents, list) else contents
                safe = utils.safe_name(name) or "attachment.bin"
                p = os.path.join(edir, safe)
                with open(p, "wb") as fh:
                    fh.write(data)
                arts.append(os.path.relpath(p, outdir))
                utils.log_ok(f"PDF embedded file: {name}")
            findings.append({
                "category": "PDF embedded file",
                "detail": f"{len(arts)} attachment(s) extracted",
                "confidence": "high", "flags": [], "artifacts": arts})
    except Exception as exc:
        utils.log_warn(f"pypdf parse failed: {exc}")

    return findings
