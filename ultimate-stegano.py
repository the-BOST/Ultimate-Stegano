#!/usr/bin/env python3
"""Ultimate Stegano — multi-format steganography analyzer for CTF & forensics.

Automatic format detection, multi-method extraction and structured reporting.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from modules import utils  # noqa: E402
from modules import (  # noqa: E402
    binary_analyzer, image_analyzer, audio_analyzer, video_analyzer,
    pdf_analyzer, archive_analyzer, network_analyzer,
)
from modules.utils import C, _c  # noqa: E402

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# format detection
# ---------------------------------------------------------------------------
EXT_BY_CATEGORY = {
    "image": {"png", "jpg", "jpeg", "bmp", "gif", "tiff", "tif", "webp", "ico"},
    "audio": {"wav", "mp3", "flac", "ogg", "aac", "au", "m4a"},
    "video": {"mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "mpg", "mpeg"},
    "pdf": {"pdf"},
    "archive": {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "jar"},
    "network": {"pcap", "pcapng", "cap"},
}


def detect_format(filepath: str) -> tuple[str, str, str]:
    """Return (category, real_ext, mime). Detects falsified extensions."""
    name_ext = os.path.splitext(filepath)[1].lstrip(".").lower()

    mime = "unknown"
    real_ext = name_ext
    try:
        import magic
        mime = magic.from_file(filepath, mime=True)
    except Exception:
        rc, out, _ = utils.run(["file", "--mime-type", "-b", filepath])
        if rc == 0:
            mime = out.strip()

    # map mime -> ext hint
    mime_ext = {
        "image/png": "png", "image/jpeg": "jpg", "image/bmp": "bmp",
        "image/gif": "gif", "image/webp": "webp", "image/tiff": "tiff",
        "image/x-icon": "ico", "audio/x-wav": "wav", "audio/wav": "wav",
        "audio/mpeg": "mp3", "audio/flac": "flac", "audio/ogg": "ogg",
        "video/mp4": "mp4", "video/x-msvideo": "avi",
        "video/x-matroska": "mkv", "video/quicktime": "mov",
        "application/pdf": "pdf", "application/zip": "zip",
        "application/x-7z-compressed": "7z", "application/x-rar": "rar",
        "application/gzip": "gz",
    }.get(mime)

    if mime_ext and mime_ext != name_ext and name_ext:
        # normalise jpg/jpeg etc. before warning
        aliases = {"jpeg": "jpg", "tif": "tiff"}
        if aliases.get(name_ext, name_ext) != aliases.get(mime_ext, mime_ext):
            utils.log_warn(
                f"Extension mismatch: name says '.{name_ext}' but content "
                f"is '{mime}' (→ .{mime_ext}). Possible falsified extension.")
        real_ext = mime_ext
    elif mime_ext:
        real_ext = mime_ext

    for cat, exts in EXT_BY_CATEGORY.items():
        if real_ext in exts:
            return cat, real_ext, mime
    return "binary", real_ext or "bin", mime


DISPATCH = {
    "image": image_analyzer,
    "audio": audio_analyzer,
    "video": video_analyzer,
    "pdf": pdf_analyzer,
    "archive": archive_analyzer,
    "network": network_analyzer,
}


# ---------------------------------------------------------------------------
# single-file analysis
# ---------------------------------------------------------------------------
def analyze_file(filepath: str, args, flag_rx) -> dict:
    utils.section(f"Analyzing: {filepath}")

    with open(filepath, "rb") as fh:
        data = fh.read()
    sha = hashlib.sha256(data).hexdigest()
    category, ext, mime = detect_format(filepath)
    entropy = utils.shannon_entropy(data)

    utils.log_info(f"Category : {_c(category, C.BOLD)}  ext=.{ext}  mime={mime}")
    utils.log_info(f"Size     : {utils.human_size(len(data))}  "
                   f"entropy={entropy:.3f}  sha256={sha[:16]}…")

    # Absolute output path so a changing CWD can never misplace the report.
    out_root = utils.ensure_dir(os.path.abspath(
        os.path.join(args.output, utils.safe_name(filepath))))

    ctx = {
        "ext": ext, "category": category, "mime": mime,
        "flag_rx": flag_rx, "verbose": args.verbose,
        "password": args.password,
        "wordlist": utils.load_wordlist(args.wordlist) if args.wordlist else [],
        "wordlist_path": args.wordlist,
        "max_pw": args.max_passwords,
        "brute": args.brute,
        "rockyou": args.rockyou if args.rockyou and os.path.exists(args.rockyou)
                   else None,
        "user_wordlist": args.user_wordlist
                         if os.path.exists(args.user_wordlist) else None,
        "photorec": args.photorec,
        "photorec_timeout": args.timeout,
    }

    findings: list[dict] = []

    # Build the result up front so a report is ALWAYS written, even if an
    # analysis stage crashes partway through (crash-safe reporting).
    result = {
        "file": filepath, "category": category, "ext": ext, "mime": mime,
        "size": len(data), "size_h": utils.human_size(len(data)),
        "entropy": round(entropy, 4), "sha256": sha,
        "output": out_root, "findings": findings, "flags": [],
    }

    # Write a report immediately, before any analysis runs. This guarantees
    # report.html exists even if the process is interrupted (Ctrl-C, OOM, disk
    # full) during a long stage. It is overwritten with full results at the end.
    try:
        _write_reports(result)
    except Exception as exc:
        utils.log_err(f"could not pre-write report: {exc}")

    def _stage(name, fn):
        """Run an analysis stage; never let it abort the whole file."""
        try:
            got = fn()
            if got:
                findings.extend(got)
        except Exception as exc:
            utils.log_err(f"{name} error: {exc}")
            findings.append({
                "category": f"{name} error", "detail": str(exc),
                "confidence": "low", "flags": [], "artifacts": []})
            if args.verbose:
                import traceback
                traceback.print_exc()

    try:
        # 00_metadata + generic passes (strings, entropy, carving, polyglot-zip)
        meta_dir = utils.ensure_dir(os.path.join(out_root, "00_metadata"))
        _stage("generic", lambda: binary_analyzer.analyze(filepath, meta_dir, ctx))

        # format-specific module
        module = DISPATCH.get(category)
        if module is not None:
            fmt_dir = utils.ensure_dir(os.path.join(out_root, f"01_{category}"))
            _stage(f"{category} analyzer",
                   lambda: module.analyze(filepath, fmt_dir, ctx))
        else:
            utils.log_info("No specialised module — generic binary analysis only")
    finally:
        # Resolve every artifact to a path relative to the report. Guarded so a
        # glitch here can never prevent the report from being written.
        try:
            _resolve_artifacts(findings, out_root)
        except Exception as exc:
            utils.log_err(f"artifact resolution error (non-fatal): {exc}")

        # collect flags and always emit reports
        all_flags: list[str] = []
        for f in findings:
            for fl in f.get("flags", []):
                if fl not in all_flags:
                    all_flags.append(fl)
        result["flags"] = all_flags

        report_path = os.path.join(out_root, "report.html")
        wrote = False
        try:
            _write_reports(result)
            wrote = os.path.isfile(report_path) and os.path.getsize(report_path) > 0
        except Exception as exc:
            utils.log_err(f"report writing failed: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()

        report_path = os.path.abspath(report_path)
        utils.section(f"Summary: {os.path.basename(filepath)}")
        if all_flags:
            for fl in all_flags:
                utils.log_hit(fl)
        else:
            utils.log_warn("No flag auto-recovered — inspect artifacts manually")
        utils.log_ok(f"{len(findings)} finding(s)")

        if wrote:
            size = os.path.getsize(report_path)
            utils.log_ok(f"Report written & verified on disk ({size} bytes)")
            print(f"\n  📄 REPORT : {report_path}")
            print(f"     Open   : xdg-open '{report_path}'")
            print(f"     Folder : {os.path.abspath(out_root)}\n")
        else:
            utils.log_err(f"REPORT NOT WRITTEN at {report_path} — check "
                          f"permissions / free space on this path")

        # Always refresh the global index so it aggregates EVERY file present
        # in the output directory — including files analyzed later in separate
        # terminals (the follow-up feature spawns independent processes).
        idx = _rebuild_global_index(os.path.dirname(out_root))
        if idx:
            print(f"  📊 RAPPORT GÉNÉRAL : {os.path.abspath(idx)}\n")
    return result


def _rebuild_global_index(out_dir: str):
    """(Re)build out_dir/index.html from all report.json currently present.

    Idempotent and safe to call from concurrent runs: each call rebuilds from
    whatever is on disk, so the last writer yields the complete index.
    """
    import glob
    results = []
    for jp in sorted(glob.glob(os.path.join(out_dir, "*", "report.json"))):
        try:
            with open(jp, encoding="utf-8") as fh:
                r = json.load(fh)
            r["output"] = os.path.dirname(jp)  # authoritative on-disk location
            results.append(r)
        except Exception:
            continue
    if len(results) < 2:
        return None  # a lone file doesn't need a general report
    total = sum(len(r.get("flags", [])) for r in results)
    return _write_batch_report(results, out_dir, total)


def _resolve_artifacts(findings: list, out_root: str) -> None:
    """Rewrite each finding artifact to a path relative to out_root.

    Modules store artifacts relative to the sub-dir they were handed, so the
    same name (e.g. 'spectrograms/spec_linear.png') may actually live several
    levels deeper. We locate the real file/dir under out_root and store the
    correct relative path so the links in report.html work.
    """
    import glob
    for f in findings:
        fixed = []
        for a in f.get("artifacts", []):
            if not a:
                continue
            a_norm = a.rstrip("/")
            # already correct relative to the report?
            if os.path.exists(os.path.join(out_root, a_norm)):
                fixed.append(a_norm)
                continue
            # search for the real location anywhere under out_root
            hits = glob.glob(os.path.join(out_root, "**", a_norm),
                             recursive=True)
            if hits:
                # prefer the shallowest match for determinism
                hits.sort(key=lambda p: p.count(os.sep))
                fixed.append(os.path.relpath(hits[0], out_root))
            else:
                fixed.append(a_norm)
        f["artifacts"] = fixed


def _write_reports(result: dict) -> None:
    out_root = result["output"]
    utils.ensure_dir(out_root)  # defensive: never assume the dir still exists
    # JSON
    with open(os.path.join(out_root, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    # HTML via jinja2 (fall back to a minimal page if jinja missing)
    ctx = {
        "filename": os.path.basename(result["file"]),
        "filetype": result["category"], "filesize": result["size_h"],
        "mime": result["mime"], "entropy": f"{result['entropy']:.3f}",
        "sha256": result["sha256"], "findings": result["findings"],
        "flags": result["flags"], "outdir": out_root,
        "generated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": VERSION,
    }
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        env = Environment(
            loader=FileSystemLoader(os.path.join(HERE, "templates")),
            autoescape=select_autoescape(["html"]))
        html = env.get_template("report.html.j2").render(**ctx)
    except Exception:
        rows = "".join(
            f"<li><b>{f['category']}</b>: {f['detail']} "
            f"[{f['confidence']}]</li>" for f in result["findings"])
        flags = "".join(f"<li><code>{fl}</code></li>" for fl in result["flags"])
        html = (f"<!doctype html><meta charset=utf-8><title>Ultimate Stegano</title>"
                f"<h1>{ctx['filename']}</h1><h2>Flags</h2><ul>{flags or '<li>none</li>'}"
                f"</ul><h2>Findings</h2><ul>{rows or '<li>none</li>'}</ul>")
    with open(os.path.join(out_root, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(html)


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------
def iter_targets(path: str, recursive: bool):
    if os.path.isfile(path):
        yield path
    elif os.path.isdir(path) and recursive:
        for root, _dirs, files in os.walk(path):
            for name in files:
                yield os.path.join(root, name)
    elif os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                yield full


# ---------------------------------------------------------------------------
# follow-up: offer to analyze discovered/extracted files in a new terminal
# ---------------------------------------------------------------------------
# Only files living in these sub-dirs are genuine *discovered* files (extracted
# archives, carved/recovered content) — never our own renders (spectrograms,
# bit-planes, strings.txt, reports…).
_DISCOVERY_DIRS = {"extracted_files", "extracted", "embedded", "photorec"}
_SKIP_NAMES = {"report.xml", "report.html", "report.json"}


def _collect_discovered(out_root: str) -> list[str]:
    import hashlib
    found: list[str] = []
    seen_hash: set[str] = set()
    candidates: list[str] = []
    for root, _dirs, files in os.walk(out_root):
        rel_parts = os.path.relpath(root, out_root).split(os.sep)
        in_discovery = (
            _DISCOVERY_DIRS.intersection(rel_parts)
            or any(p.startswith("carved_") for p in rel_parts)
            or "as_zip" in rel_parts
        )
        if not in_discovery:
            continue
        for name in files:
            if name.lower() in _SKIP_NAMES:
                continue
            p = os.path.join(root, name)
            try:
                if os.path.isfile(p) and os.path.getsize(p) > 0:
                    candidates.append(os.path.abspath(p))
            except OSError:
                continue
    # de-duplicate identical content (same file extracted via several paths)
    for p in sorted(candidates):
        try:
            with open(p, "rb") as fh:
                h = hashlib.sha1(fh.read(4 * 1024 * 1024)).hexdigest()
        except OSError:
            h = p
        if h in seen_hash:
            continue
        seen_hash.add(h)
        found.append(p)
    return found


def _offer_followup_analysis(result: dict, args) -> None:
    if args.analyze_found == "none":
        return
    discovered = _collect_discovered(result["output"])
    # don't re-propose the host file itself
    discovered = [d for d in discovered
                  if os.path.abspath(d) != os.path.abspath(result["file"])]
    if not discovered:
        return

    out_root = result["output"]
    utils.section(f"{len(discovered)} fichier(s) découvert(s) et extrait(s)")
    for i, d in enumerate(discovered, 1):
        try:
            sz = utils.human_size(os.path.getsize(d))
        except OSError:
            sz = "?"
        print(f"   {i:3}) {os.path.relpath(d, out_root)}  ({sz})")

    # decide which to analyze
    if args.analyze_found == "all":
        chosen = discovered
    else:  # ask
        if not sys.stdin.isatty():
            utils.log_info("Relance avec --analyze-found all pour les analyser, "
                           "ou lance-les manuellement (voir ci-dessus).")
            return
        print("\nAnalyser dans un nouveau terminal ?")
        try:
            ans = input("   [a]=tous   [1 2 …]=sélection   [Entrée/n]=non  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if ans.lower() in ("", "n", "no", "non"):
            return
        if ans.lower() in ("a", "all", "tous"):
            chosen = discovered
        else:
            idx = []
            for tok in ans.replace(",", " ").split():
                if tok.isdigit() and 1 <= int(tok) <= len(discovered):
                    idx.append(int(tok) - 1)
            chosen = [discovered[i] for i in idx]
        if not chosen:
            utils.log_warn("rien de valide sélectionné")
            return

    if len(chosen) > 12:
        if not _confirm(f"Ouvrir {len(chosen)} terminaux d'un coup ?"):
            return

    _launch_analyses(chosen, args)


def _confirm(question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(f"   {question} [o/N] ").strip().lower() in ("o", "y", "oui", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _launch_analyses(files: list[str], args) -> None:
    import shlex
    script = os.path.abspath(__file__)
    py = sys.executable  # the venv python currently running us
    term = utils.detect_terminal()

    # Rebuild the flags the child should inherit (brute, output, wordlist…).
    passthru = []
    if args.brute:
        passthru.append("-b")
    if args.verbose:
        passthru.append("-v")
    passthru += ["-o", args.output]
    # child should not recursively re-prompt
    passthru += ["--analyze-found", "none"]

    if not term:
        utils.log_warn("Aucun émulateur de terminal détecté. Commandes à lancer :")
        for f in files:
            cmd = " ".join(shlex.quote(x) for x in
                           [py, script, *passthru, f])
            print(f"   {cmd}")
        return

    launched = 0
    for f in files:
        inner = " ".join(shlex.quote(x) for x in [py, script, *passthru, f])
        if utils.open_in_terminal(inner, term):
            launched += 1
    utils.log_ok(f"{launched} terminal(aux) lancé(s) via {term}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="ultimate-stegano",
        description="Multi-format steganography analyzer for CTF & forensics.")
    p.add_argument("target", help="file or directory to analyze")
    p.add_argument("-p", "--password", help="known password to try first")
    p.add_argument("-w", "--wordlist", default=os.path.join(HERE, "word.txt"),
                   help="wordlist / flag-prefix file (default: word.txt)")
    p.add_argument("-r", "--recursive", action="store_true",
                   help="recurse into subdirectories (batch mode)")
    p.add_argument("-o", "--output", default=os.path.join(os.getcwd(), "output"),
                   help="output directory (default: ./output)")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    p.add_argument("-b", "--brute", "--brute-force", "--brutforce",
                   dest="brute", action="store_true",
                   help="deep password brute force: wordlist.txt then "
                        "rockyou.txt (steghide, ZIP, 7z, RAR)")
    p.add_argument("--wordlist2", "--user-wordlist", dest="user_wordlist",
                   default=os.path.join(HERE, "wordlist.txt"),
                   help="your own password wordlist, tried before rockyou "
                        "(default: project's wordlist.txt)")
    p.add_argument("--rockyou", default=os.path.join(HERE, "rockyou.txt"),
                   help="path to rockyou.txt (default: project root, optional)")
    p.add_argument("--photorec", action="store_true",
                   help="force PhotoRec recovery even if the type is unsure "
                        "(otherwise it runs only on disk/raw images)")
    p.add_argument("--max-passwords", type=int, default=None,
                   help="cap passwords tried in brute force "
                        "(default 2000, or 200000 with --brute)")
    p.add_argument("--timeout", type=int, default=600,
                   help="timeout (s) for long external tools (default 600)")
    p.add_argument("--analyze-found", choices=("ask", "all", "none"),
                   default="ask",
                   help="when files are discovered/extracted, open a new "
                        "terminal to analyze each: ask (default), all, none")
    p.add_argument("--version", action="version",
                   version=f"ultimate-stegano {VERSION}")
    args = p.parse_args(argv)

    if args.max_passwords is None:
        args.max_passwords = 200000 if args.brute else 2000
    if args.brute:
        has_user = os.path.exists(args.user_wordlist)
        has_rock = os.path.exists(args.rockyou)
        chain = []
        if has_user:
            chain.append(os.path.basename(args.user_wordlist))
        chain.append("rockyou.txt" if has_rock else "rockyou.txt (absent)")
        utils.log_info(f"Brute mode ON — ordre: word.txt → "
                       f"{' → '.join(chain)}  (cap {args.max_passwords})")
        if not has_rock:
            utils.log_warn("rockyou.txt introuvable — place-le à la racine du "
                           "projet pour aller plus loin (voir CREDITS.md)")

    if not os.path.exists(args.target):
        utils.log_err(f"target not found: {args.target}")
        return 2

    banner = _c(r"""
  __  __ _____ _____ __  __    _  _____ _____   ___ _____ ___ ___ ___
 |  \/  |_   _|_   _|  \/  |  /_\|_   _| __| |  / __|_   _| __/ __/ _ \
 | |\/| | | |   | | | |\/| | / _ \ | | | _|| |  \__ \ | | | _| (_ | (_) |
 |_|  |_| |_|   |_| |_|  |_|/_/ \_\|_| |___|_|  |___/ |_| |___\___\___/
          Ultimate Stegano v%s — CTF & forensics stego analyzer
""" % VERSION, C.CYAN)
    print(banner)

    # flag regex from wordlist prefixes (lines ending with '{') + defaults
    prefixes = list(utils.DEFAULT_FLAG_PREFIXES)
    for w in utils.load_wordlist(args.wordlist):
        if w.endswith("{"):
            prefixes.append(w)
    flag_rx = utils.build_flag_regex(prefixes)

    targets = list(iter_targets(args.target, args.recursive))
    if not targets:
        utils.log_err("no files to analyze")
        return 1
    utils.log_info(f"Queued {len(targets)} file(s). Output -> {args.output}")

    results = []
    for t in targets:
        try:
            r = analyze_file(t, args, flag_rx)
            results.append(r)
            _offer_followup_analysis(r, args)
        except KeyboardInterrupt:
            utils.log_err("interrupted by user")
            break
        except Exception as exc:
            utils.log_err(f"failed on {t}: {exc}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    # batch summary + general tabbed report (one tab per analyzed file)
    if len(results) > 1:
        utils.section("Batch summary")
        utils.ensure_dir(args.output)
        summary_path = os.path.join(args.output, "batch_summary.json")
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump([{"file": r["file"], "flags": r["flags"],
                        "findings": len(r["findings"])} for r in results],
                      fh, indent=2, ensure_ascii=False)
        total_flags = sum(len(r["flags"]) for r in results)
        index_path = _write_batch_report(results, args.output, total_flags)
        utils.log_ok(f"{len(results)} files · {total_flags} flag(s) total")
        utils.log_info(f"batch_summary.json -> {summary_path}")
        if index_path:
            idx_abs = os.path.abspath(index_path)
            print(f"\n  📊 RAPPORT GÉNÉRAL : {idx_abs}")
            print(f"     Open            : xdg-open '{idx_abs}'\n")

    return 0


def _write_batch_report(results: list, out_dir: str, total_flags: int):
    """Render output/index.html with one tab per analyzed file."""
    files = []
    for r in results:
        files.append({
            "name": os.path.basename(r["file"]),
            "type": r["category"], "size": r["size_h"],
            "entropy": f"{r['entropy']:.3f}", "sha256": r["sha256"],
            "flags": r["flags"], "findings": r["findings"],
            "report_rel": os.path.join(
                os.path.relpath(r["output"], out_dir), "report.html"),
        })
    ctx = {
        "files": files, "total_flags": total_flags,
        "generated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    index_path = os.path.join(out_dir, "index.html")
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        env = Environment(
            loader=FileSystemLoader(os.path.join(HERE, "templates")),
            autoescape=select_autoescape(["html"]))
        html = env.get_template("batch_report.html.j2").render(**ctx)
    except Exception as exc:
        utils.log_err(f"batch report render failed: {exc}")
        links = "".join(
            f'<li><a href="{f["report_rel"]}">{f["name"]}</a> — '
            f'{", ".join(f["flags"]) or "no flag"}</li>' for f in files)
        html = (f"<!doctype html><meta charset=utf-8>"
                f"<title>Ultimate Stegano — rapport général</title>"
                f"<h1>{len(files)} fichiers analysés</h1><ul>{links}</ul>")
    try:
        with open(index_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return index_path
    except OSError as exc:
        utils.log_err(f"could not write index.html: {exc}")
        return None


if __name__ == "__main__":
    sys.exit(main())
