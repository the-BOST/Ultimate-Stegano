"""Video analysis: metadata, key-frame extraction, embedded audio track."""

from __future__ import annotations

import os

from . import utils


def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    findings: list[dict] = []
    flag_rx = ctx.get("flag_rx")

    # container / stream metadata via ffprobe
    if utils.have_tool("ffprobe"):
        rc, out, err = utils.run(
            ["ffprobe", "-hide_banner", "-show_format", "-show_streams",
             filepath], timeout=60)
        blob = out + "\n" + err
        if blob.strip():
            utils.write_text(os.path.join(outdir, "ffprobe.txt"), blob)
            flags = utils.find_flags(blob, flag_rx)
            if flags:
                for f in flags:
                    utils.log_hit(f"flag in video metadata: {f}")
                findings.append({
                    "category": "Video metadata flag", "detail": "flag in streams",
                    "confidence": "high", "flags": flags,
                    "artifacts": ["ffprobe.txt"]})
    elif utils.have_tool("exiftool"):
        rc, out, _ = utils.run(["exiftool", filepath])
        if out:
            utils.write_text(os.path.join(outdir, "metadata.txt"), out)

    if not utils.have_tool("ffmpeg"):
        utils.log_warn("ffmpeg not installed — skipping frame/audio extraction")
        return findings

    # key frames
    fdir = utils.ensure_dir(os.path.join(outdir, "keyframes"))
    rc, _, _ = utils.run(
        ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
         "-skip_frame", "nokey", "-i", filepath,
         "-vsync", "vfr", "-frame_pts", "1",
         os.path.join(fdir, "key_%04d.png")], timeout=180)
    frames = [f for f in os.listdir(fdir) if f.endswith(".png")]
    if frames:
        utils.log_info(f"Extracted {len(frames)} key frame(s) -> keyframes/")
        findings.append({
            "category": "Key frames",
            "detail": f"{len(frames)} key frame(s) extracted for inspection",
            "confidence": "low", "flags": [], "artifacts": ["keyframes/"]})

    # demux audio track -> wav, then reuse the audio analyzer
    audio_wav = os.path.join(outdir, "audio_track.wav")
    rc, _, _ = utils.run(
        ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
         "-i", filepath, "-vn", "-acodec", "pcm_s16le", audio_wav],
        timeout=180)
    if rc == 0 and os.path.exists(audio_wav) and os.path.getsize(audio_wav):
        utils.log_info("Demuxed audio track -> audio_track.wav")
        from . import audio_analyzer
        sub = utils.ensure_dir(os.path.join(outdir, "audio_track"))
        actx = dict(ctx); actx["ext"] = "wav"
        findings += audio_analyzer.analyze(audio_wav, sub, actx)

    return findings
