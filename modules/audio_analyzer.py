"""Audio steganography: spectrograms (linear/log/mel), LSB, metadata."""

from __future__ import annotations

import os
import wave

import numpy as np

from . import utils

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

try:
    import librosa
    _HAVE_LIBROSA = True
except Exception:
    _HAVE_LIBROSA = False


def _load_samples(filepath: str, ext: str):
    """Return (samples float32 mono, sample_rate) or (None, None)."""
    if ext == "wav":
        try:
            with wave.open(filepath, "rb") as wf:
                sr = wf.getframerate()
                n = wf.getnframes()
                width = wf.getsampwidth()
                ch = wf.getnchannels()
                raw = wf.readframes(n)
            dtype = {1: np.uint8, 2: np.int16, 4: np.int32}.get(width, np.int16)
            samples = np.frombuffer(raw, dtype=dtype).astype(np.float32)
            if ch > 1:
                samples = samples.reshape(-1, ch).mean(axis=1)
            return samples, sr
        except Exception:
            pass
    if _HAVE_LIBROSA:
        try:
            samples, sr = librosa.load(filepath, sr=None, mono=True)
            return samples.astype(np.float32), sr
        except Exception:
            pass
    # fallback: decode to wav with ffmpeg
    if utils.have_tool("ffmpeg"):
        tmp = filepath + ".__conv.wav"
        rc, _, _ = utils.run(["ffmpeg", "-y", "-i", filepath, tmp], timeout=120)
        if rc == 0 and os.path.exists(tmp):
            try:
                res = _load_samples(tmp, "wav")
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            return res
    return None, None


def _spectrogram(samples, sr, outdir):
    arts = []
    if samples is None or len(samples) < 256:
        return arts
    sdir = utils.ensure_dir(os.path.join(outdir, "spectrograms"))

    # linear + log via matplotlib specgram
    for scale, fname in (("linear", "spec_linear.png"),
                         ("dB", "spec_log.png")):
        plt.figure(figsize=(12, 5))
        plt.specgram(samples, NFFT=1024, Fs=sr, noverlap=512,
                     scale=scale, cmap="viridis")
        plt.title(f"Spectrogram ({scale})")
        plt.xlabel("Time [s]"); plt.ylabel("Frequency [Hz]")
        plt.colorbar(label="Intensity")
        p = os.path.join(sdir, fname)
        plt.tight_layout(); plt.savefig(p, dpi=110); plt.close()
        arts.append(os.path.relpath(p, outdir))

    # mel scale (librosa) if available
    if _HAVE_LIBROSA:
        try:
            S = librosa.feature.melspectrogram(y=samples, sr=sr, n_mels=128)
            S_db = librosa.power_to_db(S, ref=np.max)
            plt.figure(figsize=(12, 5))
            librosa.display.specshow(S_db, sr=sr, x_axis="time",
                                     y_axis="mel", cmap="magma")
            plt.title("Mel spectrogram"); plt.colorbar(format="%+2.0f dB")
            p = os.path.join(sdir, "spec_mel.png")
            plt.tight_layout(); plt.savefig(p, dpi=110); plt.close()
            arts.append(os.path.relpath(p, outdir))
        except Exception:
            pass
    utils.log_info(f"{len(arts)} spectrogram(s) written -> spectrograms/")
    return arts


def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    ext = ctx.get("ext", "")
    findings: list[dict] = []
    flag_rx = ctx.get("flag_rx")

    # metadata
    if utils.have_tool("exiftool"):
        rc, out, _ = utils.run(["exiftool", filepath])
        if out:
            utils.write_text(os.path.join(outdir, "metadata.txt"), out)
            flags = utils.find_flags(out, flag_rx)
            if flags:
                for f in flags:
                    utils.log_hit(f"flag in audio metadata: {f}")
                findings.append({
                    "category": "Audio metadata flag", "detail": "flag in tags",
                    "confidence": "high", "flags": flags,
                    "artifacts": ["metadata.txt"]})

    samples, sr = _load_samples(filepath, ext)
    arts = _spectrogram(samples, sr, outdir)
    if arts:
        findings.append({
            "category": "Spectrogram",
            "detail": "Multi-scale spectrograms generated — inspect visually "
                      "for hidden text / QR patterns",
            "confidence": "low", "flags": [], "artifacts": arts,
        })

    # audio LSB (WAV int16)
    if samples is not None and ext == "wav":
        try:
            ints = samples.astype(np.int64)
            bits = (ints & 1).astype(np.uint8)
            packed = np.packbits(bits[: (len(bits) // 8) * 8]).tobytes()
            p = os.path.join(outdir, "audio_lsb.bin")
            with open(p, "wb") as fh:
                fh.write(packed)
            from .binary_analyzer import extract_strings
            s = "\n".join(extract_strings(packed, 4))
            if s:
                utils.write_text(os.path.join(outdir, "audio_lsb_strings.txt"), s)
                flags = utils.find_flags(s, flag_rx)
                if flags:
                    for f in flags:
                        utils.log_hit(f"flag in audio LSB: {f}")
                    findings.append({
                        "category": "Audio LSB", "detail": "flag in sample LSB",
                        "confidence": "high", "flags": flags,
                        "artifacts": ["audio_lsb.bin"]})
        except Exception:
            pass

    return findings
