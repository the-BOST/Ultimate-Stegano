"""Utility helpers shared across all analyzer modules."""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime

# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------
class C:
    R = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")


def _c(text: str, color: str) -> str:
    if _NO_COLOR:
        return text
    return f"{color}{text}{C.R}"


def log_info(msg: str) -> None:
    print(f"{_c('[*]', C.BLUE)} {msg}")


def log_ok(msg: str) -> None:
    print(f"{_c('[+]', C.GREEN)} {msg}")


def log_warn(msg: str) -> None:
    print(f"{_c('[!]', C.YELLOW)} {msg}")


def log_err(msg: str) -> None:
    print(f"{_c('[-]', C.RED)} {msg}")


def log_hit(msg: str) -> None:
    """Highlight a potential finding (flag / extracted secret)."""
    print(f"{_c('[FLAG?]', C.MAGENTA + C.BOLD)} {_c(msg, C.BOLD)}")


def section(title: str) -> None:
    bar = "=" * 70
    print(f"\n{_c(bar, C.CYAN)}")
    print(_c(f"  {title}", C.CYAN + C.BOLD))
    print(_c(bar, C.CYAN))


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------
def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def safe_name(path: str) -> str:
    """Turn a filename into a safe output-directory slug."""
    base = os.path.basename(path)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", base)


def write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(content)


def have_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run(cmd, timeout: int = 120, input_data: bytes | None = None):
    """Run an external command, returning (returncode, stdout, stderr) as text.

    Never raises on a missing binary or timeout; returns a sentinel instead so
    callers can degrade gracefully.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            input=input_data,
        )
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )
    except FileNotFoundError:
        return (127, "", f"tool not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        return (124, "", f"timeout after {timeout}s: {cmd[0]}")
    except Exception as exc:  # pragma: no cover - defensive
        return (1, "", f"error running {cmd[0]}: {exc}")


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (cnt / length) * math.log2(cnt / length) for cnt in counts.values()
    )


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


# ---------------------------------------------------------------------------
# Flag / pattern hunting
# ---------------------------------------------------------------------------
DEFAULT_FLAG_PREFIXES = [
    "flag", "FLAG", "CTF", "ctf", "HTB", "FCSC", "DGHACK",
    "picoCTF", "CyberTalents", "GH",
]


def build_flag_regex(prefixes: list[str] | None = None) -> re.Pattern:
    prefixes = prefixes or DEFAULT_FLAG_PREFIXES
    # Match PREFIX{...} and also a generic word{...} fallback.
    alt = "|".join(re.escape(p.rstrip("{")) for p in prefixes if p.strip())
    pattern = rf"(?:{alt})\{{[^}}\n]{{1,200}}\}}"
    return re.compile(pattern)


# Fallback for unknown prefixes. Deliberately strict so it does NOT fire on
# random `X{y}` noise in binary/high-entropy data: prefix must start with a
# letter and be >=3 chars, and the body must be >=4 printable chars.
GENERIC_FLAG_REGEX = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,19}\{[\x20-\x7e]{4,200}\}")


def find_flags(text: str, regex: re.Pattern | None = None,
               generic: bool = True) -> list[str]:
    """Return unique flag-like strings found in text, preserving order.

    The known-prefix regex always runs. The broad generic regex runs only when
    ``generic`` is True (good for raw strings, noisy for decode transforms).
    Generic matches that merely wrap or sit inside a known-prefix match are
    dropped so we don't report ``txtHTB{...}`` next to ``HTB{...}``.
    """
    prefix_rx = regex or build_flag_regex()
    prefix_hits: list[str] = []
    for m in prefix_rx.finditer(text):
        if m.group(0) not in prefix_hits:
            prefix_hits.append(m.group(0))

    if not generic:
        return prefix_hits

    out = list(prefix_hits)
    for m in GENERIC_FLAG_REGEX.finditer(text):
        g = m.group(0)
        if g in out:
            continue
        # skip generic matches that overlap a cleaner known-prefix hit
        if any(g in p or p in g for p in prefix_hits):
            continue
        out.append(g)
    return out


def load_wordlist(path: str) -> list[str]:
    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w)
    except OSError:
        pass
    return words


class ProgressBar:
    """Minimal dependency-free progress bar for brute-force loops.

    Animates on a TTY (throttled to ~10 fps) and stays silent when output is
    redirected, so it never pollutes piped logs.
    """

    def __init__(self, total: int, label: str = "brute force", width: int = 32):
        import time
        self.total = max(1, int(total))
        self.label = label
        self.width = width
        self.n = 0
        self._t0 = time.time()
        self._last = 0.0
        self._tty = sys.stdout.isatty()

    def update(self, inc: int = 1) -> None:
        import time
        self.n += inc
        if not self._tty:
            return
        now = time.time()
        if now - self._last < 0.1 and self.n < self.total:
            return
        self._last = now
        frac = min(1.0, self.n / self.total)
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        rate = self.n / max(1e-9, now - self._t0)
        eta = (self.total - self.n) / rate if rate > 0 else 0
        msg = (f"\r    {self.label} [{bar}] {frac * 100:5.1f}% "
               f"({self.n:,}/{self.total:,}) {rate:,.0f}/s ETA {eta:4.0f}s")
        sys.stdout.write(msg[:120])
        sys.stdout.flush()

    def finish(self) -> None:
        if self._tty:
            sys.stdout.write("\r" + " " * 118 + "\r")
            sys.stdout.flush()


WORDLIST_PLACEHOLDER = "[put your own wordlist]"


def _count_lines(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def candidate_total(ctx: dict) -> int:
    """Best-effort count of passwords the brute force will try (for the bar)."""
    cap = ctx.get("max_pw", 2000)
    n = 1 if ctx.get("password") else 0
    for w in ctx.get("wordlist", []):
        n += len(set(leet_variants(w)))
    if ctx.get("user_wordlist"):
        n += _count_lines(ctx["user_wordlist"])
    if ctx.get("brute") and ctx.get("rockyou"):
        key = "_rockyou_lines"
        if key not in ctx:
            ctx[key] = _count_lines(ctx["rockyou"])
        n += ctx[key]
    return min(cap, n) if n else cap


# ---------------------------------------------------------------------------
# Launching a new terminal to analyze a discovered file
# ---------------------------------------------------------------------------
_TERMINALS = [
    "x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal",
    "mate-terminal", "tilix", "alacritty", "kitty", "xterm",
]


def detect_terminal() -> str | None:
    for t in _TERMINALS:
        if have_tool(t):
            return t
    return None


def open_in_terminal(inner_cmd: str, term: str | None = None) -> bool:
    """Open `inner_cmd` (a shell string) in a new terminal window.

    Returns True if a terminal was launched. The window stays open after the
    command finishes (waits for Enter) so results stay visible.
    """
    import subprocess
    term = term or detect_terminal()
    if not term:
        return False
    keep = (f"{inner_cmd}; echo; "
            f"read -n1 -r -p 'Analyse terminée — appuie sur une touche pour fermer…'")
    try:
        if term in ("gnome-terminal", "tilix", "mate-terminal"):
            argv = [term, "--", "bash", "-lc", keep]
        elif term == "xfce4-terminal":
            argv = [term, "-x", "bash", "-lc", keep]
        else:  # konsole, xterm, alacritty, kitty, x-terminal-emulator
            argv = [term, "-e", "bash", "-lc", keep]
        subprocess.Popen(argv, start_new_session=True)
        return True
    except Exception:
        return False


def _stream_wordlist(path: str):
    """Yield non-empty, non-comment lines of a wordlist file, lazily."""
    try:
        with open(path, "r", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                p = line.rstrip("\r\n")
                if not p or p.startswith("#") or p == WORDLIST_PLACEHOLDER:
                    continue
                yield p
    except OSError:
        return


def password_candidates(ctx: dict):
    """Yield unique password guesses for a brute-force attempt.

    Order:
      1. explicit --password
      2. word.txt built-in seeds + leet variants
      3. wordlist.txt   (the user's own list — edit it; placeholder is skipped)
      4. rockyou.txt    (only with --brute, if present; streamed lazily)

    Everything is streamed so the 139 MB rockyou never loads fully into memory.
    Callers cap the count with itertools.islice(..., ctx['max_pw']).
    """
    seen: set[str] = set()

    def fresh(p: str) -> bool:
        if p in seen:
            return False
        seen.add(p)
        return True

    if ctx.get("password") and fresh(ctx["password"]):
        yield ctx["password"]

    for w in ctx.get("wordlist", []):
        for v in leet_variants(w):
            if fresh(v):
                yield v

    # 3) user's own wordlist.txt (always, before rockyou)
    if ctx.get("user_wordlist"):
        for p in _stream_wordlist(ctx["user_wordlist"]):
            if fresh(p):
                yield p

    # 4) rockyou.txt, only in --brute mode and if present
    if ctx.get("brute") and ctx.get("rockyou"):
        for p in _stream_wordlist(ctx["rockyou"]):
            if fresh(p):
                yield p


def leet_variants(word: str) -> list[str]:
    """Generate a few common password variants for brute forcing."""
    table = str.maketrans("aAeEiIoOsS", "4433110055")
    variants = {
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.translate(table),
        word + "123",
        word + "!",
        word + str(datetime.now().year),
    }
    return list(variants)


# ---------------------------------------------------------------------------
# File signatures for carving (magic bytes -> extension)
# ---------------------------------------------------------------------------
FILE_SIGNATURES: list[tuple[bytes, bytes | None, str]] = [
    # (header, footer-or-None, extension)
    (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "png"),
    (b"\xff\xd8\xff", b"\xff\xd9", "jpg"),
    (b"GIF87a", b"\x00\x3b", "gif"),
    (b"GIF89a", b"\x00\x3b", "gif"),
    (b"BM", None, "bmp"),
    (b"PK\x03\x04", None, "zip"),  # local file header = start of a real zip
    (b"Rar!\x1a\x07", None, "rar"),
    (b"7z\xbc\xaf\x27\x1c", None, "7z"),
    (b"\x1f\x8b\x08", None, "gz"),
    (b"BZh", None, "bz2"),
    (b"\xfd7zXZ\x00", None, "xz"),
    (b"%PDF", b"%%EOF", "pdf"),
    (b"\x25\x21PS", None, "ps"),
    (b"OggS", None, "ogg"),
    (b"RIFF", None, "riff"),  # wav / avi / webp
    (b"ID3", None, "mp3"),
    (b"\x00\x00\x01\xba", None, "mpg"),
    (b"\x1aE\xdf\xa3", None, "mkv"),
    (b"fLaC", None, "flac"),
    (b"\x7fELF", None, "elf"),
    (b"MZ", None, "exe"),
    (b"-----BEGIN ", None, "pem"),
    (b"SQLite format 3\x00", None, "sqlite"),
]

# Only these are SAFE to carve: each has a reliable footer/end marker, or a
# validator, so a spurious header match can't carve the whole file to EOF.
# Footerless, short signatures (BM, MZ, RIFF, mpg, ELF, gz…) match random
# bytes in high-entropy data and would carve gigabytes of junk — they stay in
# FILE_SIGNATURES for *detection* but are deliberately excluded from carving.
CARVE_SIGNATURES: list[tuple[bytes, bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "png"),
    (b"\xff\xd8\xff", b"\xff\xd9", "jpg"),
    (b"GIF87a", b"\x00\x3b", "gif"),
    (b"GIF89a", b"\x00\x3b", "gif"),
    (b"%PDF", b"%%EOF", "pdf"),
]

# Maximum bytes a single carved blob may span (sanity bound).
CARVE_MAX_BLOB = 64 * 1024 * 1024
# Maximum number of files the native carver will ever write for one host.
CARVE_MAX_FILES = 40
