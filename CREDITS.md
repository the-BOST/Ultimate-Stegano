# Credits & Third-Party Licenses

Ultimate Stegano is a thin orchestrator: it does **not** reimplement
steganography or forensics algorithms — it drives well-known third-party
libraries and command-line tools. All the real work is done by the projects
listed below. Full credit and copyright remain with their respective authors.

Ultimate Stegano's own code (the `ultimate-stegano.py` entry point and the
`modules/` package) is released under the **MIT License** (see `LICENSE`).
Every component below keeps its **own** license; nothing here relicenses them.

> ⚠️ License strings are given for convenience and reflect the projects'
> stated licenses at the time of writing. They are **not** legal advice.
> Verify the current, authoritative license of each project before you
> redistribute anything that bundles it.

---

## Python libraries (installed via `requirements.txt`)

These are **not** vendored in this repository — they are installed from PyPI by
the user. Each carries its own license and copyright.

| Library | Role in Ultimate Stegano | License | Project / authors |
|---|---|---|---|
| [Pillow](https://python-pillow.org/) | image loading, bit-planes, filters | HPND (PIL/MIT-style) | Jeffrey A. Clark & contributors |
| [NumPy](https://numpy.org/) | array math, LSB packing | BSD-3-Clause | NumPy developers |
| [SciPy](https://scipy.org/) | signal helpers | BSD-3-Clause | SciPy developers |
| [Matplotlib](https://matplotlib.org/) | spectrogram rendering | Matplotlib license (BSD-style) | Matplotlib development team |
| [stegano](https://github.com/cedricbonhomme/Stegano) | LSB reveal | **GPL-3.0** | Cédric Bonhomme |
| [ExifRead](https://github.com/ianare/exif-py) | EXIF parsing fallback | BSD-3-Clause | Ianaré Sévi & contributors |
| [piexif](https://github.com/hMatoba/Piexif) | EXIF handling | MIT | hMatoba |
| [pypdf](https://github.com/py-pdf/pypdf) | PDF text / metadata / attachments | BSD-3-Clause | pypdf contributors |
| [py7zr](https://github.com/miurahr/py7zr) | 7z extraction | **LGPL-2.1** | Hiroshi Miura |
| [pyzipper](https://github.com/danifus/pyzipper) | AES/ZipCrypto ZIP | MIT | Daniel Hillier |
| [Jinja2](https://palletsprojects.com/p/jinja/) | HTML report templating | BSD-3-Clause | Pallets |
| [python-magic](https://github.com/ahupp/python-magic) | MIME detection | MIT | Adam Hupp |
| [OpenCV (opencv-python)](https://opencv.org/) | optional video frame handling | Apache-2.0 | OpenCV team / wrapper by Olli-Pekka Heinisuo |
| [librosa](https://librosa.org/) | optional mel-spectrograms | ISC | librosa development team |
| [scapy](https://scapy.net/) | optional PCAP parsing | **GPL-2.0** | Philippe Biondi & the Scapy community |
| [rarfile](https://github.com/markokr/rarfile) | optional RAR support | ISC | Marko Kreen |

**Note on GPL/LGPL Python deps** (`stegano`, `py7zr`, `scapy`): their code is
**not** included in this repo; they are optional imports installed by the user
and are loaded at runtime only if present. If you redistribute an environment
that *bundles* them, that distribution must comply with their licenses.

---

## External command-line tools (invoked via `subprocess`, if installed)

Ultimate Stegano **calls** these as separate programs — it does not link to or
embed their code, and this repository does **not** ship their binaries. Install
them yourself (they are not required; the tool degrades gracefully when one is
missing).

| Tool | Role | License | Project / authors |
|---|---|---|---|
| [ExifTool](https://exiftool.org/) | metadata extraction | Perl Artistic / GPL-1.0+ | Phil Harvey |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | signature mapping | MIT | ReFirmLabs / Craig Heffner |
| [FFmpeg](https://ffmpeg.org/) (`ffmpeg`, `ffprobe`) | frames, audio demux, metadata | LGPL-2.1+ / GPL | FFmpeg team |
| [steghide](http://steghide.sourceforge.net/) | hidden-data extraction | GPL-2.0 | Stefan Hetzl |
| [stegseek](https://github.com/RickdeJager/stegseek) | fast steghide cracking | MIT | Rick de Jager |
| [zsteg](https://github.com/zed-0xff/zsteg) | PNG/BMP LSB analysis | MIT | Andrey "Zed" Zaikin |
| [outguess](https://github.com/resurrecting-open-source-projects/outguess) | statistical stego | BSD-style | Niels Provos et al. |
| [fcrackzip](https://github.com/hyc/fcrackzip) | ZIP password cracking | GPL-2.0+ | Marc Lehmann |
| [John the Ripper](https://www.openwall.com/john/) | password cracking | GPL-2.0 | Openwall / Solar Designer |
| [hashcat](https://hashcat.net/) | password cracking | MIT | Jens Steube & contributors |
| [p7zip / 7-Zip](https://www.7-zip.org/) (`7z`) | archive extraction | LGPL-2.1 (+ unRAR restriction) | Igor Pavlov |
| [unrar](https://www.rarlab.com/) | RAR extraction | freeware (RARLAB license) | Alexander Roshal |
| [poppler](https://poppler.freedesktop.org/) (`pdftotext`) | PDF text | GPL-2.0 | poppler / freedesktop.org |
| [Wireshark](https://www.wireshark.org/) (`tshark`) | PCAP analysis | GPL-2.0 | Wireshark Foundation & contributors |
| [foremost](https://foremost.sourceforge.net/) | file carving | public domain / GPL | Jesse Kornblum, Kris Kendall, Nick Mikus |
| [SoX](http://sox.sourceforge.net/) | audio conversion | GPL-2.0 / LGPL-2.1 | SoX developers |
| [TestDisk / PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) (`photorec`) | file recovery from disk images | GPL-2.0+ | Christophe Grenier (CGSecurity) |
| [file / libmagic](https://www.darwinsys.com/file/) (`file`, `strings`) | type detection, strings | BSD-2-Clause-ish | Ian Darwin & contributors |

---

## Data files

- **`word.txt`** — a small, original seed list of CTF flag prefixes and common
  passwords shipped with this project (MIT, same as the code).
- **`wordlist.txt`** — your own password wordlist, tried before rockyou. Shipped
  with a single placeholder line `[put your own wordlist]` (ignored at runtime);
  replace it with your passwords. Original to this project (MIT).
- **`rockyou.txt`** — the well-known password list originating from the 2009
  RockYou data breach, widely redistributed for authorized security testing.
  It is **not** included in this repository (size + provenance). Obtain it from
  your distro's wordlists package, e.g. on Kali/Debian:
  `gunzip -k /usr/share/wordlists/rockyou.txt.gz` and copy it to the project
  root, or point `--rockyou /path/to/rockyou.txt`.

---

## Disclaimer

Ultimate Stegano is intended for **authorized** use only: CTF competitions,
your own files, and forensics/security work you are permitted to perform.
You are responsible for complying with the licenses of every third-party
component you install and with all applicable laws.
