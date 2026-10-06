# Ultimate Stegano - Multi-Format Steganography Analyzer

Outil d'analyse stéganographique avancé pour CTF et forensics numérique. 
Détection automatique, extraction multi-méthodes et reporting structuré.

> ⚖️ **Usage autorisé uniquement** — CTF, vos propres fichiers, missions de
> forensics/sécurité que vous avez le droit d'effectuer. Code sous licence
> **MIT** (voir `LICENSE`). Ultimate Stegano ne réimplémente rien : il pilote
> des bibliothèques et outils tiers, chacun sous sa **propre** licence — tous
> les crédits et licences sont dans **[`CREDITS.md`](CREDITS.md)**.

## 🎯 Objectif

Analyseur automatique de fichiers suspects détectant et extrayant les données 
cachées par stéganographie dans images, audio, vidéo et documents.

## 📁 Structure du Projet

ultimate-stegano/
├── ultimate-stegano.py # Script principal
├── word.txt # Liste de mots pour brute force
├── requirements.txt # Dépendances Python
├── README.md # Documentation
├── modules/ # Modules d'analyse
│ ├── init.py
│ ├── image_analyzer.py # Analyse images (PNG, JPG, BMP, GIF, WebP)
│ ├── audio_analyzer.py # Analyse audio (WAV, MP3, FLAC)
│ ├── video_analyzer.py # Analyse vidéo (MP4, AVI, MKV)
│ ├── binary_analyzer.py # Analyse binaire générique
│ ├── pdf_analyzer.py # Analyse documents PDF
│ ├── archive_analyzer.py # Analyse archives (ZIP, RAR, 7z)
│ ├── network_analyzer.py # Analyse PCAP/Network dumps
│ └── utils.py # Fonctions utilitaires
├── tools/ # Outils externes intégrés
│ └── (binaires steghide, zsteg, etc.)
└── templates/ # Templates de rapports

## 🔧 Fonctionnalités (10+ features)

### 1. **Détection automatique de format**
   - Identification MIME type et magic bytes
   - Détection d'extensions falsifiées
   - Analyse de la cohérence fichier/entête

### 2. **Analyse EXIF complète**
   - Extraction métadonnées EXIF, IPTC, XMP
   - Détection de champs suspects (UserComment, MakerNote)
   - Géolocalisation GPS si présente
   - Historique de logiciels utilisés

### 3. **Spectrogrammes multi-résolutions**
   - Génération spectrogrammes audio (WAV, MP3, FLAC, OGG)
   - Spectrogrammes vidéo (extraction pistes audio)
   - Variantes : linéaire, logarithmique, Mel-scale
   - Détection visuelle de patterns (QR codes, texte)

### 4. **LSB Analysis (Least Significant Bit)**
   - Extraction LSB pour chaque canal couleur
   - Bit-plane visualization (bit 0-7)
   - LSB steganography detection (chi-square, RS analysis)
   - Alpha channel analysis (PNG)

### 5. **Brute force mot de passe intelligent**
   - Dictionnaire personnalisable (word.txt)
   - Patterns CTF automatiques (flag{, CTF{, HTB{, etc.)
   - Variantes (leet speak, majuscules, suffixes dates)
   - Multi-threading pour steghide/outguess

### 6. **Data carving et file carving**
   - Recherche signatures de fichiers (binwalk-like)
   - Extraction automatique des fichiers embarqués
   - Détection de ZIP camouflés, PDF dans images, etc.
   - Analyse des slack spaces

### 7. **Analyse de cohérence**
   - Détection d'incohérences dimensions/taille fichier
   - Analyse entropie (chi-square test)
   - Détection de padding suspect
   - Comparaison avec références du format

### 8. **Filtres et transformations d'images**
   - StegSolve-like : color filters (RGB planes)
   - Bitwise operations (XOR, AND, OR)
   - Transformations géométriques (flip, rotate)
   - Steganography detection algorithms (SPA, RS)

### 9. **Analyse de texte et strings**
   - Extraction strings ASCII/Unicode
   - Recherche patterns de flags configurables
   - Encodings alternatifs (base64, hex, rot13, etc.)
   - Détection de steganographie textuelle (espaces, zwnj)

### 10. **Analyse vidéo avancée**
   - Extraction frames clés vs inter-frames
   - Analyse motion vectors
   - Steganographie dans pistes sous-titres
   - Détection de watermarks

### 11. **Rapport structuré**
   - Organisation : `output/filename/`
   - Logs détaillés de chaque étape
   - Preuves visuelles (captures, spectrogrammes)
   - Résumé des findings avec niveau de confiance

### 12. **Mode batch**
   - Analyse récursive de dossiers
   - Traitement parallèle de fichiers
   - Export JSON/CSV des résultats

## 🛠️ Outils Intégrés

### Outils Python
- **Pillow** : manipulation images
- **stegano** : LSB steganography
- **wave, librosa** : analyse audio
- **opencv-python** : traitement vidéo
- **exifread, piexif** : métadonnées
- **scipy, numpy** : spectrogrammes
- **binwalk** : file carving
- **zsteg** : PNG/BMP analysis
- **steghide** : extraction steganographie
- **outguess** : steganographie statistique
- **fcrackzip** : brute force ZIP
- **john/ hashcat** : password cracking

### Outils système appelés
- `strings` : extraction texte
- `binwalk` : signatures fichiers
- `foremost` : data carving
- `exiftool` : métadonnées avancées
- `ffmpeg` : traitement multimédia
- `sox` : conversion audio


## 🚀 Utilisation

```bash
# Analyse simple
./ultimate-stegano.py suspect.png

# Avec mot de passe connu
./ultimate-stegano.py -p "monmdp" suspect.jpg

# Mode verbeux
./ultimate-stegano.py -v suspect.wav

# Batch processing
./ultimate-stegano.py -r ./challenges/

# Configurer patterns de flags
echo "flag{CTF{HTB{FCSC{" > word.txt
./ultimate-stegano.py -w word.txt image.png


| Type | Extensions | Méthodes |
|------|-----------|----------|
| Images | PNG, JPG, BMP, GIF, TIFF, WebP, ICO | LSB, EXIF, Steghide, Outguess, Zsteg, Filters |
| Audio | WAV, MP3, FLAC, OGG, AAC | Spectrogramme, LSB audio, Phase coding, Echo |
| Vidéo | MP4, AVI, MKV, MOV, WMV, FLV | Frame extraction, Audio tracks, Metadata |
| Documents | PDF, DOCX, ODT | Embedded files, Metadata, Object streams |
| Archives | ZIP, RAR, 7Z, TAR, GZ | Password brute force, Hidden files |
| Réseau | PCAP, PCAPNG | Protocol analysis, Data extraction |
| Divers | EXE, ELF, BIN | Section analysis, String extraction |
| 
| 
| output/
└── suspect_png/
    ├── 00_metadata/
    │   ├── EXIF.txt
    │   ├── strings.txt
    │   └── entropy_report.txt
    ├── 01_spectrograms/
    │   ├── spec_linear.png
    │   ├── spec_log.png
    │   └── spec_mel.png
    ├── 02_bitplanes/
    │   ├── red_0.png
    │   ├── red_1.png
    │   └── ...
    ├── 03_extractions/
    │   ├── lsb_raw.bin
    │   ├── steghide_attempts.log
    │   └── extracted_files/
    │       └── zip_found_0x1234.zip
    ├── 04_analysis/
    │   ├── inconsistency_report.txt
    │   └── visual_filters/
    └── report.html
    
🔍 Patterns de Détection CTF
Configuration par défaut dans word.txt :

flag{
FLAG{
CTF{
ctf{
HTB{
FCSC{
DGHACK{
picoCTF{
CyberTalents{
GH{



---

## 📦 Installation

L'environnement Python de Debian/Ubuntu est "externally managed" (PEP 668),
donc on installe dans un virtualenv local :

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Dépendances Python installées : Pillow, numpy, scipy, matplotlib, stegano,
exifread, piexif, pypdf, py7zr, pyzipper, jinja2, python-magic. Les extras
(opencv-python-headless, librosa, scapy, rarfile) activent la vidéo, le
mel-spectrogramme, l'analyse réseau scapy et le RAR.

### Outils système (optionnels mais recommandés)

Le tool fonctionne sans eux (dégradation gracieuse) mais les exploite s'ils
sont présents dans le `PATH` :

```bash
sudo apt install exiftool binwalk ffmpeg steghide p7zip-full tshark \
                 poppler-utils  # pdftotext
# optionnels : foremost outguess fcrackzip sox unrar  (+ gem install zsteg)
```

## ▶️ Lancer

### Lanceur « un clic » (start.sh)

```bash
cp start.example.sh start.sh && chmod +x start.sh   # une fois
./start.sh mon_fichier.png
```

`start.sh` copie le fichier dans `input/`, puis lance l'analyse en **brute
force** (sortie dans `output/`) — ainsi tout reste dans le projet. Il **ne
supprime rien** : pour repartir propre, lance `./clear.sh` (qui vide `input/`
et `output/` après confirmation ; `./clear.sh -y` sans confirmation).

`start.sh` est personnel (il peut appeler un alias de ta machine) et donc
**ignoré par git** ; le modèle partageable est `start.example.sh`.

### En ligne de commande

```bash
# Analyse simple
./venv/bin/python ultimate-stegano.py suspect.png

# Avec mot de passe connu / wordlist / batch récursif
./venv/bin/python ultimate-stegano.py -p "monmdp" suspect.jpg
./venv/bin/python ultimate-stegano.py -w word.txt image.png
./venv/bin/python ultimate-stegano.py -r ./challenges/ -o ./output

# Brute force profond avec rockyou.txt (steghide, ZIP, 7z, RAR)
./venv/bin/python ultimate-stegano.py -b suspect.jpg
./venv/bin/python ultimate-stegano.py -b --max-passwords 50000 secret.zip

# Forcer PhotoRec même si le type est incertain
./venv/bin/python ultimate-stegano.py --photorec image.dd
```

### Détection de contenu protégé par mot de passe & brute force

- Les archives chiffrées (ZIP ZipCrypto **et** AES, 7z, RAR) sont détectées et
  brute-forcées automatiquement. Les porteurs steghide (JPG/BMP/WAV) reçoivent
  un avertissement « contenu potentiellement caché par mot de passe ».
- `-b/--brute` (alias `--brute-force`, `--brutforce`) enchaîne les
  dictionnaires dans l'ordre : **`word.txt`** (graines intégrées) →
  **`wordlist.txt`** (ta liste perso, éditable) → **`rockyou.txt`** (si présent
  à la racine). Sans `-b`, seuls word.txt + wordlist.txt sont essayés. Le cap
  passe à 200000 en mode brute (`--max-passwords` pour ajuster). Si `stegseek`
  est installé, il casse steghide en quelques secondes avec rockyou.
- **`wordlist.txt`** est livré avec le placeholder `[put your own wordlist]`
  (cette ligne est ignorée) : remplace-le par tes propres mots de passe.
  **`rockyou.txt` n'est pas distribué** (139 Mo + données issues d'une fuite =
  RGPD) ; récupère-le toi-même (voir `CREDITS.md`) et pose-le à la racine.

### Extraction ZIP universelle (polyglots)

Quel que soit le type apparent, le fichier est **aussi testé comme une archive
ZIP** (central directory lu depuis la fin) — ce qui attrape les polyglots type
« ZIP ajouté après un PNG/JPEG ». Les archives *carvées* d'un fichier hôte sont
elles-mêmes extraites et brute-forcées récursivement.

### PhotoRec (récupération de fichiers)

`photorec` est lancé **uniquement si le type de fichier correspond** : images
disque / dumps bruts (`.dd`, `.img`, `.raw`, `.iso`, `.dmp`, `.vmdk`…) ou quand
`file` rapporte un système de fichiers / secteur d'amorçage / partition.
`--photorec` force l'exécution ; sur un PNG ordinaire il est ignoré. **Toutes
les familles de fichiers sont activées** (`fileopt,everything,enable`) pour ne
rien rater, et tout l'espace est parcouru (`partition_none,search`).

### Barre de progression

Le brute force (ZIP, 7z, steghide…) affiche une barre de progression avec
pourcentage, vitesse (essais/s) et ETA. Elle s'anime en terminal interactif et
reste silencieuse quand la sortie est redirigée.

### Analyse en cascade des fichiers découverts

Quand des fichiers sont extraits/carvés/récupérés, le tool **propose de les
analyser chacun dans un nouveau terminal**. Contrôlé par `--analyze-found` :
`ask` (défaut, propose `[a]=tous / [1 2 …]=sélection / [n]=non`), `all`
(ouvre tout automatiquement) ou `none`. Les doublons (même contenu extrait par
plusieurs chemins) sont dédupliqués par hash. Les terminaux hérités : brute,
dossier de sortie, verbosité ; sans re-proposition en cascade.

Chaque fichier produit `output/<nom>/` avec `00_metadata/`, un dossier
`01_<catégorie>/` (bitplanes, LSB, spectrogrammes, extractions…),
`report.json` et `report.html`.

### Rapport général à onglets (mode batch)

Quand plusieurs fichiers sont analysés (`-r` ou plusieurs cibles), le tool
génère **`output/index.html`** : un rapport général avec **un onglet par
fichier** (flags, findings, lien vers le rapport détaillé), plus
`output/batch_summary.json`. Le chemin est affiché en fin d'exécution.

## 📦 Installation & GitHub

Le dépôt ne contient **que** le code original (MIT) ; il ne vendor aucune
bibliothèque ni binaire tiers. Ne sont **pas** versionnés (voir `.gitignore`) :
`venv/`, `output/`, et `rockyou.txt` (139 Mo + provenance — à récupérer soi-même,
voir `CREDITS.md`).

## 📜 Licence & crédits

- Code Ultimate Stegano : **MIT** (`LICENSE`).
- Toutes les bibliothèques Python et tous les outils externes utilisés gardent
  **leur propre licence et copyright** — liste complète avec auteurs, licences
  et liens dans **[`CREDITS.md`](CREDITS.md)**. Ultimate Stegano se contente de
  les piloter (imports optionnels / appels `subprocess`) et n'embarque aucun de
  leurs binaires ni code source.

### État

Build complet et testé : images (LSB/EXIF/stegano/carving/filtres),
audio (spectrogrammes + LSB WAV), vidéo (frames + piste audio démuxée),
PDF (texte/metadata/pièces jointes), archives (ZIP ZipCrypto & AES, 7z, RAR),
réseau (tshark/scapy), binaire générique (strings, entropie, encodages
base64/hex/rot13, file carving), extraction ZIP universelle (polyglots),
brute force rockyou.txt (`-b`) et récupération PhotoRec conditionnelle.
