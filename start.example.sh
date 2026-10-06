#!/usr/bin/env bash
#
# start.example.sh — modèle partageable de lanceur "un clic".
# Copie-le en start.sh et adapte-le à ta machine :
#     cp start.example.sh start.sh && chmod +x start.sh
#     ./start.sh <monfichier>
#
# À chaque exécution : copie le fichier dans input/, puis lance l'analyse en
# brute force (sortie dans output/). Ne supprime rien — utilise ./clear.sh
# pour vider input/ et output/ manuellement.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

FILE="${1:-}"
[[ -z "$FILE" ]] && { echo "Usage: ./start.sh <fichier>"; exit 1; }
[[ ! -f "$FILE" ]] && { echo "[-] Fichier introuvable : $FILE"; exit 1; }

mkdir -p "$HERE/input" "$HERE/output"

BASENAME="$(basename -- "$FILE")"
cp -- "$FILE" "$HERE/input/$BASENAME"
echo "[+] Copié -> input/$BASENAME"

# --- Adapte ici : active ton environnement python si besoin ---------------
# shopt -s expand_aliases
# source "$HOME/.bashrc" 2>/dev/null || true
# mon-alias-python 2>/dev/null || true
# --------------------------------------------------------------------------

# Interpréteur : venv du projet par défaut, sinon python du système.
PY="python"
[[ -x "$HERE/venv/bin/python" ]] && PY="$HERE/venv/bin/python"

echo "[*] Analyse (brute force) de input/$BASENAME…"
exec "$PY" "$HERE/ultimate-stegano.py" --brute "$HERE/input/$BASENAME" -o "$HERE/output"
