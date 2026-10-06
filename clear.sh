#!/usr/bin/env bash
#
# clear.sh — vide manuellement input/ et output/.
#
# start.sh ne supprime plus rien : lance ce script quand tu veux repartir
# propre.  ./clear.sh         -> demande confirmation
#           ./clear.sh -y     -> sans confirmation

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" != "-y" && "${1:-}" != "--yes" ]]; then
    read -rp "Vider input/ et output/ ? [o/N] " ans
    case "${ans,,}" in
        o|oui|y|yes) ;;
        *) echo "Annulé."; exit 0 ;;
    esac
fi

rm -rf "$HERE/input" "$HERE/output"
mkdir -p "$HERE/input" "$HERE/output"
echo "[+] input/ et output/ vidés."
