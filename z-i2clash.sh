#!/bin/sh
set -e

RETD="$(readlink -f ".")"
TDIR="$(mktemp -d)"
trap 'rm -rf -- "$MYTMPDIR";cd "$RETD";exit' EXIT INT TERM
# Temp file downloaded list.csv
TLST="$(mktemp -qp "$TDIR")"
#TLST="list.csv.gz"
# Temp file response web server
TRSP="$(mktemp -qp "$TDIR")"
# Temp file downloaded nxdomains.txt
TNXD="$(mktemp -qp "$TDIR")"
# Temp host list fole
THLS="$(mktemp -qp "$TDIR")"
# Temp file exclude hosts
export TEXH="$(mktemp -qp "$TDIR")"
# Temp file idn
export TIDN="$(mktemp -qp "$TDIR")"

# $1 - url
# $2 - saveto
dwnld() {
    wget -q -S --header 'Accept-Encoding: gzip' -O "${2}" -o "$TRSP" -- "${1}"
    [ "$?" != "0" ] && exit 1
    RSZ="$(grep -i '^ *content-length:' "$TRSP" | sed -re 's/[^0-9]//g')"
    if [ "$RSZ" != "$(stat -c %s "${2}")" ]; then
        echo "Error download ${2}" 1>&2
        exit 2
    fi
}

HERE="$(dirname "$(readlink -f "${0}")")"
cd "$HERE"

if [ ! -d "$CDIR" ]; then
    rm -rf "$CDIR" 2>/dev/null
    mkdir "$CDIR"
fi

REPO='https://raw.githubusercontent.com/zapret-info/z-i/master'
dwnld "${REPO}/dump.csv" "$TLST"
#dwnld "${REPO}/nxdomain.txt" "$TNXD"

echo "First step"
zstdcat "$TLST" \
    | iconv -f cp1251 -t utf-8 \
    | awk -f "scripts/zapret-info2clash.awk" \
    | awk -f "scripts/getzones.awk" \
    | zstd -3 >"$THLS"

echo "Second step"
zstdcat "$THLS" \
    | grep -v -F -x -f "$TEXH" \
    | sort -u \
    | sed -re '1ipayload:' -e 's/.*/  - \x27+.&\x27/' >"${CDIR}/rules_azd.yaml"

echo "Write commit message"
zstdgrep -m1 '' "$TLST" >"../commit_msg.txt"
