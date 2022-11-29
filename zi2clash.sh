#!/bin/sh
set -e

RETD="$(readlink -f ".")"
TDIR="$(mktemp -d)"
trap 'rm -rf -- "$MYTMPDIR";cd "$RETD";exit' EXIT INT TERM
# Temp file downloaded list.csv
TLST="$(mktemp -qp "$TDIR")"
# Temp file rssponse web server
TRSP="$(mktemp -qp "$TDIR")"
# Temp file downloaded nxdomains.txt
TNXD="$(mktemp -qp "$TDIR")"
# Temp host list fole
THLS="$(mktemp -qp "$TDIR")"
# Temp file exclude hosts
TEXH="$(mktemp -qp "$TDIR")"

HERE="$(dirname "$(readlink -f "${0}")")"
cd "${HERE}"

LISTLINK='https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv'
wget -q -S --header 'Accept-Encoding: gzip' -O "${TLST}" -o "${TRSP}" "${LISTLINK}" || exit 1
LISTSIZE="$(grep -i '^ *content-length:' "${TRSP}" | sed -re 's/[^0-9]//g')"
[ "${LISTSIZE}" != "$(stat -c %s "${TLST}")" ] && echo "List 1 size differs" && exit 2

#NXDOMAINLINK='https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt'
#wget -q -S --header 'Accept-Encoding: gzip' -O "${TNXD}" -o "${TRSP}" "${NXDOMAINLINK}" || exit 1
#LISTSIZE="$(grep -i '^ *content-length:' "${TRSP}" | sed -re 's/[^0-9]//g')"
#[ "${LISTSIZE}" != "$(stat -c %s "${TNXD}")" ] && echo "List 2 size differs" && exit 2

zstdcat "${TLST}" |
	iconv -f cp1251 -t utf-8 |
	awk -f "scripts/zi2clash.awk" |
	awk -f "scripts/getzones.awk" |
	zstd -3 >"${THLS}"

zstdcat "${THLS}" |
	grep -v -F -x -f "${TEXH}" |
	sort -u |
	sed -re '1ipayload:' -e 's/.*/  - \x27+.&\x27/' >"${CDIR}/rules_azd.yaml"
