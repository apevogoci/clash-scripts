#!/bin/sh
set -e

RETD="$(readlink -f ".")"
MYTMPDIR="$(mktemp -d)"
trap 'rm -rf -- "$MYTMPDIR";cd "$RETD";exit' EXIT INT TERM
TDIR="$(mktemp -qp "$MYTMPDIR")"
CDIR="clash-conf/conf"

HERE="$(dirname "$(readlink -f "${0}")")"
cd "${HERE}"

LISTLINK='https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv'
wget -q -S --header 'Accept-Encoding: gzip' -O "${TDIR}/list.csv" -o "${TDIR}/resp.txt" "${LISTLINK}" || exit 1
LISTSIZE="$(grep -i '^ *content-length:' "${TDIR}/resp.txt" | sed -re 's/[^0-9]//g')"
[ "${LISTSIZE}" != "$(stat -c %s "${TDIR}/list.csv")" ] && echo "List 1 size differs" && exit 2

#NXDOMAINLINK='https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt'
#wget -q -S --header 'Accept-Encoding: gzip' -O "${TDIR}/nxdomain.txt" -o "${TDIR}/resp.txt" "${NXDOMAINLINK}" || exit 1
#LISTSIZE="$(grep -i '^ *content-length:' "${TDIR}/resp.txt" | sed -re 's/[^0-9]//g')"
#[ "${LISTSIZE}" != "$(stat -c %s "${TDIR}/nxdomain.txt")" ] && echo "List 2 size differs" && exit 2

zstdcat "${TDIR}/list.csv" |
	iconv -f cp1251 -t utf-8 |
	awk -f "scripts/zi2clash.awk" |
	awk -f "scripts/getzones.awk" |
	zstd -3 >"${TDIR}/hostlist_pre.txt"

zstdcat "${TDIR}/hostlist_pre.txt" |
	grep -v -F -x -f "${TDIR}/exclude-hosts.txt" |
	sort -u |
	sed -re '1ipayload:' -e 's/.*/  - \x27+.&\x27/' >"${CDIR}/rules_azd.yaml"
