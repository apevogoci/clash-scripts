BEGIN {
	FS = ";"
	IP1 = "(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))"
	IPRE = "(" IP1 "\\.){3}" IP1
	IPREWS = "^" IPRE "($|[^0-9])"
	SIPC = split("", SIP, "")
	BIPC = split("", BIP, "")
	DMNC = split("", DMN, "")
	EXHC = split("", EXH, "")
	while ((getline < "config/exclude-hosts-by-ips-dist.txt") > 0) {
		gsub(/[^0-9.]/, "", $0)
		EBIP[ip2int($0)] = 1
	}
	close("config/exclude-hosts-by-ips-dist.txt")
	TIDN = ENVIRON["TIDN"]
	TEXH = ENVIRON["TEXH"]
	CDIR = ENVIRON["CDIR"]
}

{
	split($1, IPAR, "|")
	for (x in IPAR) {
		if (IPAR[x] ~ IPREWS) {
			if (d = index(IPAR[x], "/")) {
				i = ip2int(substr(IPAR[x], 1, d - 1))
				SIP[i][1] = i - 1 + 2 ^ (32 - int(substr(IPAR[x], d + 1)))
				SIP[i][2] = IPAR[x]
			} else {
				i = ip2int(IPAR[x])
				if (length($2) > 0 && i in EBIP) {
					EXH[$2] = 1
				}
				if ((($2 == "" && $3 == "") || $1 == $2) && $5 !~ /33(-4\/2018|\320\260-5536\/2019)/) {
					BIP[i] = IPAR[x]
				}
			}
		}
	}
	delete IPAR
}

$2 ~ /(^$|\\)/ {
	next
}

{
	$0 = $2
	gsub(/\*\./, "", $0)
	gsub(/[.,]$/, "", $0)
}

/[^a-zA-Z0-9~_.-]/ {
	print | ("zstd -3 >'" TIDN "'")
	next
}

{
	DMN[$0] = 1
}

END {
	close("zstd -3 >'" TIDN "'")
	while ((("zstdcat '" TIDN "' | idn2") | getline) > 0) {
		DMN[$0] = 1
	}
	close("zstdcat '" TIDN "' | idn2")
	readf("config/exclude-hosts-dist.txt", EXH)
	readf("config/exclude-hosts-custom.txt", EXH)
	for (d in EXH) {
		print(d) > (TEXH)
		print(d) > "exclhos.txt"
	}
	readf("config/include-hosts-dist.txt", DMN)
	readf("config/include-hosts-custom.txt", DMN)
	for (d in DMN) {
		#if (! EXH[d]) {
		print d
		#}
	}
	delete DMN
	delete EXH
	#EIPC = split("", EIP, "")
	#readf_ip("config/exclude-ips-dist.txt", EIP)
	#readf_ip("config/exclude-ips-custom.txt", EIP)
	EIP = "^(" readf_re("config/exclude-ips-dist.txt") readf_re("config/exclude-ips-custom.txt")
	sub(/\|$/, ")", EIP)
	print("payload:") > (CDIR "/rules_azi.yaml")
	close(CDIR "/rules_azi.yaml")
	readf_ip("config/include-ips-dist.txt", BIP)
	readf_ip("config/include-ips-custom.txt", BIP)
	for (i in BIP) {
		p = 1
		for (j in SIP) {
			if (i >= j && i <= SIP[j][1]) {
				p = 0
				break
			}
		}
		#if (p) {
		#	print(BIP[i]) > TDIR "/iplist_blockedbyip_noid2971_collapsed.txt"
		#}
		if (p && i !~ EIP) {
			print(BIP[i] "/32") | ("sort -t. -k1,1n -k2,2n -k3,3n -k4n | sed -re 's/^/  - /' >>'" CDIR "/rules_azi.yaml'")
		}
	}
	#close(TDIR "/iplist_blockedbyip_noid2971_collapsed.txt")
	close("sort -t. -k1,1n -k2,2n -k3,3n -k4n | sed -re 's/^/  - /' >>'" CDIR "/rules_azi.yaml'")
	delete BIP
	#delete EIP
	print("payload:") > (CDIR "/rules_azs.yaml")
	close(CDIR "/rules_azs.yaml")
	for (i in SIP) {
		#printf("%x\t%x\n", i, SIP[i][1]) > "SIP"
		print(SIP[i][2]) | ("sort -t. -k1,1n -k2,2n -k3,3n -k4n | sed -re 's/^/  - /' >>'" CDIR "/rules_azs.yaml'")
	}
	close("sort -t. -k1,1n -k2,2n -k3,3n -k4n | sed -re 's/^/  - /' >>'" CDIR "/rules_azs.yaml'")
	delete SIP
}


function ip2int(ip, arr)
{
	split(ip, arr, ".")
	return (arr[1] * 0x1000000 + arr[2] * 0x10000 + arr[3] * 0x100 + arr[4])
}

function readf(F, A, l)
{
	while ((getline l < F) > 0) {
		if (length(l) > 0 && l !~ /^#/) {
			A[l] = 1
		}
	}
	close(F)
}

function readf_ip(F, A, l)
{
	while ((getline l < F) > 0) {
		if (length(l) > 0 && l ~ IPRE) {
			A[ip2int(l)] = 1
		}
	}
	close(F)
}

function readf_re(inF, re, l)
{
	re = ""
	while ((getline l < inF) > 0) {
		if (l !~ /^(#|[[:space:]]*$)/) {
			re = re l "|"
		}
	}
	close(inF)
	gsub(/\./, "\\.", re)
	return re
}
