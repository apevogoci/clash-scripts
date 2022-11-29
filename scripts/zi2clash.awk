BEGIN {
	FS = ";"
	IPRE = "((1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\\.){3}(1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])"
	SIPC = split("", SIP, "")
	BIPC = split("", BIP, "")
	DMNC = split("", DMN, "")
	EXHC = split("", EXH, "")
	#EBIP="$(sed -re ':a;$!{N;ba};s/;\n\^/|/g;s/^\^/&(^|[^0-9])(/;s/;$/)($|[^0-9])/;s/\\\./\\&/g' "config/exclude-hosts-by-ips-dist.txt")"
	#EBIP = "(^|[^0-9])(81\\.91\\.178\\.252|37\\.48\\.77\\.229|178\\.208\\.90\\.38|213\\.13\\.30\\.100|52\\.169\\.125\\.34|81\\.91\\.178\\.242|5\\.61\\.58\\.119|45\\.81\\.227\\.72|209\\.99\\.40\\.222|95\\.211\\.189\\.202|34\\.252\\.217\\.230|103\\.224\\.212\\.222)($|[^0-9])"
	while ((getline < "config/exclude-hosts-by-ips-dist.txt") > 0) {
		gsub(/[^0-9.]/, "", $0)
		EBIP[ip2int($0)] = 1
	}
	close("config/exclude-hosts-by-ips-dist.txt")
	TDIR = ENVIRON["TDIR"]
	CDIR = ENVIRON["CDIR"]
}

{
	#IBRE = $0 !~ /33(-4\/2018|\320\260-5536\/2019)/ && (($2 == "" && $3 == "") || $1 == $2)
	split($1, IPAR, "|")
	for (x in IPAR) {
		if (IPAR[x] ~ ("^" IPRE "($|[^0-9])")) {
			if (IPAR[x] ~ /\//) {
				#print(i[x]) >> "result/iplist_special_range.txt"
				m = split(IPAR[x], CIP, "/")
				t = ip2int(CIP[1])
				SIP[t][1] = t - 1 + 2 ^ (32 - int(CIP[2]))
				SIP[t][2] = IPAR[x]
				delete CIP
			} else {
				t = ip2int(IPAR[x])
				if (EBIP[t]) {
					EXH[$2] = 1
				}
				#if (IBRE) {
				if ((($2 == "" && $3 == "") || $1 == $2) && $0 !~ /33(-4\/2018|\320\260-5536\/2019)/) {
					#print(IPAR[x]) > TDIR "/iplist_blockedbyip_noid2971.txt"
					BIP[t] = IPAR[x]
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

#$1 ~ /(^|[^0-9])(81\.91\.178\.252|37\.48\.77\.229|178\.208\.90\.38|213\.13\.30\.100|52\.169\.125\.34|81\.91\.178\.242|5\.61\.58\.119|45\.81\.227\.72|209\.99\.40\.222|95\.211\.189\.202|34\.252\.217\.230|103\.224\.212\.222)($|[^0-9])/ {
#	print($2) >> TDIR "/exclude-hosts.txt"
#}
/[^a-zA-Z0-9~_.-]/ {
	#IDN[$0] = 1
	print | ("zstd -3 >'" TDIR "/idn.txt'")
	next
}

{
	DMN[$0] = 1
}

END {
	#close(TDIR "/exclude-hosts.txt")
	close("zstd -3 >'" TDIR "/idn.txt'")
	while ((("zstdcat '" TDIR "/idn.txt' | idn2") | getline) > 0) {
		DMN[$0] = 1
	}
	close("zstdcat '" TDIR "/idn.txt' | idn2")
	readf("config/exclude-hosts-dist.txt", EXH)
	readf("config/exclude-hosts-custom.txt", EXH)
	for (d in EXH) {
		print(d) > (TDIR "/exclude-hosts.txt")
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
	EIPC = split("", EIP, "")
	readf_ip("config/exclude-ips-dist.txt", EIP)
	readf_ip("config/exclude-ips-custom.txt", EIP)
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
		if (p && ! EIP[i]) {
			print(BIP[i] "/32") | ("sort -t. -k1,1n -k2,2n -k3,3n -k4n | sed -re 's/^/  - /' >>'" CDIR "/rules_azi.yaml'")
		}
	}
	#close(TDIR "/iplist_blockedbyip_noid2971_collapsed.txt")
	close("sort -t. -k1,1n -k2,2n -k3,3n -k4n | sed -re 's/^/  - /' >>'" CDIR "/rules_azi.yaml'")
	delete BIP
	delete EIP
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
