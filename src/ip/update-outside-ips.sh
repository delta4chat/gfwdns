#!/bin/bash

set -e
set -x

type jq
type python3
type mktemp
type unzip
type curl
type realpath
type find
type sort
type rm
type mv

outdir="$(realpath .)"
outfile="${outdir}/outside_ips.rs"

py="${outdir}/ip2b63.py"

tmp="$(mktemp -d -t gfwdnsChinaIpUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/ipverse/rir-ip/archive/master.zip -v -L -o rir-ip.zip $@
unzip rir-ip.zip

cd rir-ip-master
cd country

{
	echo "#![allow(non_upper_case_globals)]"
    echo "use crate::*;"

	echo "/* DE+ET+EC+TT+IT (Detect It): IPv4+IPv6 */"

    cat {de,et,ec,tt,it}/aggregated.json | jq -r '.subnets.ipv4[]' > ips.txt
	cat {de,et,ec,tt,it}/aggregated.json | jq -r '.subnets.ipv6[]' >> ips.txt

	cat ips.txt | python3 $py #-c 'import sys, ipaddress; s=sys.stdin.read().strip(); s=[line.split("/") for line in s.split("\n")]; print(*["    v6("+(",".join([(str(int(i, 16)) if len(str(int(i, 16))) <= len(hex(int(i, 16))) else hex(int(i, 16))) for i in ipaddress.IPv6Address(it[0]).exploded.split(":")]))+","+it[1]+"),//IPv6="+it[0]+"/"+it[1] for it in s], sep="\n")'

} > rs.tmp.out

mv rs.tmp.out $outfile

