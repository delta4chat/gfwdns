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
outfile="${outdir}/inside_ips.rs"

py="${outdir}/ip2b63.py"

tmp="$(mktemp -d -t gfwdnsChinaIpUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/ipverse/rir-ip/archive/master.zip -v -L -o rir-ip.zip $@
unzip rir-ip.zip

cd rir-ip-master
cd country
cd cn

{
	echo "#![allow(non_upper_case_globals)]"
    echo "use crate::*;"

    echo "/* CN: IPv4+IPv6 */"

	cat aggregated.json | jq -r '.subnets.ipv4[]' > ips.txt
	cat aggregated.json | jq -r '.subnets.ipv6[]' >> ips.txt
	
	cat ips.txt | python3 $py
} > rs.tmp.out

mv rs.tmp.out $outfile

