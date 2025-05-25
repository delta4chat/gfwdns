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
type tee

outdir="$(realpath .)"
outfile="${outdir}/outside_ips.bin"
outinfo="${outdir}/outside_ips.txt"

py="${outdir}/ip2bin.py"

tmp="$(mktemp -d -t gfwdnsGlobalIpUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/ipverse/rir-ip/archive/master.zip -v -L -o rir-ip.zip $@
unzip rir-ip.zip

cd rir-ip-master
cd country

{
    cat {de,et,ec,tt,it}/aggregated.json | jq -r '.subnets.ipv4[]' > txt.tmp.out
    cat {de,et,ec,tt,it}/aggregated.json | jq -r '.subnets.ipv6[]' >> txt.tmp.out

    cat txt.tmp.out | sort -u | tee txt.tmp.out.2 | python3 $py
} > bin.tmp.out

mv bin.tmp.out $outfile
mv txt.tmp.out.2 $outinfo

