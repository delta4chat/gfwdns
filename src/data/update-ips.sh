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
inside_ips="${outdir}/inside_ips"
outside_ips="${outdir}/outside_ips"

py="${outdir}/ip2bin.py"

tmp="$(mktemp -d -t gfwdnsIpListUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/ipverse/rir-ip/archive/master.zip -v -L -o rir-ip.zip $@
unzip rir-ip.zip

cd rir-ip-master
cd country

{
    cat cn/aggregated.json | jq -r '.subnets.ipv4[]' > txt.tmp.out
    cat cn/aggregated.json | jq -r '.subnets.ipv6[]' >> txt.tmp.out

    cat txt.tmp.out | sort -u | tee txt.tmp.out.2 | python3 $py
} > bin.tmp.out

mv bin.tmp.out "$inside_ips"'.bin'
mv txt.tmp.out.2 "$inside_ips"'.txt'

####################

{
    cat {de,et,ec,tt,it}/aggregated.json | jq -r '.subnets.ipv4[]' > txt.tmp.out
    cat {de,et,ec,tt,it}/aggregated.json | jq -r '.subnets.ipv6[]' >> txt.tmp.out

    cat txt.tmp.out | sort -u | tee txt.tmp.out.2 | python3 $py
} > bin.tmp.out

mv bin.tmp.out "$outside_ips"'.bin'
mv txt.tmp.out.2 "$outside_ips"'.txt'

