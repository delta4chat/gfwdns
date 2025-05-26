#!/bin/bash

set -e
set -x

type mktemp
type curl
type realpath
type base64
type python3
type cat
type sort
type rm
type mv

outdir="$(realpath .)"
outfile="${outdir}/outside_domains.txt"

py="${outdir}/gfwlist2domains.py"

tmp="$(mktemp -d -t gfwdnsGlobalDomainsUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/gfwlist/gfwlist/raw/refs/heads/master/gfwlist.txt -v -O -L $@

{
    cat gfwlist.txt | base64 -d | python3 $py | sort -u
} > txt.tmp.out

mv txt.tmp.out $outfile

