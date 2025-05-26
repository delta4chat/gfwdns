#!/bin/bash

set -e
set -x

type mktemp
type curl
type realpath
type cat
type sort
type rm
type mv

outdir="$(realpath .)"
outfile="${outdir}/inside_domains.txt"

tmp="$(mktemp -d -t gfwdnsChinaDomainsUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/carrnot/china-domain-list/raw/refs/heads/release/domain.txt -v -O -L $@

{
    cat domain.txt | grep -v -F '"' | sort -u
} > txt.tmp.out

mv txt.tmp.out $outfile

