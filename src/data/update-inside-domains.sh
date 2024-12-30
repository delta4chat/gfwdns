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
outfile="${outdir}/inside_domains.rs"

tmp="$(mktemp -d -t gfwdnsChinaDomainsUpdater.XXXXXXXX)"
trap "rm -rfv $tmp" EXIT
cd $tmp

curl https://github.com/carrnot/china-domain-list/raw/refs/heads/release/domain.txt -v -O -L $@

{
    #echo "use crate::*;"

	echo "/* Inside Domains (ChinaList) */"
	echo "pub const LIST: &'static [&'static str] = &["

	for domain in $(cat domain.txt | sort -u | grep -v -F '"')
	do
		echo "\"${domain}\","
	done

	echo "];"
} > rs.tmp.out

mv rs.tmp.out $outfile

