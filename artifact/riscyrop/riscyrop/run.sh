#!/bin/sh

binary=$1
shift
bulk=0x100

seq 0 10000 | \
	parallel --halt soon,fail=500 -j$(nproc) \
		--timeout 30m \
		python ./find_gadgets.py -s "$binary" "$bulk" {} "$@" \
	>"$binary.out" 2>"$binary.err"

sqlite3 rop_analysis.db VACUUM
