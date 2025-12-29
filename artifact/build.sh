#!/bin/bash

#for tool in ropbot exrop crackers sgc arcanist; do
#	echo "building "$tool"...";
#	pushd $tool > /dev/null
#	docker build -t $tool .
#	popd > /dev/null
#done

echo "building ropbot ...";
pushd ropbot > /dev/null
docker build -t ropbot .
