#!/bin/bash

input=$(mktemp)
binary=$(mktemp)

trap "rm -f $input $binary" EXIT

for i in $(seq 1 1024) 2048 10240;
do
	dd if=/dev/urandom of=$binary bs=1 count=$i &>/dev/null
	echo "-----BEGIN INITSTATE-----" > $input
	base64 < $binary >> $input
	echo "-----END INITSTATE-----" >> $input
	./base64decode $input $binary
	if [ $? -ne 0 ]; then
		exit 1
	fi
done
