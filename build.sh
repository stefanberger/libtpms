#!/bin/bash
set -e

SCRIPT_HOME=$(realpath $(dirname "${0}"))
SCRIPT_NAME=$(basename "${0}")
PROJECT_NAME=libtpms
cd "${SCRIPT_HOME}"

set -x
if [ -f /.dockerenv ]; then
	if [ ! -f /.provisioned ]; then
		apt update
		apt install -y libssl-dev libc6-dev libtool m4 make automake
		touch /.provisioned
	else
		./bootstrap.sh
		./configure --with-openssl "${@}"
		make
	fi
else
	cname="${PROJECT_NAME}-provision-cache"
	
	if ! docker images -f dangling=false --format "{{.Repository}}" | grep -xq "${cname}"; then
		docker run -it -v "${SCRIPT_HOME}:/source" "${@}" --name "${cname}" ubuntu:xenial "/source/${SCRIPT_NAME}"
		docker commit "${cname}" "${cname}"
		docker rm -f "${cname}"
	fi
	
	docker run -it -v "${SCRIPT_HOME}:/source" "${@}" --rm "${cname}" "/source/${SCRIPT_NAME}"
fi
