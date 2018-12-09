#!/usr/bin/env bash

# For the license, see the LICENSE file in the root directory.

DIR=${PWD}/$(dirname "$0")
ROOT=${DIR}/..
WORKDIR=$(mktemp -d)
export LD_LIBRARY_PATH=${ROOT}/src/.libs

if ! [ -d ${LD_LIBRARY_PATH} ]; then
	echo "Wrong path to libtpms library: ${LD_LIBRARY_PATH}"
	exit 1
fi

if ! [ -f "$(readlink -f ${LD_LIBRARY_PATH}/libtpms.so)" ]; then
	echo "Cannot find libtpms at ${LD_LIBRARY_PATH}/libtpms.so"
	exit 1
fi

function cleanup()
{
	rm -rf ${WORKDIR}
}

trap "cleanup" QUIT EXIT

pushd $WORKDIR

${DIR}/fuzz $@ ${DIR}/corpus-execute-command
rc=$?

popd

exit $rc
