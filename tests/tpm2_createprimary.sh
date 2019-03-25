#!/usr/bin/env bash

# For the license, see the LICENSE file in the root directory.

ROOT=${abs_top_builddir:-$(pwd)/..}
TESTDIR=${abs_top_testdir:-$(dirname "$0")}
DIR=${PWD}

WORKDIR=$(mktemp -d)
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-${ROOT}/src/.libs}

. ${TESTDIR}/common

case "$(uname -s)" in
Linux)
	if ! [ -d ${LD_LIBRARY_PATH} ]; then
		echo "Wrong path to libtpms library: ${LD_LIBRARY_PATH}"
		exit 1
	fi

	if ! [ -f "$(readlink -f ${LD_LIBRARY_PATH}/libtpms.so)" ]; then
		echo "Cannot find libtpms at ${LD_LIBRARY_PATH}/libtpms.so"
		exit 1
	fi
	;;
*)
	;;
esac

function cleanup()
{
	rm -rf ${WORKDIR}
}

trap "cleanup" QUIT EXIT

pushd $WORKDIR &>/dev/null

${DIR}/tpm2_createprimary
rc=$?

fs=$(get_filesize NVChip)
[ $? -ne 0 ] && exit 1
if [ $fs -ne 131072 ]; then
	echo "Error: Unexpected size of NVChip file."
	echo "Expected: 131072"
	echo "Got     : $fs"
	rc=1
fi

popd &>/dev/null

exit $rc
