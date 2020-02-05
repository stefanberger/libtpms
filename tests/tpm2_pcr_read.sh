#!/usr/bin/env bash

# For the license, see the LICENSE file in the root directory.

ROOT=${abs_top_builddir:-$(pwd)/..}
TESTDIR=${abs_top_testdir:-$(dirname "$0")}
DIR=${PWD}

SCRIPT="$(basename $0)"
SUFFIX=${SCRIPT##*.}
SCRIPT="${SCRIPT%.*}"
EXEC=${SCRIPT}

if [ ${SUFFIX} = "pcclient" ]; then
  EXEC="${EXEC}_pcclient"
fi

WORKDIR=$(mktemp -d)

. ${TESTDIR}/common

function cleanup()
{
	rm -rf ${WORKDIR}
}

trap "cleanup" QUIT EXIT

pushd $WORKDIR &>/dev/null

${DIR}/${EXEC}
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
