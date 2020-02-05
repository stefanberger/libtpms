#!/usr/bin/env bash

TESTDIR=${abs_top_testdir:-$(dirname "$0")}
DIR=${PWD}

SCRIPT="$(basename $0)"
SUFFIX=${SCRIPT##*.}
SCRIPT="${SCRIPT%.*}"
EXEC=${SCRIPT}

if [ ${SUFFIX} = "pcclient" ]; then
  EXEC="${EXEC}_pcclient"
fi

MAXLINES=128
l=1

corpus=$(ls "$TESTDIR/corpus-execute-command/"*)

while :; do
  echo "Passing test cases $l to $((l + MAXLINES))"
  tmp=$(echo "${corpus}" | sed -n "${l},$((l + MAXLINES))p")
  [ -z "${tmp}" ] && exit 0
  ${DIR}/${EXEC} ${tmp}
  rc=$?
  [ $rc -ne 0 ] && exit $rc
  l=$((l + MAXLINES))
done
