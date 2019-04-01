#!/usr/bin/env bash

TESTDIR=${abs_top_testdir:-$(dirname "$0")}
DIR=${PWD}

${DIR}/fuzz "$TESTDIR/corpus-execute-command/"*
