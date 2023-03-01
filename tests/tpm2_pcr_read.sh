#!/usr/bin/env bash

# For the license, see the LICENSE file in the root directory.

DIR=$(dirname "$0")

"${DIR}/tpm2_run_test.sh" tpm2_pcr_read
exit $?
