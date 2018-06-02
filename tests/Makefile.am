#
# tests/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

AM_CFLAGS = -I../include $(SANITIZERS)
AM_LDFLAGS = -ltpms -L../src/.libs $(SANITIZERS)

check_PROGRAMS = base64decode nvram_offsets
TESTS = base64decode.sh nvram_offsets

nvram_offsets_SOURCES = nvram_offsets.c
nvram_offsets_CFLAGS = $(AM_CFLAGS) \
	-I$(top_srcdir)/include/libtpms \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/tpm2 \
	-I$(top_srcdir)/src/tpm2/crypto \
	-I$(top_srcdir)/src/tpm2/crypto/openssl \
	-DTPM_POSIX
nvram_offsets_LDFLAGS = $(AM_LDFLAGS)

if WITH_FUZZER
check_PROGRAMS += fuzz
fuzz_CFLAGS = -fsanitize=fuzzer $(AM_CFLAGS)
fuzz_LDFLAGS = -fsanitize=fuzzer $(AM_LDFLAGS)
endif

if LIBTPMS_USE_FREEBL

check_PROGRAMS += freebl_sha1flattensize
TESTS += freebl_sha1flattensize

endif

freebl_sha1flattensize_SOURCES = \
	freebl_sha1flattensize.c
freebl_sha1flattensize_CFLAGS = \
	$(shell nss-config --cflags) \
	$(shell nspr-config --cflags) \
	-Wall -Werror
freebl_sha1flattensize_LDFLAGS = \
	-lfreebl \
	$(shell nspr-config --libs) \
	$(shell nss-config --libs)

EXTRA_DIST = \
	freebl_sha1flattensize.c \
	base64decode.c \
	base64decode.sh
