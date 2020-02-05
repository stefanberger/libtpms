#
# tests/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

TESTS_ENVIRONMENT = \
  abs_top_testdir=`cd '$(top_srcdir)'/tests; pwd` \
  abs_top_builddir=`cd '$(top_builddir)'; pwd` \
  abs_top_srcdir=`cd '$(top_srcdir)'; pwd`

AM_CFLAGS = -I$(top_srcdir)/include $(SANITIZERS)
AM_LDFLAGS = -ltpms -L$(top_builddir)/src/.libs $(SANITIZERS)

check_PROGRAMS = \
	base64decode \
	nvram_offsets \
	tpm2_createprimary \
	tpm2_pcr_read \
	tpm2_selftest

TESTS = \
	base64decode.sh \
	fuzz.sh \
	nvram_offsets \
	tpm2_createprimary.sh \
	tpm2_pcr_read.sh \
	tpm2_selftest.sh

nvram_offsets_SOURCES = nvram_offsets.c
nvram_offsets_CFLAGS = $(AM_CFLAGS) \
	-I$(top_srcdir)/include/libtpms \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/tpm2 \
	-I$(top_srcdir)/src/tpm2/crypto \
	-I$(top_srcdir)/src/tpm2/crypto/openssl \
	-DTPM_POSIX
nvram_offsets_LDFLAGS = $(AM_LDFLAGS)

check_PROGRAMS += fuzz
fuzz_SOURCES = fuzz.cc
fuzz_CXXFLAGS = $(FUZZER) $(AM_CFLAGS)
fuzz_LDFLAGS = $(FUZZER) $(LIB_FUZZING_ENGINE) $(AM_LDFLAGS)
if !WITH_FUZZER
if !WITH_FUZZING_ENGINE
fuzz_SOURCES += fuzz-main.c
endif
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

if WITH_PROFILE_TEST

SUFFIXES: .extra
.sh.extra:
	$(LN_S) $(CURDIR)/$< $@

AM_EXTRA_LDFLAGS = -ltpms-@TEST_PROFILE@ -L$(top_builddir)/src/.libs $(SANITIZERS)

check_PROGRAMS += \
	base64decode_extra \
	nvram_offsets_extra \
	tpm2_createprimary_extra \
	tpm2_pcr_read_extra \
	tpm2_selftest_extra \
	fuzz_extra

TESTS += \
	base64decode.extra \
	fuzz.extra \
	nvram_offsets_extra \
	tpm2_createprimary.extra \
	tpm2_pcr_read.extra \
	tpm2_selftest.extra

base64decode_extra_SOURCES = base64decode.c
base64decode_extra_LDFLAGS = $(AM_EXTRA_LDFLAGS)

nvram_offsets_extra_SOURCES = $(nvram_offsets_SOURCES)
nvram_offsets_extra_CFLAGS = $(nvram_offsets_CFLAGS)
nvram_offsets_extra_LDFLAGS = $(AM_EXTRA_LDFLAGS)

tpm2_createprimary_extra_SOURCES = tpm2_createprimary.c
tpm2_createprimary_extra_CFLAGS = $(AM_CFLAGS) -DWITH_EXTRA
tpm2_createprimary_extra_LDFLAGS = $(AM_EXTRA_LDFLAGS)

tpm2_pcr_read_extra_SOURCES = tpm2_pcr_read.c
tpm2_pcr_read_extra_CFLAGS = $(AM_CFLAGS) -DWITH_EXTRA
tpm2_pcr_read_extra_LDFLAGS = $(AM_EXTRA_LDFLAGS)

tpm2_selftest_extra_SOURCES = tpm2_selftest.c
tpm2_selftest_extra_LDFLAGS = $(AM_EXTRA_LDFLAGS)

fuzz_extra_SOURCES = $(fuzz_SOURCES)
fuzz_extra_CXXFLAGS = $(fuzz_CXXFLAGS)
fuzz_extra_LDFLAGS = $(FUZZER) $(LIB_FUZZING_ENGINE) $(AM_EXTRA_LDFLAGS)

endif # WITH_PROFILE_TEST

EXTRA_DIST = \
	freebl_sha1flattensize.c \
	base64decode.c \
	base64decode.sh \
	common \
	tpm2_createprimary.c \
	tpm2_createprimary.sh \
	tpm2_pcr_read.c \
	tpm2_pcr_read.sh \
	tpm2_selftest.c \
	tpm2_selftest.sh \
	fuzz.sh

CLEANFILES = \
	*.gcov \
	*.gcda \
	*.gcno \
	*.extra
