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
AM_LDFLAGS = -no-undefined $(SANITIZERS)
LDADD = $(top_builddir)/src/libtpms.la

check_PROGRAMS = \
	base64decode

TESTS = \
	base64decode.sh

if WITH_TPM2
check_PROGRAMS += \
	nvram_offsets \
	tpm2_createprimary \
	tpm2_cve-2023-1017 \
	tpm2_cve-2023-1018 \
	tpm2_pcr_read \
	tpm2_selftest \
	tpm2_setprofile

TESTS += \
	fuzz.sh \
	nvram_offsets \
	tpm2_createprimary.sh \
	tpm2_cve-2023-1017.sh \
	tpm2_cve-2023-1018.sh \
	tpm2_pcr_read.sh \
	tpm2_selftest.sh \
	tpm2_setprofile.sh
endif

nvram_offsets_SOURCES = nvram_offsets.c
nvram_offsets_CFLAGS = $(AM_CFLAGS) \
	-I$(top_srcdir)/include/libtpms \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/tpm2 \
	-I$(top_srcdir)/src/tpm2/crypto \
	-I$(top_srcdir)/src/tpm2/crypto/openssl \
	-DTPM_POSIX
nvram_offsets_LDFLAGS = $(AM_LDFLAGS)


if WITH_TPM2
if ENABLE_STATIC_TESTS

# object_size needs ANY_OBJECT_Marshal which only is accessible with '-static'
check_PROGRAMS += \
	object_size
TESTS += \
	object_size

object_size_SOURCES = object_size.c
object_size_CFLAGS = $(AM_CFLAGS) \
	-static \
	-I$(top_srcdir)/include/libtpms \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/tpm2 \
	-I$(top_srcdir)/src/tpm2/crypto \
	-I$(top_srcdir)/src/tpm2/crypto/openssl \
	-DTPM_POSIX
object_size_LDFLAGS = $(AM_LDFLAGS)
endif # ENABLE_STATIC_TESTS
endif # WITH_TPM2

if WITH_TPM2
check_PROGRAMS += fuzz
endif
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

EXTRA_DIST = \
	freebl_sha1flattensize.c \
	base64decode.c \
	base64decode.sh \
	common \
	tpm2_createprimary.c \
	tpm2_createprimary.sh \
	tpm2_cve-2023-1017.c \
	tpm2_cve-2023-1017.sh \
	tpm2_cve-2023-1018.c \
	tpm2_cve-2023-1018.sh \
	tpm2_pcr_read.c \
	tpm2_pcr_read.sh \
	tpm2_run_test.sh \
	tpm2_selftest.c \
	tpm2_selftest.sh \
	tpm2_setprofile.c \
	tpm2_setprofile.sh \
	fuzz.sh

CLEANFILES = \
	*.gcov \
	*.gcda \
	*.gcno
