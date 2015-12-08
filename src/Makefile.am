#
# src/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

lib_LTLIBRARIES=libtpms.la

#
# TPM1.2
#

noinst_LTLIBRARIES = libtpms_tpm12.la

libtpms_la_LIBADD = libtpms_tpm12.la

libtpms_tpm12_la_LIBADD =

libtpms_tpm12_la_CFLAGS = -include tpm_library_conf.h \
                          -I$(top_srcdir)/include/libtpms \
                          $(HARDENING_CFLAGS)

#Build 1.2 TPM
libtpms_tpm12_la_CFLAGS += -DTPM_V12
# build a PC Client TPM
libtpms_tpm12_la_CFLAGS += -DTPM_PCCLIENT
# upon initialization have the TPM load the volatile state
libtpms_tpm12_la_CFLAGS += -DTPM_VOLATILE_LOAD
# build the TPM enabled and activated
libtpms_tpm12_la_CFLAGS += -DTPM_ENABLE_ACTIVATE
# build with AES support for symmetric crypto
libtpms_tpm12_la_CFLAGS += -DTPM_AES
# build with libtpms callback support
libtpms_tpm12_la_CFLAGS += -DTPM_LIBTPMS_CALLBACKS
# let the default NVRAM write to disk
libtpms_tpm12_la_CFLAGS += -DTPM_NV_DISK
# build a POSIX type of TPM
libtpms_tpm12_la_CFLAGS += -DTPM_POSIX

libtpms_tpm12_la_CFLAGS += @DEBUG_DEFINES@

CRYPTO_OBJFILES =

libtpms_tpm12_la_SOURCES = \
	tpm12/tpm_admin.c \
	tpm12/tpm_audit.c \
	tpm12/tpm_auth.c \
	tpm12/tpm_cryptoh.c \
	tpm12/tpm_counter.c \
	tpm12/tpm_daa.c \
	tpm12/tpm_debug.c \
	tpm12/tpm_delegate.c \
	tpm12/tpm_digest.c \
	tpm12/tpm_error.c \
	tpm12/tpm_global.c \
	tpm12/tpm_identity.c \
	tpm12/tpm_init.c \
	tpm12/tpm_libtpms_io.c \
	tpm12/tpm_key.c \
	tpm12/tpm_load.c \
	tpm12/tpm_maint.c \
	tpm12/tpm_memory.c \
	tpm12/tpm_migration.c \
	tpm12/tpm_nonce.c \
	tpm12/tpm_nvfile.c \
	tpm12/tpm_nvram.c \
	tpm12/tpm_owner.c \
	tpm12/tpm_pcr.c \
	tpm12/tpm_permanent.c \
	tpm12/tpm_platform.c \
	tpm12/tpm_process.c \
	tpm12/tpm_secret.c \
	tpm12/tpm_session.c \
	tpm12/tpm_sizedbuffer.c \
	tpm12/tpm_startup.c \
	tpm12/tpm_store.c \
	tpm12/tpm_storage.c \
	tpm12/tpm_ticks.c \
	tpm12/tpm_time.c \
	tpm12/tpm_transport.c \
	tpm12/tpm_ver.c \
	tpm12/tpm_svnrevision.c \
	tpm_tpm12_interface.c \
	tpm_tpm12_tis.c

noinst_HEADERS = \
	tpm12/tpm_admin.h \
	tpm12/tpm_audit.h \
	tpm12/tpm_auth.h \
	tpm12/tpm_commands.h \
	tpm12/tpm_constants.h \
	tpm12/tpm_counter.h \
	tpm12/tpm_crypto.h \
	tpm12/tpm_cryptoh.h \
	tpm12/tpm_daa.h \
	tpm12/tpm_debug.h \
	tpm12/tpm_delegate.h \
	tpm12/tpm_digest.h \
	tpm12/tpm_global.h \
	tpm12/tpm_identity.h \
	tpm12/tpm_init.h \
	tpm12/tpm_io.h \
	tpm12/tpm_key.h \
	tpm_library_conf.h \
	tpm_library_intern.h \
	tpm12/tpm_load.h \
	tpm12/tpm_maint.h \
	tpm12/tpm_migration.h \
	tpm12/tpm_nonce.h \
	tpm12/tpm_nvfile.h \
	tpm12/tpm_nvram_const.h \
	tpm12/tpm_nvram.h \
	tpm12/tpm_owner.h \
	tpm12/tpm_pcr.h \
	tpm12/tpm_permanent.h \
	tpm12/tpm_platform.h \
	tpm12/tpm_process.h \
	tpm12/tpm_secret.h \
	tpm12/tpm_session.h \
	tpm12/tpm_sizedbuffer.h \
	tpm12/tpm_startup.h \
	tpm12/tpm_storage.h \
	tpm12/tpm_store.h \
	tpm12/tpm_structures.h \
	tpm12/tpm_svnrevision.h \
	tpm12/tpm_ticks.h \
	tpm12/tpm_time.h \
	tpm12/tpm_transport.h \
	tpm12/tpm_ver.h
	

if LIBTPMS_USE_FREEBL

libtpms_tpm12_la_SOURCES += tpm12/tpm_crypto_freebl.c
libtpms_tpm12_la_LIBADD += -lfreebl -lgmp -lnspr4 -lnssutil3 -lnss3

#work-around broken freebl includes
libtpms_tpm12_la_CFLAGS += $(shell [ ! -r /usr/include/nss3/alghmac.h ] && \
	touch alghmac.h && \
	echo -I./)
# tpm12/tpm_crypto_freebl.c: work around #include "blapi.h" : should be <nss3/blapi.h>
libtpms_tpm12_la_CFLAGS += $(shell nss-config --cflags)
#including nss3/blapi.h requires a look into nspr4 dir
libtpms_tpm12_la_CFLAGS += $(shell nspr-config --cflags)

else 

if LIBTPMS_USE_OPENSSL

libtpms_tpm12_la_SOURCES += tpm12/tpm_crypto.c
libtpms_tpm12_la_LIBADD += -lcrypto

endif # LIBTPMS_USE_OPENSSL

endif # LIBTPMS_USE_FREEBL

#
# Library API layer
#

libtpms_la_SOURCES = \
	tpm_library.c

libtpms_la_CFLAGS = \
	$(libtpms_tpm12_la_CFLAGS)

libtpms_la_LDFLAGS = -Wl,--version-script=./libtpms.syms \
                     -version-info $(LIBTPMS_VERSION_INFO) \
                     -no-undefined


LDFLAGS_ARCH  = $(findstring -m32, $(CFLAGS))
LDFLAGS_ARCH += $(findstring -m64, $(CFLAGS))
LDFLAGS_ARCH += $(findstring -m32, $(LDFLAGS))
LDFLAGS_ARCH += $(findstring -m64, $(LDFLAGS))

check-local:
	@($(CC) $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms 2>/dev/null || \
	 (echo "There are undefined symbols in libtpms ($(LDFLAGS_ARCH))";\
	  $(CC) $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms 2>&1 | grep libtpms))
	@$(CC) $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms 2>/dev/null

EXTRA_DIST = \
	tpm12/tpm_crypto_freebl.c \
	tpm12/tpm_crypto.c \
	libtpms.syms
