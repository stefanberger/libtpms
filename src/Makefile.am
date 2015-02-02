#
# src/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

lib_LTLIBRARIES=libtpms.la

libtpms_la_LIBADD=

libtpms_la_LDFLAGS = -Wl,--version-script=./libtpms.syms \
                     -version-info $(LIBTPMS_VERSION_INFO) \
                     -no-undefined

libtpms_la_CFLAGS = -include tpm_library_conf.h -I$(top_srcdir)/include/libtpms \
                    $(HARDENING_CFLAGS)

#Build 1.2 TPM
libtpms_la_CFLAGS += -DTPM_V12
# build a PC Client TPM
libtpms_la_CFLAGS += -DTPM_PCCLIENT
# upon initialization have the TPM load the volatile state
libtpms_la_CFLAGS += -DTPM_VOLATILE_LOAD
# build the TPM enabled and activated
libtpms_la_CFLAGS += -DTPM_ENABLE_ACTIVATE
# build with AES support for symmetric crypto
libtpms_la_CFLAGS += -DTPM_AES
# build with libtpms callback support
libtpms_la_CFLAGS += -DTPM_LIBTPMS_CALLBACKS
# let the default NVRAM write to disk
libtpms_la_CFLAGS += -DTPM_NV_DISK
# build a POSIX type of TPM
libtpms_la_CFLAGS += -DTPM_POSIX

libtpms_la_CFLAGS += @DEBUG_DEFINES@

CRYPTO_OBJFILES =

libtpms_la_SOURCES = \
	tpm_admin.c \
	tpm_audit.c \
	tpm_auth.c \
	tpm_cryptoh.c \
	tpm_counter.c \
	tpm_daa.c \
	tpm_debug.c \
	tpm_delegate.c \
	tpm_digest.c \
	tpm_error.c \
	tpm_global.c \
	tpm_identity.c \
	tpm_init.c \
	tpm_libtpms_io.c \
	tpm_key.c \
	tpm_library.c \
	tpm_load.c \
	tpm_maint.c \
	tpm_memory.c \
	tpm_migration.c \
	tpm_nonce.c \
	tpm_nvfile.c \
	tpm_nvram.c \
	tpm_owner.c \
	tpm_pcr.c \
	tpm_permanent.c \
	tpm_platform.c \
	tpm_process.c \
	tpm_secret.c \
	tpm_session.c \
	tpm_sizedbuffer.c \
	tpm_startup.c \
	tpm_store.c \
	tpm_storage.c \
	tpm_ticks.c \
	tpm_time.c \
	tpm_tis.c \
	tpm_transport.c \
	tpm_ver.c \
	tpm_svnrevision.c

noinst_HEADERS = \
	tpm_admin.h \
	tpm_audit.h \
	tpm_auth.h \
	tpm_commands.h \
	tpm_constants.h \
	tpm_counter.h \
	tpm_crypto.h \
	tpm_cryptoh.h \
	tpm_daa.h \
	tpm_debug.h \
	tpm_delegate.h \
	tpm_digest.h \
	tpm_global.h \
	tpm_identity.h \
	tpm_init.h \
	tpm_io.h \
	tpm_key.h \
	tpm_library_conf.h \
	tpm_library_intern.h \
	tpm_load.h \
	tpm_maint.h \
	tpm_migration.h \
	tpm_nonce.h \
	tpm_nvfile.h \
	tpm_nvram_const.h \
	tpm_nvram.h \
	tpm_owner.h \
	tpm_pcr.h \
	tpm_permanent.h \
	tpm_platform.h \
	tpm_process.h \
	tpm_secret.h \
	tpm_session.h \
	tpm_sizedbuffer.h \
	tpm_startup.h \
	tpm_storage.h \
	tpm_store.h \
	tpm_structures.h \
	tpm_svnrevision.h \
	tpm_ticks.h \
	tpm_time.h \
	tpm_transport.h \
	tpm_ver.h
	

if LIBTPMS_USE_FREEBL

libtpms_la_SOURCES += tpm_crypto_freebl.c
libtpms_la_LIBADD += -lfreebl -lgmp -lnspr4 -lnssutil3 -lnss3

#work-around broken freebl includes
libtpms_la_CFLAGS += $(shell [ ! -r /usr/include/nss3/alghmac.h ] && \
	touch alghmac.h && \
	echo -I./)
# tpm_crypto_freebl.c: work around #include "blapi.h" : should be <nss3/blapi.h>
libtpms_la_CFLAGS += $(shell nss-config --cflags)
#including nss3/blapi.h requires a look into nspr4 dir
libtpms_la_CFLAGS += $(shell nspr-config --cflags)

else 

if LIBTPMS_USE_OPENSSL

libtpms_la_SOURCES += tpm_crypto.c
libtpms_la_LIBADD += -lcrypto

endif # LIBTPMS_USE_OPENSSL

endif # LIBTPMS_USE_FREEBL

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
	tpm_crypto_freebl.c \
	tpm_crypto.c \
	libtpms.syms
