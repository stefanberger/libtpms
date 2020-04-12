add_library(tpm12_objects OBJECT 
    tpm_admin.c
    tpm_audit.c
    tpm_auth.c
    tpm_cryptoh.c
    tpm_counter.c
    tpm_daa.c
    tpm_debug.c
    tpm_delegate.c
    tpm_digest.c
    tpm_error.c
    tpm_global.c
    tpm_identity.c
    tpm_init.c
    tpm_libtpms_io.c
    tpm_key.c
    tpm_load.c
    tpm_maint.c
    tpm_memory.c
    tpm_migration.c
    tpm_nonce.c
    tpm_nvfile.c
    tpm_nvram.c
    tpm_owner.c
    tpm_pcr.c
    tpm_permanent.c
    tpm_platform.c
    tpm_process.c
    tpm_secret.c
    tpm_session.c
    tpm_sizedbuffer.c
    tpm_startup.c
    tpm_store.c
    tpm_storage.c
    tpm_ticks.c
    tpm_time.c
    tpm_transport.c
    tpm_ver.c
    tpm_svnrevision.c
    $<$<BOOL:${WITH_OPENSSL}>:tpm_crypto.c>
)

target_compile_definitions(tpm12_objects PUBLIC
    # Build 1.2 TPM
    TPM_V12
    # build a PC Client TPM
    TPM_PCCLIENT
    # upon initialization have the TPM load the volatile state
    TPM_VOLATILE_LOAD
    # build the TPM enabled and activated
    TPM_ENABLE_ACTIVATE
    # build with AES support for symmetric crypto
    TPM_AES
    # build with libtpms callback support
    TPM_LIBTPMS_CALLBACKS
    # let the default NVRAM write to disk
    TPM_NV_DISK
    # build a POSIX type of TPM
    TPM_POSIX
    # build without maintenance commands
    TPM_NOMAINTENANCE_COMMANDS
)

target_include_directories(tpm12_objects PUBLIC
    ${PROJECT_SOURCE_DIR}/include/libtpms
    ${PROJECT_SOURCE_DIR}/src
)