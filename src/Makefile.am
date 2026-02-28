#
# src/Makefile.am
#
# For the license, see the LICENSE file in the root directory.
#

AM_CFLAGS = @AM_CFLAGS@
AM_LDFLAGS = @AM_LDFLAGS@ $(HARDENING_LDFLAGS) $(SANITIZERS) $(FUZZER)
noinst_LTLIBRARIES =
noinst_HEADERS =

lib_LTLIBRARIES = libtpms.la
libtpms_la_LIBADD =

common_CFLAGS = -include tpm_library_conf.h \
                -I$(top_srcdir)/include/libtpms \
		-I$(top_builddir)/include/libtpms \
		$(AM_CFLAGS) \
                $(HARDENING_CFLAGS) \
               $(SANITIZERS) \
               $(FUZZER) \
               $(LIBCRYPTO_EXTRA_CFLAGS)

# build with libtpms callback support
common_CFLAGS += -DTPM_LIBTPMS_CALLBACKS
# let the default NVRAM write to disk
common_CFLAGS += -DTPM_NV_DISK

if WITH_TPM1
#
# TPM1.2
#

noinst_LTLIBRARIES += libtpms_tpm12.la

libtpms_la_LIBADD += libtpms_tpm12.la

libtpms_tpm12_la_LIBADD =

libtpms_tpm12_la_CFLAGS = $(common_CFLAGS)

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
# build a POSIX type of TPM
libtpms_tpm12_la_CFLAGS += -DTPM_POSIX
# build without maintenance commands
libtpms_tpm12_la_CFLAGS += -DTPM_NOMAINTENANCE_COMMANDS

CRYPTO_OBJFILES =

libtpms_tpm12_la_SOURCES = \
	tpm12/tpm_admin.c \
	tpm12/tpm_audit.c \
	tpm12/tpm_auth.c \
	tpm12/tpm_cryptoh.c \
	tpm12/tpm_counter.c \
	tpm12/tpm_daa.c \
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
	tpm12/tpm_migration.c \
	tpm12/tpm_nonce.c \
	tpm12/tpm_nvram.c \
	tpm12/tpm_openssl_helpers.c \
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

noinst_HEADERS += \
	tpm12/tpm_admin.h \
	tpm12/tpm_audit.h \
	tpm12/tpm_auth.h \
	tpm12/tpm_commands.h \
	tpm12/tpm_constants.h \
	tpm12/tpm_counter.h \
	tpm12/tpm_crypto.h \
	tpm12/tpm_cryptoh.h \
	tpm12/tpm_daa.h \
	tpm_debug.h \
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
	tpm_nvfile.h \
	tpm12/tpm_nvram_const.h \
	tpm12/tpm_nvram.h \
	tpm12/tpm_openssl_helpers.h \
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

endif # WITH_TPM1

# TPM2
#

if WITH_TPM2

noinst_LTLIBRARIES += libtpms_tpm2.la

libtpms_la_LIBADD += libtpms_tpm2.la

libtpms_tpm2_la_LIBADD = $(LIBRT_LIBS)

libtpms_tpm2_la_CFLAGS = $(common_CFLAGS)

libtpms_tpm2_la_CFLAGS += -D_POSIX_
libtpms_tpm2_la_CFLAGS += -DTPM_POSIX

libtpms_tpm2_la_SOURCES = \
	tpm2/ACTCommands.c \
	tpm2/AsymmetricCommands.c \
	tpm2/AttestationCommands.c \
	tpm2/AuditCommands.c \
	tpm2/CapabilityCommands.c \
	tpm2/ClockCommands.c \
	tpm2/ContextCommands.c \
	tpm2/DictionaryCommands.c \
	tpm2/DuplicationCommands.c \
	tpm2/EACommands.c \
	tpm2/EphemeralCommands.c \
	tpm2/HashCommands.c \
	tpm2/HierarchyCommands.c \
	tpm2/IntegrityCommands.c \
	tpm2/ManagementCommands.c \
	tpm2/NVCommands.c \
	tpm2/ObjectCommands.c \
	tpm2/RandomCommands.c \
	tpm2/SessionCommands.c \
	tpm2/SigningCommands.c \
	tpm2/StartupCommands.c \
	tpm2/SymmetricCommands.c \
	tpm2/TestingCommands.c \
	tpm2/TPMCmd/Platform/src/Cancel.c \
	tpm2/TPMCmd/Platform/src/Clock.c \
	tpm2/TPMCmd/Platform/src/DebugHelpers.c \
	tpm2/TPMCmd/Platform/src/Entropy.c \
	tpm2/TPMCmd/Platform/src/ExtraData.c \
	tpm2/TPMCmd/Platform/src/Failure.c \
	tpm2/TPMCmd/Platform/src/Init.c \
	tpm2/TPMCmd/Platform/src/LocalityPlat.c \
	tpm2/TPMCmd/Platform/src/NVMem.c \
	tpm2/TPMCmd/Platform/src/NVVirtual.c \
	tpm2/TPMCmd/Platform/src/PlatformACT.c \
	tpm2/TPMCmd/Platform/src/PlatformData.c \
	tpm2/TPMCmd/Platform/src/PlatformPcr.c \
	tpm2/TPMCmd/Platform/src/PowerPlat.c \
	tpm2/TPMCmd/Platform/src/PPPlat.c \
	tpm2/TPMCmd/Platform/src/RunCommand.c \
	tpm2/TPMCmd/Platform/src/SelfTest.c \
	tpm2/TPMCmd/Platform/src/Unique.c \
	tpm2/TPMCmd/Platform/src/VendorInfo.c \
	tpm2/TPMCmd/Simulator/src/TPMCmdp.c \
	tpm2/TPMCmd/tpm/cryptolibs/EccRef/TpmEcc_Signature_ECDSA.c \
	tpm2/TPMCmd/tpm/cryptolibs/RsaRef/PrimeData.c \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/BnConvert.c \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/BnEccConstants.c \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/BnMath.c \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/BnMemory.c \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/TpmBigNumThunks.c \
	tpm2/TPMCmd/tpm/src/command/Attestation/Attest_spt.c \
	tpm2/TPMCmd/tpm/src/command/Attestation/Quote.c \
	tpm2/TPMCmd/tpm/src/command/ClockTimer/ACT_spt.c \
	tpm2/TPMCmd/tpm/src/command/Context/Context_spt.c \
	tpm2/TPMCmd/tpm/src/command/Duplication/Duplicate.c \
	tpm2/TPMCmd/tpm/src/command/Duplication/Import.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicyAuthorize.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicyAuthorizeNV.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicyPCR.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicySecret.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicySigned.c \
	tpm2/TPMCmd/tpm/src/command/EA/Policy_spt.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicyTicket.c \
	tpm2/TPMCmd/tpm/src/command/EA/PolicyTransportSPDM.c \
	tpm2/TPMCmd/tpm/src/command/Hierarchy/CreatePrimary.c \
	tpm2/TPMCmd/tpm/src/command/Hierarchy/ReadOnlyControl.c \
	tpm2/TPMCmd/tpm/src/command/NVStorage/NV_Read.c \
	tpm2/TPMCmd/tpm/src/command/NVStorage/NV_ReadPublic2.c \
	tpm2/TPMCmd/tpm/src/command/NVStorage/NV_ReadPublic.c \
	tpm2/TPMCmd/tpm/src/command/NVStorage/NV_spt.c \
	tpm2/TPMCmd/tpm/src/command/Object/Create.c \
	tpm2/TPMCmd/tpm/src/command/Object/CreateLoaded.c \
	tpm2/TPMCmd/tpm/src/command/Object/MakeCredential.c \
	tpm2/TPMCmd/tpm/src/command/Object/ObjectChangeAuth.c \
	tpm2/TPMCmd/tpm/src/command/Object/Object_spt.c \
	tpm2/TPMCmd/tpm/src/command/PCR/PCR_Read.c \
	tpm2/TPMCmd/tpm/src/command/Symmetric/EncryptDecrypt_spt.c \
	tpm2/TPMCmd/tpm/src/crypt/AlgorithmTests.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptEccData.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptSelfTest.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptUtil.c \
	tpm2/TPMCmd/tpm/src/crypt/ecc/TpmEcc_Signature_ECDAA.c \
	tpm2/TPMCmd/tpm/src/crypt/ecc/TpmEcc_Signature_Schnorr.c \
	tpm2/TPMCmd/tpm/src/crypt/ecc/TpmEcc_Signature_SM2.c \
	tpm2/TPMCmd/tpm/src/crypt/ecc/TpmEcc_Signature_Util.c \
	tpm2/TPMCmd/tpm/src/crypt/ecc/TpmEcc_Util.c \
	tpm2/TPMCmd/tpm/src/crypt/math/TpmMath_Debug.c \
	tpm2/TPMCmd/tpm/src/crypt/math/TpmMath_Util.c \
	tpm2/TPMCmd/tpm/src/crypt/Ticket.c \
	tpm2/TPMCmd/tpm/src/events/_TPM_Init.c \
	tpm2/TPMCmd/tpm/src/main/CommandDispatcher.c \
	tpm2/TPMCmd/tpm/src/main/ExecCommand.c \
	tpm2/TPMCmd/tpm/src/main/SessionProcess.c \
	tpm2/TPMCmd/tpm/src/subsystem/CommandAudit.c \
	tpm2/TPMCmd/tpm/src/subsystem/DA.c \
	tpm2/TPMCmd/tpm/src/subsystem/Hierarchy.c \
	tpm2/TPMCmd/tpm/src/subsystem/NvDynamic.c \
	tpm2/TPMCmd/tpm/src/subsystem/NvReserved.c \
	tpm2/TPMCmd/tpm/src/subsystem/Object.c \
	tpm2/TPMCmd/tpm/src/subsystem/PCR.c \
	tpm2/TPMCmd/tpm/src/subsystem/PP.c \
	tpm2/TPMCmd/tpm/src/subsystem/Session.c \
	tpm2/TPMCmd/tpm/src/subsystem/Time.c \
	tpm2/TPMCmd/tpm/src/support/AlgorithmCap.c \
	tpm2/TPMCmd/tpm/src/support/Bits.c \
	tpm2/TPMCmd/tpm/src/support/CommandCodeAttributes.c \
	tpm2/TPMCmd/tpm/src/support/Entity.c \
	tpm2/TPMCmd/tpm/src/support/Global.c \
	tpm2/TPMCmd/tpm/src/support/Handle.c \
	tpm2/TPMCmd/tpm/src/support/IoBuffers.c \
	tpm2/TPMCmd/tpm/src/support/Locality.c \
	tpm2/TPMCmd/tpm/src/support/Manufacture.c \
	tpm2/TPMCmd/tpm/src/support/Marshal.c \
	tpm2/TPMCmd/tpm/src/support/MathOnByteBuffers.c \
	tpm2/TPMCmd/tpm/src/support/Memory.c \
	tpm2/TPMCmd/tpm/src/support/Power.c \
	tpm2/TPMCmd/tpm/src/support/PropertyCap.c \
	tpm2/TPMCmd/tpm/src/support/Response.c \
	tpm2/TPMCmd/tpm/src/support/ResponseCodeProcessing.c \
	tpm2/TPMCmd/tpm/src/support/SecChannel.c \
	tpm2/TPMCmd/tpm/src/support/TpmFail.c \
	tpm2/TPMCmd/tpm/src/support/TpmSizeChecks.c \
	tpm2/TPMCmd/tpm/src/X509/TpmASN1.c \
	tpm2/TPMCmd/tpm/src/X509/X509_ECC.c \
	tpm2/TPMCmd/tpm/src/X509/X509_RSA.c \
	tpm2/TPMCmd/tpm/src/X509/X509_spt.c \
	tpm2/TPMCmd/TpmConfiguration/TpmVendorCommandHandlers/Vendor_TCG_Test.c \
	tpm2/Unmarshal.c \
	\
	tpm_tpm2_interface.c \
	tpm_tpm2_tis.c \
	\
	tpm2/BackwardsCompatibilityBitArray.c \
	tpm2/BackwardsCompatibilityObject.c \
	tpm2/LibtpmsCallbacks.c \
	tpm2/NVMarshal.c \
	tpm2/RuntimeAlgorithm.c \
	tpm2/RuntimeAttributes.c \
	tpm2/RuntimeCommands.c \
	tpm2/RuntimeProfile.c \
	tpm2/StateMarshal.c \
	tpm2/Volatile.c

noinst_HEADERS += \
	compiler.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptCmac_fp.h \
	tpm2/CryptDes_fp.h \
	tpm2/TPMCmd/Platform/include/PlatformACT.h \
	tpm2/TPMCmd/Platform/include/PlatformClock.h \
	tpm2/TPMCmd/Platform/include/PlatformData.h \
	tpm2/TPMCmd/Platform/include/Platform.h \
	tpm2/TPMCmd/Platform/include/PlatformInternal.h \
	tpm2/TPMCmd/Platform/include/prototypes/platform_public_interface.h \
	tpm2/TPMCmd/Simulator/include/prototypes/Simulator_fp.h \
	tpm2/TPMCmd/Simulator/include/TpmTcpProtocol.h \
	tpm2/TPMCmd/Simulator/src/simulatorPrivate.h \
	tpm2/TPMCmd/Simulator/src/simulator_sysheaders.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/TpmBuildSwitches.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile_CommandList.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile_Common.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile_ErrorCodes.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/TpmProfile_Misc.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/VendorCommands/CommandAttributeData_s_ccAttr.inl \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/VendorCommands/CommandAttributeData_s_commandAttributes.inl \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/VendorCommands/CommandDispatchData_CommandStructures.inl \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/VendorCommands/CommandDispatchData_s_CommandDataArray.inl \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/VendorCommands/prototypes/Vendor_TCG_Test_fp.h \
	tpm2/TPMCmd/TpmConfiguration/TpmConfiguration/VendorCommands/VendorCommandList.h \
	tpm2/TPMCmd/tpm/cryptolibs/common/include/CryptoInterface.h \
	tpm2/TPMCmd/tpm/cryptolibs/common/include/EccConstantData.inl \
	tpm2/TPMCmd/tpm/cryptolibs/common/include/MathLibraryInterface.h \
	tpm2/TPMCmd/tpm/cryptolibs/common/include/MathLibraryInterfaceTypes.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/BnEccConstants.c \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/BnSupport_Interface.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/BnUtil_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/TpmBigNum.h \
	tpm2/TPMCmd/tpm/include/platform_interface/pcrstruct.h \
	tpm2/TPMCmd/tpm/include/platform_interface/platform_to_tpm_interface.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/ExecCommand_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/Manufacture_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/platform_failure_mode_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/platform_init_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/platform_pcr_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/platform_virtual_nv_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/_TPM_Hash_Data_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/_TPM_Hash_End_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/_TPM_Hash_Start_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/prototypes/_TPM_Init_fp.h \
	tpm2/TPMCmd/tpm/include/platform_interface/tpm_to_platform_interface.h \
	tpm2/TPMCmd/tpm/include/private/CommandAttributeData.h \
	tpm2/TPMCmd/tpm/include/private/CommandAttributes.h \
	tpm2/TPMCmd/tpm/include/private/CommandDispatchData.h \
	tpm2/TPMCmd/tpm/include/private/CryptEcc.h \
	tpm2/TPMCmd/tpm/include/private/CryptHash.h \
	tpm2/TPMCmd/tpm/include/private/CryptRand.h \
	tpm2/TPMCmd/tpm/include/private/CryptRsa.h \
	tpm2/TPMCmd/tpm/include/private/CryptSym.h \
	tpm2/TPMCmd/tpm/include/private/CryptTest.h \
	tpm2/TPMCmd/tpm/include/private/EccTestData.h \
	tpm2/TPMCmd/tpm/include/private/Global.h \
	tpm2/TPMCmd/tpm/include/private/HashTestData.h \
	tpm2/TPMCmd/tpm/include/private/InternalRoutines.h \
	tpm2/TPMCmd/tpm/include/private/KdfTestData.h \
	tpm2/TPMCmd/tpm/include/private/Marshal.h \
	tpm2/TPMCmd/tpm/include/private/NV.h \
	tpm2/TPMCmd/tpm/include/private/OIDs.h \
	tpm2/TPMCmd/tpm/include/private/PRNG_TestVectors.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ActivateCredential_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ACT_SetTimeout_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ACT_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/AlgorithmCap_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/AlgorithmTests_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Attest_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Bits_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CertifyCreation_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Certify_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CertifyX509_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ChangeEPS_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ChangePPS_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ClearControl_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Clear_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ClockRateAdjust_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ClockSet_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CommandAudit_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CommandCodeAttributes_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CommandDispatcher_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Commit_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ContextLoad_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ContextSave_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Context_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Create_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CreateLoaded_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CreatePrimary_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptEccCrypt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptEccKeyExchange_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptEccMain_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptEccSignature_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptHash_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptPrime_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptPrimeSieve_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptRand_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptRsa_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptSelfTest_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptSmac_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptSym_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/CryptUtil_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/DA_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/DictionaryAttackLockReset_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/DictionaryAttackParameters_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ECC_Decrypt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ECC_Encrypt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Duplicate_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ECC_Parameters_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ECDH_KeyGen_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ECDH_ZGen_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/EC_Ephemeral_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/EncryptDecrypt2_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/EncryptDecrypt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/EncryptDecrypt_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Entity_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/EventSequenceComplete_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/EvictControl_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/FlushContext_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/GetCapability_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/GetCommandAuditDigest_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/GetRandom_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/GetSessionAuditDigest_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/GetTestResult_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/GetTime_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Handle_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Hash_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/HashSequenceStart_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/HierarchyChangeAuth_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/HierarchyControl_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Hierarchy_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/HMAC_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/HMAC_Start_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Import_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/IncrementalSelfTest_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/IoBuffers_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/LoadExternal_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Load_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Locality_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/MAC_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/MAC_Start_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/MakeCredential_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/MathOnByteBuffers_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Memory_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_Certify_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_ChangeAuth_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_DefineSpace2_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_DefineSpace_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NvDynamic_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_Extend_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_GlobalWriteLock_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_Increment_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_Read_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_ReadLock_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_ReadPublic2_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_ReadPublic_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NvReserved_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_SetBits_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_UndefineSpace_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_UndefineSpaceSpecial_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_Write_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/NV_WriteLock_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ObjectChangeAuth_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Object_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Object_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_Allocate_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_Event_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_Extend_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_Read_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_Reset_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_SetAuthPolicy_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PCR_SetAuthValue_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyAuthorize_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyAuthorizeNV_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyAuthValue_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyCapability_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyCommandCode_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyCounterTimer_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyCpHash_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyDuplicationSelect_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyGetDigest_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyLocality_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyNameHash_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyNV_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyNvWritten_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyOR_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyParameters_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyPassword_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyPCR_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyPhysicalPresence_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyRestart_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicySecret_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicySigned_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Policy_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyTemplate_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyTicket_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PolicyTransportSPDM_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Power_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PP_Commands_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PP_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/PropertyCap_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Quote_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ReadClock_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ReadOnlyControl_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ReadPublic_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ResponseCodeProcessing_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Response_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Rewrap_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/RSA_Decrypt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/RSA_Encrypt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SecChannel_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SelfTest_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SequenceComplete_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SequenceUpdate_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Session_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SessionProcess_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SetAlgorithmSet_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SetCapability_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SetCommandCodeAuditStatus_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/SetPrimaryPolicy_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Shutdown_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Sign_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/StartAuthSession_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Startup_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/StirRandom_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TestParms_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Ticket_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Time_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmASN1_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmEcc_Signature_ECDAA_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmEcc_Signature_ECDSA_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmEcc_Signature_Schnorr_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmEcc_Signature_SM2_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmEcc_Signature_Util_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmEcc_Util_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmMath_Debug_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmMath_Util_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/TpmSizeChecks_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/Unseal_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/VerifySignature_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/X509_ECC_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/X509_RSA_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/X509_spt_fp.h \
	tpm2/TPMCmd/tpm/include/private/prototypes/ZGen_2Phase_fp.h \
	tpm2/TPMCmd/tpm/include/private/RsaTestData.h \
	tpm2/TPMCmd/tpm/include/private/SelfTest.h \
	tpm2/TPMCmd/tpm/include/private/SymmetricTestData.h \
	tpm2/TPMCmd/tpm/include/private/SymmetricTest.h \
	tpm2/TPMCmd/tpm/include/private/TpmASN1.h \
	tpm2/TPMCmd/tpm/include/private/Tpm.h \
	tpm2/TPMCmd/tpm/include/private/X509.h \
	tpm2/TPMCmd/tpm/include/tpm_public/ACT.h \
	tpm2/TPMCmd/tpm/include/tpm_public/BaseTypes.h \
	tpm2/TPMCmd/tpm/include/tpm_public/Capabilities.h \
	tpm2/TPMCmd/tpm/include/tpm_public/CompilerDependencies_gcc.h \
	tpm2/TPMCmd/tpm/include/tpm_public/CompilerDependencies.h \
	tpm2/TPMCmd/tpm/include/tpm_public/CompilerDependencies_msvc.h \
	tpm2/TPMCmd/tpm/include/tpm_public/endian_swap.h \
	tpm2/TPMCmd/tpm/include/tpm_public/GpMacros.h \
	tpm2/TPMCmd/tpm/include/tpm_public/MinMax.h \
	tpm2/TPMCmd/tpm/include/tpm_public/prototypes/TpmFail_fp.h \
	tpm2/TPMCmd/tpm/include/tpm_public/TpmAlgorithmDefines.h \
	tpm2/TPMCmd/tpm/include/tpm_public/TPMB.h \
	tpm2/TPMCmd/tpm/include/tpm_public/TpmCalculatedAttributes.h \
	tpm2/TPMCmd/tpm/include/tpm_public/tpm_debug.h \
	tpm2/TPMCmd/tpm/include/tpm_public/tpm_public.h \
	tpm2/TPMCmd/tpm/include/tpm_public/TpmTypes.h \
	tpm2/TPMCmd/tpm/include/tpm_public/VerifyConfiguration.h \
	tpm2/Unmarshal_fp.h \
	\
	tpm2/BackwardsCompatibility.h \
	tpm2/BackwardsCompatibilityBitArray.h \
	tpm2/BackwardsCompatibilityObject.h \
	tpm2/LibtpmsCallbacks.h \
	tpm2/NVMarshal.h \
	tpm2/RuntimeAlgorithm_fp.h \
	tpm2/RuntimeAttributes_fp.h \
	tpm2/RuntimeCommands_fp.h \
	tpm2/RuntimeProfile_fp.h \
	tpm2/StateMarshal.h \
	tpm2/Utils.h \
	tpm2/Volatile.h

if LIBTPMS_USE_OPENSSL

libtpms_tpm2_la_SOURCES += \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/BnToOsslMath.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptCmac.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptDes.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptEccCrypt.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptEccKeyExchange.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptEccMain.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptEccSignature.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptHash.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptPrime.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptPrimeSieve.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptRand.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptRsa.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptSmac.c \
	tpm2/TPMCmd/tpm/src/crypt/CryptSym.c \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/ExpDCache.c \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/Helpers.c \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/TpmToOsslDesSupport.c \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/TpmToOsslSupport.c

noinst_HEADERS += \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/BnOssl.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/BnToOsslMath_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/BnConvert_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/BnMath_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/BnMemory_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/BnValues.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/BnToOsslMath.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/ExpDCache_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/Helpers_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/TpmToOsslDesSupport_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/TpmToOsslHash.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/TpmToOsslSupport_fp.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/TpmToOsslSym.h \
	tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/TpmToOsslSymTDES.h \
	tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/TpmBigNum/TpmToTpmBigNumMath.h \
	tpm2/TPMCmd/tpm/include/private/LibSupport.h \
	tpm2/TPMCmd/tpm/include/tpm_public/tpm_radix.h

libtpms_tpm2_la_CFLAGS += \
	-I $(srcdir)/tpm2 \
	-I $(srcdir)/tpm2/crypto/openssl \
	-I $(srcdir)/tpm2/TPMCmd/Platform/include/ \
	-I $(srcdir)/tpm2/TPMCmd/Simulator/include/ \
	-I $(srcdir)/tpm2/TPMCmd/Simulator/include/prototypes \
	-I $(srcdir)/tpm2/TPMCmd/TpmConfiguration \
	-I $(srcdir)/tpm2/TPMCmd/tpm/include/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/include/private \
	-I $(srcdir)/tpm2/TPMCmd/tpm/include/private/prototypes/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/common/include/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/TpmBigNum/include/TpmBigNum/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/Ossl/ \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/Ossl/include \
	-I $(srcdir)/tpm2/TPMCmd/tpm/cryptolibs/Ossl/include/Ossl/

libtpms_tpm2_la_LIBADD += -lcrypto

endif # LIBTPMS_USE_OPENSSL

endif # WITH_TPM2

#
# Library API layer
#

libtpms_la_SOURCES = \
	disabled_interface.c \
	tpm_debug.c \
	tpm_library.c \
	tpm_memory.c \
	tpm_nvfile.c

libtpms_la_CFLAGS = $(common_CFLAGS)

libtpms_la_LDFLAGS = -version-info $(LIBTPMS_VERSION_INFO) \
                     -no-undefined $(AM_LDFLAGS)

if HAVE_VERSION_SCRIPT
libtpms_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libtpms.syms
endif

LDFLAGS_ARCH  = $(findstring -m32, $(AM_CFLAGS))
LDFLAGS_ARCH += $(findstring -m64, $(AM_CFLAGS))
LDFLAGS_ARCH += $(findstring -m32, $(AM_LDFLAGS))
LDFLAGS_ARCH += $(findstring -m64, $(AM_LDFLAGS))

check-local: SHELL?="/usr/bin/env bash"
check-local:
	@case $(host_os) in \
	  openbsd*) ADDLIBS="-lc" ;; \
	  darwin*|freebsd*) LDFLAGS_OS="-shared" ;; \
	  *) ADDLIBS="" ;; \
	esac; \
	 [[ "$(host_cpu)" =~ "powerpc64" ]] || ($(CC) $$LDFLAGS_OS $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms $$ADDLIBS 2>/dev/null || \
	 (echo "There are undefined symbols in libtpms ($$LDFLAGS_OS $(LDFLAGS_ARCH))";\
	  $(CC) $$LDFLAGS_OS $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms $$ADDLIBS 2>&1 | grep libtpms))
	@case $(host_os) in \
	  openbsd*) ADDLIBS="-lc" ;; \
	  darwin*|freebsd*) LDFLAGS_OS="-shared" ;; \
	  *) ADDLIBS="" ;; \
	esac; \
	[[ "$(host_cpu)" =~ "powerpc64" ]] || $(CC) $$LDFLAGS_OS $(LDFLAGS_ARCH) -nostdlib -L./.libs -ltpms $$ADDLIBS 2>/dev/null
	rm a.out || true

EXTRA_DIST = \
	tpm12/tpm_crypto_freebl.c \
	tpm12/tpm_crypto.c \
	libtpms.syms \
	test.syms

CLEANFILES = \
	a.out \
	*.gcov \
	*.gcda \
	*.gcno \
	tpm12/*.gcov \
	tpm12/*.gcda \
	tpm12/*.gcno \
	tpm2/*.gcov \
	tpm2/*.gcda \
	tpm2/*.gcno \
	tpm2/crypto/openssl/*.gcov \
	tpm2/crypto/openssl/*.gcda \
	tpm2/crypto/openssl/*.gcno
