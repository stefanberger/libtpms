# Get build options
with_tpm1 = get_option('tpm1')
with_tpm2 = get_option('tpm2')
crypto_backend = get_option('crypto_backend')

# TPM2 requires OpenSSL in this build configuration
if with_tpm2 and crypto_backend != 'openssl'
  error('TPM2 support currently requires the openssl crypto backend.')
endif

# --- Crypto Dependencies and Flags ---
crypto_deps = []
tpm1_crypto_sources = []
freebl_inc = []
openssl_flags = []
if crypto_backend == 'openssl'
  crypto_deps += dependency('openssl', version: '>=1.1.0', required: true)
  if with_tpm1
    tpm1_crypto_sources += 'tpm12/tpm_crypto.c'
  endif
  if get_option('use_openssl_functions')
    openssl_flags += [
      '-DUSE_OPENSSL_FUNCTIONS_SYMMETRIC=1',
      '-DUSE_OPENSSL_FUNCTIONS_EC=1',
      '-DUSE_OPENSSL_FUNCTIONS_ECDSA=1',
      '-DUSE_OPENSSL_FUNCTIONS_RSA=1',
      '-DUSE_OPENSSL_FUNCTIONS_SSKDF=1'
    ]
  else
    openssl_flags += [
      '-DUSE_OPENSSL_FUNCTIONS_SYMMETRIC=0',
      '-DUSE_OPENSSL_FUNCTIONS_EC=0',
      '-DUSE_OPENSSL_FUNCTIONS_ECDSA=0',
      '-DUSE_OPENSSL_FUNCTIONS_RSA=0',
      '-DUSE_OPENSSL_FUNCTIONS_SSKDF=0'
    ]
  endif
else # freebl
  nss_dep = dependency('nss')
  nspr_dep = dependency('nspr')
  gmp_dep = dependency('gmp')
  crypto_deps += [nss_dep, nspr_dep, gmp_dep]
  crypto_deps += meson.get_compiler('c').find_library('freebl', required: true)
  freebl_inc += include_directories(nss_dep.get_variable(pkgconfig: 'includedir'))
  freebl_inc += include_directories(nspr_dep.get_variable(pkgconfig: 'includedir'))
  if with_tpm1
    tpm1_crypto_sources += 'tpm12/tpm_crypto_freebl.c'
  endif
endif

# --- Library Definitions ---

# Include directory for the library's own public headers
lib_inc = include_directories('../include/libtpms')

# Common source files
common_sources = files(
  'tpm_debug.c',
  'tpm_library.c',
  'tpm_memory.c',
  'tpm_nvfile.c',
  'disabled_interface.c'
)

link_with_libs = []
extra_deps = []

# Common c_args for all libraries
common_c_args = [
  '-DTPM_NV_DISK',
  '-DTPM_LIBTPMS_CALLBACKS',
  '-DOPENSSL_SUPPRESS_DEPRECATED',
  '-include', 'tpm_library_conf.h'
]

if with_tpm1
  message('Building with TPM 1.2 support')
  tpm1_sources = files(
    'tpm12/tpm_admin.c', 'tpm12/tpm_audit.c', 'tpm12/tpm_auth.c',
    'tpm12/tpm_cryptoh.c', 'tpm12/tpm_counter.c', 'tpm12/tpm_daa.c',
    'tpm12/tpm_delegate.c', 'tpm12/tpm_digest.c', 'tpm12/tpm_error.c',
    'tpm12/tpm_global.c', 'tpm12/tpm_identity.c', 'tpm12/tpm_init.c',
    'tpm12/tpm_libtpms_io.c', 'tpm12/tpm_key.c', 'tpm12/tpm_load.c',
    'tpm12/tpm_maint.c', 'tpm12/tpm_migration.c', 'tpm12/tpm_nonce.c',
    'tpm12/tpm_nvram.c', 'tpm12/tpm_openssl_helpers.c', 'tpm12/tpm_owner.c',
    'tpm12/tpm_pcr.c', 'tpm12/tpm_permanent.c', 'tpm12/tpm_platform.c',
    'tpm12/tpm_process.c', 'tpm12/tpm_secret.c', 'tpm12/tpm_session.c',
    'tpm12/tpm_sizedbuffer.c', 'tpm12/tpm_startup.c', 'tpm12/tpm_store.c',
    'tpm12/tpm_storage.c', 'tpm12/tpm_ticks.c', 'tpm12/tpm_time.c',
    'tpm12/tpm_transport.c', 'tpm12/tpm_ver.c', 'tpm12/tpm_svnrevision.c',
    'tpm_tpm12_interface.c', 'tpm_tpm12_tis.c',
    tpm1_crypto_sources
  )

  tpm1_lib = static_library('tpms_tpm12', tpm1_sources,
    c_args: common_c_args + openssl_flags + [
      '-DTPM_V12',
      '-DTPM_PCCLIENT',
      '-DTPM_POSIX',
      '-DTPM_AES',
      '-DTPM_NOMAINTENANCE_COMMANDS',
      '-DTPM_ENABLE_ACTIVATE',
      '-DTPM_VOLATILE_LOAD',
    ],
    include_directories: [lib_inc] + freebl_inc,
  )
  link_with_libs += tpm1_lib
endif

if with_tpm2
  message('Building with TPM 2.0 support')
  rt_dep = meson.get_compiler('c').find_library('rt', required: false)
  extra_deps += rt_dep

  tpm2_sources = files(
    'tpm2/ACT_spt.c', 'tpm2/ACTCommands.c', 'tpm2/AlgorithmCap.c',
    'tpm2/AlgorithmTests.c', 'tpm2/AsymmetricCommands.c',
    'tpm2/AttestationCommands.c', 'tpm2/Attest_spt.c', 'tpm2/AuditCommands.c',
    'tpm2/Bits.c', 'tpm2/BnEccConstants.c', 'tpm2/BnConvert.c', 'tpm2/BnMath.c',
    'tpm2/BnMemory.c', 'tpm2/Cancel.c', 'tpm2/CapabilityCommands.c',
    'tpm2/Clock.c', 'tpm2/ClockCommands.c', 'tpm2/CommandAudit.c',
    'tpm2/CommandCodeAttributes.c', 'tpm2/CommandDispatcher.c',
    'tpm2/ContextCommands.c', 'tpm2/Context_spt.c', 'tpm2/CryptEccData.c',
    'tpm2/CryptSelfTest.c', 'tpm2/CryptUtil.c', 'tpm2/DA.c',
    'tpm2/DebugHelpers.c', 'tpm2/DictionaryCommands.c',
    'tpm2/DuplicationCommands.c', 'tpm2/EACommands.c',
    'tpm2/EncryptDecrypt_spt.c', 'tpm2/Entity.c', 'tpm2/Entropy.c',
    'tpm2/EphemeralCommands.c', 'tpm2/ExecCommand.c', 'tpm2/ExtraData.c',
    'tpm2/Global.c', 'tpm2/Handle.c', 'tpm2/HashCommands.c',
    'tpm2/Hierarchy.c', 'tpm2/HierarchyCommands.c', 'tpm2/IntegrityCommands.c',
    'tpm2/IoBuffers.c', 'tpm2/Locality.c', 'tpm2/LocalityPlat.c',
    'tpm2/ManagementCommands.c', 'tpm2/Manufacture.c', 'tpm2/Marshal.c',
    'tpm2/MathOnByteBuffers.c', 'tpm2/Memory.c', 'tpm2/NVCommands.c',
    'tpm2/NvDynamic.c', 'tpm2/NVMem.c', 'tpm2/NvReserved.c', 'tpm2/NV_spt.c',
    'tpm2/Object.c', 'tpm2/ObjectCommands.c', 'tpm2/Object_spt.c', 'tpm2/PCR.c',
    'tpm2/PlatformACT.c', 'tpm2/PlatformData.c', 'tpm2/PlatformPCR.c',
    'tpm2/Policy_spt.c', 'tpm2/Power.c', 'tpm2/PowerPlat.c', 'tpm2/PP.c',
    'tpm2/PPPlat.c', 'tpm2/PrimeData.c', 'tpm2/PropertyCap.c',
    'tpm2/RandomCommands.c', 'tpm2/Response.c',
    'tpm2/ResponseCodeProcessing.c', 'tpm2/RunCommand.c', 'tpm2/Session.c',
    'tpm2/SessionCommands.c', 'tpm2/SessionProcess.c',
    'tpm2/SigningCommands.c', 'tpm2/StartupCommands.c',
    'tpm2/SymmetricCommands.c', 'tpm2/TestingCommands.c', 'tpm2/Ticket.c',
    'tpm2/Time.c', 'tpm2/TpmASN1.c', 'tpm2/TpmBigNumThunks.c',
    'tpm2/TpmEcc_Signature_ECDAA.c', 'tpm2/TpmEcc_Signature_ECDSA.c',
    'tpm2/TpmEcc_Signature_Schnorr.c', 'tpm2/TpmEcc_Signature_SM2.c',
    'tpm2/TpmEcc_Signature_Util.c', 'tpm2/TpmEcc_Util.c',
    'tpm2/TpmMath_Debug.c', 'tpm2/TpmMath_Util.c', 'tpm2/TpmSizeChecks.c',
    'tpm2/TPMCmdp.c', 'tpm2/TpmFail.c', 'tpm2/Unique.c', 'tpm2/Unmarshal.c',
    'tpm2/VendorInfo.c', 'tpm2/Vendor_TCG_Test.c', 'tpm2/X509_ECC.c',
    'tpm2/X509_RSA.c', 'tpm2/X509_spt.c', 'tpm_tpm2_interface.c',
    'tpm_tpm2_tis.c', 'tpm2/BackwardsCompatibilityBitArray.c',
    'tpm2/BackwardsCompatibilityObject.c', 'tpm2/LibtpmsCallbacks.c',
    'tpm2/NVMarshal.c', 'tpm2/RuntimeAlgorithm.c', 'tpm2/RuntimeAttributes.c',
    'tpm2/RuntimeCommands.c', 'tpm2/RuntimeProfile.c', 'tpm2/StateMarshal.c',
    'tpm2/Volatile.c',
    'tpm2/crypto/openssl/BnToOsslMath.c', 'tpm2/crypto/openssl/CryptCmac.c',
    'tpm2/crypto/openssl/CryptDes.c', 'tpm2/crypto/openssl/CryptEccCrypt.c',
    'tpm2/crypto/openssl/CryptEccKeyExchange.c', 'tpm2/crypto/openssl/CryptEccMain.c',
    'tpm2/crypto/openssl/CryptEccSignature.c', 'tpm2/crypto/openssl/CryptHash.c',
    'tpm2/crypto/openssl/CryptPrime.c', 'tpm2/crypto/openssl/CryptPrimeSieve.c',
    'tpm2/crypto/openssl/CryptRand.c', 'tpm2/crypto/openssl/CryptRsa.c',
    'tpm2/crypto/openssl/CryptSmac.c', 'tpm2/crypto/openssl/CryptSym.c',
    'tpm2/crypto/openssl/ExpDCache.c', 'tpm2/crypto/openssl/Helpers.c',
    'tpm2/crypto/openssl/TpmToOsslDesSupport.c', 'tpm2/crypto/openssl/TpmToOsslSupport.c'
  )

  tpm2_lib = static_library('tpms_tpm2', tpm2_sources,
    c_args: common_c_args + openssl_flags + [
      '-D_POSIX_C_SOURCE=200809L',
      '-DTPM_POSIX',
      '-include', 'config.h'
    ],
    include_directories: [
      lib_inc,
      '.',
      'tpm2',
      'tpm2/crypto',
      'tpm2/crypto/openssl'
    ],
  )
  link_with_libs += tpm2_lib
endif

# Define the final shared library
libtpms = shared_library('tpms',
  common_sources,
  c_args: common_c_args + ['-include', 'config.h'],
  link_with: link_with_libs,
  dependencies: crypto_deps + extra_deps,
  include_directories: [lib_inc],
  install: true,
)
