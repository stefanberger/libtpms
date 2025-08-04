# Find the OpenSSL dependency (libcrypto)
crypto_dep = dependency('openssl', version: '>=1.1.0', required: true)

# Include directory for the library's own public headers
lib_inc = include_directories('../include/libtpms')

# Get the value of the options
with_tpm1 = get_option('tpm1')
with_tpm2 = get_option('tpm2')

# Start with the common source files
libtpms_sources = files(
  'tpm_debug.c',
  'tpm_library.c',
  'tpm_memory.c',
  'tpm_nvfile.c',
  'disabled_interface.c'
)

if with_tpm1
  # Add TPM1 sources here in the next step
  message('Building with TPM 1.2 support')
endif

if with_tpm2
  # Add TPM2 sources here in the next step
  message('Building with TPM 2.0 support')
endif

# Define the shared library
libtpms = shared_library('tpms',
  libtpms_sources,
  c_args: [
    '-DTPM_NV_DISK',
    '-include', 'tpm_library_conf.h'
  ],
  dependencies: crypto_dep,
  include_directories: [lib_inc],
  install: true,
)