# Find the OpenSSL dependency (libcrypto)
crypto_dep = dependency('openssl', version: '>=1.1.0', required: true)

# Include directory for the library's own public headers
lib_inc = include_directories('../include/libtpms')

# Start with the absolute minimum common files to prove compilation works
libtpms_sources = files(
  'tpm_debug.c',
  'tpm_library.c',
  'tpm_memory.c',
  'tpm_nvfile.c',
  'disabled_interface.c'
)

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
