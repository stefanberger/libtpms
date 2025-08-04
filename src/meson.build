# Define an include directory that points to the library's public headers
project_inc = include_directories('../include/libtpms')

# Define an include directory for the generated config.h in the build directory
# This is where config.h will be generated.
build_inc = include_directories('.')

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
  include_directories: [project_inc, build_inc],
  install: true,
)