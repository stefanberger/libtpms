tpm_library_h = configure_file(
  input: 'tpm_library.h.in',
  output: 'tpm_library.h',
  configuration: conf_data,
)

install_headers(
  'tpm_error.h',
  'tpm_memory.h',
  'tpm_nvfilename.h',
  'tpm_tis.h',
  'tpm_types.h',
  tpm_library_h,
  subdir: 'libtpms'
)
