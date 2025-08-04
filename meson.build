project('libtpms', ['c', 'cpp'],
        version: '0.11.0',
        license: 'BSD-3-Clause AND LicenseRef-TCGL',
        default_options: ['c_std=c99'])

c_compiler = meson.get_compiler('c')

# Add an include directory that points to the build directory.
add_project_arguments('-I' + meson.current_build_dir(), language: 'c')

# Add common warning flags
warning_flags = [
  '-Wall',
  '-Werror',
  '-Wshadow',
  '-Wreturn-type',
  '-Wsign-compare',
  '-Wno-self-assign',
  '-Wmissing-prototypes'
]
supported_warning_flags = c_compiler.get_supported_arguments(warning_flags)
add_project_arguments(supported_warning_flags, language: 'c')

# Get build options
with_tpm1 = get_option('tpm1')
with_tpm2 = get_option('tpm2')
crypto_backend = get_option('crypto_backend')

if crypto_backend == 'openssl'
  add_project_arguments(['-DUSE_OPENSSL_CRYPTO_LIBRARY=1'], language: 'c')
else
  add_project_arguments(['-DUSE_FREEBL_CRYPTO_LIBRARY=1'], language: 'c')
endif

# Add hardening flags for non-plain build types
if get_option('buildtype') != 'plain'
  hardening_c_flags = []
  # Stack protector
  if c_compiler.has_argument('-fstack-protector-strong')
    hardening_c_flags += '-fstack-protector-strong'
  elif c_compiler.has_argument('-fstack-protector')
    hardening_c_flags += '-fstack-protector'
  endif
  # Fortify source only works with optimization
  if get_option('optimization') != '0'
    if c_compiler.has_argument('-D_FORTIFY_SOURCE=2')
      hardening_c_flags += '-D_FORTIFY_SOURCE=2'
    endif
  endif
  add_project_arguments(hardening_c_flags, language: 'c')

  hardening_ld_flags = []
  # Linker hardening
  if c_compiler.has_link_argument('-Wl,-z,relro')
    hardening_ld_flags += '-Wl,-z,relro'
  endif
  if c_compiler.has_link_argument('-Wl,-z,now')
    hardening_ld_flags += '-Wl,-z,now'
  endif
  add_project_link_arguments(hardening_ld_flags, language: 'c')
endif

# Create a configuration header file
conf_data = configuration_data()
conf_data.set('PACKAGE_VERSION', '"' + meson.project_version() + '"')

# Check for headers
if c_compiler.has_header('arpa/inet.h')
  conf_data.set('HAVE_ARPA_INET_H', 1)
endif
if c_compiler.has_header('time.h')
  conf_data.set('HAVE_TIME_H', 1)
endif

configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: conf_data
)

# Add subdirectories to the build
# Add subdirectories to the build
subdir('include')
subdir('src')
subdir('man')
subdir('tests')

summary_info = {}
summary_info += {'Build directory':   meson.current_build_dir()}
summary_info += {'Source path':       meson.current_source_dir()}
summary_info += {'TPM1':              with_tpm1}
summary_info += {'TPM2':              with_tpm2}
summary_info += {'Crypto backend':    crypto_backend}

summary(summary_info, bool_yn: true, section: 'Build environment')
