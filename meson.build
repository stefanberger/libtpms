project('libtpms', 'c',
        version: '0.11.0',
        license: 'BSD-3-Clause AND LicenseRef-TCGL',
        default_options: ['c_std=c99'])

# Add an include directory that points to the build directory.
add_project_arguments('-I' + meson.current_build_dir(), language: 'c')

# Create a configuration header file
conf_data = configuration_data()
conf_data.set('PACKAGE_VERSION', '"' + meson.project_version() + '"')

# Check for headers
c_compiler = meson.get_compiler('c')
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
subdir('include')
subdir('src')