project('libtpms', 'c',
        version: '0.11.0',
        license: 'BSD-3-Clause AND LicenseRef-TCGL',
        default_options: ['c_std=c99'])

# Add an include directory that points to the build directory.
# This is necessary so that source files can find the generated config.h
add_project_arguments('-I' + meson.current_build_dir(), language: 'c')

# Create a configuration header file
conf_data = configuration_data()
conf_data.set('PACKAGE_VERSION', '"' + meson.project_version() + '"')
configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: conf_data
)

# Add the src subdirectory to the build
subdir('src')
