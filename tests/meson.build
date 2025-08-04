test_env = {
  'abs_top_srcdir': meson.project_source_root(),
  'abs_top_builddir': meson.project_build_root(),
  'abs_top_testdir': meson.project_source_root() / 'tests',
}

sh = find_program('sh')

exe = executable('base64decode', files('base64decode.c'), dependencies: [libtpms_dep])
test('base64decode.sh', sh, args: files('base64decode.sh'), depends: exe, workdir: meson.current_build_dir())

src_inc = [
      '../include/libtpms',
      '../src',
      '../src/tpm2',
      '../src/tpm2/crypto',
      '../src/tpm2/crypto/openssl',
]

if get_option('tpm2')
  exe = executable('nvram_offsets', 'nvram_offsets.c',
    dependencies: [libtpms_dep],
    include_directories: src_inc,
    c_args: ['-DTPM_POSIX', '-D_POSIX_C_SOURCE=200809L'],
  )
  test('nvram_offsets', exe, env: test_env)

  exe = executable('tpm2_createprimary', files('tpm2_createprimary.c'), dependencies: [libtpms_dep])
  test('tpm2_createprimary.sh', sh, args: files('tpm2_createprimary.sh'), depends: exe, workdir: meson.current_build_dir())

  exe = executable('tpm2_cve-2023-1017', files('tpm2_cve-2023-1017.c'), dependencies: [libtpms_dep])
  test('tpm2_cve-2023-1017.sh', sh, args: files('tpm2_cve-2023-1017.sh'), depends: exe, workdir: meson.current_build_dir())

  exe = executable('tpm2_cve-2023-1018', files('tpm2_cve-2023-1018.c'), dependencies: [libtpms_dep])
  test('tpm2_cve-2023-1018.sh', sh, args: files('tpm2_cve-2023-1018.sh'), depends: exe, workdir: meson.current_build_dir())

  exe = executable('tpm2_selftest', files('tpm2_selftest.c'), dependencies: [libtpms_dep])
  test('tpm2_selftest.sh', sh, args: files('tpm2_selftest.sh'), depends: exe, workdir: meson.current_build_dir())

  exe = executable('tpm2_pcr_read', files('tpm2_pcr_read.c'), dependencies: [libtpms_dep])
  test('tpm2_pcr_read.sh', sh, args: files('tpm2_pcr_read.sh'), depends: exe, workdir: meson.current_build_dir())

  exe = executable('tpm2_setprofile', files('tpm2_setprofile.c'), dependencies: [libtpms_dep])
  test('tpm2_setprofile.sh', sh, args: files('tpm2_setprofile.sh'), depends: exe, workdir: meson.current_build_dir())

  fuzz_sources = ['fuzz.cc']
  if not get_option('fuzzing_engine')
    fuzz_sources += 'fuzz-main.c'
  endif
  exe = executable('fuzz', fuzz_sources, dependencies: [libtpms_dep], c_args: ['-DTPM_POSIX', '-D_POSIX_C_SOURCE=200809L'])
  test('fuzz.sh', sh, args: files('fuzz.sh'), depends: exe, workdir: meson.current_build_dir())

  if get_option('static_tests')
    exe = executable('object_size', files('object_size.c'),
      dependencies: [libtpms_dep],
      include_directories: src_inc,
      c_args: ['-static', '-DTPM_POSIX', '-D_POSIX_C_SOURCE=200809L'],
    )
    test('object_size', exe, env: test_env)
  endif
endif

if crypto_backend == 'freebl'
  exe = executable('freebl_sha1flattensize', 'freebl_sha1flattensize.c',
    dependencies: [libtpms_dep, nss_dep, nspr_dep],
    link_args: ['-lfreebl']
  )
  # FIXME: test fails
  # test('freebl_sha1flattensize', exe, env: test_env)
endif
