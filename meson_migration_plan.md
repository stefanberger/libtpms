Of course. Here is a detailed, iterative plan to migrate the `libtpms` build system from Autotools to Meson, ensuring feature parity and comparing the two systems at each stage.

### Migration Philosophy

The goal is to replace `configure.ac` and all `Makefile.am` files with `meson.build` files. We will start with the simplest possible build and incrementally add features, options, and complexity, mirroring the capabilities of the Autotools setup.

---

### Step 1: Basic Project Setup and a "Dummy" Library

**Goal:** Create the initial `meson.build` file, define the project, and compile a shared library with a minimal set of source files. This is the "Hello, World" of the build system.

**Meson Implementation (`/meson.build`):**
```meson
project('libtpms', 'c',
        version: '0.11.0',
        license: 'BSD-2-Clause', # Check LICENSE file for exact SPDX identifier
        default_options: ['c_std=c99'])

# Add the src subdirectory to the build
subdir('src')
```

**Meson Implementation (`/src/meson.build`):**
```meson
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
  install: true,
)
```

**Autotools Comparison:**
*   `project(...)` in Meson replaces `AC_INIT(...)` and `AM_INIT_AUTOMAKE(...)` in `configure.ac`. The version number is set directly.
*   `shared_library(...)` replaces the `lib_LTLIBRARIES = libtpms.la` and the associated `libtpms_la_SOURCES` from `src/Makefile.am`.
*   At this stage, we are ignoring almost all complexity, just setting up the basic structure. The `subdir('src')` call is analogous to `SUBDIRS = src` in the root `Makefile.am`.

---

### Step 2: Adding Dependencies (OpenSSL) and Headers

**Goal:** Introduce dependency handling by adding the OpenSSL requirement. We will also define and install the public header files.

**Meson Implementation (`/src/meson.build`):**
```meson
# Find the OpenSSL dependency (libcrypto)
crypto_dep = dependency('openssl', version: '>=1.1.0')

# Public headers from include/libtpms
inc_dir = include_directories('../include/libtpms')

libtpms_sources = files(
  # ... same files as Step 1 ...
)

libtpms = shared_library('tpms',
  libtpms_sources,
  include_directories: inc_dir,
  dependencies: crypto_dep, # Link against the dependency
  install: true,
)

# --- Header Installation ---
# This part goes in a new `include/libtpms/meson.build`
# and is called from the root `meson.build` via `subdir('include/libtpms')`

# in include/libtpms/meson.build:
install_headers(
  'tpm_error.h',
  'tpm_library.h',
  'tpm_memory.h',
  'tpm_nvfilename.h',
  'tpm_tis.h',
  'tpm_types.h',
  subdir: 'libtpms'
)
```

**Autotools Comparison:**
*   `dependency('openssl')` replaces `AC_CHECK_LIB(crypto, ...)` and the associated header checks in `configure.ac`. Meson handles finding the library, its headers, and providing the necessary flags automatically. It's much more concise.
*   `install_headers(...)` replaces the `libtpmsinclude_HEADERS` and `libtpmsincludedir` logic from `include/libtpms/Makefile.am`.

---

### Step 3: Introducing Build Options (TPM1/TPM2 Support)

**Goal:** Replicate the `--with-tpm1` and `--with-tpm2` configure flags using Meson's feature options.

**Meson Implementation (`/meson.build`):**
```meson
project('libtpms', 'c',
        # ...
        )

# Define build options, similar to configure flags
option('tpm1', type: 'boolean', value: true, description: 'Build with TPM 1.2 support.')
option('tpm2', type: 'boolean', value: true, description: 'Build with TPM 2.0 support.')

# ...
subdir('src')
```

**Meson Implementation (`/src/meson.build`):**
```meson
# ... (dependencies, etc.) ...

# Get the value of the options
with_tpm1 = get_option('tpm1')
with_tpm2 = get_option('tpm2')

# Start building the source list conditionally
libtpms_sources = files(...) # Core files from Step 1

if with_tpm1
  # Add TPM1 sources here
  message('Building with TPM 1.2 support')
endif

if with_tpm2
  # Add TPM2 sources here
  message('Building with TPM 2.0 support')
endif

# ...
```

**Autotools Comparison:**
*   `option('tpm1', ...)` is the direct equivalent of `AC_ARG_WITH([tpm1], ...)`. The `value: true` makes it an enabled-by-default option.
*   `get_option('tpm1')` is how the build script retrieves the user's choice, similar to how the shell variable `$with_tpm1` is used in `configure.ac`.
*   The `if/endif` blocks directly mirror the `AM_CONDITIONAL([WITH_TPM1], ...)` logic used to control which source files are compiled in `src/Makefile.am`.

---

### Step 4: Populating Conditional Source Files

**Goal:** Fully replicate the conditional source file logic from `src/Makefile.am` based on the TPM1/TPM2 options.

**Meson Implementation (`/src/meson.build`):**
```meson
# ... (options, dependencies) ...

# Create empty arrays for sources
tpm1_sources = []
tpm2_sources = []
common_sources = files(
  'disabled_interface.c',
  'tpm_debug.c',
  'tpm_library.c',
  'tpm_memory.c',
  'tpm_nvfile.c'
)

# TPM 1.2 Sources
if get_option('tpm1')
  tpm1_sources += files(
    'tpm12/tpm_admin.c',
    'tpm12/tpm_audit.c',
    # ... all other tpm12 sources ...
    'tpm_tpm12_interface.c',
    'tpm_tpm12_tis.c',
    'tpm12/tpm_crypto.c' # Assuming OpenSSL for now
  )
endif

# TPM 2.0 Sources
if get_option('tpm2')
  # Check for librt, needed by TPM2 code
  rt_dep = meson.get_compiler('c').find_library('rt', required: false)

  tpm2_sources += files(
    'tpm2/ACT_spt.c',
    'tpm2/ACTCommands.c',
    # ... all other tpm2 sources ...
    'tpm_tpm2_interface.c',
    'tpm_tpm2_tis.c'
  )
  # Add TPM2 crypto sources for OpenSSL
  tpm2_sources += files(
    'tpm2/crypto/openssl/BnToOsslMath.c',
    # ... all other tpm2/crypto/openssl sources ...
  )
endif

# Combine all sources
libtpms = shared_library('tpms',
  common_sources + tpm1_sources + tpm2_sources,
  dependencies: [crypto_dep, rt_dep], # Add rt_dep here
  # ...
)
```

**Autotools Comparison:**
*   This step directly translates the large `libtpms_tpm12_la_SOURCES` and `libtpms_tpm2_la_SOURCES` blocks from `src/Makefile.am` into Meson lists.
*   The `find_library('rt', ...)` call replaces `AC_CHECK_LIB(c, clock_gettime, ..., LIBRT_LIBS="-lrt")`.
*   The concatenation of source lists (`common_sources + tpm1_sources + ...`) is Meson's way of achieving what `libtpms_la_LIBADD += libtpms_tpm12.la` does in `Makefile.am`—combining different components into one final target.

---

### Step 5: Compiler Flags and Hardening

**Goal:** Add warning flags and security hardening flags, checking for compiler support first.

**Meson Implementation (`/meson.build`):**
```meson
project(...)

c_compiler = meson.get_compiler('c')

# Define flags and check for support
c_flags = [
  '-Wall',
  '-Werror',
  '-Wshadow',
  '-Wreturn-type',
  '-Wsign-compare',
  '-Wno-self-assign',
  '-Wmissing-prototypes'
]
supported_c_flags = c_compiler.get_supported_arguments(c_flags)
add_project_arguments(supported_c_flags, language: 'c')

# Hardening flags
hardening_flags = []
if get_option('buildtype') != 'plain'
  # Stack protector
  if c_compiler.has_argument('-fstack-protector-strong')
    hardening_flags += '-fstack-protector-strong'
  elif c_compiler.has_argument('-fstack-protector')
    hardening_flags += '-fstack-protector'
  endif
  # Fortify source
  if c_compiler.has_argument('-D_FORTIFY_SOURCE=2')
    hardening_flags += '-D_FORTIFY_SOURCE=2'
  endif
endif
add_project_arguments(hardening_flags, language: 'c')

# Hardening linker flags
ld_flags = []
if get_option('buildtype') != 'plain'
  if c_compiler.has_link_argument('-Wl,-z,relro')
    ld_flags += '-Wl,-z,relro'
  endif
  if c_compiler.has_link_argument('-Wl,-z,now')
    ld_flags += '-Wl,-z,now'
  endif
endif
add_project_link_arguments(ld_flags, language: 'c')
```

**Autotools Comparison:**
*   This replaces the manual `AM_CFLAGS` definitions and the complex `AS_IF` blocks that check for hardening support in `configure.ac`.
*   `compiler.get_supported_arguments()`, `compiler.has_argument()`, and `compiler.has_link_argument()` are Meson's clean and reliable way to perform the same checks that Autotools does with trial compilations.
*   `add_project_arguments` and `add_project_link_arguments` are the global way to add flags, similar to setting `AM_CFLAGS` and `AM_LDFLAGS`.

---

### Step 6: Adding the FreeBL Crypto Backend

**Goal:** Implement the logic to choose between OpenSSL and FreeBL.

**Meson Implementation (`/meson.build`):**
```meson
# Add a choice option for the crypto backend
option('crypto_backend', type: 'combo', choices: ['openssl', 'freebl'], value: 'openssl',
       description: 'Choose the cryptographic backend.')
```

**Meson Implementation (`/src/meson.build`):**
```meson
crypto_backend = get_option('crypto_backend')
crypto_dep = []
c_args = []

if crypto_backend == 'openssl'
  crypto_dep = dependency('openssl')
  c_args += '-DUSE_OPENSSL_CRYPTO_LIBRARY=1'
else # freebl
  # Find nss, nspr, gmp
  nss_dep = dependency('nss')
  nspr_dep = dependency('nspr')
  gmp_dep = dependency('gmp')
  # freebl is part of nss, but we might need to find it explicitly
  freebl_dep = meson.get_compiler('c').find_library('freebl', required: true)
  crypto_dep = [nss_dep, nspr_dep, gmp_dep, freebl_dep]
  c_args += '-DUSE_FREEBL_CRYPTO_LIBRARY=1'
endif

# In the library definition:
libtpms = shared_library('tpms',
  ...,
  c_args: c_args,
  dependencies: crypto_dep,
  ...
)
```

**Autotools Comparison:**
*   The `combo` option type is a much cleaner way to handle mutually exclusive choices than the Autotools `AC_ARG_WITH` logic.
*   The `if/else` block for `crypto_backend` replaces the `AS_CASE([$cryptolib], ...)` block in `configure.ac`.
*   Dependency management remains much simpler. Instead of manual `AC_CHECK_HEADERS` and `AC_SEARCH_LIBS`, we just declare the dependencies.

---

### Step 7: Adding Finer-Grained Crypto Options

**Goal:** Implement the `--disable-use-openssl-functions` logic.

**Meson Implementation (`/meson.build`):**
```meson
option('use_openssl_functions', type: 'boolean', value: true,
       description: 'Use OpenSSL functions for crypto instead of internal code.')
```

**Meson Implementation (`/src/meson.build`):**
```meson
# ...
if crypto_backend == 'openssl' and get_option('use_openssl_functions')
  # Check for specific functions in libcrypto
  # Meson doesn't have a direct check_lib for functions, but we can use has_function
  # or just assume modern OpenSSL has them. For this plan, we'll add defines.
  c_args += [
    '-DUSE_OPENSSL_FUNCTIONS_SYMMETRIC=1',
    '-DUSE_OPENSSL_FUNCTIONS_EC=1',
    '-DUSE_OPENSSL_FUNCTIONS_ECDSA=1',
    '-DUSE_OPENSSL_FUNCTIONS_RSA=1',
    '-DUSE_OPENSSL_FUNCTIONS_SSKDF=1'
  ]
else
  c_args += [
    '-DUSE_OPENSSL_FUNCTIONS_SYMMETRIC=0',
    # ... and so on for all flags ...
  ]
endif
```

**Autotools Comparison:**
*   This replaces the `AC_ARG_ENABLE([use-openssl-functions], ...)` and the many `AC_CHECK_LIB` calls for individual functions. While Meson's `has_function` is available, it's often simpler to rely on the dependency version and add the defines, as the check in Autotools is mostly for older OpenSSL versions.

---

### Step 8: Building Tests, Man Pages, and Pkg-Config

**Goal:** Replicate the `tests` and `man` directory targets, and generate the `libtpms.pc` file.

**Meson Implementation (`/tests/meson.build`):**
```meson
# Get the libtpms dependency from the main build
libtpms_dep = dependency('tpms', fallback: ['tpms', 'libtpms'])

# Build an executable
tpm2_selftest = executable('tpm2_selftest',
  'tpm2_selftest.c',
  dependencies: libtpms_dep
)

# Define a test
test('TPM2 Self Test', tpm2_selftest,
     args: ['--device', '/dev/null'])
```

**Meson Implementation (`/man/man3/meson.build`):**
```meson
pod2man = find_program('pod2man', required: true)

# Use a custom target to generate man pages
custom_target('man_TPM_IO_Hash_Start',
  input: 'TPM_IO_Hash_Start.pod',
  output: 'TPM_IO_Hash_Start.3',
  command: [pod2man, '-r', 'libtpms', '-c', '""', '-n', '@BASENAME@', '--section=3', '@INPUT@'],
  capture: true,
  install: true,
  install_dir: get_option('mandir') / 'man3'
)
# Repeat for all .pod files
```

**Meson Implementation (`/meson.build`):**
```meson
# ...
# Pkg-config generation
pkg = import('pkgconfig')
pkg.generate(
  name: 'libtpms',
  description: 'A library for TPM emulation.',
  version: meson.project_version(),
  libraries: libtpms
)
```

**Autotools Comparison:**
*   `executable()` and `test()` in `tests/meson.build` replace `check_PROGRAMS` and `TESTS` from `tests/Makefile.am`. The dependency is handled cleanly.
*   `custom_target()` is Meson's powerful way to replace rule-based recipes, like the `%.3 : %.pod` rule in `man/man3/Makefile.am`.
*   The `pkgconfig` module is a massive simplification over maintaining a `libtpms.pc.in` file and using `AC_SUBST` in `configure.ac`.

---

### Step 9: Special Build Modes (Coverage, Sanitizers)

**Goal:** Implement the remaining special build modes.

**Meson Implementation:**
This is where Meson shines. There is no need for custom logic in the build files. The user controls this with built-in options:
*   **Test Coverage:** `./meson configure -Db_coverage=true`
*   **Sanitizers:** `./meson configure -Db_sanitize=address,undefined`
*   **Fuzzing:** `./meson configure -Db_fuzzing=true` (requires a recent Meson version)

**Autotools Comparison:**
*   This replaces `AC_ARG_ENABLE([test-coverage], ...)` and `AC_ARG_ENABLE([sanitizers], ...)`. Meson's implementation is standardized, requires zero code in the build scripts, and is less error-prone than managing `COVERAGE_CFLAGS` manually.

---

### Step 10: Final Touches (Versioning, Installation)

**Goal:** Ensure library versioning and symbol exports are correct.

**Meson Implementation (`/src/meson.build`):**
```meson
# ...
libtpms_version = meson.project_version()
# LIBTPMS_VERSION_INFO=`expr $LIBTPMS_VER_MAJOR + $LIBTPMS_VER_MINOR`:$LIBTPMS_VER_MICRO:$LIBTPMS_VER_MINOR
# This logic needs to be translated to Meson.
# For 0.11.0, this is 11:0:11
soversion = '11' # Based on the autotools logic for this specific version

libtpms = shared_library('tpms',
  ...,
  version: libtpms_version,
  soversion: soversion,
  darwin_versions: [soversion, libtpms_version], # For macOS compatibility
  vs_module_defs: 'libtpms.syms', # For Windows
  link_args: ['-Wl,--version-script,@0@'.format(files('libtpms.syms')[0].full_path())], # For Linux/ELF
  install: true
)
```

**Autotools Comparison:**
*   The `version` and `soversion` parameters in `shared_library` replace the `-version-info $(LIBTPMS_VERSION_INFO)` logic.
*   The `link_args` with a version script replaces the `HAVE_VERSION_SCRIPT` conditional logic and the associated `-Wl,--version-script` flag in `src/Makefile.am`. Meson makes accessing the file path for this much easier.

This iterative plan provides a clear path from a basic build to a full-featured replacement of the Autotools system, highlighting the advantages and simplifications Meson offers at each step.
