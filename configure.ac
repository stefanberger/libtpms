#
# configure.in
#
# See the LICENSE file for the license associated with this file.

AC_INIT([libtpms], [0.6.0])
AC_PREREQ(2.12)
AC_CONFIG_SRCDIR(Makefile.am)
AM_CONFIG_HEADER(config.h)

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign 1.6 subdir-objects])

LIBTPMS_VER_MAJOR=`echo $PACKAGE_VERSION | awk -F. '{print $1}'`
LIBTPMS_VER_MINOR=`echo $PACKAGE_VERSION | awk -F. '{print $2}'`
LIBTPMS_VER_MICRO=`echo $PACKAGE_VERSION | awk -F. '{print $3}'`
LIBTPMS_VERSION=$PACKAGE_VERSION
LIBTPMS_VERSION_INFO=`expr $LIBTPMS_VER_MAJOR + $LIBTPMS_VER_MINOR`:$LIBTPMS_VER_MICRO:$LIBTPMS_VER_MINOR

AC_SUBST([LIBTPMS_VER_MAJOR])
AC_SUBST([LIBTPMS_VER_MINOR])
AC_SUBST([LIBTPMS_VER_MICRO])
AC_SUBST([LIBTPMS_VERSION])
AC_SUBST([LIBTPMS_VERSION_INFO])

DEBUG=""
AC_MSG_CHECKING([for debug-enabled build])
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [create a debug build]),
  [if test "$enableval" = "yes"; then
     DEBUG="yes"
     AC_MSG_RESULT([yes])
   else
     DEBUG="no"
     AC_MSG_RESULT([no])
   fi],
  [DEBUG="no",
   AC_MSG_RESULT([no])])

# If the user has not set CFLAGS, do something appropriate
test_CFLAGS=${CFLAGS+set}
if test "$test_CFLAGS" != set; then
	if test "$DEBUG" == "yes"; then
		CFLAGS="-O0 -g -DDEBUG"
	else
		CFLAGS="-g -O2"
	fi
elif test "$DEBUG" == "yes"; then
	CFLAGS="$CFLAGS -O0 -g -DDEBUG"
fi

debug_defines=
if test "$DEBUG" == "yes"; then
	debug_defines="-DTPM_DEBUG"
	# Enable the following only if ABSOLUTELY necessary
	# volatile state will be written and behavior changes
	#"-DTPM_VOLATILE_STORE"
fi
AC_SUBST(DEBUG_DEFINES, $debug_defines)

cryptolib=freebl

AC_ARG_WITH([openssl],
            AC_HELP_STRING([--with-openssl],
                           [build libtpms with openssl library]),
              [AC_CHECK_LIB(crypto,
                            [AES_set_encrypt_key],
                            [],
                            AC_MSG_ERROR(Faulty openssl crypto library))
               AC_CHECK_HEADERS([openssl/aes.h],[],
                            AC_MSG_ERROR(Is openssl-devel/libssl-dev installed?))
               AC_MSG_RESULT([Building with openssl crypto library])
               cryptolib=openssl
              ]
)

case "$cryptolib" in
freebl)
	AM_CONDITIONAL(LIBTPMS_USE_FREEBL, true)
	AM_CONDITIONAL(LIBTPMS_USE_OPENSSL, false)
        AC_DEFINE([USE_FREEBL_CRYPTO_LIBRARY],
                  [1],
                  [use freebl crypto library])

	CFLAGS_save=$CFLAGS

	AC_CHECK_HEADERS([gmp.h],[],
			 AC_MSG_ERROR(gmp-devel/libgmp-dev is bad))

	CFLAGS="$(nspr-config --cflags)"
	if test $? -ne 0; then
		AC_MSG_ERROR(Could not find nspr-config. Is nspr-devel/libnspr4-dev installed?)
	fi
	CPPFLAGS=$CFLAGS
	AC_CHECK_HEADERS([plbase64.h],[],
			 AC_MSG_ERROR(You must install nspr-devel/libnspr4-dev))

	CFLAGS="$(nss-config --cflags) $CFLAGS"
	if test $? -ne 0; then
		AC_MSG_ERROR(Could not find nss-config. Is nss-devel/libnss3-dev installed?)
	fi
	CPPFLAGS="$CPPFLAGS $CFLAGS"
	AC_CHECK_HEADERS([sslerr.h],[],
			 AC_MSG_ERROR(nss-devel/libnss3-dev is bad))

	# Check for missing headers
	AC_CHECK_HEADERS([blapi.h],[],
			 AC_MSG_ERROR(nss-softokn-freebl-devel/libnss3-dev is missing blapi.h))
	# Check for missing freebl library or missing library functions
	LIBS_save="$LIBS"
	LIBS="$(nss-config --libs) $(nspr-config --libs)"
	AC_SEARCH_LIBS([AES_CreateContext], [freebl],[],
             AC_MSG_ERROR("Could not find AES_CreateContext(). Is nss-softokn-freebl-devel/libnss3-dev installed?"),
             [])
	LIBS="$LIBS_save"
	CFLAGS="$CFLAGS_save $CFLAGS"
	;;
openssl)
	AM_CONDITIONAL(LIBTPMS_USE_FREEBL, false)
	AM_CONDITIONAL(LIBTPMS_USE_OPENSSL, true)
        AC_DEFINE([USE_OPENSSL_CRYPTO_LIBRARY],
                  [1],
                  [use openssl crypto library])
	;;
esac

LT_INIT
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

#AM_GNU_GETTEXT_VERSION([0.15])
#AM_GNU_GETTEXT([external])

AC_HEADER_STDC
AC_C_CONST
AC_C_INLINE

AC_TYPE_SIZE_T

# Some version of gcc fail with -Wstack-protector enabled
TMP="$($CC -fstack-protector-strong 2>&1)"
if echo $TMP | $GREP 'unrecognized command line option' >/dev/null; then
  HARDENING_CFLAGS="-fstack-protector "
else
  HARDENING_CFLAGS="-fstack-protector-strong "
fi

dnl Must not have -O0 but must have a -O for -D_FORTIFY_SOURCE=2
TMP1="$(echo $CFLAGS | sed -n 's/.*\(-O0\).*/\1/p')"
TMP2="$(echo $CFLAGS | sed -n 's/.*\(-O\).*/\1/p')"
if test -z "$TMP1" && test -n "$TPM2"; then
  HARDENING_CFLAGS+="-D_FORTIFY_SOURCE=2 "
fi
dnl Check ld for 'relro' and 'now'
if $LD --help 2>&1 | $GREP '\-z relro ' > /dev/null; then
  HARDENING_CFLAGS+="-Wl,-z,relro "
fi
if $LD --help 2>&1 | $GREP '\-z now ' > /dev/null; then
  HARDENING_CFLAGS+="-Wl,-z,now "
fi
AC_SUBST([HARDENING_CFLAGS])

if test "$test_CFLAGS" != set; then
  CFLAGS="$CFLAGS -Wall -Werror -Wreturn-type -Wsign-compare"
fi

AC_CONFIG_FILES(Makefile                   \
		dist/libtpms.spec          \
		include/Makefile           \
		include/libtpms/Makefile   \
		include/libtpms/tpm_library.h \
		man/Makefile               \
		man/man3/Makefile          \
		src/Makefile               \
		libtpms.pc                 \
		tests/Makefile)
AC_OUTPUT

if test -z "$enable_debug" ; then
    enable_debug="no"
fi

echo
echo "CFLAGS=$CFLAGS"
echo "HARDENING_CFLAGS=$HARDENING_CFLAGS"
echo "LDFLAGS=$LDFLAGS"
echo
echo "Version to build : $PACKAGE_VERSION"
echo "Crypto library   : $cryptolib"
echo "Debug build      : $enable_debug"
echo
echo
