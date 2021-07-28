AC_INIT([mod_vulture],[1.0.0],[contact@vultureproject.org])

AC_SUBST(NAMEVER, AC_PACKAGE_TARNAME()-AC_PACKAGE_VERSION())

# This section defines the --with-apxs2 option.
AC_ARG_WITH(
	[apxs2],
	[  --with-apxs2=PATH       Full path to the apxs2 executable.],
	[
		APXS2=${withval}
	],)


if test "x$APXS2" = "x"; then
   # The user didn't specify the --with-apxs2-option.

   # Search for apxs2 in the specified directories
   AC_PATH_PROG(APXS2, apxs2,,
		/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

   if test "x$APXS2" = "x"; then
      # Didn't find apxs2 in any of the specified directories.
      # Search for apxs instead.
      AC_PATH_PROG(APXS2, apxs,,
		   /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
   fi

fi

# Test if $APXS2 exists and is an executable.
if test ! -x "$APXS2"; then
   # $APXS2 isn't a executable file.
   AC_MSG_ERROR([
Could not find apxs2. Please specify the path to apxs2
using the --with-apxs2=/full/path/to/apxs2 option.
The executable may also be named 'apxs'.
])
fi

# Replace any occurrences of @APXS2@ with the value of $APXS2 in the Makefile.
AC_SUBST(APXS2)

# Use environment variable APXS2_OPTS to pass params to APXS2 command
AC_ARG_VAR(APXS2_OPTS, [Additional command line options to pass to apxs2.])

# We need APR
PKG_CHECK_MODULES(APR, [apr-1, apr-util-1])
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LIBS)

# We need Apache sources
old_CFLAGS=$CFLAGS
CFLAGS="${HTTP_CFLAGS} $APR_CFLAGS $CFLAGS"
AC_CHECK_HEADERS([http_core.h], [HAVE_HTTP=1], [HAVE_HTTP=0])
if test "x$HAVE_HTTP" = "x0" ; then
   AC_MSG_ERROR([
Could not find http_core.h file. Please specify the path to http source directory
using the HTTP_CFLAGS option.
])
fi
CFLAGS=$old_CFLAGS
AC_SUBST(HTTP_CFLAGS)
AC_SUBST(HTTP_LIBS)

# We need the libxml2 library
PKG_CHECK_MODULES(LIBXML2, libxml-2.0)
AC_SUBST(LIBXML2_CFLAGS)
AC_SUBST(LIBXML2_LIBS)

# We need the pcre library
PKG_CHECK_MODULES(LIBPCRE, libpcre)
AC_SUBST(LIBPCRE_CFLAGS)
AC_SUBST(LIBPCRE_LIBS)

# We need OpenSSL for crypto and HTTPS callouts.
PKG_CHECK_MODULES(OPENSSL, openssl)
old_CFLAGS=$CFLAGS
CFLAGS="${OPENSSL_CFLAGS} $CFLAGS"
AC_CHECK_HEADERS([openssl/ossl_typ.h], [HAVE_OPENSSL=1], [HAVE_OPENSSL=0])
if test "x$have_openssl" = "x0" ; then
   AC_MSG_ERROR([
Could not find openssl/ossl_typ.h file. Please specify the path to openssl directory
using the OPENSSL_CFLAGS option.
])
fi
# Check libssl & EVP_EncryptInit
old_LDFLAGS="$LDFLAGS"
LDFLAGS="$OPENSSL_LIBS $LDFLAGS"
AC_CHECK_LIB([ssl], [EVP_EncryptInit], [HAVE_OPENSSL=1], [HAVE_OPENSSL=0])
if test "x$HAVE_OPENSSL" = "x0" ; then
   AC_MSG_ERROR([Could not find libssl.so file. Please specify the path to ssl directory
using the OPENSSL_LIBS option.
])
fi
LDFLAGS=$old_LDFLAGS
CFLAGS=$old_CFLAGS
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

# Redis
PKG_CHECK_MODULES(HIREDIS, [hiredis], [HAVE_HIREDIS=1], [HAVE_HIREDIS=0])
if test "x$HAVE_HIREDIS" = "x0" ; then
	if test -x "$HIREDIS_CFLAGS" ; then
		AC_MSG_ERROR([
            HIREDIS not found. Please specify headers directory with HIREDIS_CFLAGS
        ])
    else
        # Check hiredis.h and libhiredis.so presence
	    old_CFLAGS=$CFLAGS
	    CFLAGS="${HIREDIS_CFLAGS} $CFLAGS"
	    AC_CHECK_HEADERS([hiredis.h], [HAVE_HIREDIS=1], [HAVE_HIREDIS=0])
		if test "x$HAVE_HIREDIS" = "x0" ; then
		   AC_MSG_ERROR([Could not find hiredis.h file. Please specify the path to hiredis directory
		using the HIREDIS_CFLAGS option.
		])
		fi
		old_LDFLAGS="$LDFLAGS"
		LDFLAGS="$HIREDIS_LIBS $LDFLAGS"
	    AC_CHECK_LIB([redisvCommand], [hiredis], [HAVE_HIREDIS=1], [HAVE_HIREDIS=0])
        if test "x$HAVE_HIREDIS" = "x0" ; then
           AC_MSG_ERROR([Could not find libhiredis.so file. Please specify the path to hiredis directory
        using the HIREDIS_LIBS option.
        ])
		fi
	    LDFLAGS=$old_LDFLAGS
	    CFLAGS=$old_CFLAGS
	fi
fi
AC_SUBST(HIREDIS_CFLAGS)
AC_SUBST(HIREDIS_LIBS)

# We need mod_security2
old_CFLAGS=$CFLAGS
CFLAGS="${MODSEC_CFLAGS} $LIBXML2_CFLAGS $HIREDIS_CFLAGS $APR_CFLAGS $LIBPCRE_CFLAGS $HTTP_CFLAGS $CFLAGS"
AC_CHECK_HEADERS([modsecurity.h], [HAVE_MODSEC=1], [HAVE_MODSEC=0])
if test "x$HAVE_MODSEC" = "x0" ; then
   AC_MSG_ERROR([
Could not find modsecurity.h file. Please specify the path to modsecurity directory
using the MODSEC_CFLAGS option.
])
fi
CFLAGS=$old_CFLAGS
AC_SUBST(MODSEC_LIBS)
AC_SUBST(MODSEC_CFLAGS)

# We need gssapi
old_LDFLAGS=$LDFLAGS
LDFLAGS="$GSSAPI_LIBS $LDFLAGS"
AC_CHECK_LIB([gssapi], [gss_import_name])
LDFLAGS=$old_LDFLAGS
AC_SUBST(GSSAPI_LIBS)

# We need gssapi_krb5
old_LDFLAGS=$LDFLAGS
LDFLAGS="$GSSAPI_KRB5_LIBS $LDFLAGS"
AC_CHECK_LIB([gssapi_krb5], [gss_krb5_ccache_name])
LDFLAGS=$old_LDFLAGS
AC_SUBST(GSSAPI_KRB5_LIBS)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([Makefile])
AC_OUTPUT