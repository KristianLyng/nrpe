#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([nrpe], [3.0], [https://github.com/KristianLyng/nrpe])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE(nrpe, 3.0, [-Wall -Werror foreign])

m4_pattern_forbid([^_?PKG_[A-Z_]+$],[pkg.m4 missing, please install pkg-config])

AC_ARG_WITH([ssl],
	AS_HELP_STRING([--with-ssl],
		[use ssl @<:@default=check@:>@]),
	[],
	[with_ssl=check])

AS_IF([test "x$with_ssl" != "xno"],
	[PKG_CHECK_MODULES([SSL], 
		[libssl],
		[AC_DEFINE([HAVE_SSL],[1],[Define we have SSL])],
		[AC_MSG_ERROR([nrpe requires libssl.])]) ]
	)

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stdint.h stdlib.h string.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm bzero endgrent endpwent getcwd gethostbyname inet_ntoa memset putenv select socket strchr strcspn strdup strerror strpbrk strspn strstr])

# This corresponds to FreeBSD's WARNS level 6
DEVELOPER_CFLAGS="-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch -Wshadow -Wcast-align -Wunused-parameter -Wchar-subscripts -Winline -Wnested-externs -Wredundant-decls -Wformat"

# Additional flags for GCC 4
EXTRA_DEVELOPER_CFLAGS="-Wextra -Wno-missing-field-initializers -Wno-sign-compare"

# --enable-developer-warnings
AC_ARG_ENABLE(developer-warnings,
	AS_HELP_STRING([--enable-developer-warnings],[enable strict warnings (default is NO)]),
	CFLAGS="${CFLAGS} ${DEVELOPER_CFLAGS}")

# --enable-debugging-symbols
AC_ARG_ENABLE(debugging-symbols,
	AS_HELP_STRING([--enable-debugging-symbols],[enable debugging symbols (default is NO)]),
	CFLAGS="${CFLAGS} -O0 -g -fno-inline")

# --enable-diagnostics
AC_ARG_ENABLE(diagnostics,
	AS_HELP_STRING([--enable-diagnostics],[enable run-time diagnostics (default is NO)]),
	CFLAGS="${CFLAGS} -DDIAGNOSTICS")

# --enable-extra-developer-warnings
AC_ARG_ENABLE(extra-developer-warnings,
	AS_HELP_STRING([--enable-extra-developer-warnings],[enable even stricter warnings (default is NO)]),
	CFLAGS="${CFLAGS} ${EXTRA_DEVELOPER_CFLAGS}")

# --enable-stack-protector
AC_ARG_ENABLE(stack-protector,
	AS_HELP_STRING([--enable-stack-protector],[enable stack protector (default is NO)]),
	CFLAGS="${CFLAGS} -fstack-protector-all")

# --enable-tests
AC_ARG_ENABLE(tests,
	AS_HELP_STRING([--enable-tests],[build test programs (default is NO)]))
AM_CONDITIONAL([ENABLE_TESTS], [test x$enable_tests = xyes])

# --enable-werror
AC_ARG_ENABLE(werror,
	AS_HELP_STRING([--enable-werror],[use -Werror (default is NO)]),
	CFLAGS="${CFLAGS} -Werror")



AC_CONFIG_FILES([Makefile
	src/Makefile])
AC_OUTPUT
