#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([nrpe], [3.0], [https://github.com/KristianLyng/nrpe])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE(nrpe, 3.0, [-Wall -Werror foreign])
AM_CFLAGS="-Wall -Werror"
PKG_CHECK_MODULES([libssl], [libssl],[AC_DEFINE([HAVE_SSL],[1],[Define we have SSL])],[AC_MSG_ERROR([nrpe requires libssl.])])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h])

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
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm bzero endgrent endpwent getcwd gethostbyname inet_ntoa memset pow putenv select socket strchr strcspn strdup strerror strpbrk strspn strstr])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
