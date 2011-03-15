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

# --enable-werror
AC_ARG_ENABLE(werror,
	AS_HELP_STRING([--enable-werror],[use -Werror (default is NO)]),
	CFLAGS="${CFLAGS} -Werror")

AC_ARG_WITH([default-port],
	AS_HELP_STRING([--with-default-portl],
		[set the default port used by the nrpe-server and plugin@<:@default=5666@:>@]),
	[],
	[with_default_port=5666])

AC_ARG_WITH([default-socket-timeout],
	AS_HELP_STRING([--with-default-socket-timeout],
		[set the default socket timeout in seconds @<:@default=10@:>@]),
	[],
	[with_default_socket_timeout=10])

AC_ARG_WITH([default-connection-timeout],
	AS_HELP_STRING([--with-default-connection-timeout],
		[set the default connection timeout in seconds @<:@default=300@:>@]),
	[],
	[with_default_connection_timeout=300])

AC_ARG_WITH([with-nrpe-hello],
	AS_HELP_STRING([--with-nrpe-hello],
		[set the nrpe HELLO-command @<:@default=_NRPE_CHECK@:>@]),
	[],
	[with_nrpe_hello="_NRPE_CHECK"])

AC_ARG_WITH([with-log-facility],
	AS_HELP_STRING([--with-log-facility],
		[set the log facility used by nrpe @<:@default=daemon@:>@]),
	[],
	[with_log_facility="daemon"])

AC_ARG_WITH([with-max-filename-length],
	AS_HELP_STRING([--with-max-filename-length],
		[maximum filename length @<:@default=256@:>@]),
	[],
	[with_max_filename_length=256])

AC_ARG_WITH([with-packetbuffer-length],
	AS_HELP_STRING([--with-max-packetbuffer-length],
		[maxium amount of packet data sent in a single query/response @<:@default=1024@:>@]),
	[],
	[with_max_packetbuffer_length=1024])

AC_ARG_WITH([with-max-command-arguments],
	AS_HELP_STRING([--with-max-command-arguments],
		[maximum command arguments allowed @<:@default=16@:>@]),
	[],
	[with_max_command_arguments=16])

AC_ARG_WITH([with-max-input-buffer],
	AS_HELP_STRING([--with-max-input-buffer],
		[set the max size of most internal buffers @<:@default=2048@:>@]),
	[],
	[with_max_input_buffer=2048])

AC_ARG_WITH([with-max-host-address-length],
	AS_HELP_STRING([--with-max-host-address-length],
		[set the max size allowed for host addresses @<:@default=256@:>@]),
	[],
	[with_max_host_address_length=256])

AC_DEFINE_UNQUOTED(DEFAULT_SERVER_PORT, [$with_default_port],[default port])
AC_DEFINE_UNQUOTED(NRPE_LOG_FACILITY,["$with_log_facility"],[log facility])
AC_DEFINE_UNQUOTED(DEFAULT_SOCKET_TIMEOUT,[$with_default_socket_timeout],[default socket timeout in seconds])
AC_DEFINE_UNQUOTED(DEFAULT_CONNECTION_TIMEOUT,[$with_default_connection_timeout],[connection timeout in seconds])
AC_DEFINE_UNQUOTED(NRPE_HELLO_COMMAND,["$with_nrpe_hello"],[hello-command])
AC_DEFINE_UNQUOTED(MAX_FILENAME_LENGTH,[$with_max_filename_length],[Maximum filename length])
AC_DEFINE_UNQUOTED(MAX_PACKETBUFFER_LENGTH,[$with_max_packetbuffer_length],[Maximum packetsize (may break protocol-compatibility)])
AC_DEFINE_UNQUOTED(MAX_COMMAND_ARGUMENTS,[$with_max_command_arguments],[Maximum amount of command arguments])
AC_DEFINE_UNQUOTED(MAX_INPUT_BUFFER,[$with_max_input_buffer],[Input buffer size])
AC_DEFINE_UNQUOTED(MAX_HOST_ADDRESS_LENGTH,[$with_max_host_address_length],[Maximum length of addresses])


AC_CONFIG_FILES([Makefile
	src/Makefile])
AC_OUTPUT
