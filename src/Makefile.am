AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall

bin_PROGRAMS = check_nrpe nrpe
check_nrpe_SOURCES = check_nrpe.c utils.c
check_nrpe_LDADD = -lssl

nrpe_SOURCES = nrpe.c utils.c
nrpe_LDADD = -lssl

