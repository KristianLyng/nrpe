AM_CPPFLAGS = -I$(top_srcdir)/include @SSL_CFLAGS@

bin_PROGRAMS = check_nrpe nrpe

check_nrpe_SOURCES = check_nrpe.c utils.c
check_nrpe_LDADD =  @SSL_LIBS@

nrpe_SOURCES = nrpe.c utils.c
nrpe_LDADD =  @SSL_LIBS@

