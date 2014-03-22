AM_CPPFLAGS = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(openssl_CFLAGS) $(libplist_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libgnutls_LIBS) $(libtasn1_LIBS) $(openssl_LIBS) $(libplist_LIBS)

if ENABLE_DEVTOOLS
noinst_PROGRAMS = ideviceclient afccheck filerelaytest housearresttest lckd-client ideviceheartbeat

ideviceclient_SOURCES = ideviceclient.c
ideviceclient_CFLAGS = $(AM_CFLAGS)
ideviceclient_LDFLAGS = $(AM_LDFLAGS)
ideviceclient_LDADD = $(top_builddir)/src/libimobiledevice.la

lckd_client_SOURCES = lckdclient.c
lckd_client_CFLAGS = $(AM_CFLAGS) $(libglib2_CFLAGS)
lckd_client_LDFLAGS = -lreadline $(AM_LDFLAGS) $(libglib2_LIBS)
lckd_client_LDADD = $(top_builddir)/src/libimobiledevice.la

afccheck_SOURCES = afccheck.c
afccheck_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS)
afccheck_LDFLAGS = $(AM_LDFLAGS)
afccheck_LDADD = $(top_builddir)/src/libimobiledevice.la

filerelaytest_SOURCES = filerelaytest.c
filerelaytest_CFLAGS = $(AM_CFLAGS)
filerelaytest_LDFLAGS = $(AM_LDFLAGS)
filerelaytest_LDADD = $(top_builddir)/src/libimobiledevice.la

housearresttest_SOURCES = housearresttest.c
housearresttest_CFLAGS = $(AM_CFLAGS)
housearresttest_LDFLAGS = $(AM_LDFLAGS)
housearresttest_LDADD = $(top_builddir)/src/libimobiledevice.la

ideviceheartbeat_SOURCES = ideviceheartbeat.c
ideviceheartbeat_CFLAGS = $(AM_CFLAGS)
ideviceheartbeat_LDFLAGS = $(AM_LDFLAGS)
ideviceheartbeat_LDADD = $(top_builddir)/src/libimobiledevice.la

endif # ENABLE_DEVTOOLS

EXTRA_DIST = ideviceclient.c lckdclient.c afccheck.c filerelaytest.c housearresttest.c ideviceheartbeat.c
