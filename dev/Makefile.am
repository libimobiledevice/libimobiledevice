INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS)

if ENABLE_DEVTOOLS
noinst_PROGRAMS = ideviceclient lckd-client afccheck msyncclient ideviceenterrecovery filerelaytest

ideviceclient_SOURCES = ideviceclient.c
ideviceclient_LDADD = ../src/libimobiledevice.la

lckd_client_SOURCES = lckdclient.c
lckd_client_CFLAGS = $(AM_CFLAGS)
lckd_client_LDFLAGS = -lreadline $(AM_LDFLAGS)
lckd_client_LDADD = ../src/libimobiledevice.la

afccheck_SOURCES = afccheck.c
afccheck_CFLAGS = $(AM_CFLAGS)
afccheck_LDFLAGS = $(AM_LDFLAGS)
afccheck_LDADD = ../src/libimobiledevice.la

msyncclient_SOURCES = msyncclient.c
msyncclient_CFLAGS = $(AM_CFLAGS)
msyncclient_LDFLAGS = $(AM_LDFLAGS)
msyncclient_LDADD = ../src/libimobiledevice.la

ideviceenterrecovery_SOURCES = ideviceenterrecovery.c
ideviceenterrecovery_CFLAGS = $(AM_CFLAGS)
ideviceenterrecovery_LDFLAGS = $(AM_LDFLAGS)
ideviceenterrecovery_LDADD = ../src/libimobiledevice.la

filerelaytest_SOURCES = filerelaytest.c
filerelaytest_CFLAGS = $(AM_CFLAGS)
filerelaytest_LDFLAGS = $(AM_LDFLAGS)
filerelaytest_LDADD = ../src/libimobiledevice.la

endif # ENABLE_DEVTOOLS

EXTRA_DIST = ideviceclient.c lckdclient.c afccheck.c msyncclient.c ideviceenterrecovery.c
