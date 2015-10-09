AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgcrypt_CFLAGS) $(openssl_CFLAGS) $(libplist_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgcrypt_LIBS) $(openssl_LIBS) $(libplist_LIBS)

bin_PROGRAMS = idevice_id ideviceinfo idevicename idevicepair idevicesyslog ideviceimagemounter idevicescreenshot ideviceenterrecovery idevicedate idevicebackup idevicebackup2 ideviceprovision idevicedebugserverproxy idevicediagnostics idevicedebug idevicenotificationproxy idevicecrashreport

ideviceinfo_SOURCES = ideviceinfo.c
ideviceinfo_CFLAGS = $(AM_CFLAGS)
ideviceinfo_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
ideviceinfo_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicename_SOURCES = idevicename.c
idevicename_CFLAGS = $(AM_CFLAGS)
idevicename_LDFLAGS = $(AM_LDFLAGS)
idevicename_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicepair_SOURCES = idevicepair.c
idevicepair_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS)
idevicepair_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS) $(libusbmuxd_LIBS)
idevicepair_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicesyslog_SOURCES = idevicesyslog.c
idevicesyslog_CFLAGS = $(AM_CFLAGS)
idevicesyslog_LDFLAGS = $(AM_LDFLAGS)
idevicesyslog_LDADD = $(top_builddir)/src/libimobiledevice.la

idevice_id_SOURCES = idevice_id.c
idevice_id_CFLAGS = $(AM_CFLAGS)
idevice_id_LDFLAGS = $(AM_LDFLAGS)
idevice_id_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicebackup_SOURCES = idevicebackup.c
idevicebackup_CFLAGS = $(AM_CFLAGS)
idevicebackup_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
idevicebackup_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicebackup2_SOURCES = idevicebackup2.c
idevicebackup2_CFLAGS = $(AM_CFLAGS)
idevicebackup2_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
idevicebackup2_LDADD = $(top_builddir)/src/libimobiledevice.la

ideviceimagemounter_SOURCES = ideviceimagemounter.c
ideviceimagemounter_CFLAGS = $(AM_CFLAGS)
ideviceimagemounter_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
ideviceimagemounter_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicescreenshot_SOURCES = idevicescreenshot.c
idevicescreenshot_CFLAGS = $(AM_CFLAGS)
idevicescreenshot_LDFLAGS = $(AM_LDFLAGS)
idevicescreenshot_LDADD = $(top_builddir)/src/libimobiledevice.la

ideviceenterrecovery_SOURCES = ideviceenterrecovery.c
ideviceenterrecovery_CFLAGS = $(AM_CFLAGS)
ideviceenterrecovery_LDFLAGS = $(AM_LDFLAGS)
ideviceenterrecovery_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicedate_SOURCES = idevicedate.c
idevicedate_CFLAGS = $(AM_CFLAGS)
idevicedate_LDFLAGS = $(AM_LDFLAGS)
idevicedate_LDADD = $(top_builddir)/src/libimobiledevice.la

ideviceprovision_SOURCES = ideviceprovision.c
ideviceprovision_CFLAGS = $(AM_CFLAGS)
ideviceprovision_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
ideviceprovision_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicedebugserverproxy_SOURCES = idevicedebugserverproxy.c
idevicedebugserverproxy_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS)
idevicedebugserverproxy_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
idevicedebugserverproxy_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicediagnostics_SOURCES = idevicediagnostics.c
idevicediagnostics_CFLAGS = $(AM_CFLAGS)
idevicediagnostics_LDFLAGS = $(AM_LDFLAGS)
idevicediagnostics_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicedebug_SOURCES = idevicedebug.c
idevicedebug_CFLAGS = $(AM_CFLAGS)
idevicedebug_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
idevicedebug_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicenotificationproxy_SOURCES = idevicenotificationproxy.c
idevicenotificationproxy_CFLAGS = $(AM_CFLAGS)
idevicenotificationproxy_LDFLAGS = $(AM_LDFLAGS)
idevicenotificationproxy_LDADD = $(top_builddir)/src/libimobiledevice.la

idevicecrashreport_SOURCES = idevicecrashreport.c
idevicecrashreport_CFLAGS = -I$(top_srcdir) $(AM_CFLAGS)
idevicecrashreport_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
idevicecrashreport_LDADD = $(top_builddir)/src/libimobiledevice.la
