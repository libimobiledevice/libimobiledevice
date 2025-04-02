AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(ssl_lib_CFLAGS) \
	$(libplist_CFLAGS) \
	$(LFS_CFLAGS)

AM_LDFLAGS = \
	$(libplist_LIBS)

bin_PROGRAMS = \
	idevicebtlogger\
	idevice_id \
	ideviceinfo \
	idevicename \
	idevicepair \
	idevicesyslog \
	ideviceimagemounter \
	idevicescreenshot \
	ideviceenterrecovery \
	idevicedate \
	idevicebackup \
	idevicebackup2 \
	ideviceprovision \
	idevicedebugserverproxy \
	idevicediagnostics \
	idevicedebug \
	idevicedevmodectl \
	idevicenotificationproxy \
	idevicecrashreport \
	idevicesetlocation \
	afcclient

idevicebtlogger_SOURCES = idevicebtlogger.c
idevicebtlogger_CFLAGS = $(AM_CFLAGS)
idevicebtlogger_LDFLAGS = $(top_builddir)/common/libinternalcommon.la $(AM_LDFLAGS)
idevicebtlogger_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

ideviceinfo_SOURCES = ideviceinfo.c
ideviceinfo_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
ideviceinfo_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
ideviceinfo_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicename_SOURCES = idevicename.c
idevicename_CFLAGS = $(AM_CFLAGS)
idevicename_LDFLAGS = $(AM_LDFLAGS)
idevicename_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicepair_SOURCES = idevicepair.c
idevicepair_CFLAGS = $(AM_CFLAGS)
idevicepair_LDFLAGS = $(AM_LDFLAGS) $(libusbmuxd_LIBS)
idevicepair_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la $(top_builddir)/common/libinternalcommon.la $(limd_glue_LIBS) $(ssl_lib_LIBS)

idevicesyslog_SOURCES = idevicesyslog.c
idevicesyslog_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicesyslog_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicesyslog_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevice_id_SOURCES = idevice_id.c
idevice_id_CFLAGS = $(AM_CFLAGS)
idevice_id_LDFLAGS = $(AM_LDFLAGS)
idevice_id_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicebackup_SOURCES = idevicebackup.c
idevicebackup_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicebackup_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicebackup_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicebackup2_SOURCES = idevicebackup2.c
idevicebackup2_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicebackup2_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicebackup2_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

ideviceimagemounter_SOURCES = ideviceimagemounter.c
ideviceimagemounter_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS) $(libtatsu_CFLAGS)
ideviceimagemounter_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS) $(libtatsu_LIBS)
ideviceimagemounter_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicescreenshot_SOURCES = idevicescreenshot.c
idevicescreenshot_CFLAGS = $(AM_CFLAGS)
idevicescreenshot_LDFLAGS = $(AM_LDFLAGS)
idevicescreenshot_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

ideviceenterrecovery_SOURCES = ideviceenterrecovery.c
ideviceenterrecovery_CFLAGS = $(AM_CFLAGS)
ideviceenterrecovery_LDFLAGS = $(AM_LDFLAGS)
ideviceenterrecovery_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicedate_SOURCES = idevicedate.c
idevicedate_CFLAGS = $(AM_CFLAGS)
idevicedate_LDFLAGS = $(AM_LDFLAGS)
idevicedate_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

ideviceprovision_SOURCES = ideviceprovision.c
ideviceprovision_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
ideviceprovision_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
ideviceprovision_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicedebugserverproxy_SOURCES = idevicedebugserverproxy.c
idevicedebugserverproxy_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicedebugserverproxy_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicedebugserverproxy_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicediagnostics_SOURCES = idevicediagnostics.c
idevicediagnostics_CFLAGS = $(AM_CFLAGS)
idevicediagnostics_LDFLAGS = $(AM_LDFLAGS)
idevicediagnostics_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicedebug_SOURCES = idevicedebug.c
idevicedebug_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicedebug_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicedebug_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la $(top_builddir)/common/libinternalcommon.la

idevicedevmodectl_SOURCES = idevicedevmodectl.c
idevicedevmodectl_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicedevmodectl_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicedevmodectl_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la $(top_builddir)/common/libinternalcommon.la

idevicenotificationproxy_SOURCES = idevicenotificationproxy.c
idevicenotificationproxy_CFLAGS = $(AM_CFLAGS)
idevicenotificationproxy_LDFLAGS = $(AM_LDFLAGS)
idevicenotificationproxy_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicecrashreport_SOURCES = idevicecrashreport.c
idevicecrashreport_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
idevicecrashreport_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
idevicecrashreport_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

idevicesetlocation_SOURCES = idevicesetlocation.c
idevicesetlocation_CFLAGS = $(AM_CFLAGS)
idevicesetlocation_LDFLAGS = $(AM_LDFLAGS)
idevicesetlocation_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la

afcclient_SOURCES = afcclient.c
afcclient_CFLAGS = $(AM_CFLAGS) $(limd_glue_CFLAGS)
afcclient_LDFLAGS = $(AM_LDFLAGS) $(limd_glue_LIBS)
if HAVE_READLINE
  afcclient_CFLAGS += $(readline_CFLAGS)
  afcclient_LDFLAGS += $(readline_LIBS)
endif
afcclient_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la $(limd_glue_LIBS)
