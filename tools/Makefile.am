AM_CPPFLAGS = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS)

bin_PROGRAMS = idevice_id ideviceinfo idevicepair idevicesyslog idevicebackup ideviceimagemounter idevicescreenshot

ideviceinfo_SOURCES = ideviceinfo.c
ideviceinfo_CFLAGS = $(AM_CFLAGS)
ideviceinfo_LDFLAGS = $(AM_LDFLAGS)
ideviceinfo_LDADD = ../src/libimobiledevice.la

idevicepair_SOURCES = idevicepair.c
idevicepair_CFLAGS = $(AM_CFLAGS) -I../src
idevicepair_LDFLAGS = $(AM_LDFLAGS)
idevicepair_LDADD = ../src/libimobiledevice.la

idevicesyslog_SOURCES = idevicesyslog.c
idevicesyslog_CFLAGS = $(AM_CFLAGS)
idevicesyslog_LDFLAGS = $(AM_LDFLAGS)
idevicesyslog_LDADD = ../src/libimobiledevice.la

idevice_id_SOURCES = idevice_id.c
idevice_id_CFLAGS = $(AM_CFLAGS)
idevice_id_LDFLAGS = $(AM_LDFLAGS)
idevice_id_LDADD = ../src/libimobiledevice.la

idevicebackup_SOURCES = idevicebackup.c
idevicebackup_CFLAGS = $(AM_CFLAGS)
idevicebackup_LDFLAGS = $(AM_LDFLAGS)
idevicebackup_LDADD = ../src/libimobiledevice.la

ideviceimagemounter_SOURCES = ideviceimagemounter.c
ideviceimagemounter_CFLAGS = $(AM_CFLAGS)
ideviceimagemounter_LDFLAGS = $(AM_LDFLAGS)
ideviceimagemounter_LDADD = ../src/libimobiledevice.la

idevicescreenshot_SOURCES = idevicescreenshot.c
idevicescreenshot_CFLAGS = $(AM_CFLAGS)
idevicescreenshot_LDFLAGS = $(AM_LDFLAGS)
idevicescreenshot_LDADD = ../src/libimobiledevice.la

ideviceenterrecovery_SOURCES = ideviceenterrecovery.c
ideviceenterrecovery_CFLAGS = $(AM_CFLAGS)
ideviceenterrecovery_LDFLAGS = $(AM_LDFLAGS)
ideviceenterrecovery_LDADD = ../src/libimobiledevice.la
