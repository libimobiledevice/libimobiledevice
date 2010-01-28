INCLUDES = -I$(top_srcdir)/include

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libglib2_CFLAGS) $(libgnutls_CFLAGS) $(libtasn1_CFLAGS) $(libgthread2_CFLAGS) $(LFS_CFLAGS)
AM_LDFLAGS = $(libglib2_LIBS) $(libgnutls_LIBS) $(libtasn1_LIBS) $(libgthread2_LIBS)

bin_PROGRAMS = idevice_id ideviceinfo idevicesyslog idevicebackup

ideviceinfo_SOURCES = ideviceinfo.c
ideviceinfo_CFLAGS = $(AM_CFLAGS)
ideviceinfo_LDFLAGS = $(AM_LDFLAGS)
ideviceinfo_LDADD = ../src/libimobiledevice.la

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

