AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/3rd_party/libsrp6a-sha512 \
	-I$(top_srcdir)/3rd_party/ed25519 \
	-I$(top_srcdir)

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(ssl_lib_CFLAGS) \
	$(LFS_CFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(libusbmuxd_CFLAGS) \
	$(libplist_CFLAGS) \
	$(limd_glue_CFLAGS)

AM_LDFLAGS = \
	$(ssl_lib_LIBS) \
	$(PTHREAD_LIBS) \
	$(libusbmuxd_LIBS) \
	$(libplist_LIBS) \
	$(limd_glue_LIBS)

lib_LTLIBRARIES = libimobiledevice-1.0.la
libimobiledevice_1_0_la_LIBADD = $(top_builddir)/common/libinternalcommon.la
if HAVE_WIRELESS_PAIRING
libimobiledevice_1_0_la_LIBADD += $(top_builddir)/3rd_party/ed25519/libed25519.la $(top_builddir)/3rd_party/libsrp6a-sha512/libsrp6a-sha512.la
endif
libimobiledevice_1_0_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(LIBIMOBILEDEVICE_SO_VERSION) -no-undefined
if DARWIN
libimobiledevice_1_0_la_LDFLAGS += -framework CoreFoundation -framework SystemConfiguration
endif
libimobiledevice_1_0_la_SOURCES = \
	idevice.c idevice.h \
	service.c service.h \
	property_list_service.c property_list_service.h \
	device_link_service.c device_link_service.h \
	lockdown.c lockdown.h \
	lockdown-cu.c \
	afc.c afc.h \
	file_relay.c file_relay.h \
	notification_proxy.c notification_proxy.h \
	installation_proxy.c installation_proxy.h \
	sbservices.c sbservices.h \
	mobile_image_mounter.c mobile_image_mounter.h \
	screenshotr.c screenshotr.h \
	mobilesync.c mobilesync.h \
	mobilebackup.c mobilebackup.h \
	house_arrest.c house_arrest.h \
	mobilebackup2.c mobilebackup2.h \
	misagent.c misagent.h \
	restore.c restore.h \
	diagnostics_relay.c diagnostics_relay.h \
	heartbeat.c heartbeat.h \
	debugserver.c debugserver.h \
	webinspector.c webinspector.h \
	mobileactivation.c mobileactivation.h \
	preboard.c preboard.h  \
	companion_proxy.c companion_proxy.h \
	reverse_proxy.c reverse_proxy.h \
	syslog_relay.c syslog_relay.h \
	bt_packet_logger.c bt_packet_logger.h

if WIN32
libimobiledevice_1_0_la_LDFLAGS += -avoid-version -static-libgcc
libimobiledevice_1_0_la_LIBADD += -lole32 -lws2_32 -lgdi32
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libimobiledevice-1.0.pc
