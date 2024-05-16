AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(ssl_lib_CFLAGS) \
	$(LFS_CFLAGS) \
	$(libusbmuxd_CFLAGS) \
	$(limd_glue_CFLAGS) \
	$(libplist_CFLAGS)

AM_LDFLAGS = \
	$(ssl_lib_LIBS) \
	${libpthread_LIBS} \
	$(libusbmuxd_LIBS) \
	$(limd_glue_LIBS) \
	$(libplist_LIBS)

noinst_LTLIBRARIES = libinternalcommon.la
libinternalcommon_la_LIBADD = 
libinternalcommon_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined
libinternalcommon_la_SOURCES = \
	debug.c debug.h \
	userpref.c userpref.h

if WIN32
libinternalcommon_la_LIBADD += -lole32 -lws2_32
endif
