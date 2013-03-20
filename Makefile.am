AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = common src include $(CYTHON_SUB) $(DEV_SUB) tools docs

DISTCHECK_CONFIGURE_FLAGS = --enable-dev-tools

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libimobiledevice-1.0.pc

EXTRA_DIST = docs

docs/html: $(top_builddir)/doxygen.cfg $(top_srcdir)/src/*.c $(top_srcdir)/src/*.h $(top_srcdir)/include/libimobiledevice/*.h
	rm -rf docs/html
	doxygen doxygen.cfg

docs: doxygen.cfg docs/html

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h dev/*.c

