AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src include fdi swig dev tools

DISTCHECK_CONFIGURE_FLAGS = --enable-dev-tools

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libimobiledevice-1.0.pc

EXTRA_DIST= docs

docs:
	rm -fr docs
	doxygen doxygen.cfg

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h dev/*.c

