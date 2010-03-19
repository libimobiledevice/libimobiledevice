AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src include swig dev tools docs

DISTCHECK_CONFIGURE_FLAGS = --enable-dev-tools

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libimobiledevice-1.0.pc

EXTRA_DIST = docs

docs/html: doxygen.cfg src/*.c src/*.h include/libimobiledevice/*.h
	rm -rf docs/html
	doxygen doxygen.cfg

docs: doxygen.cfg docs/html

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h dev/*.c

