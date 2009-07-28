AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src include fdi swig $(DEV_SUB)

DISTCHECK_CONFIGURE_FLAGS = --enable-dev-tools

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libiphone-1.0.pc

EXTRA_DIST= docs
dist-hook: doc

doc:
	rm -fr docs
	doxygen doxygen.cfg

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h dev/*.c

