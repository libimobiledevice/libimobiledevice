AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src include fdi swig udev $(DEV_SUB)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libiphone-1.0.pc

doc:
	doxygen doxygen.cfg

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h dev/*.c

release:
	git archive --format=tar --prefix=libiphone-${RELEASE}/ tags/${RELEASE} | bzip2 > libiphone-${RELEASE}.tar.bz2
