AUTOMAKE_OPTIONS = foreign

SUBDIRS = src include fdi udev $(DEV_SUB)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libiphone-1.0.pc

doc:
	doxygen doxygen.cfg

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h dev/*.c
