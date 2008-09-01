AUTOMAKE_OPTIONS = foreign
SUBDIRS = src 

doc:
	doxygen doxygen.cfg

indent:
	indent -kr -ut -ts4 -l120 src/*.c src/*.h
