#!/bin/sh
aclocal -I m4
libtoolize
autoheader
automake --add-missing
autoconf

if [ -z "$NOCONFIGURE" ]; then
    ./configure "$@"
fi
