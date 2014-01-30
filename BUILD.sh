#!/bin/bash

PREFIX=${PREFIX:-/opt/dovecot-2.2-build}
EPREFIX=${EPREFIX:-/opt/dovecot-2.2-build}

CFLAGS="-O3 -I$PREFIX/include"
LDFLAGS="-Wl,-rpath -Wl,$EPREFIX/lib -L$EPREFIX/lib"
export CFLAGS LDFLAGS

# make sure we find anything we preinstall
export PATH=$EPREFIX/bin:$PATH

#autoconf-1.14.1
#automake-1.14.1
./configure --prefix=$PREFIX --exec-prefix=$EPREFIX
