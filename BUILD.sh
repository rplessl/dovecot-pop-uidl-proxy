#!/bin/bash
PREFIX=/opt/dovecot-2.2
EPREFIX=/opt/dovecot-2.2

CFLAGS="-O3 -I$PREFIX/include"
LDFLAGS="-Wl,-rpath -Wl,$EPREFIX/lib -L$EPREFIX/lib"
export CFLAGS LDFLAGS

./configure --prefix=$PREFIX --exec-prefix=$EPREFIX
