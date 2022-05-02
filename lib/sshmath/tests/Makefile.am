# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshmath/tests Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

TESTS = t-mathtest t-test-ec t-mathspeed

EXTRA_PROGRAMS = t-mathtest t-test-ec t-mathspeed

EXTRA_DIST = 

noinst_HEADERS = timeit.h

LDADD = ../libsshmath.a ../../sshutil/libsshutil.a
INCLUDES = -I../.. -I. -I.. -I$(srcdir) -I$(srcdir)/.. -I../../sshmath \
  -I$(srcdir)/../../sshmath -I../../sshutil -I$(srcdir)/../../sshutil \
  -I../../zlib -I$(srcdir)/../../zlib

t_mathtest_SOURCES = t-mathtest.c
t_mathtest_DEPENDCIES = $(LDADD)
t_test_ec_SOURCES = t-test-ec.c
t_test_ec_DEPENDCIES = $(LDADD)
t_mathspeed_SOURCES = t-mathspeed.c
t_mathspeed_DEPENDCIES = $(LDADD)

