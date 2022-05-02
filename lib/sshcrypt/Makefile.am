# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshcrypt Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests

bin_PROGRAMS = ssh-keygen

noinst_LIBRARIES = libsshcrypt.a

libsshcrypt_a_SOURCES = \
  genhash.c \
  md5.c \
  sha.c \
  ripemd160.c \
  \
  genmac.c \
  hmac.c \
  macs.c \
  \
  genciph.c \
  nociph.c \
  des.c \
  arcfour.c \
#ifdef SSHDIST_CRYPT_MARS
  mars.c \
#endif SSHDIST_CRYPT_MARS
  \
  genpkcs.c \
  genmp.c \
  dlglue.c \
  dlfix.c \
  \
  \
  bufzip.c \
  \
  genaux.c \
  genrand.c \
  namelist.c \
  keyblob.c \
  libmonitor.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshcrypt_a_OBJECTS) $(libsshcrypt_a_LIBADD) :END_FILE_LIST

include_HEADERS = \
  sshcrypt.h \
  namelist.h \
  keyblob.h \
  sshcrypti.h \
  sshrotate.h \
  sha.h \
  md5.h \
  ripemd160.h \
  des.h \
  arcfour.h \
#ifdef SSHDIST_CRYPT_MARS
  mars.h \
#endif SSHDIST_CRYPT_MARS
#ifdef SSHDIST_CRYPT_SKIPJACK
#
#endif SSHDIST_CRYPT_SKIPJACK
#ifdef SSHDIST_CRYPT_HMAC
  hmac.h \
#endif SSHDIST_CRYPT_HMAC
#ifdef SSHDIST_CRYPT_SSHMACS
  macs.h \
#endif SSHDIST_CRYPT_SSHMACS
#ifdef SSHDIST_CRYPT_GENPKCS
  genmp.h \
#endif SSHDIST_CRYPT_GENPKCS
#ifdef SSHDIST_CRYPT_RSA
#
#endif SSHDIST_CRYPT_RSA
#ifdef SSHDIST_CRYPT_ECP
#
#
#endif SSHDIST_CRYPT_ECP
#ifdef SSHDIST_CRYPT_EC2N
#
#
#endif SSHDIST_CRYPT_EC2N
#ifdef SSHDIST_CRYPT_RSA
#
#endif SSHDIST_CRYPT_RSA
#ifdef SSHDIST_CRYPT_DL
  dlglue.h \
  dlfix.h \
#endif SSHDIST_CRYPT_DL
#ifdef SSHDIST_CRYPT_COMPRESS
  bufzip.h \
#endif SSHDIST_CRYPT_COMPRESS
#ifdef SSHDIST_CRYPT_COMPRESS_LZS
#
#endif SSHDIST_CRYPT_COMPRESS_LZS
  libmonitor.h


noinst_HEADERS = \
  nociph.h \
  timeit.h

libsshcrypt_a_LIBADD = @CRYPTO_CONF_OBJS@
libsshcrypt_a_DEPENDENCIES = @CRYPTO_CONF_OBJS@

EXTRA_DIST = \
  sshcrypt.h
# the sshcrypt.h above is a kludge; otherwise something handles the last
# backquote wrong

SUFFIXES = .S .s
CLEANFILES = tmp-*.s

LDADD = libsshcrypt.a \
../sshutil/libsshutil.a ../sshmath/libsshmath.a
INCLUDES = -I../.. -I. -I$(srcdir) -I../sshutil -I$(srcdir)/../sshutil \
	-I../sshmath -I$(srcdir)/../sshmath -I../zlib -I$(srcdir)/../zlib \
	-I../sshscard -I$(srcdir)/../sshscard \
	-I../trq -I$(srcdir)/../trq

ssh_keygen_SOURCES = ssh-keygen.c 
ssh_keygen_LDADD = libsshcrypt.a \
../sshutil/libsshutil.a \
  ../zlib/libz.a \
  ../sshmath/libsshmath.a
.s.o:
	$(CC) -c $(CFLAGS) $(SFLAGS) $<

.S.o:
	$(CPP) $(CPPFLAGS) $(INCLUDES) $(DEFS) $< | grep -v '^#' >tmp-$*.s
	$(CC) $(CFLAGS) $(SFLAGS) -c tmp-$*.s
	mv tmp-$*.o $@
	rm -f tmp-$*.s

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
