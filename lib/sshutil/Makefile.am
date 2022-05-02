# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# lib/sshutil Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1996 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

SUBDIRS = tests
CONFOBJS = @LIBOBJS@

noinst_LIBRARIES = libsshutil.a

libsshutil_a_SOURCES = \
	bufaux.c		\
	sshbuffer.c		\
	sshunixeloop.c		\
	sshunixfdstream.c	\
	match.c			\
	mpaux.c			\
	sshgetput.c		\
	signals.c		\
	sshtcp.c		\
	sshunixtcp.c		\
	sshstream.c		\
	sshdebug.c		\
	sshenum.c		\
	sshencode.c		\
	sshsocks.c		\
	sshunixlocalstream.c	\
	sshstreampair.c		\
	sshfilterstream.c	\
	base64.c		\
	sshutf8.c		\
	sshfilexferc.c		\
	sshfilexfers.c		\
	sshfilexferi.c		\
	sshunixrealpath.c	\
	sshurl.c		\
	sshinet.c		\
	cstack.c		\
	vlint32.c		\
	crc32.c			\
	filelock.c		\
	sshpacketwrapper.c	\
	sshpacketstream.c	\
	sshpacketimpl.c		\
	sshmalloc.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshutil_a_OBJECTS) $(libsshutil_a_LIBADD) :END_FILE_LIST
libsshutil_a_LIBADD = $(CONFOBJS)
libsshutil_a_DEPENDENCIES = $(CONFOBJS)

include_HEADERS = \
	sshincludes.h		\
	sshstream.h		\
	sshtimeouts.h		\
	snprintf.h		\
	sshunixeloop.h		\
	sshgetput.h		\
	signals.h		\
	sshdebug.h		\
	bufaux.h		\
	sshbuffer.h		\
	sshenum.h		\
	sshencode.h		\
	sshunixfdstream.h	\
	sshstreampair.h		\
	sshtcp.h		\
	sshsocks.h		\
	match.h			\
	mpaux.h			\
	sshfilterstream.h	\
	base64.h		\
	sshutf8.h		\
	sshlocalstream.h	\
	sshfilexfer.h		\
	sshurl.h		\
	sshinet.h		\
	cstack.h		\
	vlint32.h		\
	crc32.h			\
	filelock.h		\
	sshpacketstream.h	\
	sshmalloc.h

noinst_HEADERS = sshpacketint.h sshfilexferi.h

EXTRA_DIST = \
	memmove.c memset.c putenv.c random.c remove.c snprintf.c   \
	strcasecmp.c strerror.c strncasecmp.c crypt.c sshwindist.h

INCLUDES = -I../.. -I. -I$(srcdir) 		\
	-I../sshmath -I$(srcdir)/../sshmath 	\
	-I../zlib -I$(srcdir)/../zlib 		\
	-I../trq -I$(srcdir)/../trq

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
