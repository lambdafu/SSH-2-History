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

libsshutil_a_SOURCES = bufaux.c sshbuffer.c cflexer.c \
		  cparser.c crc32.c sshunixeloop.c sshunixfdstream.c \
		  globals.c mpaux.c nspace.c sshgetput.c filelock.c \
		  signals.c sshtcp.c sshunixtcp.c sshstream.c \
		  sshdebug.c sshenum.c sshencode.c \
		  vlint32.c sshmalloc.c sshsocks.c \
		  sshstreampair.c  sshunixdevicestream.c \
		  sshunixlocalstream.c sshunixtcplocalstream.c \
		  sshfilterstream.c mapping.c sshudp.c sshunixudp.c cstack.c \
		  base64.c sshutf8.c cmalloc.c ber.c asn1.c \
		  sshpacketstream.c sshpacketimpl.c sshpacketwrapper.c \
		  psystem.c match.c \
		  sshfilexferc.c sshfilexfers.c sshfilexferi.c \
		  sshunixrealpath.c sshurl.c sshinet.c \
		  sshtimemeasure.c sshdllist.c sshunixserial.c \
		  sshgenutils.c

list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshutil_a_OBJECTS) $(libsshutil_a_LIBADD) :END_FILE_LIST
libsshutil_a_LIBADD = $(CONFOBJS)
libsshutil_a_DEPENDENCIES = $(CONFOBJS)

include_HEADERS = sshincludes.h sshstream.h sshtimeouts.h snprintf.h \
		  sshmalloc.h sshunixeloop.h sshdevicestream.h \
                  sshgetput.h signals.h sshdebug.h vlint32.h \
		  filelock.h globals.h \
		  bufaux.h sshbuffer.h crc32.h sshenum.h \
		  cflexer.h cparser.h nspace.h mpaux.h sshencode.h \
		  sshunixfdstream.h sshtcp.h sshsocks.h sshstreampair.h \
		  sshfilterstream.h mapping.h sshudp.h \
		  base64.h sshutf8.h cstack.h sshpacketstream.h \
                  cmalloc.h ber.h asn1.h psystem.h match.h sshlocalstream.h \
		  sshfilexfer.h sshurl.h sshinet.h \
		  sshtimemeasure.h sshdllist.h sshgenutils.h sshserialstream.h

noinst_HEADERS = sshpacketint.h sshfilexferi.h

EXTRA_DIST = memmove.c memset.c putenv.c random.c remove.c snprintf.c \
		strcasecmp.c strerror.c strncasecmp.c crypt.c sshwindist.h

INCLUDES = -I../.. -I. -I$(srcdir) -I../sshmath -I$(srcdir)/../sshmath -I../zlib -I$(srcdir)/../zlib -I../trq

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file ; \
	done
