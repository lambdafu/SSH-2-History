## Process this file with automake to produce Makefile.in

#
# lib/sshsession Makefile.am
#
# Author: Tero Kivinen <kivinen@ssh.fi>
#
# Copyright (c) 1997 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

noinst_LIBRARIES = libsshsession.a
include_HEADERS = sshunixpipestream.h sshunixptystream.h sigchld.h tty.h \
	ttymodes.h \
	sshsessionincludes.h sshuser.h tcbc2.h
noinst_HEADERS = pty-int.h

libsshsession_a_SOURCES = sshunixpipestream.c sshunixptystream.c sigchld.c \
	tty.c sshunixuser.c wtmp.c
list_libssh_a_objects:
	@echo BEGIN_FILE_LIST: $(libsshsession_a_OBJECTS) $(libsshsession_a_LIBADD) :END_FILE_LIST

libsshsession_a_DEPENDENCIES = $(SSHSESSION_CONFOBJS)
libsshsession_a_LIBADD = $(SSHSESSION_CONFOBJS)

EXTRA_DIST = tcbc2.c pty-bsd.c pty-cray.c pty-getpseudotty.c pty-getpty.c \
	pty-openpty.c pty-ptmx.c pty-pts.c pty-sco.c

INCLUDES = -I../.. -I. -I$(srcdir) -I../sshutil -I$(srcdir)/../sshutil

includes:
	for file in $(include_HEADERS); do \
		$(COPY_INCLUDE) $(srcdir)/$$file ../../include/$$file; \
	done
