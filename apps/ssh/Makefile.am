# THIS FILE WAS AUTOMAGICALLY GENERATED FROM Makefile.am.raw 
# You should edit Makefile.am.raw instead of this file. 

## Process this file with automake to produce Makefile.in

#
# ssh2 Makefile.am
#
# Author: Tatu Ylonen <ylo@ssh.fi>
#
# Copyright (c) 1997 SSH Communications Security, Finland
#                    All rights reserved
#

AUTOMAKE_OPTIONS = 1.0 foreign dist-zip no-dependencies

etcdir = @ETCDIR@

bin_PROGRAMS = ssh2 \
	       scp2 \
	       sftp2 \
	       sftp-server2 \
               ssh-agent2 \
	       ssh-keygen2 \
	       @CONFPROGRAMS@ \
	       ssh-add2

sbin_PROGRAMS = sshd2
EXTRA_PROGRAMS = ssh-askpass2
man_MANS = ssh2.1 \
	   sshd2.8 \
	   ssh-keygen2.1 \
	   ssh-add2.1 \
	   ssh-agent2.1 \
	   scp2.1 \
	   sftp2.1

EXTRA_DIST = test-in-host test-analyze-compilation test-analyze-check \
  test-analyze-self-test sshd2_config ssh2_config $(MANS)

noinst_HEADERS = auths-passwd.h readpass.h ssh2includes.h \
	sshauthmethods.h sshclient.h sshcommon.h \
	sshconfig.h sshserver.h sshstdiofilter.h \
	ssh2version.h sshuserfiles.h authc-pubkey.h authc-passwd.h \
	sshagentint.h sshagent.h auths-pubkey.h sshchx11.h sshchagent.h \
	sshchssh1agent.h sshchsession.h sshchtcpfwd.h \
	sshglob.h sshagentcache.h auths-common.h

noinst_LIBRARIES = libssh2.a

INCLUDES = -I. -I$(srcdir) -I../.. -I$(srcdir) -I../../include \
	   -I$(top_builddir) -I$(top_srcdir) \
	   -I$(srcdir)/../../include 

LDADD = -L. -L../../lib -lssh2 -lssh
DEPENDENCIES = ./libssh2.a ../../lib/libssh.a

libssh2_a_SOURCES = agentclient.c sshchagent.c sshserver.c \
		    agentpath.c sshchsession.c sshstdiofilter.c \
		    authc-passwd.c sshchssh1agent.c sshunixconfig.c \
		    authc-pubkey.c sshchtcpfwd.c sshunixuserfiles.c \
		    auths-passwd.c sshchx11.c sshuserfiles.c \
		    auths-pubkey.c sshclient.c \
		    sshcommon.c readpass.c sshconfig.c \
		    sshauthmethodc.c sshauthmethods.c \
		    sshglob.c sshagentcache.c auths-common.c

ssh2_SOURCES = ssh2.c
ssh2_DEPENDENCIES = $(DEPENDENCIES)

sshd2_SOURCES = sshd2.c
sshd2_DEPENDENCIES = $(DEPENDENCIES)

ssh_agent2_SOURCES = ssh-agent2.c
ssh_agent2_DEPENDENCIES = $(DEPENDENCIES)


ssh_add2_SOURCES = ssh-add2.c
ssh_add2_DEPENDENCIES = $(DEPENDENCIES)

ssh_askpass2_SOURCES = ssh-askpass2.c 
ssh_askpass2_LDADD = $(LDADD) $(X_LIBS) $(X_PRE_LIBS) -lX11

ssh_keygen2_SOURCES = ssh-keygen2.c
ssh_keygen2_DEPENDENCIES = $(DEPENDENCIES) ../../lib/sshreadline/libsshreadline.a
ssh_keygen2_LDADD = $(LDADD) -L../../lib/sshreadline -lsshreadline

scp2_SOURCES = scp2.c
scp2_DEPENDENCIES = $(DEPENDENCIES)

sftp2_SOURCES = sftp2.c 
sftp2_DEPENDENCIES = $(DEPENDENCIES) ../../lib/sshreadline/libsshreadline.a
sftp2_LDADD = $(LDADD) -L../../lib/sshreadline -lsshreadline

sftp_server2_SOURCES = sftp-server2.c
sftp_server2_DEPENDENCIES = $(DEPENDENCIES)

# defines

SSH_DEFS = -DHOST_KEY_FILE=\"$(HOST_KEY_FILE)\" -DHOST_CONFIG_FILE=\"$(HOST_CONFIG_FILE)\" -DSERVER_CONFIG_FILE=\"$(SERVER_CONFIG_FILE)\" -DSSH_PROGRAM=\"$(SSH_PROGRAM)\" -DETCDIR=\"$(etcdir)\" -DSSH_BINDIR=\"$(bindir)\" -DTIS_MAP_FILE=\"$(TIS_MAP_FILE)\"

COMPILE = $(CC) $(KERBEROS_INCS) $(INCLUDES) $(SSH_DEFS) $(DEFS) $(CPPFLAGS) $(CFLAGS) $(X_CFLAGS)

includes:

make-install-dirs:
	-if test '!' -d $(DESTDIR)$(etcdir)/ssh2; then mkdir -p $(DESTDIR)$(etcdir)/ssh2; fi

generate-host-key:
	-@if test -f $(DESTDIR)$(etcdir)/ssh2/hostkey; \
	  then echo "You already have a host key in $(DESTDIR)$(etcdir)/ssh2/hostkey"; \
	else \
	    umask 022; echo "Generating 1024 bit host key."; \
	    ./ssh-keygen2 -P -b 1024 -t dsa -c "1024-bit dsa hostkey" -o $(DESTDIR)$(etcdir)/ssh2/hostkey; \
	  fi

install-symlinks:
	-mv -f $(DESTDIR)$(bindir)/ssh $(DESTDIR)$(bindir)/ssh.old
	-mv -f $(DESTDIR)$(bindir)/ssh-agent $(DESTDIR)$(bindir)/ssh-agent.old
	-mv -f $(DESTDIR)$(bindir)/ssh-add $(DESTDIR)$(bindir)/ssh-add.old
	-mv -f $(DESTDIR)$(bindir)/ssh-askpass $(DESTDIR)$(bindir)/ssh-askpass.old
	-mv -f $(DESTDIR)$(bindir)/ssh-keygen $(DESTDIR)$(bindir)/ssh-keygen.old
	-mv -f $(DESTDIR)$(bindir)/scp $(DESTDIR)$(bindir)/scp.old
	-mv -f $(DESTDIR)$(bindir)/sftp $(DESTDIR)$(bindir)/sftp.old
	-mv -f $(DESTDIR)$(bindir)/sftp-server $(DESTDIR)$(bindir)/sftp-server.old
	(cd $(DESTDIR)$(bindir) && $(LN_S) ssh2 ssh)
	(cd $(DESTDIR)$(bindir) && $(LN_S) ssh-agent2 ssh-agent)
	(cd $(DESTDIR)$(bindir) && $(LN_S) ssh-add2 ssh-add)
	(cd $(DESTDIR)$(bindir) && $(LN_S) ssh-askpass2 ssh-askpass)
	(cd $(DESTDIR)$(bindir) && $(LN_S) ssh-keygen2 ssh-keygen)
	(cd $(DESTDIR)$(bindir) && $(LN_S) scp2 scp)
	(cd $(DESTDIR)$(bindir) && $(LN_S) sftp2 sftp)
	(cd $(DESTDIR)$(bindir) && $(LN_S) sftp-server2 sftp-server)
	-mv -f $(DESTDIR)$(sbindir)/sshd $(DESTDIR)$(sbindir)/sshd.old
	(cd $(DESTDIR)$(sbindir) && $(LN_S) sshd2 sshd)
	-mv -f $(DESTDIR)$(mandir)/man1/ssh.1 $(DESTDIR)$(mandir)/man1/ssh.old.1
	-mv -f $(DESTDIR)$(mandir)/man1/ssh-add.1 $(DESTDIR)$(mandir)/man1/ssh-add.old.1
	-mv -f $(DESTDIR)$(mandir)/man1/ssh-agent.1 $(DESTDIR)$(mandir)/man1/ssh-agent.old.1
	-mv -f $(DESTDIR)$(mandir)/man1/ssh-keygen.1 $(DESTDIR)$(mandir)/man1/ssh-keygen.old.1
	-mv -f $(DESTDIR)$(mandir)/man1/scp.1 $(DESTDIR)$(mandir)/man1/scp.old.1
	-mv -f $(DESTDIR)$(mandir)/man1/sftp.1 $(DESTDIR)$(mandir)/man1/sftp.old.1
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) ssh2.1 ssh.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) ssh-add2.1 ssh-add.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) ssh-agent2.1 ssh-agent.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) ssh-keygen2.1 ssh-keygen.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) scp2.1 scp.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) sftp2.1 sftp.1)
	-mv -f $(DESTDIR)$(mandir)/man8/sshd.8 $(DESTDIR)$(mandir)/man8/sshd.old.8
	(cd $(DESTDIR)$(mandir)/man8 && $(LN_S) sshd2.8 sshd.8)

clean-up-old:
	 -rm -f $(DESTDIR)$(bindir)/ssh.old $(DESTDIR)$(bindir)/ssh-agent.old \
	 $(DESTDIR)$(bindir)/ssh-add.old $(DESTDIR)$(bindir)/ssh-askpass.old  \
	 $(DESTDIR)$(bindir)/ssh-keygen.old $(DESTDIR)$(bindir)/scp.old	  \
	 $(DESTDIR)$(bindir)/sftp.old $(DESTDIR)$(bindir)/sftp-server.old     \
	 $(sbindir)/sshd.old 
	 -rm -f $(DESTDIR)$(mandir)/man1/ssh-add.old.1 $(DESTDIR)$(mandir)/man1/ssh.old.1   \
	 $(DESTDIR)$(mandir)/man1/ssh-agent.old.1 $(DESTDIR)$(mandir)/man1/ssh-keygen.old.1	\
	 $(DESTDIR)$(mandir)/man1/scp.old.1 $(DESTDIR)$(mandir)/man1/sftp.old.1             \
	 $(DESTDIR)$(mandir)/man8/sshd.old.8

install-data-hook: make-install-dirs generate-host-key install-symlinks
	-@if test '!' -f $(DESTDIR)$(etcdir)/ssh2/sshd2_config ; then \
	 echo Installing $(DESTDIR)$(etcdir)/ssh2/sshd2_config ; \
	 $(INSTALL_DATA) $(srcdir)/sshd2_config $(DESTDIR)$(etcdir)/ssh2/sshd2_config ; \
	fi
	-@if test '!' -f $(DESTDIR)$(etcdir)/ssh2/ssh2_config ; then \
	 echo Installing $(DESTDIR)$(etcdir)/ssh2/ssh2_config ; \
	 $(INSTALL_DATA) $(srcdir)/ssh2_config $(DESTDIR)$(etcdir)/ssh2/ssh2_config ; \
	fi
