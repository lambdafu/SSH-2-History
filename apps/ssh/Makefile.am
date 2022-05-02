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

etcdir = /etc

bin_PROGRAMS = ssh2 scp2 sftp2 sftp-server2 \
               ssh-agent2 ssh-keygen2 ssh-add2 @CONFPROGRAMS@
sbin_PROGRAMS = sshd2
EXTRA_PROGRAMS = ssh-askpass2
man_MANS = ssh2.1 sshd2.8 ssh-keygen2.1 ssh-add2.1 ssh-agent2.1 scp2.1 sftp2.1

EXTRA_DIST = test-in-host test-analyze-compilation test-analyze-check \
  test-analyze-self-test sshd2_config ssh2_config $(MANS)

noinst_HEADERS = auths-passwd.h readpass.h signals.h ssh2includes.h \
	sshauthmethods.h sshclient.h sshcommon.h \
	sshconfig.h sshserver.h sshstdiofilter.h \
	ssh2version.h sshuserfiles.h authc-pubkey.h authc-passwd.h \
	sshagentint.h sshagent.h auths-pubkey.h sshchx11.h sshchagent.h \
	sshchssh1agent.h sshchsession.h sshchtcpfwd.h

INCLUDES = -I. -I$(srcdir) -I../.. -I$(srcdir) -I../../include \
	   -I$(srcdir)/../../include 

LDADD = -L../../lib -lssh
DEPENDENCIES = ../../lib/libssh.a

ssh2_SOURCES = ssh2.c sshauthmethodc.c readpass.c sshunixuserfiles.c \
	       sshuserfiles.c \
	       sshchx11.c sshchsession.c sshchagent.c sshchssh1agent.c \
	       sshchtcpfwd.c sshstdiofilter.c \
       	       sshcommon.c sshconfig.c sshunixconfig.c sshclient.c \
	       agentpath.c authc-pubkey.c authc-passwd.c agentclient.c

ssh2_DEPENDENCIES = $(DEPENDENCIES)

sshd2_SOURCES = sshd2.c signals.c sshauthmethods.c auths-passwd.c \
		auths-pubkey.c sshunixuserfiles.c \
	        sshuserfiles.c \
	        sshchx11.c sshchsession.c sshchagent.c sshchssh1agent.c \
	        sshchtcpfwd.c \
		sshcommon.c sshconfig.c sshunixconfig.c sshserver.c \
                agentpath.c 

sshd2_DEPENDENCIES = $(DEPENDENCIES)

ssh_agent2_SOURCES = ssh-agent2.c agentpath.c sshunixuserfiles.c \
	             sshuserfiles.c \
                     sshconfig.c sshunixconfig.c 
ssh_agent2_DEPENDENCIES = $(DEPENDENCIES)

ssh_add2_SOURCES = ssh-add2.c agentclient.c agentpath.c \
		   sshuserfiles.c \
	           sshunixuserfiles.c readpass.c sshconfig.c sshunixconfig.c 
ssh_add2_DEPENDENCIES = $(DEPENDENCIES)

ssh_askpass2_SOURCES = ssh-askpass2.c 
ssh_askpass2_LDADD = $(LDADD) $(X_LIBS) $(X_PRE_LIBS) -lX11

ssh_keygen2_SOURCES = readpass.c ssh-keygen2.c sshunixuserfiles.c \
	              sshuserfiles.c \
		      sshconfig.c sshunixconfig.c 

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
	-if test '!' -d $(etcdir)/ssh2; then mkdir $(etcdir)/ssh2; fi

generate-host-key:
	-@if test -f $(etcdir)/ssh2/hostkey; \
	  then echo "You already have a host key in $(etcdir)/ssh2/hostkey"; \
	else \
	    umask 022; echo "Generating 1024 bit host key."; \
	    ./ssh-keygen2 -P -b 1024 -t dsa -c "1024-bit dsa hostkey" -o $(etcdir)/ssh2/hostkey; \
	  fi

install-symlinks:
	rm -f $(bindir)/ssh $(bindir)/ssh-agent $(bindir)/ssh-add
	rm -f $(bindir)/ssh-askpass $(bindir)/ssh-keygen $(bindir)/scp
	rm -f $(bindir)/sftp $(bindir)/sftp-server
	(cd $(bindir) && $(LN_S) ssh2 ssh)
	(cd $(bindir) && $(LN_S) ssh-agent2 ssh-agent)
	(cd $(bindir) && $(LN_S) ssh-add2 ssh-add)
	(cd $(bindir) && $(LN_S) ssh-askpass2 ssh-askpass)
	(cd $(bindir) && $(LN_S) ssh-keygen2 ssh-keygen)
	(cd $(bindir) && $(LN_S) scp2 scp)
	(cd $(bindir) && $(LN_S) sftp2 sftp)
	(cd $(bindir) && $(LN_S) sftp-server2 sftp-server)
	rm -f $(sbindir)/sshd
	(cd $(sbindir) && $(LN_S) sshd2 sshd)
	rm -f $(mandir)/man1/ssh.1 $(mandir)/man1/ssh-add.1
	rm -f $(mandir)/man1/ssh-agent.1 $(mandir)/man1/ssh-keygen.1
	rm -f $(mandir)/man1/scp.1 $(mandir)/man1/sftp.1
	(cd $(mandir)/man1 && $(LN_S) ssh2.1 ssh.1)
	(cd $(mandir)/man1 && $(LN_S) ssh-add2.1 ssh-add.1)
	(cd $(mandir)/man1 && $(LN_S) ssh-agent2.1 ssh-agent.1)
	(cd $(mandir)/man1 && $(LN_S) ssh-keygen2.1 ssh-keygen.1)
	(cd $(mandir)/man1 && $(LN_S) scp2.1 scp.1)
	(cd $(mandir)/man1 && $(LN_S) sftp2.1 sftp.1)
	rm -f $(mandir)/man8/sshd.8
	(cd $(mandir)/man8 && $(LN_S) sshd2.8 sshd.8)

install-data-hook: make-install-dirs generate-host-key install-symlinks
	-@if test '!' -f $(etcdir)/ssh2/sshd2_config ; then \
	 echo Installing $(etcdir)/ssh2/sshd2_config ; \
	 $(INSTALL_DATA) $(srcdir)/sshd2_config $(etcdir)/ssh2/sshd2_config ; \
	fi
	-@if test '!' -f $(etcdir)/ssh2/ssh2_config ; then \
	 echo Installing $(etcdir)/ssh2/ssh2_config ; \
	 $(INSTALL_DATA) $(srcdir)/ssh2_config $(etcdir)/ssh2/ssh2_config ; \
	fi
