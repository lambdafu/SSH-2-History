/*

  ssh2d.c
  
  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#include "ssh2includes.h"
#include "sshunixptystream.h"
#include "sshtcp.h"
#include "signals.h"
#include "sshunixfdstream.h"
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshtimeouts.h"
#include "sshserver.h"
#include "sshconfig.h"
#include "sshcipherlist.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshmsgs.h"
#include "sigchld.h"
#include <syslog.h>

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;
#endif /* LIBWRAP */

#define SSH_DEBUG_MODULE "Sshd2"

/* Program name, without path. */
const char *av0;

typedef struct SshServerData
{
  SshConfig config;
  SshRandomState random_state;
  SshPrivateKey private_server_key;
  Boolean debug;
  SshTcpListener listener;
  SshUser user;
  Boolean ssh_fatal_called;
} *SshServerData;

typedef struct SshServerConnectionRec
{
  SshServerData shared;
  SshServer server;
} *SshServerConnection;

void server_disconnect(int reason, const char *msg, void *context)
{
  SshServerConnection c = context;

  switch(reason)
    {
    case SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
      ssh_log_event(SSH_LOGFACILITY_SECURITY, SSH_LOG_NOTICE,
		    "Disallowed connect from denied host. '%s'",
		    msg);
      break;
    case SSH_DISCONNECT_PROTOCOL_ERROR:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_SECURITY,
		      SSH_LOG_INFORMATIONAL,
		      "Protocol error: '%s'", msg);
      break;
    case SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL, 
		      "Key exchange failed: '%s'", msg);
      break;
    case SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "Host authentication failed: '%s'", msg);
      break;
    case SSH_DISCONNECT_MAC_ERROR:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "MAC failed, disconnecting: '%s'", msg);
      break;
    case SSH_DISCONNECT_COMPRESSION_ERROR:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "compression error, disconnecting: '%s'", msg);
      break;
    case SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "service not available: '%s'", msg);
      break;
    case SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "protocol version not supported: '%s'", msg);
      break;
    case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "host key not verifiable: '%s'", msg);
      break;
    case SSH_DISCONNECT_CONNECTION_LOST:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "connection lost: '%s'", msg);
      break;
    case SSH_DISCONNECT_BY_APPLICATION:
      if(c->shared->config->fascist_logging)
	ssh_log_event(SSH_LOGFACILITY_AUTH,
		      SSH_LOG_INFORMATIONAL,
		      "disconnected by application: '%s'", msg);	
      break;
    case SSH_DISCONNECT_AUTHENTICATION_ERROR:
      ssh_log_event(SSH_LOGFACILITY_AUTH, SSH_LOG_NOTICE,
		    "User authentication failed: '%s'",
		    msg);
      break;
    default:
      ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR,
		    "Unknown reason code for disconnect. msg: '%s'",
		    msg);
      ssh_debug("Unknown reason code for disconnect. msg: '%s'", msg);
      break;
    }

  /* Destroy the server object. */
  ssh_server_destroy(c->server);
  memset(c, 'F', sizeof(*c));
  ssh_xfree(c);
}

void server_debug(int type, const char *msg, void *context)
{
  ssh_debug("server_debug: %s", msg);
}

#if 0
/* Create a private server key if configuration says us to do that
   (i.e. we'll be using RSA key exchange) */

SshPrivateKey generate_server_key(SshConfig config, SshRandomState rs)
{
  SshPrivateKey privkey;

  if (config->server_key_bits == 0)
    return NULL;
  
  if (ssh_private_key_generate(rs, 
			       &privkey,
			       config->server_key_type,
			       SSH_PKF_SIZE, config->server_key_bits,
			       SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      ssh_fatal("Unable to generate %d - bit %s server key.", 
		config->server_key_bits,
		config->server_key_type);
    }

  return privkey;
}
#endif /* 0 */

/* Checks the remote version number, and execs a compatibility program as
   appropriate. */

void ssh_server_version_check(const char *version, void *context)
{
  SshServerConnection c = (SshServerConnection)context;
  char *args[100], *aa;
  char buf[200];
  int i, arg;
  extern char **environ;
  
  ssh_debug("Remote version: %s\n", version);
  
  if (strncmp(version, "SSH-1.", 6) == 0 &&
      strncmp(version, "SSH-1.99", 8) != 0 &&
      c->server->config->ssh1compatibility == TRUE &&
      c->server->config->ssh1_path != NULL &&
      c->server->config->ssh1_args != NULL)
    {
      ssh_debug("Executing %s for ssh1 compatibility.",
		c->server->config->ssh1_path);
      
      arg = 0;
      args[arg++] = "sshd";
      args[arg++] = "-i";
      args[arg++] = "-V";
      snprintf(buf, sizeof(buf), "%s\n", version); /* add newline */
      args[arg++] = buf;
      for (i = 1; c->server->config->ssh1_args[i]; i++)
	{
	  if (arg >= sizeof(args)/sizeof(args[0]) - 2)
	    ssh_fatal("Too many arguments for compatibility ssh1.");
	  aa = c->server->config->ssh1_args[i];
	  if (strcmp(aa, "-f") == 0 ||
	      strcmp(aa, "-b") == 0 ||
	      strcmp(aa, "-g") == 0 ||
	      strcmp(aa, "-h") == 0 ||
	      strcmp(aa, "-k") == 0 ||
	      strcmp(aa, "-p") == 0)
	    {
	      args[arg++] = aa;
	      if (c->server->config->ssh1_args[i + 1])
		args[arg++] = c->server->config->ssh1_args[++i];
	    }
	  else
	    if (strcmp(aa, "-d") == 0)
	      {
		args[arg++] = aa;
		if (c->server->config->ssh1_args[i + 1])
		  i++; /* Skip the level. */
	      }
	    else
	      if (strcmp(aa, "-q") == 0 ||
		  strcmp(aa, "-i") == 0)
		args[arg++] = aa;
	}
      args[arg++] = NULL;

      /* Set the input file descriptor to be fd 0. */
      if (c->server->config->ssh1_fd != 0)
	{
	  if (dup2(c->server->config->ssh1_fd, 0) < 0)
	    ssh_fatal("Making ssh1 input fd 0 (dup2) failed: %s",
		      strerror(errno));
	  if (dup2(c->server->config->ssh1_fd, 1) < 0)
	    ssh_fatal("Making ssh1 input fd 1 (dup2) failed: %s",
		      strerror(errno));
	  close(c->server->config->ssh1_fd);
	}
      
      /* Exec the ssh1 server. */
      execve(c->server->config->ssh1_path, args, environ);
      ssh_fatal("Executing ssh1 in compatibility mode failed.");
    }
}

/* This function is called whenever we receive a new connection. */

void new_connection_callback(SshIpError error, SshStream stream,
			     void *context)
{
  SshServerData data = context;
  SshServerConnection c;
  pid_t ret;
  const char *s;
  
  if (error != SSH_IP_NEW_CONNECTION)
    {
      ssh_warning("new_connection_callback: unexpected error %d", (int)error);
      return;
    }

  ssh_debug("new_connection_callback");

  /* Fork to execute the new child, unless in debug mode. */
  if (data->debug)
    ret = 0;
  else
    ret = fork();
  if (ret == 0)
    {
      /* Child. */

      /* Destroy the listener. */
      if (data->listener)
	ssh_tcp_destroy_listener(data->listener);

      data->listener = NULL;

      /* Save the file descriptor.  It is only used if we exec ssh1 for
	 compatibility mode. */
      data->config->ssh1_fd = ssh_stream_fd_get_readfd(stream);
      
#ifdef HAVE_LIBWRAP
  {
    struct request_info req;
    void *old_handler;
    
    old_handler = signal(SIGCHLD, SIG_DFL);
		
    request_init(&req, RQ_DAEMON, av0, RQ_FILE, ssh_stream_fd_get_readfd(stream), NULL);
    fromhost(&req); /* validate client host info */
    if (!hosts_access(&req))
      {
	ssh_warning("Denied connection from %s by tcp wrappers.", eval_client(&req));
	ssh_log_event(SSH_LOGFACILITY_SECURITY, SSH_LOG_NOTICE,
		      "Denied connection from %s by tcp wrappers.", eval_client(&req));
	refuse(&req); /* If connection is not allowed, clean up and exit. */
      }

    signal(SIGCHLD, old_handler);
    
  }
#endif /* HAVE_LIBWRAP */
  
      /* Create a context structure for the connection. */
      c = ssh_xcalloc(1, sizeof(*c));
      c->shared = data;
      c->server = ssh_server_wrap(stream, data->config, data->random_state,
				  data->private_server_key, server_disconnect,
				  server_debug,
				  (data->config->ssh1compatibility &&
				   data->config->ssh1_path != NULL) ?
				  ssh_server_version_check : NULL,
				  (void *)c);
    }
  else
    {
      /* Parent */
      if (ret == -1)
	{
	  s = "Forking a server for a new connection failed.";
	  ssh_warning(s);
	  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_WARNING, s);
	  ssh_stream_write(stream, (const unsigned char *)s, strlen(s));
	  ssh_stream_write(stream, (const unsigned char *)"\r\n", 2);
	}
      ssh_stream_fd_mark_forked(stream);
      ssh_stream_destroy(stream);

      /* Stir the random state so that future connections get a
         different seed. */
      ssh_random_stir(data->random_state);

      /* Update the random seed file on disk. */
      ssh_randseed_update(data->user, data->random_state, data->config);
    }

  ssh_debug("new_connection_callback returning");
}

void server_ssh_debug(const char *msg, void *context)
{
  SshServerData data = (SshServerData)context;

  if (data->config && data->config->quiet_mode)
    return;

  if (data->debug)
    fprintf(stderr, "debug: %s\r\n", msg);
}

void server_ssh_warning(const char *msg, void *context)
{
  SshServerData data = (SshServerData)context; 

  if (data->config && data->config->quiet_mode)
    return;

  fprintf(stderr, "WARNING: %s\r\n", msg);
}

void server_ssh_fatal(const char *msg, void *context)
{
  SshServerData data = (SshServerData)context;
  data->ssh_fatal_called = TRUE;

  ssh_log_event(SSH_LOGFACILITY_DAEMON, SSH_LOG_ERROR, "FATAL ERROR: %s", 
		msg);

  fprintf(stderr, "FATAL: %s\r\n", msg);  
  exit(255);
}

/* Helper functions for server_ssh_log */
int ssh_log_severity(SshLogSeverity severity)
{
  switch(severity)
    {
    case SSH_LOG_INFORMATIONAL:
      return LOG_INFO;
    case SSH_LOG_NOTICE:
      return LOG_NOTICE;
    case SSH_LOG_WARNING:
      return LOG_WARNING;
    case SSH_LOG_ERROR:
      return LOG_ERR;
    case SSH_LOG_CRITICAL:
      return LOG_CRIT;
    }
  
  ssh_debug("ssh_log_severity: Unknown severity.");
  return -1;
}

int ssh_log_facility(SshLogFacility facility)
{
  switch (facility)
    {
    case SSH_LOGFACILITY_AUTH:
    case SSH_LOGFACILITY_SECURITY:
      return LOG_AUTH;
    case SSH_LOGFACILITY_DAEMON:
      return LOG_DAEMON;
    case SSH_LOGFACILITY_USER:
      return LOG_USER;
    case SSH_LOGFACILITY_MAIL:
      return LOG_MAIL;
    }
  ssh_debug("ssh_log_facility: Unknown facility.");
  return -1;
}

/* This is the logging callback */

void server_ssh_log(SshLogFacility facility, SshLogSeverity
		    severity, const char *msg, void *context)
{
  SshServerData data = (SshServerData)context; 
  SshConfig config = data->config;
  int fac, sev;
  static int logopen = 0;
  static int logopt;
  static int logfac;

  if (! logopen)
    {
      logopt = LOG_PID;
#ifdef LOG_PERROR
      if (config->verbose_mode)
	logopt |= LOG_PERROR;
#endif /* LOG_PERROR */
      logfac = LOG_DAEMON;

      openlog(av0, logopt, logfac);
      logopen = 1;
    }

  /* Configuring for QuietMode and FascistLogging is an 'apparent
     user error', but if FascistLogging is enabled, we log
     everything. ssh_fatal()s are also logged.
     */
  if ((!config->quiet_mode || config->fascist_logging) || 
      data->ssh_fatal_called)
    {
      fac = ssh_log_facility(facility);
      sev = ssh_log_severity(severity);
      if( fac != -1 && sev != -1)
	{
	  syslog(((fac != logfac) ? fac : 0) | sev, "%s", msg);
#ifndef LOG_PERROR
	  /* Print it also to stderr. XXX */
#endif /* LOG_PERROR */
	}
    }
}

/* check whether parameter with options is correctly specified */

Boolean parameter_defined(const char param, int num, char **elements)
{
  int optidx;
  
  for (optidx = 1; optidx < num ; optidx++)
    {
      if (elements[optidx][0] == '-' || elements[optidx][0] == '+')
	if (elements[optidx][1] == param)
	  if (elements[optidx + 1][0] != '-' && elements[optidx + 1][0] != '+')
	    return TRUE;
    }
  
  return FALSE;
}

/*
 *
 *  SSH2 server main()
 *
 */

int main(int argc, char **argv)
{
  int i, ac;
  char *oarg, **av;
  Boolean flagvalue;
  SshServerData data;
  SshUser user;
  char config_fn[1024];
  char pidfile[100];
  FILE *f;

  /* Save program name. */
  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];

  /* Initializations */

#if HAVE_OSF1_C2_SECURITY
  /* this is still very heavily under construction. */
  tcbc2_initialize_security(argc, argv);
#endif /* HAVE_OSF1_C2_SECURITY */
  
  ssh_split_arguments(argc, argv, &ac, &av);
  
  data = ssh_xcalloc(1, sizeof(*data));
  user = ssh_user_initialize(NULL, TRUE);
  
  data->ssh_fatal_called = FALSE;

  /* Create config context. */
  data->config = ssh_server_create_config();

  /* Register debug, fatal, and warning callbacks. */
  ssh_debug_register_callbacks(server_ssh_fatal, server_ssh_warning,
			       server_ssh_debug, (void *)data);
  
  /* Register log callback */
  ssh_log_register_callback(server_ssh_log, (void *)data);

  /* If -d is the first flag, we set debug level here.  It is reset
     later, but something may be lost, if we leave it 'til that. */
  if ((ac >= 3) && (strcmp("-d", av[1]) == 0))
    {
      ssh_debug_set_level_string(av[2]);
      if (strcmp("0", av[2]) != 0)
	data->debug = TRUE;
      else
	data->debug = FALSE;
    }
  else if ((ac >= 2) && (strcmp("-v", av[1]) == 0))
    {
      ssh_debug_set_level_string("2");
      data->debug = TRUE;
    }

  ssh_event_loop_initialize();
  
  /* Save command line options for ssh1 compatibility code. */
  data->config->ssh1_args = argv;

  /* Save information about current user. */
  data->user = user;
  
  /* Prevent core dumps to avoid revealing sensitive information. */
  signals_prevent_core(data);
  ssh_register_signal(SIGPIPE, NULL, NULL);

  /* Register SIGCHLD signal handler, to kill those darn zombies */

  ssh_sigchld_initialize();
  
  /* Read the standard server configuration file. if one wasn't specified
     on the commandline. */
  if (!parameter_defined('f', argc, argv))
    {
      snprintf(config_fn, sizeof(config_fn), "%s/%s",
	       ssh_userdir(user, TRUE), SSH_SERVER_CONFIG_FILE);
      if (!ssh_config_read_file(user, data->config, NULL, config_fn, NULL))
	ssh_warning("%s: Failed to read config file %s", av0, config_fn);
    }
  
  /* Parse the command line parameters. */ 
  for (i = 1; i < ac; i++)
    {
      if ((i + 1) < ac)
	oarg = av[i+1];
      else
	oarg = NULL;
      
      /* Do we have a flag here ? */

      if ((av[i][0] == '-' || av[i][0] == '+') && strlen(av[i]) == 2)
        {
          flagvalue = (av[i][0] == '-');
          
          switch (av[i][1])
            {
	      /* Debug mode */
	    case 'd':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -d parameter (need debug level).",
			  av0);
	      data->config->verbose_mode = flagvalue;
	      ssh_debug_set_level_string(oarg);
	      i++;
	      break;

	      /* Verbose mode (= -d 2) */
	    case 'v':
	      data->config->verbose_mode = TRUE;
	      ssh_debug_set_level_string("2");
	      break;

	      /* An additional configuration file */
	    case 'f':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -f parameter.", av0);
	      strncpy(config_fn, oarg, sizeof(config_fn));
	      if (!ssh_config_read_file(user, data->config, NULL, config_fn, NULL))
		ssh_warning("%s: Failed to read config file %s", av0,
			    config_fn);
	      i++;
	      break;
	  
	      /* Specify the login grace period */
	    case 'g':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -g parameter.", av0);	      
	      data->config->login_grace_time = atoi(oarg);
	      if (data->config->login_grace_time < 1)
		ssh_fatal("%s: Illegal login grace time %s seconds",
			  av0, oarg);
	      i++;
	      break;
	      
	      /* specify the host key file */
	    case 'h':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -h parameter.", av0);	      

	      ssh_xfree(data->config->host_key_file);
	      data->config->host_key_file = ssh_xstrdup(oarg);
	      ssh_xfree(data->config->public_host_key_file);
	      snprintf(config_fn, sizeof(config_fn), "%s.pub", 
		       data->config->host_key_file);
	      data->config->public_host_key_file = ssh_xstrdup(config_fn);
	      i++;
	      break;

	      /* is inetd enabled ? */
	    case 'i':
	      data->config->inetd_mode = flagvalue;
	      break;
	      
	      /* Give one line of configuration data directly */
	    case 'o':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -o parameter.", av0);
	      ssh_config_parse_line(data->config, oarg);	      
	      i++;
	      break;
	      
	      /* Specify the port */
	    case 'p':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -p parameter.", av0);	      
	      
	      ssh_xfree(data->config->port);
	      data->config->port = ssh_xstrdup(oarg);
	      i++;
	      break;

	      /* Quiet mode */
	    case 'q':
	      data->config->quiet_mode = flagvalue;
	      break;

	    default:
	      fprintf(stderr, "%s: unknown option -%c\n", av0, av[i][1]);
	      exit(1);
	    }
	}
    }

  data->debug = data->config->verbose_mode;
    
  /* load the host key */
  
  if (!ssh_server_load_host_key(data->config, 
				&(data->config->private_host_key),
				&(data->config->public_host_key_blob),
				&(data->config->public_host_key_blob_len),
				NULL))
    {
      ssh_fatal("Unable to load the host keys");
    }

  /* load the random seed */
  data->random_state = ssh_randseed_open(user, data->config);

#if 0
  /* read the server key (if needed) */ 
  data->private_server_key = generate_server_key(data->config, 
						 data->random_state);
#endif /* 0 */
 
  ssh_debug("Becoming server.");
  
  /* Check if we are being called from inetd. */
  if (data->config->inetd_mode)
    {
      SshStream stream;

      /* We are being called from inetd.  Take stdio to be the connection
	 and proceed with the new connection. */
      stream = ssh_stream_fd_stdio();
      ssh_debug("processing stdio connection");
      new_connection_callback(SSH_IP_NEW_CONNECTION, stream, (void *)data);
      ssh_debug("got_connection returned");
    }
  else
    {
      /* Start as daemon. */

      ssh_debug("Creating listener");
      data->listener = ssh_tcp_make_listener(data->config->listen_address, 
					     data->config->port, 
					     new_connection_callback,
					     (void *)data);
      if (data->listener == NULL)
	ssh_fatal("Creating listener failed: port %s probably already in use!",
		  data->config->port);
      ssh_debug("Listener created");

      /* If not debugging, fork into background. */
      if (!data->debug)
	{
#ifdef HAVE_DAEMON
	  if (daemon(0, 0) < 0)
	    ssh_fatal("daemon(): %.100s", strerror(errno));
#else /* HAVE_DAEMON */
#ifdef TIOCNOTTY
	  int fd;
#endif /* TIOCNOTTY */
	  /* Running as a daemon; fork to background. */
	  if (fork() != 0)
	    {
	      /* Parent */
	      exit(0);
	    }
	  
	  /* Redirect stdin, stdout, and stderr to /dev/null. */
	  freopen("/dev/null", "r", stdin);
	  freopen("/dev/null", "w", stdout);
	  freopen("/dev/null", "w", stderr);
	    
	  /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
	  fd = open("/dev/tty", O_RDWR|O_NOCTTY);
	  if (fd >= 0)
	    {
	      (void)ioctl(fd, TIOCNOTTY, NULL);
	      close(fd);
	    }
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
#ifdef ultrix
	  setpgrp(0, 0);
#else /* ultrix */
	  if (setsid() < 0)
	    ssh_fatal("setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON */
	}
    }

  /* Save our process id in the pid file. */
  snprintf(pidfile, sizeof(pidfile), "/var/run/sshd2_%s.pid",
	   data->config->port);
  SSH_DEBUG(5, ("Trying to create pidfile %s", pidfile));
  f = fopen(pidfile, "w");
  if (f == NULL)
    {
      snprintf(pidfile, sizeof(pidfile), ETCDIR "/ssh2/sshd2_%s.pid",
	       data->config->port);
      SSH_DEBUG(5, ("Trying to create pidfile %s", pidfile));
      f = fopen(pidfile, "w");
    }
  if (f != NULL)
    {
      SSH_DEBUG(5, ("Writing pidfile %s", pidfile));
      fprintf(f, "%ld\n", (long)getpid());
      fclose(f);
    }
  
  ssh_debug("Running event loop");
  ssh_event_loop_run();
  
  signals_reset();
  
  ssh_debug("Exiting event loop");
  ssh_event_loop_uninitialize();

  for (i = 0; i < ac; i++)
    ssh_xfree(av[i]);
  ssh_xfree(av);
  
  if (data->listener)
    remove(pidfile);
  
  return 0;
}
