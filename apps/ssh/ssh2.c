/*

  ssh2.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#include "ssh2includes.h"
#include "sshclient.h"
#include "sshunixptystream.h"
#include "tty.h"
#include "signals.h"
#include "sshtimeouts.h"
#include "sshfilterstream.h"
#include "sshtcp.h"
#include "sshunixfdstream.h"
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "sshmsgs.h"
#include "sshuser.h"
#include "sshconfig.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshstdiofilter.h"

#define SSH_DEBUG_MODULE "Ssh2"

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#include <syslog.h>
#ifdef NEED_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif /* NEED_SYS_SYSLOG_H */
int allow_severity = SSH_LOG_INFORMATIONAL;
int deny_severity = SSH_LOG_WARNING;
#endif /* LIBWRAP */

/* Program name, without path. */
const char *av0;
SshRandomState random_state;

void client_disconnect(int reason, const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;

  ssh_debug("client_disconnect: %s", msg);

  switch(reason)
    {
    case SSH_DISCONNECT_CONNECTION_LOST:
      ssh_warning("\r\nDisconnected; connection lost.");
      break;
    case SSH_DISCONNECT_BY_APPLICATION:
      ssh_warning("\r\nDisconnected by application.");
      break;
    case SSH_DISCONNECT_PROTOCOL_ERROR:
      ssh_warning("\r\nDisconnected; protocol error.");
      break;
    case SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:
      ssh_warning("\r\nDisconnected; service not available.");
      break;
    case SSH_DISCONNECT_MAC_ERROR:
      ssh_warning("\r\nDisconnected; MAC error.");
      break;
    case SSH_DISCONNECT_COMPRESSION_ERROR:
      ssh_warning("\r\nDisconnected; compression error.");
      break;
    case SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:
      ssh_warning("\r\nDisconnected; host not allowed to connect.");
      break;
    case SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED:
      ssh_warning("\r\nDisconnected; host authentication failed.");
      break;
    case SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED:
      ssh_warning("\r\nDisconnected; protocol version not supported.");
      break;
    case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:
      ssh_warning("\r\nDisconnected; host key not verifiable.");
      break;
    case SSH_DISCONNECT_AUTHENTICATION_ERROR:
      ssh_warning("\r\nDisconnected; authentication error.");
      break;
    case SSH_DISCONNECT_KEY_EXCHANGE_FAILED:
      ssh_warning("\r\nDisconnected; key exchange failed.");
      break;
    default:
      ssh_warning("\r\nDisconnected; unknown disconnect code %d (message: %s).",
		  reason, msg);
      break;      
    }
  
  ssh_client_destroy(data->client);
  data->client = NULL;
}

void client_debug(int type, const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;
  
  switch (type)
    {
    case SSH_DEBUG_DEBUG:
      if (data->debug)
	fprintf(stderr, "%s\r\n", msg);
      break;
      
    case SSH_DEBUG_DISPLAY:
      fprintf(stderr, "%s\r\n", msg);
      break;
      
    default:
      fprintf(stderr, "UNKNOWN DEBUG DATA TYPE %d: %s\r\n", type, msg);
      break;
    }
  clearerr(stderr); /*XXX*/
}

void client_ssh_debug(const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;

  if(data->config->quiet_mode)
    return;

  if (data->debug)
    fprintf(stderr, "debug: %s\r\n", msg);
  clearerr(stderr); /*XXX*/
}

void client_ssh_warning(const char *msg, void *context)
{
  SshClientData data = (SshClientData)context;
  if(data->config->quiet_mode)
    return;

  fprintf(stderr, "%s\r\n", msg);
}

void client_ssh_fatal(const char *msg, void *context)
{
  fprintf(stderr, "FATAL: %s\r\n", msg);
  ssh_leave_non_blocking();
  ssh_leave_raw_mode();
  exit(255);
}

void session_close(void *context)
{
  SshClientData data = (void *)context;
  int ret = 0;
  SshCommon common = data->client->common;

  /* We save the number of channels, because if nm_channels is 0 we
     eventually destroy the common structure, and using
     common->num_channels later would be an error. */
  unsigned int num_channels = common->num_channels;
  
  ssh_debug("session_close");

  if (num_channels == 0)
    {      
      if (data->client)
	{
	  ssh_debug("destroying client struct...");
	  ssh_client_destroy(data->client);
	  data->client = NULL;
	}
    }

  ssh_leave_non_blocking();
  ssh_leave_raw_mode();
  
  /* If there are forwarded channels open, we fork to background to wait
     for them to complete. */
  if (num_channels != 0)
    {
      ssh_debug("Forking... parent pid = %d", getpid());
      
      ret = fork();
      if (ret == -1)
	{
	  ssh_warning("Fork failed.");
	}
      else if (ret != 0)
	{
	  exit(0);
	}
      ssh_debug("num_channels now %d", common->num_channels);
      ssh_warning("ssh2[%d]: number of forwarded channels still "
		  "open, forked to background to wait for completion.",
		  getpid());

#ifdef HAVE_DAEMON
      if (daemon(0, 1) < 0)
	ssh_fatal("daemon(): %.100s", strerror(errno));
#else /* HAVE_DAEMON */
#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
	ssh_fatal("setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON*/
    }
}

int ssh_stream_sink_filter(SshBuffer *data,
			   size_t offset,
			   Boolean eof_received,
			   void *context)
{
  size_t received_len;

  received_len = ssh_buffer_len(data) - offset;

  ssh_buffer_consume(data, received_len);

  return SSH_FILTER_ACCEPT(0);
}

void ssh_stream_sink_filter_destroy(void *context)
{
  ssh_leave_raw_mode();
  return;
}

void client_authenticated(const char *user, void *context)
{
  int ret = 0;
  SshClientData data = (SshClientData)context;
  SshStream filtered_stdio_stream;
#ifdef SSH_CHANNEL_TCPFWD
  SshForward fwd;
#endif /* SSH_CHANNEL_TCPFWD */
  
  ssh_debug("client_authenticated");

  /* XXX does this need something more? is this in the right place? */
  if(data->config->go_background)
    {
      ret = fork();
      if (ret == -1)
	{
	  ssh_warning("Fork failed.");
	}
      else if (ret != 0)
	{
	  exit(0);
	}
      data->allocate_pty = FALSE;
      data->config->dont_read_stdin = TRUE;
      
#ifdef HAVE_DAEMON
	  if (daemon(0, 1) < 0)
	    ssh_fatal("daemon(): %.100s", strerror(errno));
#else /* HAVE_DAEMON */
#ifdef HAVE_SETSID
#ifdef ultrix
      setpgrp(0, 0);
#else /* ultrix */
      if (setsid() < 0)
	ssh_fatal("setsid: %.100s", strerror(errno));
#endif /* ultrix */
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON*/
    }
  
#ifdef SSH_CHANNEL_TCPFWD  
  for (fwd = data->config->local_forwards; fwd; fwd = fwd->next)
    if (!ssh_client_local_tcp_ip_forward(data->client, fwd->local_addr,
					 fwd->port, fwd->connect_to_host,
					 fwd->connect_to_port))
      ssh_warning("Local TCP/IP forwarding for port %s failed.",
		  fwd->port);

  for (fwd = data->config->remote_forwards; fwd; fwd = fwd->next)
    ssh_client_remote_tcp_ip_forward(data->client, fwd->local_addr,
				     fwd->port, fwd->connect_to_host,
				     fwd->connect_to_port,
				     NULL, NULL);  
#endif /* SSH_CHANNEL_TCPFWD */

  if (data->config->dont_read_stdin)
    {
      freopen("/dev/null", "r", stdin);
    }

  if (data->no_session_channel == FALSE)
    {
      /* XXX */
      if ((data->config->escape_char != NULL) && isatty(fileno(stdin)))
	filtered_stdio_stream = 
	  ssh_stream_filter_create(ssh_stream_fd_stdio(), 
				   1024, 
				   ssh_stdio_output_filter,
				   ssh_stdio_input_filter,
				   ssh_stdio_filter_destroy,
				   (void *)data->config->escape_char);
      else 
	filtered_stdio_stream = ssh_stream_fd_stdio();
    }
  else
    {
      filtered_stdio_stream = 
	ssh_stream_filter_create(ssh_stream_fd_stdio(), 
				 1024, 
				 ssh_stdio_output_filter,
				 ssh_stdio_input_filter,
				 ssh_stdio_filter_destroy,
				 (void *)data->config->escape_char);
      filtered_stdio_stream = 
	ssh_stream_filter_create(filtered_stdio_stream, 
				 1024, 
				 ssh_stream_sink_filter,
				 ssh_stream_sink_filter,
				 ssh_stream_sink_filter_destroy,
				 NULL);
      ssh_enter_raw_mode();
    }

  ssh_client_start_session(data->client, 
			   ((data->no_session_channel == FALSE) ?
			    filtered_stdio_stream :
			    NULL),
			   ((data->no_session_channel == FALSE) ?
			    ssh_stream_fd_wrap2(-1, 2, FALSE):
			    NULL),
			   TRUE,
			   data->is_subsystem, 
			   data->command, data->allocate_pty,
			   data->term, (const char **)data->env,
			   data->forward_x11,
			   data->forward_agent,
			   NULL, session_close, (void *)data);
}

void connect_done(SshIpError error, SshStream stream, void *context)
{
  SshClientData data = (SshClientData)context;

  if (error != SSH_IP_OK)
    ssh_fatal(ssh_tcp_error_string(error));
  
  /* Save the file descriptor for ssh1 compatibility code. */
  data->config->ssh1_fd = ssh_stream_fd_get_readfd(stream);
  
  data->client = ssh_client_wrap(stream, data->config,
				 data->user_data, data->config->host_to_connect, 
				 data->config->login_as_user,
				 data->random_state,
				 client_disconnect, client_debug,
				 client_authenticated, (void *)data);

  /* This is done, because in ssh_common_* functions we don't know anything
     about the SshClient* structures. no_session_channel's value must
     however be known there.*/
  data->client->common->no_session_channel = data->no_session_channel;
}

static char *str_concat_3(char *s1, char *s2, char *s3)
{
  int l1 = strlen(s1), l2 = strlen(s2), l3 = strlen(s3);
  char *r = ssh_xmalloc(l1 + l2 + l3 + 1);

  strcpy(r, s1);
  strcpy(&(r[l1]), s2);
  strcpy(&(r[l1 + l2]), s3);

  return r;
}

static char *replace_in_string(char *str, char *src, char *dst)
{
  char *hlp1, *hlp2;

  str = ssh_xstrdup(str);

  if ((dst == NULL) || ((*dst) == '\000') || 
      (src == NULL) || ((*src) == '\000') ||
      ((hlp1 = strstr(str, src)) == NULL))
    return str;
    
  *hlp1 = '\000';
  hlp2 = str_concat_3(str, dst, &(hlp1[strlen(src)]));
  ssh_xfree(str);
  hlp1 = replace_in_string(hlp2, src, dst);
  ssh_xfree(hlp2);

  return hlp1;
}

static void finalize_password_prompt(char **prompt, char *host, char *user)
{
  char *tmp;

  tmp = replace_in_string(*prompt, "%H", (host != NULL) ? host : "");
  ssh_xfree(*prompt);
  *prompt = tmp;
  tmp = replace_in_string(*prompt, "%U", (user != NULL) ? user : "");
  ssh_xfree(*prompt);
  *prompt = tmp;
}

void ssh2_version(const char *name)
{
  fprintf(stderr, "%s: ", name);
#ifdef SSHDIST_F_SECURE_COMMERCIAL

#endif /* SSHDIST_F_SECURE_COMMERCIAL */
  fprintf(stderr, "SSH Version %s\n", SSH2_VERSION);
}

void ssh2_help(const char *name)
{
  ssh2_version(name);
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: %s [options] host [command]\n", name);
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -l user     Log in using this user name.\n");
  fprintf(stderr, "  -n          Redirect input from /dev/null.\n");
  fprintf(stderr, "  +a          Enable authentication agent forwarding.\n");
  fprintf(stderr, "  -a          Disable authentication agent forwarding.\n");
  fprintf(stderr, "  +x          Enable X11 connection forwarding.\n");
  fprintf(stderr, "  -x          Disable X11 connection forwarding.\n");
  fprintf(stderr, "  -i file     Identity file for public key authentication\n");
  fprintf(stderr, "  -F file     Read an alternative configuration file.\n");
  fprintf(stderr, "  -t          Tty; allocate a tty even if command is given.\n");
  fprintf(stderr, "  -v          Verbose; display verbose debugging messages.  Equal to `-d 2'\n");
  fprintf(stderr, "  -d level    Set debug level.\n");
  fprintf(stderr, "  -V          Display version number only.\n");
  fprintf(stderr, "  -q          Quiet; don't display any warning messages.\n");
  fprintf(stderr, "  -f          Fork into background after authentication.\n");
  fprintf(stderr, "  -e char     Set escape character; ``none'' = disable (default: ~).\n");
  fprintf(stderr, "  -c cipher   Select encryption algorithm. Multiple -c options are \n");
  fprintf(stderr, "              allowed and a single -c flag can have only one cipher.\n");
  fprintf(stderr, "  -p port     Connect to this port.  Server must be on the same port.\n");
  fprintf(stderr, "  -P          Don't use priviledged source port.\n");
  fprintf(stderr, "  -S          Don't request a session channel. \n");
  fprintf(stderr, "  -L listen-port:host:port   Forward local port to remote address\n");
  fprintf(stderr, "  -R listen-port:host:port   Forward remote port to local address\n");
  fprintf(stderr, "              These cause ssh to listen for connections on a port, and\n");
  fprintf(stderr, "              forward them to the other side by connecting to host:port.\n");
  fprintf(stderr, "  +C          Enable compression.\n");
  fprintf(stderr, "  -C          Disable compression.\n");
  fprintf(stderr, "  -o 'option' Process the option as if it was read from a configuration file.\n");
  fprintf(stderr, "  -h          Display this help.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Command can be either:\n");
  fprintf(stderr, "  remote_command [arguments] ...    Run command in remote host.\n");
  fprintf(stderr, "  -s service                        Enable a service in remote server.\n");
  fprintf(stderr, "\n");
}

/* This function digs out the first non-option parameter, ie. the host to 
   connect to.
*/

/* If you add options with parameters, add it here, too. */
#define OPTIONS_WITH_ARGUMENTS "liFdecpLRo"

char *ssh_get_host_name(int num, char ** elements)
{
  int optidx;

  for (optidx = 1; optidx < num ; optidx++)
    {
      if (elements[optidx][0] == '-' || elements[optidx][0] == '+')
	{
	  if ( strchr(OPTIONS_WITH_ARGUMENTS, elements[optidx][1]))
	    {
	      optidx++;
	    }
	  continue;
	}
      return elements[optidx];
    }

  return NULL;
}


/*
 * 
 *  SSH2 main
 * 
 */

int main(int argc, char **argv)
{
  char *oarg;
  int i, len, ac;
  char *host, *user, *userdir, *command, *socks_server, **av;
  SshClientData data;
  SshUser tuser;
  Boolean flagvalue;  
  char temp_s[1024], *temp_p;
  int have_c_arg;

  have_c_arg = 0;
  /* Save program name. */
  if (strchr(argv[0], '/'))
    av0 = strrchr(argv[0], '/') + 1;
  else
    av0 = argv[0];
  
  /* Initializations. */
  tuser = ssh_user_initialize(NULL, FALSE);
  user = ssh_xstrdup(ssh_user_name(tuser));
  data = ssh_xcalloc(1, sizeof(*data));
  ssh_event_loop_initialize();
  
  /* Initialize config with built-in defaults. */
  data->config = ssh_client_create_config();
  data->is_subsystem = FALSE;
  data->no_session_channel = FALSE;
  data->exit_status = 0;
  
  /* Split argv (and modify argc) to get rid of problems with
     options. (ex. -p22222 didn't work, but -p 22222 did.*/

  ssh_split_arguments(argc, argv, &ac, &av);
  
  /* Save arguments for ssh1 compatibility. */
  data->config->ssh1_args = argv;
  
  /* Register debug, fatal, and warning callbacks. */
  ssh_debug_register_callbacks(client_ssh_fatal, client_ssh_warning,
			       client_ssh_debug, (void *)data);
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
  else if (((ac >= 2) && ((strcmp("-v", av[1]) == 0) || 
			    (strcmp("-h", av[1]) == 0))) || (ac == 1))
    {
      if (ac <= 2)
	{
	  ssh2_help(av0);
	  exit(0);
	}
      else
	{
	  ssh_debug_set_level_string("2");
	  data->debug = TRUE;
	}
    }
  else if ((ac >= 2) && (strcmp("-V", av[1]) == 0))
    {
      ssh2_version(av0);
      exit(0);
    }
  
  /* Prevent core dumps from revealing sensitive information. */
  signals_prevent_core(data);
  ssh_register_signal(SIGPIPE, NULL, NULL);
  
  /* Try to read the global configuration file */
  ssh_config_read_file(tuser, data->config, NULL,
		       SSH_CLIENT_GLOBAL_CONFIG_FILE, NULL);

  host = NULL;
  
  host = ssh_get_host_name(ac, av);

  if (host)
    {
      data->config->host_to_connect = ssh_xstrdup(host);
    }
  else
    {
      ssh_warning("You didn't specify a host name.\n");
      ssh2_help(av0);
      exit(0);
    }
  
  ssh_debug("hostname is '%s'.", data->config->host_to_connect);

  /* Try to read in the user configuration file. */

  userdir = ssh_userdir(tuser, TRUE);
  snprintf(temp_s, sizeof (temp_s), "%s/%s",
	   userdir, SSH_CLIENT_CONFIG_FILE);
  ssh_xfree(userdir);

  ssh_config_read_file(tuser, data->config, data->config->host_to_connect, 
		       temp_s, NULL);
  
  if (data->config->login_as_user)
    {
      ssh_xfree(user);
      user = data->config->login_as_user;
    }

  host = NULL;
  command = NULL;
  
  /* Interpret the command line parameters. */
  for (i = 1; i < ac; i++)
    {
      if ((i + 1) < ac)
	oarg = av[i+1];
      else
	oarg = NULL;

      /* Do we seem to have a flag here ? */
      
      if ((av[i][0] == '-' || av[i][0] == '+') && strlen(av[i]) == 2)
	{
	  flagvalue = (av[i][0] == '-');
	  
	  switch (av[i][1])
	    {
	      
	      /* Forward agent */
	    case 'a':
	      data->config->forward_agent = !(flagvalue);
	      break;

	      /* add a cipher name to the list */
	    case 'c':	      
	      {
		char *cname;

		if (oarg == NULL || flagvalue == FALSE)
		  ssh_fatal("%s: Illegal -c parameter.", av0);
	      
		cname = ssh_cipher_get_native_name(oarg);

		if (cname == NULL)
		  ssh_fatal("%s: Cipher %s is not supported.", av0, oarg);
		
		if (!have_c_arg)
		  {
		    have_c_arg = 1;
		    if (data->config->ciphers != NULL)
		      {
			ssh_xfree(data->config->ciphers);
			data->config->ciphers = NULL;
		      }
		  }
		if (data->config->ciphers == NULL)
		  {
		    data->config->ciphers = ssh_xstrdup(cname);
		  }
		else
		  {                                 
		    char *hlp = str_concat_3(data->config->ciphers, 
					     ",", 
					     cname);
		    ssh_xfree(data->config->ciphers);
		    data->config->ciphers = hlp;
		  }
	      }
	    SSH_DEBUG(3, ("Cipherlist is \"%s\"", data->config->ciphers));
	    i++;
	    break;

	    /* Compression */
	    case 'C':
	      data->config->compression = !(flagvalue);
	      break;

	      /* Verbose mode */
	    case 'v':
	      data->config->verbose_mode = TRUE;
	      ssh_debug_set_level_string("2");
	      break;

	      /* Debug level. */
	    case 'd':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: bad -d parameter.", av0);
	      data->config->verbose_mode = flagvalue;
	      ssh_debug_set_level_string(oarg);
	      i++;
	      break;

	      /* specify escape character */
	    case 'e':
	      if (flagvalue == TRUE)
		{
		  ssh_xfree(data->config->escape_char);
		  data->config->escape_char = NULL;
		  break;
		}
 	      
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -e parameter.", av0);

	      ssh_xfree(data->config->escape_char);	      
	      data->config->escape_char = ssh_xstrdup(oarg);
	      i++;
	      break;

	      /* a "go background" flag */
	    case 'f':
	      data->config->go_background = flagvalue;
	      break;
	      
	      /* read in an alternative configuration file */
	    case 'F':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -F parameter.", av0);
	      
	      if (!ssh_config_read_file(tuser, data->config, 
					data->config->host_to_connect, 
					oarg, NULL))
		ssh_fatal("%s: Failed to read config file %s", av0, oarg);
	      i++;
	      break;

	      /* specify the identity file */
	    case 'i':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -i parameter.", av0);
	      ssh_xfree(data->config->identity_file);
	      data->config->identity_file = ssh_xstrdup(oarg);
	      i++;
	      break;
	      
	      /* specify a login name */
	    case 'l':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -l parameter.", av0);

	      ssh_xfree(data->config->login_as_user);
	      data->config->login_as_user = ssh_xstrdup(oarg);
	      user = data->config->login_as_user;
	      i++;
	      break;

#ifdef SSH_CHANNEL_TCPFWD
	      /* Specify a local forwarding */
	    case 'L':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -L parameter.", av0);

	      if(ssh_parse_forward(&(data->config->local_forwards), oarg))
		  ssh_fatal("Bad local forward definition \"%s\"",oarg);
	      i++;
	      break;
#endif /* SSH_CHANNEL_TCPFWD */

	      /* don't read stdin ? */
	    case 'n':
	      data->config->dont_read_stdin = flagvalue;
	      break;
	      
	      /* Give one line of configuration data directly. */
	    case 'o':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -o parameter.", av0);
	      
	      ssh_config_parse_line(data->config, oarg);	      
	      i++;
	      break;
	      
	      /* specify the login port */
	    case 'p':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -p parameter.", av0);
	      ssh_xfree(data->config->port);
	      data->config->port = ssh_xstrdup(oarg);
	      i++;
	      break;
	      
	      /* use priviledged port ? */
	    case 'P':
	      data->config->use_nonpriviledged_port = flagvalue;
	      break;

	      /* quiet mode */
	    case 'q':
	      data->config->quiet_mode = flagvalue;
	      break;
	      
	      /* Is this a subsystem ? */
	    case 's':
	      data->is_subsystem = flagvalue;
	      break;

	    case 'S':
	      data->no_session_channel = flagvalue;
	      break;

	      /* Force ptty allocation ? */
	    case 't':
	      data->config->force_ptty_allocation = flagvalue;
	      break;

       	      /* X11 forwarding */
	    case 'x':
	      data->config->forward_x11 = !(flagvalue);
	      break;

#ifdef SSH_CHANNEL_TCPFWD
	      /* Specify a remote forwarding */
	    case 'R':
	      if (oarg == NULL || flagvalue == FALSE)
		ssh_fatal("%s: Illegal -R parameter.", av0);   

	      if(ssh_parse_forward(&(data->config->remote_forwards), oarg))
		  ssh_fatal("Bad remote forward definition \"%s\"",oarg);
	      i++;
	      break;
#endif /* SSH_CHANNEL_TCPFWD */
	    case 'h':
	      ssh2_help(av0);
	      break;

	      /* Option unrecognized. */
	    default:
	      fprintf(stderr, "%s: unknown option -%c\n", av0, av[i][1]);
	      exit(1);
	    }
	}
      else
	{
	  /* The first non-flag argument should be the host name. */
	  if (host == NULL)
	    {
	      host = av[i];
	    }
	  else
	    {
	      if (command == NULL)
		{
		  command = ssh_xstrdup(av[i]);
		}
	      else
		{
		  len = strlen(command) + strlen(av[i]) + 2;
		  temp_p = ssh_xmalloc(len);
		  snprintf(temp_p, len, "%s %s", command, av[i]);
		  ssh_xfree(command);
		  command = temp_p;		  
		}	      
	    } 
	}
    }

  
  if (host == NULL)
    ssh_fatal("%s: No host name given.", av0);

  /* Initializations */

  
  data->config->login_as_user = user;
  host = data->config->host_to_connect;

  finalize_password_prompt(&data->config->password_prompt, host, user);

  data->random_state = ssh_randseed_open(tuser, data->config);

  data->user_data = tuser;
  if (command != NULL && strlen(command) < 1)
    {
      ssh_xfree(command);
      command = NULL;
    }  
  data->command = command;
  data->allocate_pty = (command == NULL);      
  data->forward_x11 = data->config->forward_x11;
  data->forward_agent = data->config->forward_agent;  
  
  if ((data->term = getenv("TERM")) == NULL)
    data->term = ssh_xstrdup("vt100");
  else
    data->term = ssh_xstrdup(data->term);    

  data->env = NULL;
  data->debug = data->config->verbose_mode;

  /* Figure out the name of the socks server, if any.  It can specified
     at run time using the SSH_SOCKS_SERVER environment variable, or at
     compile time using the SOCKS_DEFAULT_SERVER define.  The environment
     variable overrides the compile-time define. */
  socks_server = getenv("SSH_SOCKS_SERVER");
#ifdef SOCKS_DEFAULT_SERVER
  if (!socks_server)
    socks_server = SOCKS_DEFAULT_SERVER;
#endif /* SOCKS_DEFAULT_SERVER */
  if (socks_server && strcmp(socks_server, "") == 0)
    socks_server = NULL;
  
  /* Connect to the remote host. */
  ssh_debug("connecting to %s...", host);
  ssh_tcp_connect_with_socks(host, data->config->port, 
			     socks_server, 5, 
			     connect_done, (void *)data);
  
  ssh_debug("entering event loop");
  ssh_event_loop_run();

  signals_reset();

  /* Update random seed file. */
  ssh_randseed_update(tuser, data->random_state, data->config);
  
  ssh_debug("uninitializing event loop");

  ssh_event_loop_uninitialize();
  ssh_user_free(tuser, FALSE);

  for(i = 0; i < ac; i++)
    ssh_xfree(av[i]);
  ssh_xfree(av);
  
  /* XXX free user, command, host ? */

  /* XXX should be done with static variable, and data should be freed */
  return data->exit_status;
}
