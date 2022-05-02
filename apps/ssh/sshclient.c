/*

  sshclient.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  SSH client functionality for processing a connection.  Most of the
  implementation is actually shared with the server (in sshcommon.c).

*/

#include "ssh2includes.h"
#include "sshtrans.h"
#include "sshauth.h"
#include "sshconn.h"
#include "sshauthmethods.h"
#include "sshcommon.h"
#include "sshclient.h"
#include "sshuserfiles.h"
#include "sshmsgs.h"
#include "sshcipherlist.h"

#ifdef SSH_CHANNEL_SESSION
#include "sshchsession.h"
#endif /* SSH_CHANNEL_SESSION */

#ifdef SSH_CHANNEL_TCPFWD
#include "sshchtcpfwd.h"
#endif /* SSH_CHANNEL_TCPFWD */

#define SSH_DEBUG_MODULE "Ssh2Client"

/* Callback function that is used to check the validity of the server
   host key.
     `server_name'  The server name as passed in when the protocol
                    was created.  This is expected to be the name that
		    the user typed.
     `blob'	    The linear representation of the public key (including
                    optional certificates).
     `len'          The length of the public key blob.
     `result_cb'    This function must be called when the validity has been
     		    determined.  The argument must be TRUE if the host key
		    is to be accepted, and FALSE if it is to be rejected.
     `result_context' This must be passed to the result function.
     `context'      Context argument.
   This function should call the result callback in every case.  This is not
   allowed to destroy the protocol context.  This function is allowed to
   do basically anything before calling the result callback. */

void ssh_client_key_check(const char *server_name,
			  const unsigned char *blob, size_t len,
			  void (*result_cb)(Boolean result,
					    void *result_context),
			  void *result_context,
			  void *context)
{
  SshClient client;
  char *udir, filen[1024], comment[1024];
  unsigned char *blob2;
  size_t blob2_len;
  int i, j;
  time_t now;
  unsigned long magic;
  struct stat st;

  assert(context != NULL);

  client = (SshClient) context;
 
  if (server_name == NULL || strlen(server_name) == 0)
    {
      ssh_debug("ssh_client_key_check: server_name is NULL or zero-length");
      (*result_cb)(FALSE, result_context);
      return;
    }

  if ((udir = ssh_userdir(client->user_data, TRUE)) == NULL)
    ssh_fatal("ssh_client_key_check: no user directory.");

  snprintf(filen, sizeof(filen)-20, "%s/hostkeys", udir);
  if (stat(filen, &st) < 0)
    {
      if (mkdir(filen, 0700) < 0)
	{
	  ssh_warning("ssh_userdir: could not create user's ssh hostkey" 
		      "directory %s", filen);
        }
    }

  /* produce a file name from the server name */
  snprintf(filen, sizeof(filen)-20, "%s/hostkeys/key_%s_", 
	   udir, client->common->config->port);
  ssh_xfree(udir);
  j = strlen(filen);

  for (i = 0; server_name[i] != '\0'; i++)
    {
      if (j > sizeof(filen) - 10)
	break;

      if (isalpha(server_name[i]))
	{
	  filen[j++] = tolower(server_name[i]);
	  continue;
	}
      if (isdigit(server_name[i]) || server_name[i] == '.' || 
	  server_name[i] == '-')
	{
	  filen[j++] = server_name[i];
	  continue;
	}

      /* escape this character in octal */
      filen[j++] = '_';
      filen[j++] = '0' + (server_name[i] >> 6);
      filen[j++] = '0' + ((server_name[i] >> 3) & 7);
      filen[j++] = '0' + (server_name[i] & 7);
    }
  filen[j] = '\0';
  strcat(filen, ".pub");

  SSH_DEBUG(6, ("key_check: checking %s", filen));

  /* ok, now see if the file exists */
  
  blob2 = NULL;

  magic = ssh_key_blob_read(client->user_data, filen, NULL,
			    &blob2, &blob2_len, NULL);

  switch(magic)
    {
    case SSH_KEY_MAGIC_FAIL:
      ssh_warning("Accepting host %s key without checking.",
		server_name);
      now = time(NULL);
      snprintf(comment, sizeof(comment)-1, 
	       "host key for %s, accepted by %s %s", 
	       server_name, ssh_user_name(client->user_data), ctime(&now));
      comment[strlen(comment)-1] = '\0';

      if (ssh_key_blob_write(client->user_data, filen, 0600,
			     SSH_KEY_MAGIC_PUBLIC,
			     comment, blob, len, NULL))
	ssh_warning("Unable to write host key %s", filen);
      ssh_debug("Host key saved to %s", filen);
      ssh_debug("%s", comment);
      break;
      
    case SSH_KEY_MAGIC_PUBLIC:

      if (blob2_len == len && memcmp(blob, blob2, len) == 0)
	break;

      /* break left out intentionally */

    default:

      ssh_warning("** !! ILLEGAL HOST KEY FOR %s !! **",
		server_name);
      ssh_warning("Remove %s and try again if you think that this is normal.",
		filen);
      /* XXX we throw ssh_fatal here to avoid SIGSEGV at later time. (it's
         most definitely a bug.) */

      ssh_fatal("host key was illegal.");

      memset(blob2, 0, blob2_len);
      ssh_xfree(blob2);

      /* disconnect now */
      (*client->common->disconnect)(SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, 
				    "Illegal host key.", 
				    client->common->context);
      (*result_cb)(FALSE, result_context);
      return;
    }

  if (blob2 != NULL)
    {
      memset(blob2, 0, blob2_len);
      ssh_xfree(blob2);
    }

  ssh_debug("Host key found from the database.");
  (*result_cb)(TRUE, result_context);
}

/* Fetches values for the transport parameters (e.g., encryption algorithms)
   from the config data. */

Boolean ssh_client_update_transport_params(SshConfig config,
					   SshTransportParams params)
{
  char *hlp;

  if (config->ciphers != NULL)
    {
      hlp = ssh_cipher_list_canonialize(config->ciphers);

      if (hlp)
        {
	  ssh_xfree(params->ciphers_c_to_s);
	  params->ciphers_c_to_s = ssh_xstrdup(hlp);
	  ssh_xfree(params->ciphers_s_to_c);
	  params->ciphers_s_to_c = ssh_xstrdup(hlp);
	  ssh_xfree(hlp);
	}
    }

  if (config->compression == TRUE)
    {
      ssh_xfree(params->compressions_c_to_s);
      params->compressions_c_to_s = ssh_xstrdup("zlib");
      ssh_xfree(params->compressions_s_to_c);
      params->compressions_s_to_c = ssh_xstrdup("zlib");
    }

  hlp = ssh_public_key_list_canonialize(params->host_key_algorithms);
  ssh_xfree(params->host_key_algorithms);
  params->host_key_algorithms = hlp;

  hlp = ssh_hash_list_canonialize(params->hash_algorithms);
  ssh_xfree(params->hash_algorithms);
  params->hash_algorithms = hlp;

  return TRUE;
}

/* Checks the remote version number, and execs a compatibility program as
   appropriate. */

void ssh_client_version_check(const char *version, void *context)
{
  SshClient client = (SshClient)context;
  char *args[100], *aa;
  int i, arg;
  extern char **environ;

  ssh_debug("Remote version: %s", version);

  if (strncmp(version, "SSH-1.", 6) == 0 &&
      strncmp(version, "SSH-1.99", 8) != 0 &&
      client->config->ssh1compatibility == TRUE &&
      client->config->ssh1_path != NULL &&
      client->config->ssh1_args != NULL)
    {
      ssh_warning("Executing %s for ssh1 compatibility.",
		client->config->ssh1_path);

      /* Close the old connection to the server. */
      close(client->config->ssh1_fd);

      /* Prepare arguments for the ssh1 client. */
      arg = 0;
      args[arg++] = "ssh";
      for (i = 1; client->config->ssh1_args[i]; i++)
	{
	  if (arg >= sizeof(args)/sizeof(args[0]) - 2)
	    ssh_fatal("Too many arguments for compatibility ssh1.");
	  aa = client->config->ssh1_args[i];
	  if (strcmp(aa, "-l") == 0 ||
	      strcmp(aa, "-i") == 0 ||
	      strcmp(aa, "-e") == 0 ||
	      strcmp(aa, "-c") == 0 ||
	      strcmp(aa, "-p") == 0 ||
	      strcmp(aa, "-R") == 0 ||
	      strcmp(aa, "-o") == 0 ||
	      strcmp(aa, "-L") == 0)
	    {
	      args[arg++] = aa;
	      if (client->config->ssh1_args[i + 1])
		args[arg++] = client->config->ssh1_args[++i];
	    }
	  else
	    if (strcmp(aa, "-d") == 0)
	      {
		args[arg++] = "-v";
		if (client->config->ssh1_args[i + 1])
		  i++; /* Skip the level. */
	      }
	    else
	      if (strcmp(aa, "-n") == 0 ||
		  strcmp(aa, "-a") == 0 ||
		  strcmp(aa, "-x") == 0 ||
		  strcmp(aa, "-t") == 0 ||
		  strcmp(aa, "-v") == 0 ||
		  strcmp(aa, "-V") == 0 ||
		  strcmp(aa, "-q") == 0 ||
		  strcmp(aa, "-f") == 0 ||
		  strcmp(aa, "-P") == 0 ||
		  strcmp(aa, "-C") == 0 ||
		  strcmp(aa, "-g") == 0)
		args[arg++] = aa;
	      else
		if (aa[0] != '-')
		  args[arg++] = aa;
	}
      args[arg++] = NULL;

#if 0
      printf("args:\n");
      for (i = 0; args[i]; i++)
	printf("  %s\n", args[i]);
#endif

      /* Use ssh1 to connect. */
      execve(client->config->ssh1_path, args, environ);
      ssh_fatal("Executing ssh1 in compatibility mode failed.");
    }
}

/* Takes a stream, and creates an SSH client for processing that
   connection.  This closes the stream and returns NULL (without
   calling the destroy function) if an error occurs. The random state
   is required to stay valid until the client has been destroyed.
   ``config'' must remain valid until the client is destroyed; it is
   not automatically freed.
     `stream'        the connection stream
     `config'        configuration data (not freed, must remain valid)
     `user_data'     data for the client user
     `server_host_name' name of the server host, as typed by the user
     `user'          (initial) user to log in as (may be changed during auth)
     `random_state'  random number generator state
     `disconnect'    function to call on disconnect
     `debug'         function to call on debug message (may be NULL)
     `authenticated_notify' function to call when authenticated (may be NULL)
     `context'       context to pass to ``destroy''
   The object should be destroyed from the ``disconnect'' callback or from
   a ``close_notify'' callback (see below).  */

SshClient ssh_client_wrap(SshStream stream, SshConfig config,
			  SshUser user_data,
			  const char *server_host_name,
			  const char *user,
			  SshRandomState random_state,
			  SshClientDisconnectProc disconnect,
			  SshClientDebugProc debug,
			  void (*authenticated_notify)(const char *user,
						       void *context),
			  void *context)
{
  SshClient client;
  SshStream trans, auth;
  SshTransportParams params;

  /* Create parameters. */
  params = ssh_transport_create_params();
  if (!ssh_client_update_transport_params(config, params))
    {
      ssh_stream_destroy(stream);
      ssh_transport_destroy_params(params);
      return NULL;
    }

  /* Create the client object. */
  client = ssh_xcalloc(1, sizeof(*client));
  client->user_data = user_data;
  client->config = config;
  client->being_destroyed = FALSE;

  /* Create a transport layer protocol object. */
  ssh_debug("ssh_client_wrap: creating transport protocol");
  trans = ssh_transport_client_wrap(stream, random_state, SSH2_VERSION,
				    SSH_USERAUTH_SERVICE,
				    params, server_host_name,
				    ssh_client_key_check,
				    (void *)client,
				    (config->ssh1_path && config->ssh1compatibility) ?
				      ssh_client_version_check : NULL,
				    (void *)client);

  /* Create the authentication methods array. */
  client->methods = ssh_client_authentication_initialize();
  
  /* Create an authentication protocol object. */
  ssh_debug("ssh_client_wrap: creating userauth protocol");
  auth = ssh_auth_client_wrap(trans, user, SSH_CONNECTION_SERVICE,
			      client->methods, (void *)client);
  
  /* Create the common part of client/client objects. */
  client->common = ssh_common_wrap(stream, auth, TRUE, config, random_state,
				   server_host_name,
				   disconnect, debug, authenticated_notify,
				   context);

  if (client->common == NULL)
    {
      ssh_client_authentication_uninitialize(client->methods);
      ssh_xfree(client);
      return NULL;
    }
  
  return client;
}

/* Forcibly destroys the given client. */
  
void ssh_client_destroy(SshClient client)
{
  if(client->being_destroyed == FALSE)
    { 
      client->being_destroyed = TRUE;
      ssh_common_destroy(client->common);
      ssh_client_authentication_uninitialize(client->methods);
      memset(client, 'F', sizeof(*client));
      ssh_xfree(client);
    }
}

/* Starts a new command at the server.
     `client'       the client protocol object
     `stdio_stream' stream for stdin/stdout data
     `stderr_stream' stream for stderr data, or NULL to merge with stdout
     `auto_close'   automatically close stdio and stderr on channel close
     `is_subsystem' TRUE if command is a subsystem name instead of command
     `command'      command to execute, or NULL for shell
     `allocate_pty' TRUE if pty should be allocated for the command
     `term'         terminal type for pty (e.g., "vt100"), NULL otherwise
     `env'          NULL, or "name=value" strings to pass as environment
     `forward_x11'  TRUE to request X11 forwarding
     `forward_agent' TRUE to request agent forwarding
     `completion'   completion procedure to be called when done (may be NULL)
     `close_notify' function to call when ch closed (may be NULL)
     `context'      argument to pass to ``completion''.
   It is not an error if some forwarding fails, or an environment variable
   passing is denied.  The ``close_notify'' callback will be called
   regardless of the way the session is destroyed - ssh_client_destroy will
   call ``close_notify'' for all open channels.  It is also called if opening
   the cannnel fails.  It is legal to call ssh_conn_destroy from
   ``close_notify'', unless it has already been called. */

void ssh_client_start_session(SshClient client, SshStream stdio_stream,
			      SshStream stderr_stream, Boolean auto_close,
			      Boolean is_subsystem, const char *command,
			      Boolean allocate_pty, const char *term,
			      const char **env,
			      Boolean forward_x11, Boolean forward_agent,
			      void (*completion)(Boolean success,
						 void *context),
			      void (*close_notify)(void *context),
			      void *context)
{
  ssh_channel_start_session(client->common, stdio_stream, stderr_stream,
			    auto_close, is_subsystem, command, allocate_pty,
			    term, env, forward_x11, forward_agent,
			    completion, close_notify,
			    context);
}

#ifdef SSH_CHANNEL_TCPFWD

/* Requests forwarding of the given remote TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */

void ssh_client_remote_tcp_ip_forward(SshClient client,
				      const char *address_to_bind,
				      const char *port,
				      const char *connect_to_host,
				      const char *connect_to_port,
				      void (*completion)(Boolean success,
							 void *context),
				      void *context)
{
  ssh_channel_start_remote_tcp_forward(client->common, address_to_bind, port,
				       connect_to_host, connect_to_port,
				       completion, context);
}

/* Requests forwarding of the given local TCP/IP port.  If the completion
   procedure is non-NULL, it will be called when done. */

Boolean ssh_client_local_tcp_ip_forward(SshClient client,
					const char *address_to_bind,
					const char *port,
					const char *connect_to_host,
					const char *connect_to_port)
{
  return ssh_channel_start_local_tcp_forward(client->common, address_to_bind,
					     port, connect_to_host,
					     connect_to_port);
}

/* Opens a direct connection to the given TCP/IP port at the remote side.
   The originator values should be set to useful values and are passed
   to the other side.  ``stream'' will be used to transfer channel data. */

void ssh_client_open_remote_tcp_ip(SshClient client, SshStream stream,
				   const char *connect_to_host,
				   const char *connect_to_port,
				   const char *originator_ip,
				   const char *originator_port)
{
  ssh_channel_dtcp_open_to_remote(client->common, stream,
				  connect_to_host, connect_to_port,
				  originator_ip, originator_port);
}

#endif /* SSH_CHANNEL_TCPFWD */
