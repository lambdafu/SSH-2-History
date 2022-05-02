/*

ssh-agent.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

The ssh authentication agent.

*/

#include "sshincludes.h"
#include "sshcross.h"
#include "sshencode.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "sshagent.h"
#include "sshagentint.h"
#include "sshuser.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"

typedef struct SshAgentImplRec *SshAgentImpl;

typedef struct SshAgentConnectionRec {
  struct SshAgentConnectionRec *next;
  SshAgentImpl agent;
  SshCrossDown down;
  char *forwarding_path;
} *SshAgentConnection;

typedef struct SshAgentKeyRec {
  struct SshAgentKeyRec *next;
  unsigned char *certs;
  size_t certs_len;
  SshPrivateKey private_key;
  char *description;
} *SshAgentKey;

struct SshAgentImplRec {
  SshAgentConnection connections;
  SshLocalListener listener;
  SshAgentKey keys;
  char *socket_name;
  char *socket_dir_name;
};

/* XXX Initialize the state */
SshRandomState agent_random_state;

/* Note: we don't process can_send callbacks.  This assumes that we always
   send small enough packets that they fit in buffers. */


/* Formats and sends a packet down the connection.  The variable argument list
   specifies the contents of the packet as specified in sshencode.h. */

void ssh_agenti_send(SshAgentConnection conn, unsigned int packet_type, ...)
{
  va_list ap;

  va_start(ap, packet_type);
  ssh_cross_down_send_encode_va(conn->down, (SshCrossPacketType)packet_type,
				ap);
  va_end(ap);
}

/* Formats and sends a SSH_AGENT_FAILURE packet. */

void ssh_agenti_send_error(SshAgentConnection conn, unsigned int err)
{
  ssh_agenti_send(conn, SSH_AGENT_FAILURE,
		  SSH_FORMAT_UINT32, (long)err,
		  SSH_FORMAT_END);
}

/* Looks up a key with the given certs.  The certs are required to match
   bitwise exactly.  This returns NULL if no such key is found. */

SshAgentKey ssh_agenti_find_key(SshAgentImpl agent,
				const unsigned char *certs, size_t certs_len)
{
  SshAgentKey key;

  for (key = agent->keys; key; key = key->next)
    if (key->certs_len == certs_len &&
	memcmp(key->certs, certs, certs_len) == 0)
      return key;
  return NULL;
}

/* Adds the given private key to be managed by the agent.  `private_blob',
   `public_blob', and `description' must have been allocated by ssh_xmalloc;
   this will free them when no longer needed.  This returns TRUE on
   SUCCESS, FALSE on failure. */

Boolean ssh_agenti_add_key(SshAgentImpl agent,
			   unsigned char *private_blob,
			   size_t private_len,
			   unsigned char *public_blob,
			   size_t public_len,
			   char *description)
{
  SshAgentKey key;

  /* Check if we already have the key. */
  key = ssh_agenti_find_key(agent, public_blob, public_len);
  if (key != NULL)
    {
      ssh_debug("ssh_agenti_add_key: key already found");
      ssh_xfree(private_blob);
      ssh_xfree(public_blob);
      ssh_xfree(description);
      return TRUE; /* Return success anyway. */
    }

  /* Import private key. */
  key = ssh_xcalloc(1, sizeof(*key));
  if (ssh_private_key_import(private_blob, private_len, NULL, 0,
			     &key->private_key) != SSH_CRYPTO_OK)
    {
      ssh_debug("ssh_agenti_add_key: private key import failed");
      ssh_xfree(key);
      ssh_xfree(private_blob);
      ssh_xfree(public_blob);
      ssh_xfree(description);
      return FALSE;
    }
  ssh_xfree(private_blob);

  /* Fill in the remaining fields and add to the list of keys. */
  key->certs = public_blob;
  key->certs_len = public_len;
  key->description = description;
  key->next = agent->keys;
  agent->keys = key;
  return TRUE;
}

/* Deletes all keys from the agent. */

void ssh_agenti_delete_keys(SshAgentImpl agent)
{
  SshAgentKey key;

  /* XXX should we check if there are operations in progress on some key?
     (should only be relevant when we add support for smartcards). */
  while (agent->keys != NULL)
    {
      key = agent->keys;
      agent->keys = key->next;

      ssh_xfree(key->certs);
      ssh_xfree(key->description);
      ssh_private_key_free(key->private_key);
      memset(key, 'F', sizeof(*key));
      ssh_xfree(key);
    }
}

/* Lists all keys in possession of the agent.  This sends the response
   message to the client. */

void ssh_agenti_list_keys(SshAgentConnection conn)
{
  SshAgentKey key;
  unsigned long num_keys;
  SshBuffer buffer;

  /* Build the list of keys first, counting the keys at the same time. */
  num_keys = 0;
  ssh_buffer_init(&buffer);
  for (key = conn->agent->keys; key; key = key->next)
    {
      num_keys++;
      ssh_encode_buffer(&buffer,
			SSH_FORMAT_UINT32_STR, key->certs, key->certs_len,
			SSH_FORMAT_UINT32_STR,
			  key->description, strlen(key->description),
			SSH_FORMAT_END);
    }

  /* Construct and send the final response packet. */
  ssh_agenti_send(conn, SSH_AGENT_KEY_LIST,
		  SSH_FORMAT_UINT32, num_keys,
		  SSH_FORMAT_DATA, ssh_buffer_ptr(&buffer), ssh_buffer_len(&buffer),
		  SSH_FORMAT_END);
  ssh_buffer_uninit(&buffer);
}

/* Performs a private-key operation using the agent.  `op_name'
   identifies the operation to perform, and `public_key' the key.  (Both
   allocated by ssh_xmalloc, and are freed by this function when no longer
   needed.)  This will send a response packet when the operation is
   complete (which may be either during this call or some time later). */

void ssh_agenti_private_key_op(SshAgentConnection conn, char *op_name,
			       const unsigned char *public_blob,
			       size_t public_len,
			       const unsigned char *data, size_t len)
{
  SshAgentKey key;
  const unsigned char *arg;
  size_t arg_len;
  unsigned char *outputbuf;
  size_t outputlen;
  SshPrivateKey privkey;

  ssh_debug("ssh_agenti_private_key_op %s", op_name);
  key = ssh_agenti_find_key(conn->agent, public_blob, public_len);
  if (key == NULL)
    {
      ssh_debug("ssh_agenti_find_key: key not found");
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_KEY_NOT_FOUND);
      return;
    }
  privkey = key->private_key;

  if (strcmp(op_name, "sign") == 0)
    {
      if (ssh_decode_array(data, len,
			   SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
			   SSH_FORMAT_END) != len)
	{
	  ssh_debug("ssh_agenti_private_key_op: sign: bad data");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  return;
	}
      outputlen = ssh_private_key_max_signature_output_len(privkey);
      outputbuf = ssh_xmalloc(outputlen);
      if (ssh_private_key_sign_digest(privkey, arg, arg_len,
				      outputbuf, outputlen,
				      &outputlen, agent_random_state) !=
	  SSH_CRYPTO_OK)
	{
	  ssh_debug("ssh_agenti_private_key_op: sign failed");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
	  return;
	}
      ssh_agenti_send(conn, SSH_AGENT_OPERATION_COMPLETE,
		      SSH_FORMAT_UINT32_STR, outputbuf, outputlen,
		      SSH_FORMAT_END);
    }
  else if (strcmp(op_name, "hash-and-sign") == 0)
    {
      if (ssh_decode_array(data, len,
			   SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
			   SSH_FORMAT_END) != len)
	{
	  ssh_debug("ssh_agenti_private_key_op: hash-and-sign: bad data");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  return;
	}
      outputlen = ssh_private_key_max_signature_output_len(privkey);
      outputbuf = ssh_xmalloc(outputlen);
      if (ssh_private_key_sign(privkey, arg, arg_len, outputbuf, outputlen,
			       &outputlen, agent_random_state) !=
	  SSH_CRYPTO_OK)
	{
	  ssh_debug("ssh_agenti_private_key_op: hash-and-sign failed");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
	  return;
	}
      ssh_agenti_send(conn, SSH_AGENT_OPERATION_COMPLETE,
		      SSH_FORMAT_UINT32_STR, outputbuf, outputlen,
		      SSH_FORMAT_END);
    }
  else if (strcmp(op_name, "decrypt") == 0)
    {
      if (ssh_decode_array(data, len,
			   SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
			   SSH_FORMAT_END) != len)
	{
	  ssh_debug("ssh_agenti_private_key_op: decrypt: bad data");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  return;
	}
      outputlen = ssh_private_key_max_decrypt_output_len(privkey);
      outputbuf = ssh_xmalloc(outputlen);
      if (ssh_private_key_decrypt(privkey, arg, arg_len,
				  outputbuf, outputlen,
				  &outputlen) != SSH_CRYPTO_OK)
	{
	  ssh_debug("ssh_agenti_private_key_op: decrypt failed");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
	  return;
	}
      ssh_agenti_send(conn, SSH_AGENT_OPERATION_COMPLETE,
		      SSH_FORMAT_UINT32_STR, outputbuf, outputlen,
		      SSH_FORMAT_END);
    }
  else if (strcmp(op_name, "ssh1-challenge-response") == 0)
    {
      if (ssh_decode_array(data, len,
			   SSH_FORMAT_UINT32_STR_NOCOPY, &arg, &arg_len,
			   SSH_FORMAT_END) != len)
	{
	  ssh_debug("ssh_agenti_private_key_op: sign: bad data");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  return;
	}
      ssh_debug("ssh_agenti_private_key_op: ssh1-challenge-response not yet implemented");
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
    }
  else
    {
      ssh_debug("ssh_agenti_private_key_op: unknown op '%.50s'", op_name);
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
    }
}

/* This function is called whenever the agent receives a packet from a client.
   This will process the request, and eventually send a response. */

void ssh_agenti_received_packet(SshCrossPacketType type,
				const unsigned char *data, size_t len,
				void *context)
{
  SshAgentConnection conn = (SshAgentConnection)context;
  unsigned char *private_blob, *public_blob;
  size_t bytes, private_len, public_len;
  char *description, *op_name, *forwarding_host;

  switch ((int)type)
    {
    case SSH_AGENT_REQUEST_VERSION:
      if (conn->forwarding_path == NULL)
	conn->forwarding_path = ssh_xstrdup("(local)");
      ssh_debug("ssh_agenti_received_packet: version request with path '%s'",
		conn->forwarding_path);
      if (len != 0)
	{
	  ssh_debug("ssh_agenti_received_packet: REQUEST_VERSION bad data");
	  ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  break;
	}
      /* Send our version number. */
      ssh_agenti_send(conn, SSH_AGENT_VERSION_RESPONSE,
		      SSH_FORMAT_UINT32, 2L,
		      SSH_FORMAT_END);
      break;

    case SSH_AGENT_ADD_KEY:
      if (ssh_decode_array(data, len,
			   SSH_FORMAT_UINT32_STR,
			     &private_blob, &private_len,
			   SSH_FORMAT_UINT32_STR,
			     &public_blob, &public_len,
			   SSH_FORMAT_UINT32_STR, &description, NULL,
			   SSH_FORMAT_END) != len)
	{
	  ssh_debug("ssh_agenti_received_packet: ADD_KEY bad data");
	  ssh_agenti_send(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  break;
	}
      if (ssh_agenti_add_key(conn->agent, private_blob, private_len,
			     public_blob, public_len, description))
	ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
      else
	ssh_agenti_send_error(conn, SSH_AGENT_ERROR_FAILURE);
      break;

    case SSH_AGENT_DELETE_ALL_KEYS:
      if (len != 0)
	{
	  ssh_debug("ssh_agenti_received_packet: DELETE_ALL_KEYS bad data");
	  ssh_agenti_send(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  break;
	}
      ssh_agenti_delete_keys(conn->agent);
      ssh_agenti_send(conn, SSH_AGENT_SUCCESS, SSH_FORMAT_END);
      break;
      
    case SSH_AGENT_LIST_KEYS:
      if (len != 0)
	{
	  ssh_debug("ssh_agenti_received_packet: LIST_KEYS bad data");
	  ssh_agenti_send(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  break;
	}
      ssh_agenti_list_keys(conn);
      break;
      
    case SSH_AGENT_PRIVATE_KEY_OP:
      bytes = ssh_decode_array(data, len,
			       SSH_FORMAT_UINT32_STR, &op_name, NULL,
			       SSH_FORMAT_UINT32_STR,
			         &public_blob, &public_len,
			       SSH_FORMAT_END);
      if (bytes == 0)
	{
	  ssh_debug("ssh_agenti_received_packet: PRIVATE_KEY_OP bad data");
	  ssh_agenti_send(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
	  break;
	}
      ssh_agenti_private_key_op(conn, op_name, public_blob, public_len,
				data + bytes, len - bytes);
      break;

    case SSH_AGENT_FORWARDING_NOTICE:
      if (ssh_decode_array(data, len,
			   SSH_FORMAT_UINT32_STR, &forwarding_host, NULL,
			   SSH_FORMAT_UINT32_STR, NULL, NULL,
			   SSH_FORMAT_UINT32, NULL, /* port */
			   SSH_FORMAT_END) != len)
	{
	  ssh_debug("ssh_agenti_received_packet: FORWARDING_NOTICE bad data");
	  break;
	}
      if (conn->forwarding_path == NULL)
	conn->forwarding_path = forwarding_host;
      else
	{
	  conn->forwarding_path = ssh_xrealloc(conn->forwarding_path,
					       strlen(conn->forwarding_path) +
					       strlen(forwarding_host) + 2);
	  strcat(conn->forwarding_path, ",");
	  strcat(conn->forwarding_path, forwarding_host);
	  ssh_xfree(forwarding_host);
	}
      break;
      
    default:
      ssh_agenti_send_error(conn, SSH_AGENT_ERROR_UNSUPPORTED_OP);
      break;
    }
}

void ssh_agenti_received_eof(void *context)
{
  SshAgentConnection conn, *connp;

  conn = (SshAgentConnection)context;
  
  /* Remove from list of active connections. */
  for (connp = &conn->agent->connections; *connp && *connp != conn;
       connp = &(*connp)->next)
    ;
  if (!*connp)
    ssh_fatal("ssh_agenti_received_eof: connection %lx not found",
	      (unsigned long)conn);
  assert(*connp == conn);
  *connp = conn->next;

  /* XXX may need to cancel or wait operations on smartcards. */

  /* Destroy and free the object.  This also closes the stream. */
  ssh_cross_down_destroy(conn->down);
  if (conn->forwarding_path)
    ssh_xfree(conn->forwarding_path);
  memset(conn, 'F', sizeof(*conn));
  ssh_xfree(conn);
}

/* Processes a new incoming connection to the agent.  This is called when
   a new client connects. */

void ssh_agenti_connection(SshStream stream, void *context)
{
  SshAgentImpl agent = (SshAgentImpl)context;
  SshAgentConnection conn;

  conn = ssh_xcalloc(1, sizeof(*conn));
  conn->down = ssh_cross_down_create(stream,
				     ssh_agenti_received_packet,
				     ssh_agenti_received_eof,
				     NULL,
				     (void *)conn);
  conn->next = agent->connections;
  agent->connections = conn;
  conn->agent = agent;
  ssh_cross_down_can_receive(conn->down, TRUE);
}

/* Creates the authentication agent and starts listening for connections.
   XXX add support for smartcard readers. */

SshAgentImpl ssh_agenti_create(char **path_return)
{
  SshAgentImpl agent;

  agent = ssh_xcalloc(1, sizeof(*agent));
  agent->connections = NULL;
  agent->listener = ssh_agenti_create_listener(getuid(), path_return,
					       ssh_agenti_connection,
					       FALSE,
					       (void *)agent);
  if (!agent->listener)
    {
      ssh_xfree(agent);
      return NULL;
    }

  return agent;
}

/* This is called periodically by a timeout, and checks whether the parent
   process is still alive. */

void ssh_agenti_check_parent(void *context)
{
  SshAgentImpl agent = (SshAgentImpl)context;
  
  /* Try to send a dummy signal to the parent process. */
  if (kill(getppid(), 0) < 0)
    {
      remove(agent->socket_name);
      if (strchr(agent->socket_name, '/'))
	*strrchr(agent->socket_name, '/') = '\0';
      rmdir(agent->socket_name); /* may fail if there are other sockets in it*/

      /* Note: instead of doing ssh_event_loop_abort we call exit here.  This
	 is to avoid the possibility that someone leaves a connection to the
	 agent open and could exploit the keys after the legitimate user has
	 logged off. */
      exit(1);
    }

  /* Re-schedule this timeout. */
  ssh_register_timeout(10, 0, ssh_agenti_check_parent,
		       (void *)agent);
}

/* Main program for the unix version of the agent. */

int main(int ac, char **av)
{
  int binsh = 1, opt;
  extern int optind;
  extern char *optarg;
  char *socket_name;
  char buf[100];
  SshAgentImpl agent;
  int pid;
  SshUser user;

  /* Get user database information for the current user. */
  user = ssh_user_initialize(NULL);
  
  while ((opt = getopt(ac, av, "cs")) != EOF)
    switch (opt)
      {
      case 'c':
	binsh = 0;
	break;
      case 's':
	binsh = 1;
	break;
      default:
	fprintf(stderr, "%s: unknown option '%c'.\n", av[0], opt);
	fprintf(stderr, "Usage: ssh-agent [-c] [-s] [command [args...]]\n");
	exit(1);
      }

  /* Ignore broken pipe signals. */
  signal(SIGPIPE, SIG_IGN);
  
  /* Initialize the event loop. */
  ssh_event_loop_initialize();
  
  /* Determine the path of the agent socket and create the agent. */
  agent = ssh_agenti_create(&socket_name);
  if (agent == NULL)
    {
      /* Agent creation failed.  If we don't have a command, just return
	 error.  Otherwise, give an error but still execute the command.
	 (This is more robust than existing, as the agent is often started
	 during loging.) */
      if (optind >= ac)
	{
	  ssh_fatal("Cannot safely create agent socket '%s'", socket_name);
	}
      else
	{
	  ssh_warning("Cannot safely create agent socket '%s'", socket_name);
	  execvp(av[optind], av + 1);
	  perror(av[1]);
	  exit(1);
	}
    }

  /* We have now created the agent.  Fork a child to be the agent. */
  pid = fork();
  if (pid != 0)
    {
      /* Close our copy of the agent listener, so that it will get really
	 closed when the parent exits. */
      ssh_local_destroy_listener(agent->listener);
      
      /* Exit or exec the command. */
      if (optind >= ac)
	{
	  /* No arguments - print environment variable setting commands
	     and exit. */
	  if (binsh)
	    {
	      printf("%s=%s; export %s;\n",
		     SSH_AGENT_VAR, socket_name, SSH_AGENT_VAR);
	      printf("%s=%d; export %s;\n", SSH_AGENT_PID, pid, SSH_AGENT_PID);
	      printf("echo Agent pid %d;\n", pid);
	    }
	  else
	    {			/* shell is *csh */
	      printf("setenv %s %s;\n", SSH_AGENT_VAR, socket_name);
	      printf("setenv %s %d;\n", SSH_AGENT_PID, pid);
	      printf("echo Agent pid %d;\n", pid);
	    }
	  exit(0);
	}
      else
	{
	  /* We have a command.  Put the new environment variables in
	     environment and exec the command. */
	  snprintf(buf, sizeof(buf), "%s=%s", SSH_AGENT_VAR, socket_name);
	  putenv(ssh_xstrdup(buf));
	  snprintf(buf, sizeof(buf), "%s=%d", SSH_AGENT_PID, pid);
	  putenv(ssh_xstrdup(buf));
	  execvp(av[1], av + 1);
	  perror(av[1]);
	  exit(1);
	}
    }

  /* We are the child, and become the agent. */
  close(0);
  close(1);
  close(2);
  chdir("/");
  
  /* Disconnect from the controlling tty. */
#ifdef TIOCNOTTY
  {
    int fd;
#ifdef O_NOCTTY
    fd = open("/dev/tty", O_RDWR | O_NOCTTY);
#else
    fd = open("/dev/tty", O_RDWR);
#endif
    if (fd >= 0)
      {
	(void)ioctl(fd, TIOCNOTTY, NULL);
	close(fd);
      }
  }
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
#ifdef ultrix
  setpgrp(0, 0);
#else /* ultrix */
  if (setsid() < 0)
    ssh_warning("setsid: %.100s", strerror(errno));
#endif
#endif /* HAVE_SETSID */

  agent->socket_name = ssh_xstrdup(socket_name);

  /* Load the random seed file. */
  agent_random_state = ssh_randseed_open(user, NULL);
  
  /* Register a timeout to periodically check whether the parent has
     exited (which means we should exit too). */
  if (optind < ac)
    {
      ssh_register_timeout(10, 0, ssh_agenti_check_parent,
			   (void *)agent);
    }

  /* Keep running the event loop until we exit. */
  ssh_event_loop_run();

  /* Uninitialize the event loop. */
  ssh_event_loop_uninitialize();

  /* Update the random seed file. */
  ssh_randseed_update(user, agent_random_state, NULL);
  
  /* Free the random seed. */
  ssh_random_free(agent_random_state);

  /* Free user database information about the current user. */
  ssh_user_free(user, FALSE);

  /* Remove the socket that we listened on. */
  remove(agent->socket_name);
  if (strchr(agent->socket_name, '/'))
    *strrchr(agent->socket_name, '/') = '\0';
  rmdir(agent->socket_name); /* This may fail if there are other sockets. */
  
  /* Exit. */
  return 0;
}
