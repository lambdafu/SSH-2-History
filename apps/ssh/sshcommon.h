/*
  sshcommon.h

  Authors:
        Tatu Ylönen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Interface to the SSH2 channel protocols.  This interface is shared
  by server and client code.  Most of the real stuff is in
  channel type specific modules (sshch*.c and sshch*.h).

*/

#ifndef SSHCOMMON_H
#define SSHCOMMON_H

#include "sshstream.h"
#include "sshconfig.h"
#include "sshcrypt.h"
#include "sshconn.h"

/* XXX temporarily defined here. */
#ifndef SSHDIST_WINDOWS
#define SSH_CHANNEL_SESSION
#define SSH_CHANNEL_AGENT
#define SSH_CHANNEL_SSH1_AGENT
#define SSH_CHANNEL_TCPFWD
#if !defined (X_DISPLAY_MISSING) && defined (XAUTH_PATH)
#define SSH_CHANNEL_X11
#endif /* X_DISPLAY_MISSING */
#else /* SSHDIST_WINDOWS */

#endif /* SSHDIST_WINDOWS */

/* Data type for representing the common protocol object for both server and
   client. */
typedef struct SshCommonRec *SshCommon;

struct SshCommonRec
{
  /* TRUE if we are a client, FALSE if we are a server. */
  Boolean client;

  /* The connection protocol object. */
  SshConn conn;

  /* Configuration data. */
  SshConfig config;
  
  /* Number of active channels on the common. */
  unsigned int num_channels;

  /* Function to call when a disconnect message is received.  This function
     is supposed to destroy the object. */
  SshConnDisconnectProc disconnect;
  
  /* Function to call when a debug message is received, or NULL. */
  SshConnDebugProc debug;

  /* Function to call when the user has been authenticated.  This may be
     NULL. */
  void (*authenticated_notify)(const char *user, void *context);

  /* Context argument to ``disconnect'' and ``debug'' callbacks. */
  void *context;

  /* An initialized random state.  This is not automatically freed on
     destruction. */
  SshRandomState random_state;

  /* Name of the server host in client (NULL in server). */
  char *server_host_name;
  
  /* Authenticated user name. */
  char *user;
  
  /* Data for the user. */
  SshUser user_data;

  /* Remote ip address and port. */
  char *remote_ip;
  char *remote_port;

  /* Local ip address and port. */
  char *local_ip;
  char *local_port;

  /* Authenticated host name, or empty if none. */
  char *authenticated_client_host;

  /* An array of contexts returned by the type create function for each
     channel type. */
  void **type_contexts;
  
  /* Dynamically built array of global requests.  This array is allocated
     using ssh_xmalloc. */
  unsigned int num_global_requests;
  SshConnGlobalRequest *global_requests;

  /* Dynamically built array of channel opens.  This array is allocated
     using ssh_xmalloc. */
  unsigned int num_channel_opens;
  SshConnChannelOpen *channel_opens;
};

/* A function of this type will be called to notify the application that
   the user has been authenticated. */
typedef void (*SshCommonAuthenticatedNotify)(const char *user, void *context);

/* Creates the common processing object for the SSH server/client connection.
   This also creates the connection protocol object.
     `connection'   the connection to the other side
     `auth'         authentication protocol object
     `client'       TRUE if we are a client, FALSE if a server
     `config'       configuration data
     `random_state' initialized random state
     `server_host_name' name of server host, or NULL in server
     `disconnect'    function to call on disconnect
     `debug'         function to call on debug message (may be NULL)
     `authenticated_notify' function to call when authenticated (may be NULL)
     `context'       context to pass to ``destroy''
   The object should be destroyed from the ``disconnect'' callback or from
   a ``close_notify'' callback (see below).  */
SshCommon ssh_common_wrap(SshStream connection,
			  SshStream auth,
			  Boolean client,
			  SshConfig config,
			  SshRandomState random_state,
			  const char *server_host_name,
			  SshConnDisconnectProc disconnect,
			  SshConnDebugProc debug,
			  SshCommonAuthenticatedNotify authenticated_notify,
			  void *context);

/* Destroys the common protocol object.  This will not call the disconnect
   callback in any situation. */
void ssh_common_destroy(SshCommon common);

/* A function of this type is called once during the creation of the
   SshCommon object for each defined channel type.  The value returned
   by this function will be passed as contact to the open function
   for this channel type, and to the SshChannelTypeDestroyProc, which
   will be called when the SshCommon object is destroyed.  This function
   typically allocates and initializes a context for the channel type. */
typedef void *(*SshChannelTypeCreateProc)(SshCommon common);

/* A function of this type is called once during destruction of a SshCommon
   object for each defined channel type.  The function should close any
   channels of that type, and should destroy the context. */
typedef void (*SshChannelTypeDestroyProc)(void *context);

/* Returns the channel type context for the channel type identified by
   the name. */
void *ssh_common_get_channel_type_context(SshCommon common,
					  const char *name);

/* Informs the channel type independent code that a new channel has been
   created. */
void ssh_common_new_channel(SshCommon common);

/* Informs the channel type independent code that a channel has been
   destroyed.  This may destroy the SshCommon object if there are no
   more channels, causing a call to the channel type specific destroy
   function.  Care should be taken to call this function as the last thing
   done in a channel destroy function. */
void ssh_common_destroy_channel(SshCommon common);

#endif /* SSHCOMMON_H */
