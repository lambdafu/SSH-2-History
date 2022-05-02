/*

sshauthmethods.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

SSH2 authentication methods for the server.

*/

#include "ssh2includes.h"
#include "sshauth.h"
#include "auths-passwd.h"
#include "auths-pubkey.h"

static SshAuthServerMethod server_methods[] =
{
  { "publickey", ssh_server_auth_pubkey },
  { "password", ssh_server_auth_passwd },
  { NULL, NULL }
};

/* Initializes the authentication methods array for the server. */

SshAuthServerMethod *ssh_server_authentication_initialize()
{
  return server_methods;
}

/* Frees the returned authentication method array. */

void ssh_server_authentication_uninitialize(SshAuthServerMethod *methods)
{
  /* We returned a static array, nothing to do here for now. */
}




