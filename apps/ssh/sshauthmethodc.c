/*

  sshauthmethodc.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  SSH2 authentication methods for the client.

*/

#include "ssh2includes.h"
#include "sshencode.h"
#include "sshauth.h"
#include "readpass.h"
#include "authc-pubkey.h"
#include "authc-passwd.h"

/* table of the supported authentication methods */

SshAuthClientMethod ssh_client_auth_methods[] =
{
  { "publickey", ssh_client_auth_pubkey }, 
  { "password", ssh_client_auth_password },
  { NULL, NULL }
};

/* Initializes the authentication methods array for the client. */

SshAuthClientMethod *ssh_client_authentication_initialize()
{
  return ssh_client_auth_methods;
}

/* Frees the returned authentication method array. */

void ssh_client_authentication_uninitialize(SshAuthClientMethod *methods)
{
  /* We returned a static array, nothing to do here for now. */
}
