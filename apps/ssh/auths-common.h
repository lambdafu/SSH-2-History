/*

  auths-common.h

  Author: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Common functions for both pubkey- and password-authentication on the
  server side.

*/

#ifndef AUTHS_COMMON_H
#define AUTHS_COMMON_H

#include "sshincludes.h"
#include "sshuser.h"
#include "sshcommon.h"

Boolean ssh_server_auth_check_user(SshUser *ucp, const char *user,
                                   SshConfig config);
Boolean ssh_server_auth_check_host(SshCommon common);

#endif /* AUTHS_COMMON_H */
