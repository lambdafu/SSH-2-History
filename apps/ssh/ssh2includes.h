/*

ssh2includes.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#ifndef SSH2INCLUDES_H
#define SSH2INCLUDES_H

#include "sshincludes.h"
#include "sshsessionincludes.h"
#include "ssh2version.h"

/* File executed in user's home directory during login. */
#define SSH_USER_RC     ".ssh/rc"

#define SSH_SYSTEM_RC   ETCDIR "/sshrc"

/* XXX temporary definition for the ssh2 log facility.  This should
   probably move to a different header later. */
#define SSH_LOGFACILITY SSH_LOGFACILITY_USER

#endif /* SSH2INCLUDES_H */
