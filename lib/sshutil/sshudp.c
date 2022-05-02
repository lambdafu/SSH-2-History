/*

  Author: Timo J. Rinne <tri@ssh.fi>

  Copyright (c) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Generic code of the UDP communications interface.

  */

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshudp.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

#define SSH_DEBUG_MODULE "SshUdpGeneric"

char *ssh_udp_error_string(SshUdpError error)
{
  switch (error)
    {
    case SSH_UDP_OK:
     return "OK";
    case SSH_UDP_HOST_UNREACHABLE:
     return "Destination Host Unreachable";
    case SSH_UDP_PORT_UNREACHABLE:
     return "Destination Port Unreachable";
    case SSH_UDP_NO_DATA:
     return "No Data";
    default:
     return "Unknown Error";
    }
  /*NOTREACHED*/
}
