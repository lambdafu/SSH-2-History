/*

sshunixdevicestream.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Generic interface for opening a data stream to/from a device (hardware
device or pseudo-device).  This is the unix implementation.

*/

#include "sshincludes.h"
#include "sshdevicestream.h"
#include "sshunixeloop.h"
#include "sshunixfdstream.h"

/* Opens a stream for the device specified by the given name.  Returns NULL
   on failure. */

SshStream ssh_device_open(const char *name)
{
  int fd;

  /* Try to open the device. */
  fd = open(name, O_RDWR);

  /* On error, return NULL. */
  if (fd < 0)
    return NULL;

  /* On success, wrap the device file descriptor into a stream and return
     the stream. */
  return ssh_stream_fd_wrap(fd, TRUE);
}
