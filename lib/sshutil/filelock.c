/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri Aug  9 16:35:12 1996 [ttsalo]

  File locking functions.

  */

/*
 * $Id: filelock.c,v 1.7 1998/01/28 10:14:10 ylo Exp $
 * $Log: filelock.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef macintosh
int filelock_lock_shared(int fd, off_t offset, off_t len)
{
  ssh_fatal("filelock_lock_shared unimplemented");
}

int filelock_lock_exclusive(int fd, off_t offset, off_t len)
{
  ssh_fatal("filelock_lock_exclusive unimplemented");
}
     
int filelock_unlock(int fd, off_t offset, off_t len)
{
  ssh_fatal("filelock_unlock unimplemented");
}
#else /* macintosh */
#ifdef WINDOWS
int filelock_lock_shared(int fd, off_t offset, off_t len)
{
  ssh_fatal("filelock_lock_shared unimplemented");
}

int filelock_lock_exclusive(int fd, off_t offset, off_t len)
{
  ssh_fatal("filelock_lock_exclusive unimplemented");
}
     
int filelock_unlock(int fd, off_t offset, off_t len)
{
  ssh_fatal("filelock_unlock unimplemented");
}

#else /* WINDOWS */
#ifdef HAVE_LOCKF

int filelock_lock_shared(int fd, off_t offset, off_t len)
{
  if (lseek(fd, offset, SEEK_SET) != offset)
    return 0;
  else
    return lockf(fd, F_LOCK, len);
}

int filelock_lock_exclusive(int fd, off_t offset, off_t len)
{
  if (lseek(fd, offset, SEEK_SET) != offset)
    return 0;
  else
    return lockf(fd, F_LOCK, len);
}
     
int filelock_unlock(int fd, off_t offset, off_t len)
{
  if (lseek(fd, offset, SEEK_SET) != offset)
    return 0;
  else
    return lockf(fd, F_ULOCK, len);
}

#else /* HAVE_LOCKF */

/* fcntl locking */

struct flock fs;

int filelock_lock_shared(int fd, off_t offset, off_t len)
{
  fs.l_type = F_RDLCK;
  fs.l_whence = SEEK_SET;
  fs.l_start = offset;
  fs.l_len = len;
  fs.l_pid = getpid();
  printf("fd=%d offset=%d len=%d pid=%d\n", fd, (int)offset, (int)len, (int)fs.l_pid);
  return fcntl(fd, F_SETLKW, &fs);
}

int filelock_lock_exclusive(int fd, off_t offset, off_t len)
{
  fs.l_type = F_WRLCK;
  fs.l_whence = SEEK_SET;
  fs.l_start = offset;
  fs.l_len = len;
  fs.l_pid = getpid();
  printf("fd=%d offset=%d len=%d pid=%d\n", fd, (int)offset, (int)len, (int)fs.l_pid);
  return fcntl(fd, F_SETLKW, &fs);
}
     
int filelock_unlock(int fd, off_t offset, off_t len)
{
  fs.l_type = F_UNLCK;
  fs.l_whence = SEEK_SET;
  fs.l_start = offset;
  fs.l_len = len;
  fs.l_pid = getpid();
  return fcntl(fd, F_SETLKW, &fs);
}

#endif /* HAVE_LOCKF */
#endif /* WINDOWS */
#endif /* macintosh */
