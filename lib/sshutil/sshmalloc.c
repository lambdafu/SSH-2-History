/*

sshmalloc.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Mar 20 21:23:10 1995 ylo

Versions of malloc and friends that check their results, and never return
failure (they call fatal if they encounter an error).

*/

/*
 * $Id: sshmalloc.c,v 1.7 1999/01/18 11:07:53 sjl Exp $
 * $Log: sshmalloc.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#define SSH_DEBUG_MODULE "SshMalloc"

#undef malloc
#undef calloc
#undef realloc
#undef free

void *ssh_xmalloc(unsigned long size)
{
  void *ptr;

  if (size > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xmalloc: allocation too large (allocating %ld bytes)",
              size);

  if (size == 0)
    size = 1;
  ptr = (void *)malloc((size_t) size);
  if (ptr == NULL)
    ssh_fatal("ssh_xmalloc: out of memory (allocating %ld bytes)", size);
  return ptr;
}

void *ssh_xcalloc(unsigned long nitems, unsigned long size)
{
  void *ptr;
  
  if (nitems == 0)
    nitems = 1;
  if (size == 0)
    size = 1;

  if (size * nitems > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xcalloc: allocation too large (allocating %ld*%ld bytes)",
          size, nitems);
  
  ptr = (void *)calloc((size_t) nitems, (size_t) size);
  
  if (ptr == NULL)
    ssh_fatal("ssh_xcalloc: out of memory (allocating %ld*%ld bytes)",
          nitems, size);
  return ptr;
}

void *ssh_xrealloc(void *ptr, unsigned long new_size)
{
  void *new_ptr;

  if (ptr == NULL)
    return ssh_xmalloc(new_size);

  if (new_size > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xrealloc: allocation too large (allocating %ld bytes)",
              (long)new_size);
  
  if (new_size == 0)
    new_size = 1;
  new_ptr = (void *)realloc(ptr, (size_t) new_size);
  if (new_ptr == NULL)
    ssh_fatal("ssh_xrealloc: out of memory (new_size %ld bytes)",
              (long)new_size);
  return new_ptr;
}

void ssh_xfree(void *ptr)
{
  if (ptr != NULL)
    free(ptr);
}

void *ssh_xstrdup(const void *p)
{
  const char *str;
  char *cp;

  SSH_ASSERT(p != NULL);
  str = (const char *)p;
  cp = ssh_xmalloc(strlen(str) + 1);
  strcpy(cp, str);
  return (void *)cp;
}

void *ssh_xmemdup(const void *p, unsigned long len)
{
  const char *str = (const char *)p;
  char *cp;
  
  if (len > XMALLOC_MAX_SIZE)
    ssh_fatal("ssh_xmemdup: allocation too large (allocating %ld bytes)", len);
  
  cp = ssh_xmalloc(len + 1);
  memcpy(cp, str, (size_t)len);
  cp[len] = '\0';
  return (void *)cp;
}
