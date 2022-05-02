/*

sshagentcache.c

  Authors:
        Timo J. Rinne <tri@ssh.fi>

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

The minimal `certificate cache' for ssh authentication agent.

*/

#include "sshincludes.h"
#include "sshagentcache.h"

struct SshAgentCacheCertRec {
  unsigned char *certs;
  size_t certs_len;
  char *description;
  int identifier;
  struct SshAgentCacheCertRec *next;
};

struct SshAgentCacheRec {
  struct SshAgentCacheCertRec *queue;
  size_t count;
};

SshAgentCache ssh_agenti_cache_allocate()
{
  SshAgentCache r;

  r = ssh_xcalloc(1, sizeof (*r));
  return r;
}

void ssh_agenti_cache_free(SshAgentCache cache)
{
  ssh_agenti_cache_clear(cache);
  ssh_xfree(cache);
  return;
}

void ssh_agenti_cache_clear(SshAgentCache cache)
{
  struct SshAgentCacheCertRec *item, *next;

  item = cache->queue;
  while (item)
    {
      next = item->next;
      ssh_xfree(item->certs);
      ssh_xfree(item->description);
      ssh_xfree(item);
      item = next;
    }
  memset(cache, 0, sizeof (*cache));
  return;
}

void ssh_agenti_cache_insert(SshAgentCache cache,
                             unsigned char *certs,
                             size_t certs_len,
                             char *description,
                             int identifier)
{
  struct SshAgentCacheCertRec *item;  

  item = ssh_xcalloc(1, sizeof (*item));
  item->description = ssh_xstrdup(description ? description : "");
  item->certs = ssh_xmemdup(certs, certs_len);
  item->certs_len = certs_len;
  item->identifier = identifier;
  item->next = cache->queue;
  cache->queue = item;
  cache->count++;
  return;
}

Boolean ssh_agenti_cache_search_by_id(SshAgentCache cache,
                                      int identifier,
                                      unsigned char **certs,
                                      size_t *certs_len,
                                      char **description)
{
  struct SshAgentCacheCertRec *item;

  item = cache->queue;
  while (item)
    {
      if (item->identifier == identifier)
        {
          if (certs)
            *certs = ssh_xmemdup(item->certs, item->certs_len);
          if (certs_len)
            *certs_len = item->certs_len;
          if (description)
            *description = ssh_xstrdup(item->description);
          return TRUE;
        }
      item = item->next;
    }
  return FALSE;
}

Boolean ssh_agenti_cache_search_by_certs(SshAgentCache cache,
                                         unsigned char *certs,
                                         size_t certs_len,
                                         char **description,
                                         int *identifier)
{
  struct SshAgentCacheCertRec *item;

  item = cache->queue;
  while (item)
    {
      if ((item->certs_len == certs_len) &&
          (memcmp(item->certs, certs, certs_len) == 0))
        {
          if (identifier)
            *identifier = item->identifier;
          if (description)
            *description = ssh_xstrdup(item->description);
          return TRUE;
        }
      item = item->next;
    }
  return FALSE;
}

Boolean ssh_agenti_cache_search_by_description(SshAgentCache cache,
                                               char *description,
                                               unsigned char **certs,
                                               size_t *certs_len,
                                               int *identifier)
{
  struct SshAgentCacheCertRec *item;

  item = cache->queue;
  while (item)
    {
      if (strcmp(item->description, description ? description : "") == 0)
        {
          if (certs)
            *certs = ssh_xmemdup(item->certs, item->certs_len);
          if (certs_len)
            *certs_len = item->certs_len;
          if (identifier)
            *identifier = item->identifier;
          return TRUE;
        }
      item = item->next;
    }
  return FALSE;
}

/* eof (sshagentcache.c) */
