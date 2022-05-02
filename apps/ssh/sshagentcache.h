/*

sshagentcache.h

  Authors:
        Timo J. Rinne <tri@ssh.fi>

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

The minimal `certificate cache' for ssh authentication agent.

*/

#ifndef SSHAGENTCACHE_H
#define SSHAGENTCACHE_H 1
typedef struct SshAgentCacheRec *SshAgentCache;

/* Allocate a cache object */
SshAgentCache ssh_agenti_cache_allocate(void);

/* Clear and deallocate the cache object */
void ssh_agenti_cache_free(SshAgentCache cache);

/* Clear the cache object */
void ssh_agenti_cache_clear(SshAgentCache cache);

/* Insert a certificate to the cache object */
void ssh_agenti_cache_insert(SshAgentCache cache,
                             unsigned char *certs,
                             size_t certs_len,
                             char *description,
                             int identifier);

/* Search the certificate from the cache by identifier number.
   If certificate is found, TRUE is returned and certificate 
   information is copied to the gicen locations (if non-NULL). 
   Returned certificate and description has to be freed with 
   ssh_xfree. */
Boolean ssh_agenti_cache_search_by_id(SshAgentCache cache,
                                      int identifier,
                                      unsigned char **certs,
                                      size_t *certs_len,
                                      char **description);

/* Search the certificate from the cache by certs string.
   If certificate is found, TRUE is returned and certificate 
   information is copied to the gicen locations (if non-NULL). 
   Returned description has to be freed with ssh_xfree. */
Boolean ssh_agenti_cache_search_by_certs(SshAgentCache cache,
                                         unsigned char *certs,
                                         size_t certs_len,
                                         char **description,
                                         int *identifier);

/* Search the certificate from the cache by description string.
   If certificate is found, TRUE is returned and certificate 
   information is copied to the gicen locations (if non-NULL). 
   Returned certificate has to be freed with ssh_xfree. */
Boolean ssh_agenti_cache_search_by_description(SshAgentCache cache,
                                               char *description,
                                               unsigned char **certs,
                                               size_t *certs_len,
                                               int *identifier);
#endif /* ! SSHAGENTCACHE_H */
/* eof (sshagentcache.h) */
