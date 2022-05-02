/*

  cmalloc.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Feb 15 20:02:47 1997 [mkojo]

  Mallocation to a context, with out possibility to free specific elements.

  */

/*
 * $Id: cmalloc.h,v 1.2 1998/01/28 10:13:57 ylo Exp $
 * $Log: cmalloc.h,v $
 * $EndLog$
 */

#ifndef CMALLOC_H
#define CMALLOC_H

typedef struct SshCMallocContextRec *SshCMallocContext;

/* Initialize the mallocation context. This same context can be used for
   all data, that is rather static i.e. need not to be freed separately.
   Of course this method can be used for allocation in general, but it is
   not recommended. */

SshCMallocContext ssh_cmalloc_init(void);

/* Free all data allocated using this particular context. This function
   makes all allocated space invalid. */

void ssh_cmalloc_free(SshCMallocContext context);

/* Allocate byte buffer of length size from the context. If enough
   memory is not available the function will not return. */

/* Allocated data is not aligned. */
unsigned char *ssh_cmalloc_b(SshCMallocContext context, size_t size);

/* Allocated data is aligned to sizeof(unsigned long).
   XXX This should make allocation for structures possible (need to
       verify this). */
void *ssh_cmalloc_s(SshCMallocContext context, size_t size);

#endif /* CMALLOC_H */
