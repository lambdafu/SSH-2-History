/*

  cmalloc.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Feb 15 19:37:35 1997 [mkojo]

  Mallocation from a context. These routines allocate data to a context,
  to be freed by one call to cmalloc_free. There is no other way of
  freeing data, than freeing it all.

  */

/*
 * $Id: cmalloc.c,v 1.4 1998/04/28 07:15:32 tmo Exp $
 * $Log: cmalloc.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "cmalloc.h"

#undef malloc
#undef calloc
#undef realloc
#undef free

/* Structure for holding allocated data. */

typedef struct SshCMallocDataRec
{
  struct SshCMallocDataRec *next;

  unsigned char *ptr;
  size_t free_bytes;
} SshCMallocData;

/* Main context for all allocated data through cmalloc. Uses buckets of
   different sizes. Reason for this is to minimize the space needed and to
   make it more probable that there exists already enough allocated memory
   in the cmalloc context. */

/* Minimum amount of allocation is 1024 (2^10) bytes. */
#define SSH_CMALLOC_BUCKET_START 10

/* Maximum amount of allocation is 1024*1024 (2^20) bytes. */
#define SSH_CMALLOC_BUCKET_COUNT 10

struct SshCMallocContextRec
{
  SshCMallocData *bucket[SSH_CMALLOC_BUCKET_COUNT];
};

/* Initialize the cmalloc context. Clear all buckets. */

SshCMallocContext ssh_cmalloc_init(void)
{
  SshCMallocContext created = ssh_xmalloc(sizeof(*created));
  int i;
  
  for (i = 0; i < SSH_CMALLOC_BUCKET_COUNT; i++)
    created->bucket[i] = NULL;

  return created;
}

void ssh_cmalloc_free(SshCMallocContext context)
{
  SshCMallocData *temp, *next;
  int i;

  /* Free all data in buckets. */
  
  for (i = 0; i < SSH_CMALLOC_BUCKET_COUNT; i++)
    {
      temp = context->bucket[i];
      context->bucket[i] = NULL;
      while (temp)
	{
	  next = temp->next;
	  ssh_xfree(temp);
	  temp = next;
	}
    }
  /* Free the context also. */
  ssh_xfree(context);
}

unsigned char *ssh_cmalloc_internal(SshCMallocContext context,
				    size_t size,
				    size_t align)
{
  unsigned char *ptr;
  SshCMallocData *data;
  unsigned int i;
  size_t bucket_size;
  unsigned int alignment;

  if (size == 0)
    {
      ssh_fatal("ssh_cmalloc: tried to allocate zero (0) bytes.");
    }
  
  if (size > (1 << (SSH_CMALLOC_BUCKET_COUNT + SSH_CMALLOC_BUCKET_START)))
    {
      ssh_fatal("ssh_cmalloc: tried to allocate too much (%d bytes).", size);
    }

  /* Select bucket. */
  for (bucket_size = (1 << SSH_CMALLOC_BUCKET_START), i = 0;
       bucket_size < size;
       bucket_size <<= 1, i++)
    ;
  
  if (context->bucket[i] != NULL)
    {
      /* Compute align_ptr */
      alignment = (unsigned long)(context->bucket[i]->ptr) & (align - 1);
      if (alignment != 0x0)
	{
	  if (context->bucket[i]->free_bytes - (align - alignment) >= size)
	    {
	      ptr = context->bucket[i]->ptr + (align - alignment);
	      context->bucket[i]->ptr += size;
	      context->bucket[i]->free_bytes -= (size + (align - alignment));
	    }
	}
      else
	/* Check if enough data is available. */
	if (context->bucket[i]->free_bytes >= size)
	  {
	    ptr = context->bucket[i]->ptr;
	    context->bucket[i]->ptr += size;
	    context->bucket[i]->free_bytes -= size;
	    return ptr;
	  }
    }
  
  /* Not enough space. */

  /* Allocate just one new small block of data and link it as
     first of the particular bucket list.

     Here we can skip the alignment checking because ssh_xmalloc always
     aligns correctly (and we don't want to align more than what is
     needed). */
  data =
    (SshCMallocData *)ssh_xmalloc(bucket_size + size + sizeof(SshCMallocData));
  data->next = context->bucket[i];
  context->bucket[i] = data;
  data->free_bytes = bucket_size + size;

  /* However here we need to do some checking (to make the data ptr aligned).
   */
  alignment = sizeof(SshCMallocData) & (align - 1);
  if (alignment != 0x0)
    data->ptr = ((unsigned char *)data) + sizeof(SshCMallocData) +
      (align - alignment);
  else
    data->ptr = ((unsigned char *)data) + sizeof(SshCMallocData);

  /* Give the caller requested amount of data. */

  ptr = context->bucket[i]->ptr;
  context->bucket[i]->ptr += size;
  context->bucket[i]->free_bytes -= size;
  return ptr;
}

unsigned char *ssh_cmalloc_b(SshCMallocContext context,
			     size_t size)
{
  return ssh_cmalloc_internal(context, size, 1);
}
     
void *ssh_cmalloc_s(SshCMallocContext context,
		    size_t size)
{
  return (void *)ssh_cmalloc_internal(context, size, sizeof(unsigned long));
}

/* cmalloc.c */
