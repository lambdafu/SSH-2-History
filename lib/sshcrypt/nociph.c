/*

  nociph.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov  2 04:25:01 1996 [mkojo]

  Cipher 'none'.

  */

/*
 * $Id: nociph.c,v 1.6 1998/11/04 12:06:52 ylo Exp $
 * $Log: nociph.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "nociph.h"

void none_transform(void *context, unsigned char *dest,
                    const unsigned char *src, size_t len,
                    unsigned char *iv)
{
  if (src != dest)
    memcpy(dest, src, len);
}

/* nociph.c */
                    
