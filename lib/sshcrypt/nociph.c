/*

  nociph.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov  2 04:25:01 1996 [mkojo]

  Cipher 'none'.

  */

/*
 * $Id: nociph.c,v 1.5 1998/07/28 02:34:57 ylo Exp $
 * $Log: nociph.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

void none_transform(void *context, unsigned char *dest,
		    const unsigned char *src, size_t len)
{
  if (src != dest)
    memcpy(dest, src, len);
}

/* nociph.c */
		    
