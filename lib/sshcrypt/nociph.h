/*

  nociph.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov  2 04:22:51 1996 [mkojo]

  Cipher 'none'.

  */

/*
 * $Id: nociph.h,v 1.4 1998/01/28 10:10:43 ylo Exp $
 * $Log: nociph.h,v $
 * $EndLog$
 */

#ifndef NOCIPH_H
#define NOCIPH_H

void none_transform(void *context, unsigned char *dest,
		    const unsigned char *src, size_t len);

#endif /* NOCIPH_H */
