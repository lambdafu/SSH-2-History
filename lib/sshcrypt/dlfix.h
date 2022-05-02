/*

  dlfix.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jul 21 17:40:10 1997 [mkojo]

  Discrete logarithm predefined groups.

  */

/*
 * $Id: dlfix.h,v 1.2 1998/01/28 10:09:55 ylo Exp $
 * $Log: dlfix.h,v $
 * $EndLog$
 */

#ifndef DLFIX_H
#define DLFIX_H

/* Search a parameter set of name "name". Returns TRUE if found. */

Boolean ssh_dlp_set_param(const char *name, const char **outname,
			  MP_INT *p, MP_INT *q, MP_INT *g);

#endif /* DLFIX_H */
