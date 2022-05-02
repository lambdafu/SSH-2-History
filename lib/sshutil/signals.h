/*

  Author: Tomi Salo <ttsalo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Jul  8 17:40:06 1996 [ttsalo]

  signals.h

  Derived straight from signals.c
  
  */

/*
 * $Id: signals.h,v 1.5 1998/06/05 05:53:54 tri Exp $
 * $Log: signals.h,v $
 * $EndLog$
 */

#ifndef SSH_SIGNALS_H
#define SSH_SIGNALS_H

void
signals_prevent_core(void);

void
signals_reset(void);

#endif /* SSH_SIGNALS_H */
