/*

signals.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

*/

#ifndef SIGNALS_H
#define SIGNALS_H

/* Sets signal handlers so that core dumps are prevented.  This also
   sets the maximum core dump size to zero as an extra precaution (where
   supported).  The old core dump size limit is saved. */
void signals_prevent_core(void *ctx);

/* Sets all signals to their default state.  Restores RLIMIT_CORE previously
   saved by prevent_core(). */
void signals_reset();

#endif /* SIGNALS_H */
