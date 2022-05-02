/*

signals.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Fri Jan 19 18:09:37 1995 ylo

Manipulation of signal state.  This file also contains code to set the
maximum core dump size.

*/

/*
 * $Id: signals.c,v 1.6 1998/08/06 12:11:58 tmo Exp $
 * $Log: signals.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef HAVE_SIGNAL

#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
#endif /* HAVE_SETRLIMIT */

#ifndef NSIG
#define NSIG 100
#endif

unsigned long original_core_limit;

static RETSIGTYPE signal_handler(int sig)
{
  ssh_fatal("Received signal %d.", sig);
  exit(255);
}

/* Sets signal handlers so that core dumps are prevented.  This also
   sets the maximum core dump size to zero as an extra precaution (where
   supported).  The old core dump size limit is saved. */

void signals_prevent_core(void)
{
  int sig;

  for (sig = 1; sig <= NSIG; sig++)
    switch (sig)
      {
#ifdef SIGSTOP
      case SIGSTOP:
#endif
#ifdef SIGTSTP
      case SIGTSTP:
#endif
#ifdef SIGCONT
      case SIGCONT:
#endif
#ifdef SIGCHLD
      case SIGCHLD:
#endif
#ifdef SIGTTIN
      case SIGTTIN:
#endif
#ifdef SIGTTOU
      case SIGTTOU:
#endif
#ifdef SIGIO
      case SIGIO:
#endif
#if defined(SIGURG) && SIGURG != SIGIO
      case SIGURG:
#endif
#ifdef SIGWINCH
      case SIGWINCH:
#endif
#ifdef SIGINFO
      case SIGINFO:
#endif
	signal(sig, SIG_DFL);
	break;
      default:
	signal(sig, signal_handler);
	break;
      }

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    original_core_limit = rl.rlim_cur;
    rl.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}

/* Sets all signals to their default state.  Restores RLIMIT_CORE previously
   saved by prevent_core(). */

void signals_reset(void)
{
  int sig;

  for (sig = 1; sig <= NSIG; sig++)
    signal(sig, SIG_DFL);

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = original_core_limit;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}

#else  /* ! HAVE_SIGNAL */

void 
signals_prevent_core()
{
}

void
signals_reset()
{
}

#endif /* HAVE_SIGNAL */
