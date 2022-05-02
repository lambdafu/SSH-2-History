/*

  signals.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Manipulation of signal state.  This file also contains code to set the
maximum core dump size.

*/

/*
 * $Log: signals.c,v $
 * $EndLog$
 */

#include "ssh2includes.h"
#include "signals.h"
#include "sshunixeloop.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

#ifndef NSIG
#define NSIG 32
#endif

unsigned long original_core_limit;

void core_signal_handler(int sig, void *ctx)
{
  /* XXX logging */
  
  fprintf(stderr, "\nReceived signal %d. (no core)\n", sig);
  exit(255);
}

/* Test if given signal is terminal ("TRUE") or not. */

Boolean ssh_sig_terminal(int sig)
{
  switch (sig)
    {
      case SIGSTOP:
      case SIGTSTP:
      case SIGCONT:
      case SIGCHLD:
      case SIGTTIN:
      case SIGTTOU:
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
#if defined(SIGFREEZE)
      case SIGFREEZE:
#endif
#if defined(SIGTHAW)
      case SIGTHAW:
#endif
        return FALSE;
      
      default:	
	break;      
    }
  return TRUE;
}

/* Sets signal handlers so that core dumps are prevented.  This also
   sets the maximum core dump size to zero as an extra precaution (where
   supported).  The old core dump size limit is saved. */

void signals_prevent_core(void *ctx)
{
  int sig;

  /* Put a handler on all signals that look terminal */
  
  for (sig = 1; sig <= NSIG; sig++)
    if (ssh_sig_terminal(sig))
      ssh_register_signal(sig, core_signal_handler, ctx);

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

void signals_reset()
{
  int sig;

  /* unregister all signals that we have an handler on */
  
  for (sig = 1; sig <= NSIG; sig++)
    if (ssh_sig_terminal(sig))
      ssh_unregister_signal(sig);

#if defined(HAVE_SETRLIMIT) && defined(RLIMIT_CORE)
  {
    struct rlimit rl;
    getrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = original_core_limit;
    setrlimit(RLIMIT_CORE, &rl);
  }
#endif /* HAVE_SETRLIMIT && RLIMIT_CORE */
}
