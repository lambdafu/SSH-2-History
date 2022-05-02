/*

osfc2.c

Author: Christophe Wolfhugel

Copyright (c) 1995 Christophe Wolfhugel

Free use of this file is permitted for any purpose as long as
this copyright is preserved in the header.

This program implements the use of the OSF/1 C2 security extensions
within ssh. See the file COPYING for full licensing informations.

*/

/*
 * $Id: tcbc2.c,v 1.1 1998/07/27 10:24:27 sjl Exp $
 * $Log: tcbc2.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "tcbc2.h"
#include <sys/security.h>
#include <prot.h>

#ifdef HAVE_SIA_H
#include <sia.h>
#endif /* HAVE_SIA_H */

static SshTcbC2Context tcbc2_ctx;

void
tcbc2_initialize_security(int ac, char **av)
{
  FILE *f;
  char buf[256];
  char siad[] = "siad_ses_init=";
  int i;

  tcbc2_ctx.c2security = -1;
  
  for (i = 0; i < 8; i++)
    tcbc2_ctx.osflim[i] = -1;

  if (access(SIAIGOODFILE, F_OK) == -1)
    {
      /* Broken OSF/1 system, better don't run on it. */
      ssh_warning("%s does not exist. Your OSF/1 system is probably broken.\n",
		  SIAIGOODFILE);
      exit(1);
    }
  if ((f = fopen(MATRIX_CONF, "r")) == NULL)
    {
      /* Another way OSF/1 is probably broken. */
      ssh_warning("%s unreadable. Your OSF/1 system is probably broken.\n",
		  MATRIX_CONF); 
      exit(1);
    }
  
  /* Read matrix.conf to check if we run C2 or not */
  while (fgets(buf, sizeof(buf), f) != NULL)
    {
      if (strncmp(buf, siad, sizeof(siad) - 1) == 0)
	{
	  if (strstr(buf, "OSFC2") != NULL)
	    tcbc2_ctx.c2security = 1;
	  else if (strstr(buf, "BSD") != NULL)
	    tcbc2_ctx.c2security = 0;
	  break;
	}
    }
  fclose(f);
  if (tcbc2_ctx.c2security == -1)
    {
      ssh_warning("C2 security initialization failed : could not determine "
		  "security level.\n");
      exit(1);
    }
  ssh_debug("OSF/1: security level : %s", tcbc2_ctx.c2security == 0 ? "BSD" : "C2");
  if (tcbc2_ctx.c2security == 1)
    set_auth_parameters(ac, av);
}

const char *tcbc2_check_account_and_terminal(const char *username,
					      const char *terminal)
{
  if (tcbc2_ctx.c2security == 1)
    {
      struct pr_passwd *pr = getprpwnam((char *) username);
      if (pr)
	{
	  if (pr->uflg.fg_lock == 1)
	    {
	      if (pr->ufld.fd_lock == 1)
		{
		  return "\n\tYour account is locked.\n\n";
		}
	    }
	  else
	    if (pr->sflg.fg_lock == 1 && pr->sfld.fd_lock == 1)
	      {
		return "\n\tYour account is locked.\n\n";
	      }
		
	  if (pr->uflg.fg_retired)
	    {
	      if (pr->ufld.fd_retired)
		{
		  return "\n\tYour account has been retired.\n\n";
		}
	    }
	  else
	    if (pr->sflg.fg_retired && pr->sfld.fd_retired)
	      {
		return "\n\tYour account has been retired.\n\n";
	      }
	  
#ifdef HAVE_TIME_LOCK
	  if (time_lock(pr))
	    {
	      return "\n\tWrong time period to log into this account.\n\n";
	    }
#endif /* HAVE_TIME_LOCK */
	  if (pr->uflg.fg_template)
	    {
#ifdef HAVE_GETESPWNAM
	      struct es_passwd *es = getespwnam(pr->ufld.fd_template);
	      if (es)
		{
#ifdef HAVE_GETESTCNAM
		  if (terminal != NULL)
		    {
		      struct es_term *term = getestcnam(terminal);
		      if (term)
			{
			  if (auth_for_terminal_es(es, term))
			    {
			      return "\n\tNot authorized to login from that terminal.\n\n";
			    }
			}
		    }
#endif /* HAVE_GETESTCNAM */
#ifdef HAVE_LOCKED_OUT_ES
		  if (locked_out_es(es))
		    {
		      return "\n\tYour account has been locked out.\n\n";
		    }
#endif /* HAVE_LOCKED_OUT_ES */
		  
		  /** Login resources **/
		  if (es->uflg->fg_rlim_cpu == 1) 
		    tcbc2_ctx.osflim[0] = es->ufld->fd_rlim_cpu;
		  if (es->uflg->fg_rlim_fsize == 1)
		    tcbc2_ctx.osflim[1] = es->ufld->fd_rlim_fsize;
		  if (es->uflg->fg_rlim_data == 1)
		    tcbc2_ctx.osflim[2] = es->ufld->fd_rlim_data;
		  if (es->uflg->fg_rlim_stack== 1)
		    tcbc2_ctx.osflim[3] = es->ufld->fd_rlim_stack;
		  if (es->uflg->fg_rlim_core == 1)
		    tcbc2_ctx.osflim[4] = es->ufld->fd_rlim_core;
		  if (es->uflg->fg_rlim_rss == 1)
		    tcbc2_ctx.osflim[5] = es->ufld->fd_rlim_rss;
		  if (es->uflg->fg_rlim_nofile == 1)
		    tcbc2_ctx.osflim[6] = es->ufld->fd_rlim_nofile;
		  if (es->uflg->fg_rlim_vmem == 1)
		    tcbc2_ctx.osflim[7] = es->ufld->fd_rlim_vmem;
		}
#endif /* HAVE_GETESPWNAM */
	    }
	}
    }
  return NULL;
}

int
tcbc2_getprpwent(char *p, char *n, int len)
{
  time_t pschg, tnow;

  if (tcbc2_ctx.c2security == 1)
    {
      struct es_passwd *es; 
      struct pr_passwd *pr = getprpwnam(n);
      if (pr)
	{
	  strncpy(p, pr->ufld.fd_encrypt, len);
	  tcbc2_ctx.crypt_algo = pr->ufld.fd_oldcrypt;

	  tnow = time(NULL);
	  if (pr->uflg.fg_schange == 1)
	    pschg = pr->ufld.fd_schange;
	  else
	    pschg = 0;
	  if (pr->uflg.fg_template == 0)
	    {
	      /** default template, system values **/
	      if (pr->sflg.fg_lifetime == 1)
		if (pr->sfld.fd_lifetime > 0 && 
		    pschg + pr->sfld.fd_lifetime < tnow)
		  return 1;
	      if (pr->sflg.fg_lifetime && pr->sfld.fd_lifetime > 0)
		tcbc2_ctx.days_before_password_expires =
		  (pschg + pr->sfld.fd_lifetime - tnow) / 86400;
	    }
	  else                      /** user template, specific values **/
	    {
#ifdef HAVE_GETESPWNAM
	      es = getespwnam(pr->ufld.fd_template);
	      if (es)
		{
		  if (es->uflg->fg_expire == 1) 
		    if (es->ufld->fd_expire > 0 &&
			pschg + es->ufld->fd_expire < tnow)
		      return 1;
		  if (es->uflg->fg_expire == 1 &&
		      es->ufld->fd_expire > 0)
		    tcbc2_ctx.days_before_password_expires =
		      (pschg + es->ufld->fd_expire - tnow) / 86400;
		  
		}
#endif /* HAVE_GETESPWNAM */
	    }
	}
    }
  else
    {
      struct passwd *pw = getpwnam(n);
      if (pw)
	strncpy(p, pw->pw_passwd, len);
    }
  return 0;
}

char *
tcbc2_crypt(const char *pw, char *salt)
{
   if (tcbc2_ctx.c2security == 1)
     return(dispcrypt(pw, salt, tcbc2_ctx.crypt_algo));
   else
     return(crypt(pw, salt));
}
