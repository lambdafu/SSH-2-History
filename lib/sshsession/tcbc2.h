/*

  tcbc2.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
	Sami Lehtinen <sjl@ssh.fi>
	
  Copyright (C) 1997-1998 SSH Communications Security, Espoo, Finland
  All rights reserved

OSF/1 (Digital Unix) specific defines.

*/

#ifndef TCBC2_H
#define TCBC2_H

typedef struct SshTcbC2ContextRec
{
  int c2security;
  int crypt_algo;
  long osflim[8];
  /* temp kludge, remove later */
  int days_before_password_expires;
} SshTcbC2Context;

void tcbc2_initialize_security(int ac, char **av);
int tcbc2_getprpwent(char *p, char *n, int len);
char *tcbc2_crypt(const char *pw, char *salt);
const char *tcbc2_check_account_and_terminal(const char *username,
					      const char *terminal);
#endif /* TCBC2_H */


