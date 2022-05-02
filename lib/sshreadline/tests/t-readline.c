/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshreadline test
 *        $Source: /ssh/CVS/src/lib/sshreadline/tests/t-readline.c,v $
 *        $Author: ylo $
 *
 *        Creation          : 06:45 Mar 14 1997 kivinen
 *        Last Modification : 06:57 Mar 14 1997 kivinen
 *        Last check in     : $Date: 1998/01/28 10:12:57 $
 *        Revision number   : $Revision: 1.2 $
 *        State             : $State: Exp $
 *        Version           : 1.4
 *
 *        Description       : Readline library test program
 *
 *
 *        $Log: t-readline.c,v $
 *        $EndLog$
 */

#include "sshincludes.h"
#include "sshreadline.h"

int main(int argc, char **argv)
{
  unsigned char *line, *prompt;

  if (argc >= 2)
    prompt = argv[1];
  else
    prompt = "*> ";
  
  if (argc >= 3)
    line = strdup(argv[2]);
  else
    line = NULL;
  
  ssh_readline(prompt, &line, 0);

  printf("\n");
  printf("line = `%s'\n", line);
  exit(0);
}
