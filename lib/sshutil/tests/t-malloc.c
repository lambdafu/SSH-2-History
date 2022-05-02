/*

t-malloc.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1996 SSH Communications Security, Finland
                   All rights reserved

Created: Thu Oct 24 22:59:37 1996 ylo
Last modified: Wed Jan 28 09:54:23 1998 ylo

*/

#include "sshincludes.h"

char *p[10000];

int main(int ac, char **av)
{
  int pass;
  int i, j, len;

  for (pass = 0; pass < 10; pass++)
    {
      for (i = 0; i < 10000; i++)
	{
	  len = random() % 1000;
	  if (random() % 256 == 0)
	    len += random() % 65000;
	  if (random() % 2)
	    p[i] = ssh_xmalloc(len);
	  else
	    p[i] = ssh_xcalloc(len, 1);
	  if (p[i] == NULL)
	    {
	      printf("ssh_xmalloc %d bytes failed\n", len);
	      exit(1);
	    }
	  memset(p[i], i, len);
	}

      for (i = 0; i < 10000; i++)
	{
	  p[i] = ssh_xrealloc(p[i], random() % 2000);
	  if (p[i] == NULL)
	    {
	      printf("ssh_xrealloc failed\n");
	      exit(1);
	    }
	}

      for (i = 0; i < 1000; i++)
	{
	  if (p[i])
	    {
	      ssh_xfree(p[i]);
	      p[i] = NULL;
	    }
	  j = random() % 10000;
	  if (p[j])
	    {
	      ssh_xfree(p[j]);
	      p[j] = NULL;
	    }
	}

      for (i = 0; i < 1000; i++)
	p[i] = ssh_xmalloc(random() % 1000);

      for (i = 0; i < 10000; i++)
	if (p[i])
	  ssh_xfree(p[i]);

    }

  return 0;
}
