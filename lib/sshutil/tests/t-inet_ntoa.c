/*

  t-inet_ntoa.c
  
  Author: Sami Lehtinen <sjl@ssh.fi>

  
  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

 */

#include "sshincludes.h"

struct in_addr {
  unsigned long s_addr;
};

char *inet_ntoa(struct in_addr in);

main()
{
   char *addr;
   struct in_addr in;
   memset(&in, 0, sizeof(in));
   addr = inet_ntoa(in);
   if (strcmp(addr, "0.0.0.0"))
     {
       fprintf(stderr, "t-inet_ntoa failed. (addr = %s) \n", addr);
       return 1;
     }
   
   return 0;
}
