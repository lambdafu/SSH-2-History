/*
  Author: Sami Lehtinen <sjl@ssh.fi>
  Original author: William C. Ray <ray@soyokaze.biosci.ohio-state.edu>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
  
*/


#include "sshincludes.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else /* HAVE_NETINET_IN_H */
#ifndef WINDOWS /* already defined in most OS */
struct in_addr {
  SshUInt32 s_addr;
};
#endif /* ! WINDOWS */
#endif /* HAVE_NETINET_IN_H */

char *inet_ntoa(struct in_addr in)
{
  SshUInt32 my_address;
  SshUInt32 hold_address;
  int a,b,c,d;
  static char outstring[16];
  my_address = in.s_addr;

  hold_address = my_address;
  d = hold_address%256;
  hold_address = hold_address/256;
  c = hold_address%256;
  hold_address = hold_address/256;
  b = hold_address%256;
  hold_address = hold_address/256;
  a = hold_address%256;

  snprintf(outstring, sizeof(outstring), "%d.%d.%d.%d", a, b, c, d);

  return outstring;
}
