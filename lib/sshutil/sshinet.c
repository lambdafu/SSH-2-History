/*
  File: sship.c

  Authors: 
  	Tero T Mononen <tmo@ssh.fi>

  Description: 
	

  Copyright:
  	Copyright (c) 1998 SSH Communications Security, Finland
	All rights reserved

  Reviews:
  	FUPR:	

*/

#include "sshincludes.h"
#include "sshinet.h"

#define MAX_IP_ADDR_LEN 16

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else /* HAVE_NETINET_IN_H */
#ifndef WINDOWS /* already defined in most OS */
struct in_addr {
  SshUInt32 s_addr;
};
#endif /* ! WINDOWS */
#endif /* HAVE_NETINET_IN_H */

/* Mapping between protocol name and doi protocol number */
const SshKeyword ssh_ip_protocol_id_keywords[] = 
{
  { "any", IP_PROTOCOL_ID_ANY },
  { "icmp", IP_PROTOCOL_ID_ICMP },
  { "igmp", IP_PROTOCOL_ID_IGMP },
  { "ggp", IP_PROTOCOL_ID_GGP },
  { "ipip", IP_PROTOCOL_ID_IPIP },
  { "st", IP_PROTOCOL_ID_ST },
  { "tcp", IP_PROTOCOL_ID_TCP },
  { "cbt", IP_PROTOCOL_ID_CBT },
  { "egp", IP_PROTOCOL_ID_EGP },
  { "igp", IP_PROTOCOL_ID_IGP },
  { "bbn", IP_PROTOCOL_ID_BBN },
  { "nvp", IP_PROTOCOL_ID_NVP },
  { "pup", IP_PROTOCOL_ID_PUP },
  { "argus", IP_PROTOCOL_ID_ARGUS },
  { "emcon", IP_PROTOCOL_ID_EMCON },
  { "xnet", IP_PROTOCOL_ID_XNET },
  { "chaos", IP_PROTOCOL_ID_CHAOS },
  { "udp", IP_PROTOCOL_ID_UDP },
  { "mux", IP_PROTOCOL_ID_MUX },
  { "dcn", IP_PROTOCOL_ID_DCN },
  { "hmp", IP_PROTOCOL_ID_HMP },
  { "prm", IP_PROTOCOL_ID_PRM },
  { "xns", IP_PROTOCOL_ID_XNS },
  { "trunk1", IP_PROTOCOL_ID_TRUNK1 },
  { "trunk2", IP_PROTOCOL_ID_TRUNK2 },
  { "leaf1", IP_PROTOCOL_ID_LEAF1 },
  { "leaf2", IP_PROTOCOL_ID_LEAF2 },
  { "rdp", IP_PROTOCOL_ID_RDP },
  { "irtp", IP_PROTOCOL_ID_IRTP },
  { "isotp4", IP_PROTOCOL_ID_ISOTP4 },
  { "netblt", IP_PROTOCOL_ID_NETBLT },
  { "mfe", IP_PROTOCOL_ID_MFE },
  { "merit", IP_PROTOCOL_ID_MERIT },
  { "sep", IP_PROTOCOL_ID_SEP },
  { "3pc", IP_PROTOCOL_ID_3PC },
  { "idpr", IP_PROTOCOL_ID_IDPR },
  { "xtp", IP_PROTOCOL_ID_XTP },
  { "ddp", IP_PROTOCOL_ID_DDP },
  { "idprc", IP_PROTOCOL_ID_IDPRC },
  { "tp", IP_PROTOCOL_ID_TP },
  { "il", IP_PROTOCOL_ID_IL },
  { "ipv6", IP_PROTOCOL_ID_IPV6 },
  { "sdrp", IP_PROTOCOL_ID_SDRP },
  { "ipv6route", IP_PROTOCOL_ID_IPV6ROUTE },
  { "ipv6frag", IP_PROTOCOL_ID_IPV6FRAG },
  { "idrp", IP_PROTOCOL_ID_IDRP },
  { "rsvp", IP_PROTOCOL_ID_RSVP },
  { "gre", IP_PROTOCOL_ID_GRE },
  { "mhrp", IP_PROTOCOL_ID_MHRP },
  { "bna", IP_PROTOCOL_ID_BNA },
  { "esp", IP_PROTOCOL_ID_ESP },
  { "ah", IP_PROTOCOL_ID_AH },
  { "inlsp", IP_PROTOCOL_ID_INLSP },
  { "swipe", IP_PROTOCOL_ID_SWIPE },
  { "narp", IP_PROTOCOL_ID_NARP },
  { "mobile", IP_PROTOCOL_ID_MOBILE },
  { "tlsp", IP_PROTOCOL_ID_TLSP },
  { "skip", IP_PROTOCOL_ID_SKIP },
  { "ipv6icmp", IP_PROTOCOL_ID_IPV6ICMP },
  { "ipv6nonxt", IP_PROTOCOL_ID_IPV6NONXT },
  { "ipv6opts", IP_PROTOCOL_ID_IPV6OPTS },
  { "cftp", IP_PROTOCOL_ID_CFTP },
  { "local", IP_PROTOCOL_ID_LOCAL },
  { "sat", IP_PROTOCOL_ID_SAT },
  { "kryptolan", IP_PROTOCOL_ID_KRYPTOLAN },
  { "rvd", IP_PROTOCOL_ID_RVD },
  { "ippc", IP_PROTOCOL_ID_IPPC },
  { "distfs", IP_PROTOCOL_ID_DISTFS },
  { "satmon", IP_PROTOCOL_ID_SATMON },
  { "visa", IP_PROTOCOL_ID_VISA },
  { "ipcv", IP_PROTOCOL_ID_IPCV },
  { "cpnx", IP_PROTOCOL_ID_CPNX },
  { "cphb", IP_PROTOCOL_ID_CPHB },
  { "wsn", IP_PROTOCOL_ID_WSN },
  { "pvp", IP_PROTOCOL_ID_PVP },
  { "brsatmon", IP_PROTOCOL_ID_BRSATMON },
  { "sunnd", IP_PROTOCOL_ID_SUNND },
  { "wbmon", IP_PROTOCOL_ID_WBMON },
  { "wbexpak", IP_PROTOCOL_ID_WBEXPAK },
  { "isoip", IP_PROTOCOL_ID_ISOIP },
  { "vmtp", IP_PROTOCOL_ID_VMTP },
  { "securevmtp", IP_PROTOCOL_ID_SECUREVMTP },
  { "vines", IP_PROTOCOL_ID_VINES },
  { "ttp", IP_PROTOCOL_ID_TTP },
  { "nsfnet", IP_PROTOCOL_ID_NSFNET },
  { "dgp", IP_PROTOCOL_ID_DGP },
  { "tcf", IP_PROTOCOL_ID_TCF },
  { "eigrp", IP_PROTOCOL_ID_EIGRP },
  { "ospfigp", IP_PROTOCOL_ID_OSPFIGP },
  { "sprite", IP_PROTOCOL_ID_SPRITE },
  { "larp", IP_PROTOCOL_ID_LARP },
  { "mtp", IP_PROTOCOL_ID_MTP },
  { "ax25", IP_PROTOCOL_ID_AX25 },
  { "ipwip", IP_PROTOCOL_ID_IPWIP },
  { "micp", IP_PROTOCOL_ID_MICP },
  { "scc", IP_PROTOCOL_ID_SCC },
  { "etherip", IP_PROTOCOL_ID_ETHERIP },
  { "encap", IP_PROTOCOL_ID_ENCAP },
  { "encrypt", IP_PROTOCOL_ID_ENCRYPT },
  { "gmtp", IP_PROTOCOL_ID_GMTP },
  { "ifmp", IP_PROTOCOL_ID_IFMP },
  { "pnni", IP_PROTOCOL_ID_PNNI },
  { "pim", IP_PROTOCOL_ID_PIM },
  { "aris", IP_PROTOCOL_ID_ARIS },
  { "scps", IP_PROTOCOL_ID_SCPS },
  { "qnx", IP_PROTOCOL_ID_QNX },
  { "an", IP_PROTOCOL_ID_AN },
  { "ippcp", IP_PROTOCOL_ID_IPPCP },
  { "snp", IP_PROTOCOL_ID_SNP },
  { "compaq", IP_PROTOCOL_ID_COMPAQ },
  { "ipxip", IP_PROTOCOL_ID_IPXIP },
  { "vrrp", IP_PROTOCOL_ID_VRRP },
  { "pgm", IP_PROTOCOL_ID_PGM },
  { "0hop", IP_PROTOCOL_ID_0HOP },
  { "l2tp", IP_PROTOCOL_ID_L2TP },
  { "reserved", IP_PROTOCOL_ID_RESERVED },
  { NULL, 0 }
};

typedef enum {
  SSH_INET_ADDR_V4,
  SSH_INET_ADDR_V6
} SshInetAddressFamily;

#define INADDRSZ     4
#define IN6ADDRSZ   16

static SshUInt32 ssh_inet_addr(register const char *cp);
static int ssh_inet_pton(SshInetAddressFamily af, const char *src, void *dst);
static int ssh_inet_pton4(const char *src, unsigned char *dst);
static int ssh_inet_pton6(const char *src, unsigned char *dst);

/* Converts the string representation of the address to the internal
   representation. */
Boolean ssh_string_to_addr(const char *s, struct in_addr *addr)
{
  addr->s_addr = ssh_inet_addr(s);
  if ((addr->s_addr & 0xffffffff) == 0xffffffff)
    {
      if (strcmp(s, "255.255.255.255") == 0)
	return TRUE;
    }
  return (addr->s_addr & 0xffffffff) != 0xffffffff;
}

char *ssh_inet_v4tostr(char *buf, size_t len, SshUInt32 addr)
{
  unsigned char *octets = (unsigned char *)&addr;

  snprintf(buf, len, "%d.%d.%d.%d",
	   octets[0], octets[1], octets[2], octets[3]);
  return buf;
}

Boolean ssh_inet_strtov4(const char *buf, SshUInt32 *paddr)
{
  struct in_addr addr;

  ssh_string_to_addr(buf, &addr);
  *paddr = addr.s_addr;
  return (*paddr & 0xffffffff) != 0xffffffff;
}

/* Convert ip number string to binary format. The binary format is
   unsigned character array containing the ip address in network byte
   order. If the ip address is ipv4 address then this fills 4 bytes to
   the buffer, if it is ipv6 address then this will fills 16 bytes to
   the buffer. The buffer length is modified accordingly. This returns
   TRUE if the address is valid and conversion is successful (the
   buffer is large enough) and FALSE otherwise.  */
Boolean ssh_inet_strtobin(const char *ip_address, 
			  unsigned char *out_buffer,
			  size_t *out_buffer_len_in_out)
{
  if (ssh_inet_is_valid_ip_address(ip_address))
    {
      /* The ssh_inet_is_valid_ip_address only supports ipv4 addresses, so
	 this must be ipv4 address. */
      SshUInt32 ip;
      
      if (*out_buffer_len_in_out < 4)
	return FALSE;

      if (!ssh_inet_strtov4(ip_address, &ip))
	return FALSE;

      memcpy(out_buffer, &ip, 4);
      *out_buffer_len_in_out = 4;
      return TRUE;
    }
  else
    {
      return FALSE;
    }
}

/* Compares comma separated list of ip nets and ip-address. Returns
   TRUE if ip-address is inside one of the nets given in
   net-address/netmask-bits format. */
Boolean ssh_inet_compare_netmask(const char *netmask, const char *ip_in)
{
  unsigned char net[MAX_IP_ADDR_LEN], mask[MAX_IP_ADDR_LEN],
    ip[MAX_IP_ADDR_LEN];
  size_t len;
  char temp_buffer[256], *p, *ep, *next;
  int mask_bits;

  memset(net, 0, MAX_IP_ADDR_LEN);
  memset(ip, 0, MAX_IP_ADDR_LEN);

  len = MAX_IP_ADDR_LEN;
  if (!ssh_inet_strtobin(ip_in, ip, &len))
    return FALSE;

  if (len == 4)
    {
      memmove(ip + 12, ip, 4);
      memset(ip, 0, 4);
    }
  do {
    p = strchr(netmask, ',');
    if (p != NULL)
      {
	next = p + 1;
	if (p - netmask < sizeof(temp_buffer))
	  {
	    strncpy(temp_buffer, netmask, p - netmask);
	    temp_buffer[p - netmask] = '\0';
	  }
	else
	  {
	    strncpy(temp_buffer, netmask, sizeof(temp_buffer));
	    temp_buffer[sizeof(temp_buffer) - 1] = '\0';
	  }
      }
    else
      {
	next = NULL;
	strncpy(temp_buffer, netmask, sizeof(temp_buffer));
	temp_buffer[sizeof(temp_buffer) - 1] = '\0';
      }
    p = strrchr(temp_buffer, '/');
    if (p == NULL)
      {
	mask_bits = MAX_IP_ADDR_LEN * 8;
      }
    else
      {
	*p++ = '\0';
	mask_bits = strtol(p, &ep, 0);
	if (p == ep)
	  mask_bits = -1;
      }
    len = MAX_IP_ADDR_LEN;
    if (ssh_inet_strtobin(temp_buffer, net, &len) && mask_bits != -1)
      {
	if (len == 4)
	  {
	    memmove(net + 12, net, 4);
	    memset(net, 0, 4);
	    mask_bits += 96;
	  }
	if (mask_bits > 128)
	  mask_bits = 128;

	memset(mask, 0, MAX_IP_ADDR_LEN);
	memset(mask, 255, mask_bits / 8);
	if (mask_bits % 8 != 0)
	  mask[mask_bits / 8] =
	    "\000\200\300\340\360\370\374\376"[mask_bits % 8];
	for(len = 0; len < MAX_IP_ADDR_LEN; len++)
	  {
	    if ((ip[len] & mask[len]) != (net[len] & mask[len]))
	      break;
	  }
	if (len == MAX_IP_ADDR_LEN)
	  return TRUE;
      }
    netmask = next;
  } while (netmask != NULL);
  return FALSE;
}

/* Determines whether the given string is a valid numeric IP address.
   (This currently only works for IPv4 addresses, but might be changed
   in future to accept also IPv6 addresses on systems that support
   them. */
Boolean ssh_inet_is_valid_ip_address(const char *address)
{
  int i, num;

  /* Loop over four groups of numbers. */
  for (i = 0; i < 4; i++)
    {
      /* Each but the first group must be preceded by a dot. */
      if (i != 0)
	if (*address != '.')
	  return FALSE;
        else
	  address++;

      /* Each group must begin with a digit (now that we have skipped the
	 dot). */
      if (!isdigit(*address))
	return FALSE;

      /* Parse the group of digits as a number.  Check that the group does
	 not have a value greater than 255.  Beware of overflows. */
      for (num = 0; isdigit(*address) && num < 256; address++)
	num = 10 * num + *address - '0';
      if (num > 255)
	return FALSE;
    }

  /* After the four groups of numbers, we must be at end of string. */
  if (*address != '\0')
    return FALSE;

  /* Yes, it is a valid IPv4 address. */
  return TRUE;
}


/* Compares two IP addresses, and returns <0 if address1 is smaller
   (in some implementation-defined sense, usually numerically), 0 if
   they denote the same address (though possibly written differently),
   and >0 if address2 is smaller (in the implementation-defined
   sense).  The result is zero if either address is invalid. */
int ssh_inet_ip_address_compare(const char *address1, const char *address2)
{
  struct in_addr addr1, addr2;

  if (!ssh_string_to_addr(address1, &addr1) ||
      !ssh_string_to_addr(address2, &addr2))
    return 0;
  if (addr1.s_addr == addr2.s_addr)
    return 0;
  else
    if (addr1.s_addr < addr2.s_addr)
      return -1;
    else
      return 1;
}

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* int
 * ssh_inet_pton(af, src, dst)
 *	convert from presentation format (which usually means ASCII printable)
 *	to network format (which is usually some kind of binary format).
 * return:
 *	1 if the address was valid for the specified address family
 *	0 if the address wasn't valid (`dst' is untouched in this case)
 *	-1 if some other error occurred (`dst' is untouched in this case, too)
 * author:
 *	Paul Vixie, 1996.
 */
static int ssh_inet_pton(SshInetAddressFamily af, const char *src, void *dst)
{
  switch (af) 
    {
    case SSH_INET_ADDR_V4:
      return (ssh_inet_pton4(src, dst));
    case SSH_INET_ADDR_V6:
      return (ssh_inet_pton6(src, dst));
    default:
      return (-1);
    }
}

/* int
 * ssh_inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return: 1 if `src' is a valid dotted quad, else 0.
 * notice: does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
static int ssh_inet_pton4(const char *src, unsigned char *dst)
{
  SshUInt32 val;
  int base, n;
  unsigned char c;
  SshUInt32 parts[4];
  register SshUInt32 *pp = parts;

  c = *src;
  for (;;) 
    {
      /*
       * Collect number up to ``.''.
       * Values are specified as for C:
       * 0x=hex, 0=octal, isdigit=decimal.
       */
      if (!isdigit(c))
	return (0);
      val = 0; base = 10;
      if (c == '0') 
	{
	  c = *++src;
	  if (c == 'x' || c == 'X')
	    base = 16, c = *++src;
	  else
	    base = 8;
	}
      for (;;) 
	{
	  if (isdigit(c)) 
	    {
	      val = (val * base) + (c - '0');
	      c = *++src;
	    } 
	  else if (base == 16 && isxdigit(c)) 
	    {
	      val = (val << 4) |
		(c + 10 - (islower(c) ? 'a' : 'A'));
	      c = *++src;
	    } 
	  else
	    break;
	}
      if (c == '.') 
	{
	  /*
	   * Internet format:
	   *	a.b.c.d
	   *	a.b.c	(with c treated as 16 bits)
	   *	a.b	(with b treated as 24 bits)
	   */
	  if (pp >= parts + 3)
	    return (0);
	  *pp++ = val;
	  c = *++src;
	} 
      else
	break;
    }
  /*
   * Check for trailing characters.
   */
  if (c != '\0' && !isspace(c))
    return (0);

  n = pp - parts + 1;
  switch (n) 
    {
    case 0:
      return (0);		/* initial nondigit */
    case 1:				/* a -- 32 bits */
      break;
    case 2:				/* a.b -- 8.24 bits */
      if (val > 0xffffff)
	return (0);
      val |= parts[0] << 24;
      break;
    case 3:				/* a.b.c -- 8.8.16 bits */
      if (val > 0xffff)
	return (0);
      val |= (parts[0] << 24) | (parts[1] << 16);
      break;
    case 4:				/* a.b.c.d -- 8.8.8.8 bits */
      if (val > 0xff)
	return (0);
      val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
      break;
    }
  if (dst) 
    {
      val = htonl(val);
      memcpy(dst, &val, INADDRSZ);
    }
  return (1);
}

/* Convert presentation level address to network order binary form.
   return: 1 if `src' is a valid [RFC1884 2.2] address, else 0.

   notice: (1) does not touch `dst' unless it's returning 1.  
           (2) :: in a full address is silently ignored.  
   credit: inspired by Mark Andrews.  author: Paul Vixie, 1996.  */
static int ssh_inet_pton6(const char *src, unsigned char *dst)
{
  static const char xdigits_l[] = "0123456789abcdef";
  static const char xdigits_u[] = "0123456789ABCDEF";
  unsigned char tmp[IN6ADDRSZ], *tp, *endp, *colonp;
  const char *xdigits, *curtok;
  int ch, saw_xdigit;
  SshUInt32 val;

  memset((tp = tmp), '\0', IN6ADDRSZ);
  endp = tp + IN6ADDRSZ;
  colonp = NULL;

  /* Leading :: requires some special handling. */
  if (*src == ':')
    if (*++src != ':')
      return (0);
  curtok = src;
  saw_xdigit = 0;
  val = 0;

  while ((ch = *src++) != '\0') 
    {
      const char *pch;

      if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
	pch = strchr((xdigits = xdigits_u), ch);
      if (pch != NULL) 
	{
	  val <<= 4;
	  val |= (pch - xdigits);
	  if (val > 0xffff)
	    return (0);
	  saw_xdigit = 1;
	  continue;
	}
      if (ch == ':') 
	{
	  curtok = src;
	  if (!saw_xdigit) 
	    {
	      if (colonp)
		return (0);
	      colonp = tp;
	      continue;
	    }
	  if (tp + sizeof(SshUInt16) > endp)
	    return (0);
	  *tp++ = (unsigned char) (val >> 8) & 0xff;
	  *tp++ = (unsigned char) val & 0xff;
	  saw_xdigit = 0;
	  val = 0;
	  continue;
	}
      if (ch == '.' && ((tp + INADDRSZ) <= endp) && ssh_inet_pton4(curtok, tp) > 0) 
	{
	  tp += INADDRSZ;
	  saw_xdigit = 0;
	  break;	/* '\0' was seen by ssh_inet_pton4(). */
	}
      return (0);
    }
  if (saw_xdigit) 
    {
      if (tp + sizeof(SshUInt16) > endp)
	return (0);
      *tp++ = (unsigned char) (val >> 8) & 0xff;
      *tp++ = (unsigned char) val & 0xff;
    }
  if (colonp != NULL) 
    {
      const int n = tp - colonp;
      int i;

      for (i = 1; i <= n; i++) 
	{
	  endp[- i] = colonp[n - i];
	  colonp[n - i] = 0;
	}
      tp = endp;
    }
  if (tp != endp)
    return (0);
  memcpy(dst, tmp, IN6ADDRSZ);
  return (1);
}

/* Ascii internet address interpretation routine.The value returned is
   in network order. */
static SshUInt32 ssh_inet_addr(register const char *cp)
{
  struct in_addr val;

  if (cp)
    {
      if (ssh_inet_pton4(cp, (unsigned char *)&val.s_addr))
	return (val.s_addr);
    }
  return (SshUInt32)0xffffffff;
}

/* eof */
