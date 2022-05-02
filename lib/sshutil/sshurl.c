/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1998 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: Urlparse
 *        $Source: /ssh/CVS/src/lib/sshutil/sshurl.c,v $
 *        $Author: kivinen $
 *
 *        Creation          : 10:04 Jul 10 1998 kivinen
 *        Last Modification : 12:14 Jul 10 1998 kivinen
 *        Last check in     : $Date: 1998/07/10 13:28:17 $
 *        Revision number   : $Revision: 1.1 $
 *        State             : $State: Exp $
 *        Version           : 1.95
 *
 *        Description       : Library to parse urls
 */
/*
 * $Id: sshurl.c,v 1.1 1998/07/10 13:28:17 kivinen Exp $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshbuffer.h"

/*
 * Parses url given in format
 * [<scheme>:][//[<user>[:<password>]@]<host>[:<port>]]/[<path>]
 * Returns true if the url is syntactically valid, false otherwise.
 * If the incorrect url format "www.ssh.fi" is given then returns FALSE and
 * sets host to contain whole url. If some piece of url is not given it is
 * set to NULL. If some of the pieces are not needed they can be NULL and
 * those pieces will be skipped. 
 */
Boolean ssh_url_parse(const char *url, char **scheme, char **host,
	 	      char **port, char **username, char **password,
		      char **path)
{
  const char *p, *q, *start;

  p = url;

  if (scheme)
    *scheme = NULL;
  if (host)
    *host = NULL;
  if (port)
    *port = NULL;
  if (username)
    *username = NULL;
  if (password)
    *password = NULL;
  if (path)
    *path = NULL;

  while (isspace(*p))
    p++;

  if (!*p)
    {
      return FALSE;
    }

  start = p;
  while (isalpha(*p) || isdigit(*p) || *p == '+' || *p == '-' || *p == '.')
    p++;

  /* Check for scheme */
  if (*p == ':')
    {
      if (scheme != NULL)
	*scheme = ssh_xmemdup(start, p - start);
      p++;
      start = p;
    }

  p = start;
  /* Do we have host name part */
  if (p[0] == '/' && p[1] == '/')
    {
      start += 2;

      p = start;
      /* Check for username and password */
      while (*p && *p != '@' && *p != '/')
	p++;

      if (*p == '@')
	{
	  /* User name (and possible password found) */

	  q = p;
	  while (q > start && *q != ':')
	    q--;

	  if (*q == ':')
	    {
	      /* Password found */
	      if (username != NULL)
		*username = ssh_xmemdup(start, q - start);
	      if (password != NULL)
		*password = ssh_xmemdup(q + 1, p - (q + 1));
	    }
	  else
	    {
	      /* Only username found */
	      if (username != NULL)
		*username = ssh_xmemdup(start, p - start);
	    }
	  p++;
	  start = p;
	}

      p = start;
      /* Check for host name */
      while (*p && *p != ':' && *p != '/')
	p++;

      if (host != NULL)
	*host = ssh_xmemdup(start, p - start);
      start = p;
      
      if (*p == ':')
	{
	  start = ++p;

	  while (isdigit(*p))
	    p++;

	  if (port != NULL)
	    *port = ssh_xmemdup(start, p - start);
	  
	  start = p;
	}
    }

  if (!*p)
    {
      return TRUE;
    }

  if (*p != '/')
    {
      if (host != NULL && *host == NULL)
	*host = ssh_xstrdup(p);
      else
	if (path != NULL)
	  *path = ssh_xstrdup(p);
      return FALSE;
    }
  else
    {
      if (path != NULL)
	*path = ssh_xstrdup(p + 1);
      return TRUE;
    }
}

/*
 * Decode url coding. If url_out is NULL then decode inplace, and modify url.
 * Otherwise return new allocated string containing the decoded buffer. Returns
 * TRUE if decoding was successfull and FALSE otherwise.
 */
Boolean ssh_url_decode(char *url, char **url_out)
{
  char *src, *dst;
  unsigned int x;
  Boolean ok = TRUE;

  if (url_out != NULL)
    {
      *url_out = ssh_xstrdup(url);
      url = *url_out;
    }

  src = url;
  dst = url;
  while (*src)
    {
      if (*src == '%')
	{
	  if (isxdigit(src[1]) && isxdigit(src[2]))
	    {
	      if (isdigit(src[1]))
		x = src[1] - '0';
	      else
		x = tolower(src[1]) - 'a' + 10;
	      x *= 16;

	      if (isdigit(src[2]))
		x += src[2] - '0';
	      else
		x += tolower(src[2]) - 'a' + 10;

	      *dst++ = x;
	      src += 3;
	    }
	  else
	    {
	      *dst++ = *src++;
	      ok = FALSE;
	    }
	}
      else
	{
	  *dst++ = *src++;
	}
    }
  *dst = 0;
  return ok;
}

/*
 * Parses url given in format
 * [<scheme>:][//[<user>[:<password>]@]<host>[:<port>]]/[<path>]
 * Returns true if the url is syntactically valid, false otherwise.
 * If the incorrect url format "www.ssh.fi" is given then returns FALSE and
 * sets host to contain whole url. If some piece of url is not given it is
 * set to NULL. If some of the pieces are not needed they can be NULL and
 * those pieces will be skipped. This version also decodeds url %-codings.
 */
Boolean ssh_url_parse_and_decode(const char *url, char **scheme, char **host,
				 char **port, char **username, char **password,
				 char **path)
{
  Boolean ok;
  
  ok = ssh_url_parse(url, scheme, host, port, username, password, path);

  if (scheme && *scheme)
    if (!ssh_url_decode(*scheme, NULL))
      ok = FALSE;
  if (host && *host)
    if (!ssh_url_decode(*host, NULL))
      ok = FALSE;
  if (port && *port)
    if (!ssh_url_decode(*port, NULL))
      ok = FALSE;
  if (username && *username)
    if (!ssh_url_decode(*username, NULL))
      ok = FALSE;
  if (password && *password)
    if (!ssh_url_decode(*password, NULL))
      ok = FALSE;
  if (path && *path)
    if (!ssh_url_decode(*path, NULL))
      ok = FALSE;

  return ok;
}
