/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1998 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: Urlparse
 *        $Source: /ssh/CVS/src/lib/sshutil/tests/t-url.c,v $
 *        $Author: kivinen $
 *
 *        Creation          : 10:45 Jul 10 1998 kivinen
 *        Last Modification : 12:13 Jul 10 1998 kivinen
 *        Last check in     : $Date: 1998/07/10 13:28:30 $
 *        Revision number   : $Revision: 1.1 $
 *        State             : $State: Exp $
 *        Version           : 1.43
 *
 *        Description       : Test program for library to parse urls
 */
/*
 * $Id: t-url.c,v 1.1 1998/07/10 13:28:30 kivinen Exp $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshurl.h"

typedef struct TestUrlRec {
  const char *url;
  const char *scheme;
  const char *host;
  const char *username;
  const char *password;
  const char *port;
  const char *path;
  Boolean ok;
} *TestUrl;

struct TestUrlRec tests[] = {
  { "http://www.ssh.fi/testing/host",
    "http", "www.ssh.fi", NULL, NULL, NULL, "testing/host", TRUE },
  { "ftp://kivinen:foobar@ftp.ssh.fi:21/hidden",
    "ftp", "ftp.ssh.fi", "kivinen", "foobar", "21", "hidden", TRUE },
  { "scheme://username:password@host:2222/path",
    "scheme", "host", "username", "password", "2222", "path", TRUE },
  { "scheme://username:password@host/path",
    "scheme", "host", "username", "password", NULL, "path", TRUE },
  { "scheme://username@host:2222/path",
    "scheme", "host", "username", NULL, "2222", "path", TRUE },
  { "scheme://username:@host:2222/path",
    "scheme", "host", "username", "", "2222", "path", TRUE },
  { "scheme://:@host:2222/path",
    "scheme", "host", "", "", "2222", "path", TRUE },
  { "scheme://:password@host:2222/path",
    "scheme", "host", "", "password", "2222", "path", TRUE },
  { "scheme://host:2222/path",
    "scheme", "host", NULL, NULL, "2222", "path", TRUE },
  { "//username:password@host:2222/path",
    NULL, "host", "username", "password", "2222", "path", TRUE },
  { "scheme://username:password@host:2222",
    "scheme", "host", "username", "password", "2222", NULL, TRUE },
  { "scheme://username:password@host",
    "scheme", "host", "username", "password", NULL, NULL, TRUE },
  { "scheme://username:password@host/",
    "scheme", "host", "username", "password", NULL, "", TRUE },
  { "scheme://host/path",
    "scheme", "host", NULL, NULL, NULL, "path", TRUE },
  { "scheme://host",
    "scheme", "host", NULL, NULL, NULL, NULL, TRUE },
  { "//host",
    NULL, "host", NULL, NULL, NULL, NULL, TRUE },
  { "host",
    NULL, "host", NULL, NULL, NULL, NULL, FALSE },
  { "/path",
    NULL, NULL, NULL, NULL, NULL, "path", TRUE },
  { "",
    NULL, NULL, NULL, NULL, NULL, NULL, FALSE },
  { "socks://muuri.ssh.fi:1080",
    "socks", "muuri.ssh.fi", NULL, NULL, "1080", NULL, TRUE },
  { "scheme://usernam%65:pas%73word@h%6Fst:2222/%70ath",
    "scheme", "host", "username", "password", "2222", "path", TRUE },
  { "scheme://username%40host:pass%3aword@%68%6F%73%74:2222/%70ath",
    "scheme", "host", "username@host", "pass:word", "2222", "path", TRUE }
};

int main(int argc, char **argv)
{
  int i;
  char *scheme, *host, *port, *username, *password, *path;

  for(i = 0; i < sizeof(tests) / sizeof(*tests); i++)
    {
      if (ssh_url_parse_and_decode(tests[i].url, &scheme, &host,
				   &port, &username, &password, &path))
	{
	  if (!tests[i].ok)
	    ssh_fatal("ssh_url_parse returned true, even if it should have failed, url = %s", tests[i].url);
	}
      else
	{
	  if (tests[i].ok)
	    ssh_fatal("ssh_url_parse returned false, even if it should have succeeded, url = %s", tests[i].url);
	}
#define CHECK(s) \
      if (s == NULL && tests[i].s != NULL) \
	ssh_fatal("ssh_url_parse returned NULL for %s, it should have returned %s for url = %s", #s, tests[i].s, tests[i].url); \
      if (s != NULL && tests[i].s == NULL) \
	ssh_fatal("ssh_url_parse returned %s for %s, it should have returned NULL for url = %s", s, #s, tests[i].url); \
      if (s != NULL && strcmp(s, tests[i].s) != 0) \
	ssh_fatal("ssh_url_parse returned %s for %s, it should have returned %s for url = %s", s, #s, tests[i].s, tests[i].url);
      CHECK(scheme);
      CHECK(host);
      CHECK(port);
      CHECK(username);
      CHECK(password);
      CHECK(path);
    }
  return 0;
}
