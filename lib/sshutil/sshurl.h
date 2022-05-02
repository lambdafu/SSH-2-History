/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1998 Tero Kivinen <kivinen@ssh.fi>, Espoo, Finland
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 *                   All rights reserved
 */
/*
 *        Program: Urlparse
 *        $Source: /ssh/CVS/src/lib/sshutil/sshurl.h,v $
 *        $Author: kivinen $
 *
 *        Creation          : 11:09 Jul 10 1998 kivinen
 *        Last Modification : 11:46 Jul 10 1998 kivinen
 *        Last check in     : $Date: 1998/07/10 13:28:23 $
 *        Revision number   : $Revision: 1.1 $
 *        State             : $State: Exp $
 *        Version           : 1.4
 *
 *        Description       : Header fo library to parse urls
 */
/*
 * $Id: sshurl.h,v 1.1 1998/07/10 13:28:23 kivinen Exp $
 * $EndLog$
 */

#ifndef SSHURL_H
#define SSHURL_H

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
		      char **path);

/*
 * Decode url coding. If url_out is NULL then decode inplace, and modify url.
 * Otherwise return new allocated string containing the decoded buffer. Returns
 * TRUE if decoding was successfull and FALSE otherwise.
 */
Boolean ssh_url_decode(char *url, char **url_out);

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
				 char **path);

#endif /* SSHURL_H */
