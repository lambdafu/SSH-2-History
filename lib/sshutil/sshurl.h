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
 *        Last Modification : 17:20 Jan 28 1999 kivinen
 *        Last check in     : $Date: 1999/01/28 16:10:23 $
 *        Revision number   : $Revision: 1.2 $
 *        State             : $State: Exp $
 *        Version           : 1.28
 *
 *        Description       : Header fo library to parse urls
 */
/*
 * $Id: sshurl.h,v 1.2 1999/01/28 16:10:23 kivinen Exp $
 * $EndLog$
 */

#ifndef SSHURL_H
#define SSHURL_H

#include "mapping.h"

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
 * TRUE if decoding was successfull and FALSE otherwise. Len is the length of
 * the input url and length of the returned url is in stored in the len_out
 * if it is not NULL. The decoded url is returned even if the decoding fails.
 */
Boolean ssh_url_decode_bin(char *url, size_t len,
                           char **url_out, size_t *len_out);

/*
 * Decode url coding. If url_out is NULL then decode inplace, and modify url.
 * Otherwise return new allocated string containing the decoded buffer. Returns
 * TRUE if decoding was successfull and FALSE otherwise. The decoded url is
 * returned even if the decoding fails.
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

/*
 * Decode http get url which have format
 * /path?name=value&name=value&...&name=value
 * Returns path in the beginning and Mapping that has all the name
 * and value pairs stored. It also decodes all the %-encodings from the
 * name and values after splitting them.
 * If `path' is not NULL then mallocated copy of decoded path component
 * is stored there.
 * Returned mapping is storing only pointers to the variable length strings,
 * and it has internal destructor, so calling ssh_mapping_free will destroy
 * it and its contents.
 * Returns TRUE if everything went ok, and FALSE if there was a decoding error
 * while processing the url. 
 */
Boolean ssh_url_parse_form(const char *url,
                           char **path,
                           size_t *path_length,
                           SshMapping *mapping);

/*
 * Decode http post data which have format
 * name=value&name=value&...&name=value
 * Returns a Mapping that has all the name and value pairs stored. It
 * also decodes all the %-encodings from the name and values after
 * splitting them.
 * Returned mapping is storing only pointers to the variable length strings,
 * and it has internal destructor, so calling ssh_mapping_free will destroy
 * it and its contents.
 * Returns TRUE if everything went ok, and FALSE if there was a decoding error
 * while processing the url. 
 */
Boolean ssh_url_parse_post_form(const char *url, SshMapping *mapping);

#endif /* SSHURL_H */
