/*

  base64.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Dec  9 23:37:01 1996 [mkojo]

  Functions to convert to and from base64.

  */

/*
 * $Id: base64.h,v 1.5 1998/09/14 08:28:01 sjl Exp $
 * $Log: base64.h,v $
 * $EndLog$
 */

#ifndef BASE64_H
#define BASE64_H

/* Figure out whether this buffer contains base64 data. Returns number of
   base64 characters. */

size_t ssh_is_base64_buf(unsigned char *buf, size_t buf_len);
  
/* Convert to and from base64 representation. */

/* Convert data from binary to format to base 64 format. Returns null
 * terminated xmallocated string. */
unsigned char *ssh_buf_to_base64(const unsigned char *buf, size_t buf_len);

/* Convert data from base64 format to binary. Returns xmallocated data buffer
 * and length in buf_len. */
unsigned char *ssh_base64_to_buf(unsigned char *str, size_t *buf_len);

/* Remove unneeded whitespace (everything that is not in base64!).
 * Returns new xmallocated string containing the string. If len is 0
 * use strlen(str) to get length of data. */
unsigned char *ssh_base64_remove_whitespace(const unsigned char *str,
					    size_t len);

#endif /* BASE64_H */
