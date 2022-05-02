/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

Author: Tatu Ylonen <ylo@ssh.fi>

*/

/*
 * $Id: arcfour.h,v 1.7 1998/08/06 12:11:29 tmo Exp $
 * $Log: arcfour.h,v $
 * $EndLog$
 */

#ifndef ARCFOUR_H
#define ARCFOUR_H

/* Compute Arcfour context size. */
size_t arcfour_ctxsize(void);

/* Sets arcfour key for encryption. */
void arcfour_init(void *context,
		  const unsigned char *key, size_t keylen,
		  Boolean for_encryption);

/* Destroys any sensitive data in the context. */
void arcfour_free(void *context);

/* Encrypt/decrypt data. */
void arcfour_transform(void *context, unsigned char *dest,
		       const unsigned char *src, size_t len);

#endif /* ARCFOUR_H */
