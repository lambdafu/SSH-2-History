/*

  mars.h
    
  Author: Markku-Juhani Saarinen <mjos@ssh.fi>
  Date:   7 Aug 1998
  
  Copyright (c) 1998  SSH Communications Security Ltd., Espoo, Finland
  All rights reserved.

 */

#ifndef MARS_H
#define MARS_H

/* Gets the size of MARS context. */
size_t mars_ctxsize();

/* Sets an already allocated MARS key */
void mars_init(void *context, const unsigned char *key, size_t keylen,
	       Boolean for_encryption);

/* Sets the initialization vector. */
void mars_set_iv(void *context, const unsigned char *iv);

/* Gets the initialization vector. */
void mars_get_iv(void *context, unsigned char *iv);

/* Encrypt/decrypt in electronic code book mode. */
void mars_ecb(void *context, unsigned char *dest,
	      const unsigned char *src, size_t len);

/* Encrypt/decrypt in cipher block chaining mode. */
void mars_cbc(void *context, unsigned char *dest,
	      const unsigned char *src, size_t len);

/* Encrypt/decrypt in cipher feedback mode. */
void mars_cfb(void *context, unsigned char *dest,
	      const unsigned char *src, size_t len);

/* Encrypt/decrypt in output feedback mode. */
void mars_ofb(void *context, unsigned char *dest,
	      const unsigned char *src, size_t len);

#endif /* MARS_H */

