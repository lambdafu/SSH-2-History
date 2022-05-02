/*

blowfish.h

Author: Mika Kojo
Copyright (c) 1996 SSH Communications Security Oy

Created: Wed May 28 20:25 1996

The blowfish encryption algorithm, created by Bruce Schneier.

*/

/*
 * $Id: blowfish.h,v 1.17 1998/11/04 12:05:31 ylo Exp $
 * $Log: blowfish.h,v $
 * $EndLog$
 */

#ifndef BLOWFISH_H
#define BLOWFISH_H

/* Prototypes */

/* Gives the size of memory block allocated for blowfish context */
size_t blowfish_ctxsize(void);

/* Initializes an already allocated area for blowfish encryption/decryption */
void blowfish_init(void *context,
                   const unsigned char *key, size_t keylen,
                   Boolean for_encryption);

/* Encrypt/decrypt in electronic code book mode. */
void blowfish_ecb(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len,
                  unsigned char *iv);

/* Encrypt/decrypt in cipher block chaining mode. */
void blowfish_cbc(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len,
                  unsigned char *iv);

/* Encrypt/decrypt in cipher feedback mode. */
void blowfish_cfb(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len,
                  unsigned char *iv);

/* Encrypt/decrypt in output feedback mode. */
void blowfish_ofb(void *context, unsigned char *dest,
                  const unsigned char *src, size_t len,
                  unsigned char *iv);

#endif

