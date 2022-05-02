/*

mpaux.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul 16 04:29:30 1995 ylo

This file contains various auxiliary functions related to multiple
precision integers.

*/

/*
 * $Id: mpaux.h,v 1.4 1998/01/28 10:14:23 ylo Exp $
 * $Log: mpaux.h,v $
 * $EndLog$
 */

#ifndef MPAUX_H
#define MPAUX_H

#include "gmp.h"

/* Converts a multiple-precision integer into bytes to be stored in the buffer.
   The buffer will contain the value of the integer, msb first. */
void mp_linearize_msb_first(unsigned char *buf, unsigned int len, 
			    MP_INT *value);

/* Extract a multiple-precision integer from buffer.  The value is stored
   in the buffer msb first. */
void mp_unlinearize_msb_first(MP_INT *value, const unsigned char *buf,
			      unsigned int len);

/* Following routines, which are equivalent to the functions given above
   are used extensively within the crypto library. */

/* Size macros */

#define ssh_mp_byte_size(op) ((mpz_sizeinbase((op), 2) + 7) / 8)
#define ssh_mp_word32_size(op) ((mpz_sizeinbase((op), 32) + 31) / 32)
#define ssh_mp_bit_size(op) mpz_sizeinbase((op), 2)

/* Multiple precision integer conversion to byte arrays and back */

void ssh_mp_to_buf(unsigned char *cp, size_t len, const MP_INT *x);

void ssh_buf_to_mp(MP_INT *x, const unsigned char *cp, size_t len);


#endif /* MPAUX_H */
