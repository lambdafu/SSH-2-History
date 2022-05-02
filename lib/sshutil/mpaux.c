/*

mpaux.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jul 16 04:29:30 1995 ylo

This file contains various auxiliary functions related to multiple
precision integers.

*/

/*
 * $Id: mpaux.c,v 1.6 1998/09/23 11:14:30 tmo Exp $
 * $Log: mpaux.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "gmp.h"
#include "sshgetput.h"

/* Some conversion routines */

/* Linearizing the multiple precision integer to a stream of 8 bit octets. */

void ssh_mp_to_buf(unsigned char *cp, size_t len, const MP_INT *x)
{
  unsigned long limb;
  size_t i;
  MP_INT aux;
  
  mpz_init_set(&aux, x);

  for (i = len; i >= 4; i -= 4)
    {
      limb = mpz_get_ui(&aux);
      SSH_PUT_32BIT(cp + i - 4, limb);
      mpz_div_2exp(&aux, &aux, 32);
    }
  for (;i > 0; i--)
    {
      cp[i - 1] = (unsigned char)(mpz_get_ui(&aux) & 0xff);
      mpz_div_2exp(&aux, &aux, 8);
    }

  mpz_clear(&aux);
}

/* Converting a stream of 8 bit octets to multiple precision integer. */

void ssh_buf_to_mp(MP_INT *x, const unsigned char *cp, size_t len)
{
  size_t i;
  unsigned long limb;

  mpz_set_ui(x, 0);
  for (i = 0; i + 4 <= len; i += 4)
    {
      limb = SSH_GET_32BIT(cp + i);
      mpz_mul_2exp(x, x, 32);
      mpz_add_ui(x, x, limb);
    }
  for (; i < len; i++)
    {
      mpz_mul_2exp(x, x, 8);
      mpz_add_ui(x, x, cp[i]);
    }
}

/* Operation of above functions is identical so use them. These functions
   might be used somewhere so we don't want to delete anything yet. */
void mp_linearize_msb_first(unsigned char *buf, unsigned int len, 
			    MP_INT *value)
{
  ssh_mp_to_buf(buf, len, value);
}

void mp_unlinearize_msb_first(MP_INT *value, const unsigned char *buf,
			      unsigned int len)
{
  ssh_buf_to_mp(value, buf, len);
}

#if 0
/* If something breaks use these. */

/* Converts a multiple-precision integer into bytes to be stored in the buffer.
   The buffer will contain the value of the integer, msb first. */

void mp_linearize_msb_first(unsigned char *buf, unsigned int len, 
			    MP_INT *value)
{
  unsigned int i;
  MP_INT aux;
  mpz_init_set(&aux, value);
  for (i = len; i >= 4; i -= 4)
    {
      unsigned long limb = mpz_get_ui(&aux);
      SSH_PUT_32BIT(buf + i - 4, limb);
      mpz_div_2exp(&aux, &aux, 32);
    }
  for (; i > 0; i--)
    {
      buf[i - 1] = mpz_get_ui(&aux);
      mpz_div_2exp(&aux, &aux, 8);
    }           
  mpz_clear(&aux);
}

/* Extract a multiple-precision integer from buffer.  The value is stored
   in the buffer msb first. */

void mp_unlinearize_msb_first(MP_INT *value, const unsigned char *buf,
			      unsigned int len)
{
  unsigned int i;
  mpz_set_ui(value, 0);
  for (i = 0; i + 4 <= len; i += 4)
    {
      unsigned long limb = SSH_GET_32BIT(buf + i);
      mpz_mul_2exp(value, value, 32);
      mpz_add_ui(value, value, limb);
    }
  for (; i < len; i++)
    {
      mpz_mul_2exp(value, value, 8);
      mpz_add_ui(value, value, buf[i]);
    }
}
#endif
