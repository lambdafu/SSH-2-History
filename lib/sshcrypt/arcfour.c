/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

Author: Tatu Ylonen <ylo@ssh.fi>

*/

/*
 * $Id: arcfour.c,v 1.7 1998/01/28 10:09:42 ylo Exp $
 * $Log: arcfour.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifndef WITHOUT_ARCFOUR

#include "arcfour.h"

typedef struct
{
   unsigned int x;
   unsigned int y;
   unsigned char state[256];
} ArcfourContext;

void arcfour_init(void *context, const unsigned char *key, 
		  size_t keylen, Boolean for_encryption)
{
  ArcfourContext *ctx = context;
  unsigned int t, u;
  size_t keyindex;
  unsigned int stateindex;
  unsigned char* state;
  unsigned int counter;

  assert(keylen > 0);

  state = &ctx->state[0];
  ctx->x = 0;
  ctx->y = 0;
  for (counter = 0; counter < 256; counter++)
    state[counter] = counter;
  keyindex = 0;
  stateindex = 0;
  for (counter = 0; counter < 256; counter++)
    {
      t = state[counter];
      stateindex = (stateindex + key[keyindex] + t) & 0xff;
      u = state[stateindex];
      state[stateindex] = t;
      state[counter] = u;
      if (++keyindex >= keylen)
	keyindex = 0;
    }
}

#if  !defined(ASM_ARCFOUR)
#if 0

/* The original version by Tatu Yl�nen. */

static inline unsigned int arcfour_byte(ArcfourContext *ctx)
{
  unsigned int x;
  unsigned int y;
  unsigned int sx, sy;
  unsigned char *state;

  state = ctx->state;
  x = (ctx->x + 1) & 0xff;
  sx = state[x];
  y = (sx + ctx->y) & 0xff;
  sy = state[y];
  ctx->x = x;
  ctx->y = y;
  state[y] = sx;
  state[x] = sy;
  return state[(sx + sy) & 0xff];
}

void arcfour_transform(void *context, unsigned char *dest, 
		       const unsigned char *src, size_t len)
{
  ArcfourContext *ctx = context;
  
  unsigned int i;
  for (i = 0; i < len; i++)
    dest[i] = src[i] ^ arcfour_byte(ctx);
}

#else

/* This attempts to be faster (but otherwise equivalent) than the
   previous code. (On P133 this runs about 20 - 40 percent faster). */

void arcfour_transform(void *context, unsigned char *dest,
		       const unsigned char *src, size_t len)
{
  ArcfourContext *ctx = context;
  unsigned int i;
  unsigned char *state;
  unsigned int x, y;
  unsigned int sx, sy;

  state = ctx->state;
  x = ctx->x;
  y = ctx->y;
  
  for (i = 0; i < len; i++)
    {
      x = (x + 1) & 0xff;
      sx = state[x];
      y = (y + sx) & 0xff;
      sy = state[y];
      state[y] = sx;
      state[x] = sy;
      dest[i] = src[i] ^ state[(sx + sy) & 0xff];
    }

  /* Set ctx correctly. */
  ctx->x = x;
  ctx->y = y;
}
#endif

#endif /* ASM_ARCFOUR */

size_t arcfour_ctxsize()
{
  return sizeof(ArcfourContext);
}

void arcfour_free(void *context)
{
  ArcfourContext *ctx = (ArcfourContext *)context;

  memset(ctx, 0, sizeof(*ctx));
  ssh_xfree(ctx);
}
      
#endif
