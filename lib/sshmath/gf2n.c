/*

  gf2n.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri Jan  2 23:53:19 1998 [mkojo]

  This file is a collection of routines for performing arithmetic in
  GF(2^n). It contains generic GF(2^n) routines and some binary polynomial
  stuff also.

  FEATURES:

    - fast gf(2^n) routines
    - general binary polynomials
    - polynomials over gf(2^n)

    - conversion between all these types
    - conversion to SshInt's which is very useful

  XXX Work in progress.

  */

/*
 * $Id: gf2n.c,v 1.15 1998/07/10 10:26:53 sjl Exp $
 * $Log: gf2n.c,v $
 * 	Fixed case in $EndLog$ .
 *
 * Revision 1.14  1998/07/10 10:05:55  vsuontam
 * Now includes some asm optimizations if WIN32 and SSHMATH_ASSEMBLER_SUBROUTINES
 * are defined
 *
 * Revision 1.12  1998/06/10 08:37:40  tmo
 * 	Removed unused varibles by #ifdef'n them out to get rid of
 * 	compilation warnings.
 *
 * Revision 1.11  1998/06/07 09:58:17  mkojo
 * 	Some additions to arithmetic library. Added, for example,
 * 	some speed-ups for elliptic curves such as ABC and Frobenius
 * 	curve multiplication.
 *
 * Revision 1.10  1998/05/27 20:44:36  mkojo
 * 	Modifications. For example, switched to faster elliptic curve
 * 	multiplication.
 *
 * Revision 1.9  1998/05/26  22:00:04  mkojo
 * 	Corrected stupid typo.
 *
 * Revision 1.8  1998/05/26  20:34:55  mkojo
 * 	Numerous corrections and changes.
 *
 * Revision 1.7  1998/05/12 22:38:40  mkojo
 * 	Fixed one bug.
 *
 * Revision 1.6  1998/05/12 22:29:04  mkojo
 * 	Added a lot of const's. Some minor changes to interface.
 *
 * Revision 1.5  1998/05/08 23:31:40  mkojo
 * 	Passes now many tests with binary polynomials, gf(2^n) and
 * 	polynomials over gf(2^n). Significant corrections in many
 * 	places.
 *
 * Revision 1.4  1998/05/07 15:10:10  mkojo
 * 	Initial tests passed with ssh_gf2n_* and ssh_bpoly_* routines.
 *
 * Revision 1.3  1998/05/05 14:12:23  mkojo
 * 	Modified slightly.
 *
 * Revision 1.2  1998/04/28 19:54:10  mkojo
 * 	Fixed a whole lot of compiler errors. This is still in
 * 	development.
 *
 * Revision 1.1  1998/04/17 17:51:56  mkojo
 * 	Initial revision. This code has appeared in CVS before, however,
 * 	here we have entirely new interface and division between routines.
 *
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmath-types.h"
#include "sshmp.h"
#include "gf2n.h"

#if 0

void hexdump(const SshWord *v, int size)
{
  int i, j;
  SshWord x;

  if (size == 0)
    {
      printf("0");
      return;
    }
  
  for (i = size; i > 0; i--)
    {
      x = v[i - 1];
      for (j = SSH_WORD_BITS; j > 0; j -= 8)
	{
	  printf("%02x", (unsigned int)((x >> (j - 8)) & 0xff));
	}
    }
}

#endif

/* The squaring table. Makes squaring a quick operation. */

SshWord ssh_gf2n_square_table[256] = 
{
 0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
 0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
 0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
 0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
 0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
 0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
 0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
 0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
 0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
 0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
 0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
 0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
 0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
 0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
 0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
 0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
 0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
 0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
 0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
 0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
 0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
 0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
 0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
 0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
 0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
 0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
 0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
 0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
 0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
 0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555,
};

/* Auxliary functions */

/* These functions (or the above versions) are used frequently and should be
   fast as possible. */

#ifndef SSHMATH_FAST_MEM_ROUTINES
void ssh_gf2n_memcpy(SshWord *dest, const SshWord *src, int length)
{
  int i;
  for (i = length >> 1; i; i--)
    {
      *dest++ = *src++;
      *dest++ = *src++;
    }
  if (length & 0x1)
    *dest = *src;
}

void ssh_gf2n_memset(SshWord *dest, SshWord value, int length)
{
  int i;
  for (i = length >> 1; i; i--)
    {
      *dest++ = value;
      *dest++ = value;
    }
  if (length & 0x1)
    *dest = value;
}

int ssh_gf2n_memcmp(const SshWord *a, const SshWord *b, int length)
{
  int i;
  for (i = length; i; i--)
    {
      if (*a != *b)
	return (*a < *b ? -1 : 1);
      a++;
      b++;
    }
  return 0;
}
#else /* SSHMATH_FAST_MEM_ROUTINES */
void ssh_gf2n_memcpy(SshWord *dest, const SshWord *src, int length)
{
  memcpy(dest, src, length * sizeof(SshWord));
}

/* This is usually used only for zeroing stuff. If value > 8 bits then
   this fails. */
void ssh_gf2n_memset(SshWord *dest, SshWord value, int length)
{
  memset(dest, value & 0xff, length * sizeof(SshWord));
}

int ssh_gf2n_memcmp(const SshWord *a, const SshWord *b, int length)
{
  return memcmp(a, b, length * sizeof(SshWord));
}
#endif /* SSHMATH_FAST_MEM_ROUTINES */

/* Move these to some common file, because these are basically equivalent
   to the versions in sshmp.c */
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
#ifndef WIN32
#define SSH_GF2N_COUNT_TRAILING_ZEROS(count, x)  \
__asm__("bsfl %1,%0" : \
	"=r" (count) : "rm" ((unsigned int)(x))); \

#define SSH_GF2N_COUNT_LEADING_ZEROS(count, x) \
  __asm__("bsrl %1,%0; xorl $31, %0" : \
	  "=r" (count) : "rm" ((unsigned int)(x)));
#else /* WIN32*/
  #include "winasmmp.h"
  #define SSH_GF2N_COUNT_LEADING_ZEROS winasm_count_leading_zeros
  #define SSH_GF2N_COUNT_TRAILING_ZEROS winasm_count_trailing_zeros
#endif

#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
/* Define this additional macro for usage here. */
#define SSH_GF2N_LOW_BIT_MASK (((SshWord)1 << (SSH_WORD_BITS/2)) - 1)
#define SSH_GF2N_HIGH_OCTET   ((SshWord)0xff << (SSH_WORD_BITS - 8))

/* Table for trailing zero computations. This table could be
   removed with some extra work in actual computations (using the
   following table instead). */
static unsigned char ssh_gf2n_trailing_zero_table[256] =
{
  8,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
  5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0
};
     
/* Table for leading zero computations. */
static unsigned char ssh_gf2n_leading_zero_table[256] =
{
  0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
};

#define SSH_GF2N_COUNT_TRAILING_ZEROS(count, x)                 \
{                                                               \
  SshWord __x = (x); int __count;                               \
  for (__count = 0; !(__x & 0xff); __x >>= 8, __count += 8)     \
    ;                                                           \
  (count) = __count + ssh_gf2n_trailing_zero_table[__x & 0xff]; \
}

#define SSH_GF2N_COUNT_LEADING_ZEROS(count, x)                          \
{                                                                       \
  SshWord __x = (x); int __count;                                       \
  for (__count = 8; !(__x & SSH_GF2N_HIGH_OCTET); __x <<= 8, __count += 8) \
    ;                                                                   \
  (count) = __count -                                                   \
    ssh_gf2n_leading_zero_table[(__x >> (SSH_WORD_BITS - 8)) & 0xff];   \
}

#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */

/* Some fast very basic functions that are used later, these are
   currently available only in C but later possibly also in assembler.

   Note that these routines are optimized and thus probably not very
   easy to understand at first. However, they are based on simple
   facts of binary operations. Also some special care has been taken
   to optimize these routines in a way that most use will be fast.
   */

/* Note that r should be zeroed before calling this function and should
   contain at least a_n + b_n unsigned int's of space. ut0 and ut1 should
   be of large enough size. */

/* NOTE: for 64 bit computers this might not be fastest multiplication
   routine available! */
void ssh_gf2n_internal_mul(SshWord *r,
			   const SshWord *a, int a_n,
			   const SshWord *b, int b_n,
			   SshWord *ut0, SshWord *ut1)
{
  int i, k, l, j, bits;
  SshWord u0, u1, w0, w1, m, *w;
  const SshWord *u;
  
  /* Check if something to do. */
  if (a_n == 0 || b_n == 0)
    return;

  /* The block method of multiplying. This is very fast. Actually one
     of the fastest that I have figured out. */
  for (i = b_n, k = 0; i; i--, k++, b++)
    {
      u0 = *b;
      u1 = 0;

      /* Compute a table of shifted versions of the given block. */
      for (l = 0; l < SSH_WORD_BITS - 1; l++)
	{
	  ut0[l] = u0;
	  ut1[l] = u1;
	  /* Write this in assembler! */
	  u1 = (u1 << 1) | (u0 >> (SSH_WORD_BITS - 1));
	  u0 = (u0 << 1);
	}
      ut0[l] = u0;
      ut1[l] = u1;

      /* Now we are ready for the inner loop, which must be made as fast
	 as possible. */

      /* Write these with assembler if possible? */
#define MUL_BIT(n)  \
      if (m & ((SshWord)1 << (n))) \
	{               \
	  w1 ^= ut1[n]; \
	  w0 ^= ut0[n]; \
	}
	      
#define MUL_BYTE(n)           \
      MUL_BIT(n);     \
      MUL_BIT(n + 1); \
      MUL_BIT(n + 2); \
      MUL_BIT(n + 3); \
      MUL_BIT(n + 4); \
      MUL_BIT(n + 5); \
      MUL_BIT(n + 6); \
      MUL_BIT(n + 7);

      switch (SSH_WORD_BITS)
	{
	case 16:
	  for (u = a, w = r + k, j = a_n; j; j--, w++, u++)
	    {
	      m = *u;
	      w1 = w0 = 0;
	      
	      MUL_BYTE(0);
	      MUL_BYTE(8);
	      
	      w[0] ^= w0;
	      w[1] ^= w1;
	    }
	  break;
#if SIZEOF_LONG==4 
	case 32:
	  for (u = a, w = r + k, j = a_n; j; j--, w++, u++)
	    {
	      m = *u;
	      w1 = w0 = 0;
	      
	      MUL_BYTE(0);
	      MUL_BYTE(8);
	      MUL_BYTE(16);
	      MUL_BYTE(24);
	      
	      w[0] ^= w0;
	      w[1] ^= w1;
	    }
	  break;
#endif /* SIZEOF_LONG==4 */
#if SIZEOF_LONG==8
	case 64:
	  for (u = a, w = r + k, j = a_n; j; j--, w++, u++)
	    {
	      m = *u;
	      w1 = w0 = 0;
	      
	      MUL_BYTE(0);
	      MUL_BYTE(8);
	      MUL_BYTE(16);
	      MUL_BYTE(24);
	      MUL_BYTE(32);
	      MUL_BYTE(40);
	      MUL_BYTE(48);
	      MUL_BYTE(56);
	      
	      
	      w[0] ^= w0;
	      w[1] ^= w1;
	    }
	  break;
#endif /* SIZEOF_LONG==8 */
	  /* We don't support at the moment "fast" multiplication
	     with larger than 32 bits. */
	default:
	  for (u = a, w = r + k, j = a_n; j; j--, w++, u++)
	    {
	      m = *u;
	      w1 = w0 = 0;
	      
	      /* Can this be optimized further. */
	      for (bits = 0; bits < SSH_WORD_BITS; bits += 32)
		{
		  MUL_BYTE(0  + bits);
		  MUL_BYTE(8  + bits);
		  MUL_BYTE(16 + bits);
		  MUL_BYTE(24 + bits);
		}
	      
	      w[0] ^= w0;
	      w[1] ^= w1;
	    }
	  break;
	}
    }
#undef MUL_BIT
#undef MUL_BYTE

}

void ssh_gf2n_internal_square(SshWord *r,
			      const SshWord *a, int a_n)
{
  int i, j;
  SshWord t;
  
  switch (SSH_WORD_BITS)
    {
    case 16:
      for (i = a_n; i; i--, a++, r += 2)
	{
	  t = a[0];
	  r[0] = ssh_gf2n_square_table[t & 0xff];
	  r[1] = ssh_gf2n_square_table[(t >> 8) & 0xff];
	}
      break;
#if SIZEOF_LONG==4
    case 32:
      for (i = a_n; i; i--, a++, r += 2)
	{
	  t = a[0];
	  r[0] = ssh_gf2n_square_table[t & 0xff];
	  r[0] |= ssh_gf2n_square_table[(t >> 8) & 0xff] << 16;
	  r[1] = ssh_gf2n_square_table[(t >> 16) & 0xff];
	  r[1] |= ssh_gf2n_square_table[(t >> 24) & 0xff] << 16;
	}
      break;
#endif /* SIZEOF_LONG==4 */
#if SIZEOF_LONG==8
    case 64:
      for (i = a_n; i; i--, a++, r += 2)
	{
	  t = a[0];
	  r[0] = ssh_gf2n_square_table[t & 0xff];
	  r[0] |= ssh_gf2n_square_table[(t >> 8) & 0xff] << 16;
	  r[0] |= ssh_gf2n_square_table[(t >> 16) & 0xff] << 32;
	  r[0] |= ssh_gf2n_square_table[(t >> 24) & 0xff] << 48;
	  
	  r[1] = ssh_gf2n_square_table[(t >> 32) & 0xff];
	  r[1] |= ssh_gf2n_square_table[(t >> 40) & 0xff] << 16;
	  r[1] |= ssh_gf2n_square_table[(t >> 48) & 0xff] << 32;
	  r[1] |= ssh_gf2n_square_table[(t >> 56) & 0xff] << 48;
	}
      break;
#endif /* SIZEOF_LONG==8 */
    default:
      /* This has never been tested!!! */
      for (i = a_n; i; i--, a++, r += 2)
	{
	  t = a[0];
	  r[0] = r[1] = 0;
	  for (j = 0; j < SSH_WORD_BITS/2; j += 8)
	    r[0] |= (ssh_gf2n_square_table[(t >> j) & 0xff] << (j * 2));
	  t >>= SSH_WORD_BITS/2;
	  for (j = 0; j < SSH_WORD_BITS/2; j += 8)
	    r[1] |= (ssh_gf2n_square_table[(t >> j) & 0xff] << (j * 2));
	}
      break;
    }
}

void ssh_gf2n_internal_mod(SshWord *a, int a_n,
			   int wm, const int *w,
			   int bm, const int *b, int bits)
{
  int i, j, word, bit;
  SshWord t, mask;
  
  if (a_n <= wm)
    return;

  for (i = a_n - 1; i > wm; i--)
    {
      t = a[i];
      a[i] = 0;
      /* Write special cases for specific reductions? Write them in
	 assembler? */
      for (j = 0; j < bits; j++)
	{
	  bit = b[j];
	  word = i - w[j];
	  if (bit == 0)
	    a[word] ^= t;
	  else
	    {
	      a[word]     ^= (t >> bit);
	      a[word - 1] ^= (t << (SSH_WORD_BITS - bit));
	    }
	}
    }

  /* Less than word bits. */
  if (i == wm)
    {
      if (bm)
	{
	  /* Slower way, but works always. */
	  mask = ~(((SshWord)1 << bm) - 1);
	  /* Get the upper part. */
	  t = a[i] & mask;
	  a[i] ^= t;
	  
	  a[i - w[0]] ^= (t >> b[0]);
	  for (j = 1; j < bits; j++)
	    {
	      bit = b[j];
	      word = i - w[j];
	      if (bit == 0)
		a[word] ^= t;
	      else
		{
		  a[word] ^= (t >> bit);
		  if (word)
		    a[word - 1] ^= (t << (SSH_WORD_BITS - bit));
		}
	    }
	}
      else
	{
	  /* Quite trivial way. */
	  t = a[i];
	  a[i] = 0;
	  /* Write special cases for specific reductions? Write them in
	     assembler? */
	  for (j = 0; j < bits; j++)
	    {
	      bit = b[j];
	      word = i - w[j];
	      if (bit == 0)
		a[word] ^= t;
	      else
		{
		  a[word] ^= (t >> bit);
		  if (word)
		    a[word - 1] ^= (t << (SSH_WORD_BITS - bit));
		}
	    }
	}
    }
}

/* Galois field routines. */

/* This is the base case. */
int ssh_gf2n_init_mod_bits(SshGF2nModuli *m,
			   const int *bits, int bits_count)
{
  int i;
  
  /* Make sure that the input 'might' be suitable. */
  if (bits_count < 2 || bits[0] != 0)
    return 0;

  /* Certify that they are in correct order. */
  for (i = 0; i < (bits_count - 1); i++)
    {
      if (bits[i] >= bits[i + 1])
	return 0;
    }

  /* Make sure that the difference between the highest bit and the next
     after that is larger than the SSH_WORD_BITS! */
  if (bits[bits_count - 1] - bits[bits_count - 2] < SSH_WORD_BITS)
    return 0;
  
  m->bits = bits_count;
  
  /* Set up the SshGF2nModuli arrays. */
  m->n  = ssh_xmalloc(sizeof(int) *  bits_count);
  m->nn = ssh_xmalloc(sizeof(int) * (bits_count - 1));
  m->w  = ssh_xmalloc(sizeof(int) *  bits_count);
  m->wn = ssh_xmalloc(sizeof(int) * (bits_count - 1));
  m->b  = ssh_xmalloc(sizeof(int) *  bits_count);
  m->bn = ssh_xmalloc(sizeof(int) * (bits_count - 1));

  /* Set up. */
  for (i = 0; i < bits_count; i++)
    {
      m->n[i] = bits[i];
      m->w[i] = bits[i] / SSH_WORD_BITS;
      m->b[i] = bits[i] % SSH_WORD_BITS;
    }
  for (i = 0; i < bits_count - 1; i++)
    {
      m->nn[i] = m->n[bits_count - 1] - m->n[i];
      m->wn[i] = m->nn[i] / SSH_WORD_BITS;
      m->bn[i] = m->nn[i] % SSH_WORD_BITS;
    } 

  /* Compute the amount of memory to allocate. */
  m->allocated = (m->w[m->bits - 1] + 1) * 2 + 1;
  m->work = ssh_xmalloc(sizeof(SshWord) * 6 * m->allocated);

  return 1;
}

int ssh_gf2n_init_mod_raw(SshGF2nModuli *m,
			  const SshWord *buf, int buf_len)
{
  int *bits, bits_count, max_bits_count, i, j;
  int rv;
  SshWord v;
  
  /* Usually we don't need more than 100 bits (in fact, we usually need
     only 3 or 5). */
  max_bits_count = 100;
  bits = ssh_xmalloc(sizeof(int) * max_bits_count);

  /* Transcribe the bits from the buffer into a bit table. */
  for (i = 0, bits_count = 0; i < buf_len; i++)
    {
      v = buf[i];
      for (j = 0; j < SSH_WORD_BITS; j++)
	{
	  if ((v >> j) & 0x1)
	    {
	      if (bits_count >= max_bits_count)
		{
		  /* Reallocate some new bits. */
		  bits = ssh_xrealloc(bits, max_bits_count + 100);
		  max_bits_count += 100;
		}
	      bits[bits_count] = i * SSH_WORD_BITS + j;
	      bits_count++;
	    }
	}
    }

  if (bits_count > 0)
    rv = ssh_gf2n_init_mod_bits(m, bits, bits_count);
  else
    rv = 0;
  ssh_xfree(bits);

  return rv;
}

int ssh_gf2n_init_mod_mp(SshGF2nModuli *m, const SshInt *mp)
{
  /* This is rather simple ;) */
  return ssh_gf2n_init_mod_raw(m, mp->v, mp->n);
}

int ssh_gf2n_init_mod_bpoly(SshGF2nModuli *m, const SshBPoly *b)
{
  return ssh_gf2n_init_mod_raw(m, b->v, b->n);
}

int ssh_gf2n_init_mod_mod(SshGF2nModuli *m, const SshGF2nModuli *mm)
{
  return ssh_gf2n_init_mod_bits(m, mm->n, mm->bits);
}

/* Some more advanced initializations routines. */
int ssh_gf2n_init_mod_ui(SshGF2nModuli *m, unsigned int u)
{
  SshWord v;
  v = u;
  return ssh_gf2n_init_mod_raw(m, &v, 1);
}

void ssh_gf2n_clear_mod(SshGF2nModuli *m)
{
  ssh_xfree(m->w);
  ssh_xfree(m->wn);
  ssh_xfree(m->b);
  ssh_xfree(m->bn);
  ssh_xfree(m->n);
  ssh_xfree(m->nn);
  ssh_xfree(m->work);
  
  m->bits = 0;
  m->w    = NULL;
  m->b    = NULL;
  m->n    = NULL;
  m->wn   = NULL;
  m->bn   = NULL;
  m->nn   = NULL;
  
  m->allocated = 0;
  m->work = NULL;
}

/* Routines handling elements. */

void ssh_gf2n_init(SshGF2nElement *e, const SshGF2nModuli *m)
{
  e->n = 0;
  e->v = ssh_xmalloc(m->allocated * sizeof(SshWord));
  e->m = m;
}

void ssh_gf2n_init_inherit(SshGF2nElement *e, const SshGF2nElement *b)
{
  ssh_gf2n_init(e, b->m);
}

void ssh_gf2n_clear(SshGF2nElement *a)
{
  ssh_xfree(a->v);
  a->v = NULL;
  a->n = 0;
  a->m = NULL;
}

/* The basic set of routines. */

int ssh_gf2n_deg(const SshGF2nElement *e)
{
  int size = e->n, r;
  SshWord v;

  if (size == 0)
    return 0;

  v = e->v[size - 1];
  if (v == 0)
    r = SSH_WORD_BITS;
  else
    {
      r = 0;
      SSH_GF2N_COUNT_LEADING_ZEROS(r, v);
    }

  return size * SSH_WORD_BITS - r;
}

/* Here we return the degree in slightly incorrect manner! Notice, that
   the degree is actually one larger than the real degree. */
int ssh_gf2n_deg_mod(const SshGF2nModuli *m)
{
  return m->n[m->bits - 1] + 1;
}

int ssh_gf2n_deg_mod_inherit(const SshGF2nElement *e)
{
  return ssh_gf2n_deg_mod(e->m);
}

int ssh_gf2n_cmp_ui(const SshGF2nElement *e, unsigned int u)
{
  SshWord v = u;
  
  if (e->n == 0 && u == 0)
    return 0;

  if (e->n == 0)
    return -1;

  if (u == 0)
    return 1;

  if (e->n > 1)
    return 1;
  
  if (e->v[0] > v)
    return 1;

  if (e->v[0] == v)
    return 0;

  return -1;
}

int ssh_gf2n_cmp(const SshGF2nElement *a, const SshGF2nElement *b)
{
  int i;
  /* Check sizes. */
  if (ssh_gf2n_deg(a) != ssh_gf2n_deg(b))
    {
      if (ssh_gf2n_deg(a) > ssh_gf2n_deg(b))
	return 1;
      return -1;
    }

  /* Of equal size. */
  for (i = a->n; i; i--)
    {
      if (a->v[i - 1] != b->v[i - 1])
	{
	  if (a->v[i - 1] > b->v[i - 1])
	    return 1;
	  return -1;
	}
    }
  return 0;
}

int ssh_gf2n_cmp_mod(const SshGF2nModuli *a, const SshGF2nModuli *b)
{
  int a_i, b_i;

  for (a_i = a->bits, b_i = b->bits; a_i && b_i; a_i--, b_i--)
    {
      if (a->n[a_i - 1] > b->n[b_i - 1])
	return 1;
      if (a->n[a_i - 1] < b->n[b_i - 1])
	return -1;
    }

  if (a_i > 0)
    return 1;
  if (b_i > 0)
    return -1;

  return 0;
}
     
void ssh_gf2n_set_ui(SshGF2nElement *ret, unsigned int u)
{
  /* Special case. */
  if (u == 0)
    {
      ret->n = 0;
      return;
    }
  ret->v[0] = u;
  ret->n = 1;
}

unsigned int ssh_gf2n_get_ui(SshGF2nElement *e)
{
  return e->v[0];
}

void ssh_gf2n_set(SshGF2nElement *ret, const SshGF2nElement *e)
{
  if (e->n == 0)
    {
      ret->n = 0;
      return;
    }
  ssh_gf2n_memcpy(ret->v, e->v, e->n);
  ret->n = e->n;
}

void ssh_gf2n_set_bpoly(SshGF2nElement *ret, const SshBPoly *b)
{
  SshBPoly m, t;

  ssh_bpoly_init(&m);
  ssh_bpoly_init(&t);

  /* Reduce. */
  ssh_bpoly_set_gf2n_mod(&m, ret->m);
  ssh_bpoly_mod(&t, b, &m);

  /* Do a copy. */
  ssh_gf2n_memcpy(ret->v, t.v, t.n);
  ret->n = t.n;

  /* Free. */
  ssh_bpoly_clear(&m);
  ssh_bpoly_clear(&t);
}

void ssh_gf2n_set_mp(SshGF2nElement *ret, const SshInt *mp)
{
  SshBPoly b;
  /* XXX We have to do a little bit of kludging here. */
  ssh_bpoly_init(&b);
  ssh_bpoly_set_mp(&b, mp);
  ssh_gf2n_set_bpoly(ret, &b);
  ssh_bpoly_clear(&b);
}

void ssh_mp_set_gf2n(SshInt *ret, const SshGF2nElement *e)
{
  SshBPoly b;
  /* XXX This should be reasonably simple. Although is a slight kludge,
     but better to do things at bpoly side, to keep things simple. */
  ssh_bpoly_init(&b);
  ssh_bpoly_set_gf2n(&b, e);
  ssh_mp_set_bpoly(ret, &b);
  ssh_bpoly_clear(&b);
}

void ssh_mp_set_gf2n_mod(SshInt *ret, const SshGF2nModuli *m)
{
  SshBPoly b;
  /* XXX This is as easy. */
  ssh_bpoly_init(&b);
  ssh_bpoly_set_gf2n_mod(&b, m);
  ssh_mp_set_bpoly(ret, &b);
  ssh_bpoly_clear(&b);
}

/* Some buffer routines. */
void ssh_gf2n_get_buf(unsigned char *buf, size_t buf_length,
		      const SshGF2nElement *op)
{
  SshBPoly b;
  ssh_bpoly_init(&b);
  ssh_bpoly_set_gf2n(&b, op);
  ssh_bpoly_get_buf(buf, buf_length, &b);
  ssh_bpoly_clear(&b);
}

void ssh_gf2n_set_buf(SshGF2nElement *ret,
		      const unsigned char *buf, size_t buf_length)
{
  SshBPoly b;
  ssh_bpoly_init(&b);
  ssh_bpoly_set_buf(&b, buf, buf_length);
  ssh_gf2n_set_bpoly(ret, &b);
  ssh_bpoly_clear(&b);
}

/* The addition routine. */

void ssh_gf2n_add(SshGF2nElement *ret, const SshGF2nElement *a,
		  const SshGF2nElement *b)
{
  int i, j;
  
  if (a->n > b->n)
    {
      /* Swap. */
      const SshGF2nElement *t;
      t = a;
      a = b;
      b = t;
    }
  /* This could be done faster. */
  for (i = a->n, j = 0; i; i--, j++)
    ret->v[j] = a->v[j] ^ b->v[j];
  /* Copy the rest. */
  for (; j < b->n; j++)
    ret->v[j] = b->v[j];

  /* Figure the correct size at the end. */
  ret->n = b->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
}

void ssh_gf2n_add_ui(SshGF2nElement *ret, const SshGF2nElement *a,
		     unsigned int u)
{
  ssh_gf2n_set(ret, a);
  if (u == 0)
    return;
  
  if (ret->n == 0)
    {
      ret->v[0] = u;
      ret->n = 1;
      return;
    }

  ret->v[0] ^= u;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
}

SshWord ssh_gf2n_random()
{
  int i;
  SshWord r;
  for (r = 0, i = SSH_WORD_BITS; i; i -= 16)
    r = (r << 16) ^ random();
  return r;
}

/* Everybody needs poor random numbers. */
void ssh_gf2n_poor_rand(SshGF2nElement *ret)
{
  int i;
  const SshGF2nModuli *m = ret->m;
  for (i = 0; i < m->w[m->bits - 1] + 1; i++)
    ret->v[i] = ssh_gf2n_random();
  ssh_gf2n_internal_mod(ret->v, m->w[m->bits - 1] + 1,
			m->w[m->bits - 1], m->wn,
			m->b[m->bits - 1], m->bn, m->bits - 1);
  ret->n = m->w[m->bits - 1] + 1;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
}

/* Fast multiplication (mod), without allocation. */
void ssh_gf2n_mul(SshGF2nElement *ret, const SshGF2nElement *a,
		  const SshGF2nElement *b)
{
  SshWord *r;
  const SshGF2nModuli *m = ret->m;
  int n;
  static SshWord ut0[SSH_WORD_BITS], ut1[SSH_WORD_BITS];

  /* Trivial cases. */
  if (a->n == 0 || b->n == 0)
    {
      ret->n = 0;
      return;
    }
  
  n = a->n + b->n + 1;
  if (ret != a && ret != b)
    r = ret->v;
  else
    r = m->work;

  /* Zero. */
  ssh_gf2n_memset(r, 0, n);

  if (a->n > b->n)
    ssh_gf2n_internal_mul(r, a->v, a->n, b->v, b->n, ut0, ut1);
  else
    ssh_gf2n_internal_mul(r, b->v, b->n, a->v, a->n, ut0, ut1);

  /* Find correct size. */
  while (n && r[n - 1] == 0)
    n--;

  /* Reduce if necessary. */
  if (n > m->w[m->bits - 1])
    {
      ssh_gf2n_internal_mod(r, n,
			    m->w[m->bits - 1], m->wn,
			    m->b[m->bits - 1], m->bn, m->bits - 1);
      
      /* Find correct size again. */
      n = m->w[m->bits - 1] + 1;
      while (n && r[n - 1] == 0)
	n--;
    }
  
  if (r != ret->v)
    ssh_gf2n_memcpy(ret->v, r, n);
  ret->n = n;
}

void ssh_gf2n_square(SshGF2nElement *ret, const SshGF2nElement *a)
{
  const SshGF2nModuli *m = ret->m;
  SshWord *r;
  int n;

  /* The trivial case. */
  if (a->n == 0)
    {
      ret->n = 0;
      return;
    }
  
  n = a->n * 2 + 1;
  if (ret != a)
    r = ret->v;
  else
    r = m->work;

  /* Actually it would be not necessary to zero the buffer. */
  ssh_gf2n_memset(r, 0, n);
  ssh_gf2n_internal_square(r, a->v, a->n);
    
  /* Find the correct size. */
  while (n && r[n - 1] == 0)
    n--;

  /* Reduce if necessary. */
  if (n > m->w[m->bits - 1])
    {
      ssh_gf2n_internal_mod(r, n,
			    m->w[m->bits - 1], m->wn,
			    m->b[m->bits - 1], m->bn, m->bits - 1);
			          
      /* Find the correct size. */
      n = m->w[m->bits - 1] + 1;
      while (n && r[n - 1] == 0)
	n--;
    }
  
  if (ret->v != r)
    ssh_gf2n_memcpy(ret->v, r, n);
  ret->n = n;
}

/* Some useful macros, that could be written in assembler? */

/* Macro that interleaves the shifting and addition together. Here we
   don't swap at the same time. This is for optimized implementation and
   does save some time in overhead. */
#define SHIFT_MACRO12(__bits__)   \
      for (j = 0, i = fsize; i; i--, j++) \
	{                         \
	  t = (fv[j] >> (__bits__)) | \
	    (fv[j + 1] << (SSH_WORD_BITS - (__bits__))); \
	  fv[j] = t ^ gv[j];      \
	}                         \
      if (!fv[fsize - 1])         \
	fsize--;                  \
      if (csize)                  \
	{                         \
	  for (j = csize; j; j--) \
	    {                     \
	      t = (cv[j] << (__bits__)) | \
		(cv[j - 1] >> (SSH_WORD_BITS - (__bits__))); \
	      bv[j] ^= t;         \
	      cv[j] = t;          \
	    }                     \
	  t = cv[0] << (__bits__); \
	  bv[0] ^= t;             \
	  cv[0] = t;              \
	  if (bv[bsize])          \
	    bsize++;              \
	  if (cv[csize])          \
	    csize++;              \
	} 

/* Here we do also the swapping thing, which makes this look rather
   different. This is otherwise similar. */
#define SHIFT_MACRO22(__bits__)   \
      for (j = 0, i = fsize; i; i--, j++) \
	{                         \
	  t = (fv[j] >> (__bits__)) | \
	    (fv[j + 1] << (SSH_WORD_BITS - (__bits__))); \
	  gv[j] ^= t ;            \
          fv[j] = t;              \
	}                         \
      if (!fv[fsize - 1])         \
	fsize--;                  \
      for (j = csize; j; j--)     \
	{                         \
	  t = (cv[j] << (__bits__)) | \
	    (cv[j - 1] >> (SSH_WORD_BITS - (__bits__))); \
	  cv[j] = bv[j] ^ t;      \
	}                         \
      t = cv[0] << (__bits__);    \
      cv[0] = bv[0] ^ t;          \
      if (cv[csize])              \
	csize++;

void ssh_gf2n_invert(SshGF2nElement *ret, const SshGF2nElement *a)
{
  int k, i, j, n, r, off;
  SshWord *bv, *cv, *fv, *gv, *iv;
  SshWord t, mask;
  int bsize, csize, fsize, gsize;
  const SshGF2nModuli *m = ret->m;

  /* Trivial cases added for completeness. */
  if (a->n == 0)
    ssh_fatal("ssh_gf2n_invert: cannot invert zero polynomial.");
  if (a->n == 1 && a->v[0] == 0x1)
    {
      ret->v[0] = 0x1;
      ret->n = 1;
      return;
    }

  /* Set working space. */
  
  bv = m->work;
  ssh_gf2n_memset(bv, 0, m->allocated * 6);
  cv = bv + 2 * m->allocated;

  /* fv and gv are the gcd part (if such can be said here). */
  
  fv = cv + 2 * m->allocated;
  fsize = a->n;
  ssh_gf2n_memcpy(fv, a->v, a->n);

  /* Get the correct size. */
  while (fsize && fv[fsize - 1] == 0)
    fsize--;
  
  /* It should be a bit faster to set the moduli this way. */
  gv = fv + m->allocated;
  gsize = m->w[m->bits - 1] + 1;
  for (i = 0; i < m->bits; i++)
    gv[m->w[i]] |= ((SshWord)1 << m->b[i]);

  /* Set the up the downwards growing areas. */
  bv += m->allocated;
  bv[0] = 0x1;
  bsize = 1;
  cv += m->allocated;
  csize = 0;
  
  /* Set the bit counter to zero. */
  k = 0;
  
  /* The almost inverse computation */

  while (1)
    {
    start:
#if 0
      printf("cv: ");
      hexdump(cv, csize);
      printf("\nfv: ");
      hexdump(fv, fsize);
      printf("\nbv: ");
      hexdump(bv, bsize);
      printf("\ngv: ");
      hexdump(gv, gsize);
      printf("\n");
#endif

      /* Stupid check, in case someone is using this in a wrong context. */
      if (fsize == 0)
	ssh_fatal("ssh_gf2n_invert: assumed to find inverse, but did not.");
      
      /* Following is optimized version of computing the loop:
	 
	 while f is even do
	   f /= 2
	   c *= 2
	   k = k + 1
	 end. */

      /* Count trailing zero words. */
      for (r = 0; !fv[r]; r++)
	;
      
      if (r)
	{
	  k += (SSH_WORD_BITS * r);

	  /* We know that fv cannot grow so we just move the pointer. */
	  fv += r;
	  fsize -= r;
	  
	  if (csize)
	    {
	      /* Move left by words. */
	      cv -= r;
	      csize += r;
	    }
	}
	
      /* The next few lines of computing the trailing zero bits can probably
	 be done somewhat faster with assembler (perhaps with one
	 instruction). */
      t = fv[0];
      SSH_GF2N_COUNT_TRAILING_ZEROS(off, t);

      /* Move k as if we would have done it already. */
      k += off;
      
      /* Stopping condition */
      t = 0;
      if (fsize == 1)
	{
	  t = fv[0];
	  if (off)
	    t >>= off;
	  if (t == 0x1)
	    break;
	}

      /* Try to determine whether it is time to swap. */
      
      /* Note that fv must be shifted to be correct. */
      if (fsize < gsize)
	goto swap;

      if (gsize < fsize - 1)
	goto noswap;
      
      if (!t)
	t = fv[fsize - 1] >> off;
      
      if (t == 0 && fsize - 1 == gsize)
	{
	  t = (fv[fsize - 1] << (SSH_WORD_BITS - off)) |
	    (fv[fsize - 2] >> off);
	  if (t < gv[gsize - 1])
	    goto swap;
	}
      else
	if (fsize == gsize && t < gv[gsize - 1])
	  goto swap;

      goto noswap;

      /* Swapping code. */
    swap:
	
      /* Shift down. */
      if (off)
	{
	  /* Using switch clause seems to be much faster
	     at least on Intel processors. */
#define CASE22(n) case n: SHIFT_MACRO22(n); break;
	  switch (off)
	    {
	      CASE22(1);
	      CASE22(2);
	      CASE22(3);
	      CASE22(4);
	      CASE22(5);
	      CASE22(6);
	      CASE22(7);
	      CASE22(8);
	      CASE22(9);
	      CASE22(10);
	      CASE22(11);
	      CASE22(12);
	      CASE22(13);
	      CASE22(14);
	      CASE22(15);
	      CASE22(16);
#if SIZEOF_LONG==4 || SIZEOF_LONG==8
	      CASE22(17);
	      CASE22(18);
	      CASE22(19);
	      CASE22(20);
	      CASE22(21);
	      CASE22(22);
	      CASE22(23);
	      CASE22(24);
	      CASE22(25);
	      CASE22(26);
	      CASE22(27);
	      CASE22(28);
	      CASE22(29);
	      CASE22(30);
	      CASE22(31);
#if SIZEOF_LONG==8 
	      CASE22(32);
	      CASE22(33);
	      CASE22(34);
	      CASE22(35);
	      CASE22(36);
	      CASE22(37);
	      CASE22(38);
	      CASE22(39);
	      CASE22(40);
	      CASE22(41);
	      CASE22(42);
	      CASE22(43);
	      CASE22(44);
	      CASE22(45);
	      CASE22(46);
	      CASE22(47);
	      CASE22(48);
	      CASE22(49);
	      CASE22(50);
	      CASE22(51);
	      CASE22(52);
	      CASE22(53);
	      CASE22(54);
	      CASE22(55);
	      CASE22(56);
	      CASE22(57);
	      CASE22(58);
	      CASE22(59);
	      CASE22(60);
	      CASE22(61);
#endif /* SIZEOF_LONG == 8 */
#endif /* SIZEOF_LONG == 4 || SIZEOF_LONG==8 */
	    default:
	      SHIFT_MACRO22(off);
	      break;
	    }
	}
      else
	{
	  /* Same code as below. */
	  for (i = fsize, j = 0; i; i--, j++)
	    gv[j] ^= fv[j];
	  for (i = bsize, j = 0; i; i--, j++)
	    cv[j] ^= bv[j];
	  if (csize < bsize)
	    csize = bsize;
	  if (gsize < fsize)
	    gsize = fsize;
	}

      /* Update length. */
      while (gsize && gv[gsize - 1] == 0)
	gsize--;
      while (csize && cv[csize - 1] == 0)
	csize--;

      /* Now do the name swapping. */
      
      /* swap g and f */
      iv = fv;
      fv = gv;
      gv = iv;
      t  = fsize;
      fsize = gsize;
      gsize = t;
      
      /* swap b and c */
      iv = bv;
      bv = cv;
      cv = iv;
      t = bsize;
      bsize = csize;
      csize = t;

      /* Return back. */
      goto start;
	  
    noswap:
      
      /* This simply computes (in hopefully optimized manner)

	 f ^= g
	 b ^= c

	 which can be thought as addition on 2^m polynomial basis.

	 (Note: The above description doesn't exactly describe what
	 happens here. But you'll figure it out. I have just interleaved
	 some operations in quest for speed-ups.)
       */

      if (off)
	{
	  /* This seems to be a good idea. */
#define CASE12(n) case n: SHIFT_MACRO12(n); break;
	  switch (off)
	    {
	      CASE12(1);
	      CASE12(2);
	      CASE12(3);
	      CASE12(4);
	      CASE12(5);
	      CASE12(6);
	      CASE12(7);
	      CASE12(8);
	      CASE12(9);
	      CASE12(10);
	      CASE12(11);
	      CASE12(12);
	      CASE12(13);
	      CASE12(14);
	      CASE12(15);
#if SIZEOF_LONG==4 || SIZEOF_LONG==8
	      CASE12(16);
	      CASE12(17);
	      CASE12(18);
	      CASE12(19);
	      CASE12(20);
	      CASE12(21);
	      CASE12(22);
	      CASE12(23);
	      CASE12(24);
	      CASE12(25);
	      CASE12(26);
	      CASE12(27);
	      CASE12(28);
	      CASE12(29);
	      CASE12(30);
	      CASE12(31);
#if SIZEOF_LONG==8
	      CASE12(32);
	      CASE12(33);
	      CASE12(34);
	      CASE12(35);
	      CASE12(36);
	      CASE12(37);
	      CASE12(38);
	      CASE12(39);
	      CASE12(40);
	      CASE12(41);
	      CASE12(42);
	      CASE12(43);
	      CASE12(44);
	      CASE12(45);
	      CASE12(46);
	      CASE12(47);
	      CASE12(48);
	      CASE12(49);
	      CASE12(50);
	      CASE12(51);
	      CASE12(52);
	      CASE12(53);
	      CASE12(54);
	      CASE12(55);
	      CASE12(56);
	      CASE12(57);
	      CASE12(58);
	      CASE12(59);
	      CASE12(60);
	      CASE12(61);
#endif /* SIZEOF_LONG==8 */
#endif /* SIZEOF_LONG==4 || SIZEOF_LONG==8 */
	    default:
	      SHIFT_MACRO12(off);
	      break;
	    }
	}
      else
	{
	  /* do the addition traditionally. */
	  for (i = gsize, j = 0; i; i--, j++)
	    fv[j] ^= gv[j];
	  for (i = csize, j = 0; i; i--, j++)
	    bv[j] ^= cv[j];
	  if (bsize < csize)
	    bsize = csize;
	  if (fsize < gsize)
	    fsize = gsize;
	}

      /* Update length. */
      while (fsize && fv[fsize - 1] == 0)
	fsize--;
      while (bsize && bv[bsize - 1] == 0)
	bsize--;

      goto start;
    }

  /* Check that we always have bsize >= w_n2 + 1, it is needed next. */
  if (bsize < m->w[m->bits - 1] + 1)
    bsize = m->w[m->bits - 1] + 1;

#if 0
  printf("bv: ");
  hexdump(bv, bsize);
  printf("\n");
#endif
  
  /* Dividing out the true reciprocal. */

  /* XXX

     NOTE: The process of dividing out can be optimized significantly.
     It could be computed for each possible case of SSH_WORD_BITS in
     a table how many iterations are needed to clean the word, and
     masked area off.

     This version has the advantage of working at the low end with
     all incarnations of moduli.
     */
  
  for (; k >= SSH_WORD_BITS; k -= SSH_WORD_BITS)
    {
      /* Do one step of the division by block of SshWord size. */
      for (j = 0; j < SSH_WORD_BITS; j += m->n[1])
	{
	  t = bv[0];
	  /* First xor is trivial. */
	  bv[0] = 0;
	  /* Follows with some non-trivial xoring. */
	  for (i = 1; i < m->bits; i++)
	    {
	      bv[m->w[i]] ^= t << m->b[i];
	      if (m->b[i])
		bv[m->w[i] + 1] ^= t >> (SSH_WORD_BITS - m->b[i]);
	    }
	}
      
      /* Shift right by one word. */
      for (i = 0, j = bsize + 1; j; j--, i++)
	bv[i] = bv[i + 1];

      if (bsize > m->w[m->bits - 1] + 1)
	bsize--;
    }

#if 0
  printf("bv: ");
  hexdump(bv, bsize);
  printf("\n");
#endif
  
  if (k)
    {
      /* The the division of variable block size. */
      for (j = 0, mask = ((SshWord)1 << k) - 1;
	   j < k; j += m->n[1])
	{
	  t = bv[0] & mask;
	  bv[0] &= (~mask);
	  for (i = 1; i < m->bits; i++)
	    {
	      bv[m->w[i]] ^= t << m->b[i];
	      if (m->b[i])
		bv[m->w[i] + 1] ^= t >> (SSH_WORD_BITS - m->b[i]);
	    }
	}
	  
      /* Shift right by k (less than WORD_BITS) bits. */
      for (i = bsize + 1, j = 0, n = SSH_WORD_BITS - k; i; i--, j++)
	bv[j] = (bv[j] >> k) | (bv[j + 1] << n);
    }

  /* Count the correct length (might have been forgotten in the process) */
  while (bsize && bv[bsize - 1] == 0)
    bsize--;

#if 0
  printf("bv: ");
  hexdump(bv, bsize);
  printf("\n");
#endif
  
  /* Copy the result to inv. */
  ssh_gf2n_memcpy(ret->v, bv, bsize);
  ret->n = bsize;
}

void ssh_gf2n_trace(SshGF2nElement *trace, const SshGF2nElement *a)
{
  int len;
  SshGF2nElement tmp, t;

  ssh_gf2n_init_inherit(&tmp, trace);
  ssh_gf2n_init_inherit(&t,   trace);

  ssh_gf2n_set_ui(&tmp, 0);
  ssh_gf2n_set(&t, a);

  for (len = 1; len < (ssh_gf2n_deg_mod_inherit(a) - 1); len++)
    {
      ssh_gf2n_square(&tmp, &t);
      ssh_gf2n_add(&t, &tmp, a);
    }

  ssh_gf2n_set(trace, &t);
  
  ssh_gf2n_clear(&tmp);
  ssh_gf2n_clear(&t);
}

void ssh_gf2n_half_trace(SshGF2nElement *trace, const SshGF2nElement *a)
{
  int len;
  SshGF2nElement tmp, t;

  ssh_gf2n_init_inherit(&tmp, trace);
  ssh_gf2n_init_inherit(&t,   trace);

  ssh_gf2n_set_ui(&tmp, 0);
  ssh_gf2n_set(&t, a);

  for (len = 1; len < ssh_gf2n_deg_mod_inherit(a)/2; len++)
    {
      ssh_gf2n_square(&tmp, &t);
      ssh_gf2n_square(&t, &tmp);
      ssh_gf2n_add(&t, &t, a);
    }

  ssh_gf2n_set(trace, &t);
  
  ssh_gf2n_clear(&tmp);
  ssh_gf2n_clear(&t);
}

void ssh_gf2n_exp_2exp(SshGF2nElement *a, const SshGF2nElement *b,
		       unsigned int e)
{
  SshGF2nElement t1;

  ssh_gf2n_init_inherit(&t1, a);
  ssh_gf2n_set(&t1, b);

  for(; e; e--)
    ssh_gf2n_square(&t1, &t1);

  ssh_gf2n_set(a, &t1);
  ssh_gf2n_clear(&t1);
}

Boolean ssh_gf2n_quad_solve(SshGF2nElement *z, const SshGF2nElement *b)
{
  SshGF2nElement t1, t2, t3, t4;
  Boolean solution = FALSE;
  int i;

  if ((ssh_gf2n_deg_mod_inherit(z) - 1) & 0x1)
    {
      /* Special case of size odd. */
      ssh_gf2n_init_inherit(&t1, z);
      ssh_gf2n_half_trace(z, b);

      /* Verify. */
      ssh_gf2n_square(&t1, z);
      ssh_gf2n_add(&t1, &t1, z);

      if (ssh_gf2n_cmp(&t1, b) == 0)
	solution = TRUE;

      ssh_gf2n_clear(&t1);
    }
  else
    {
      ssh_gf2n_init_inherit(&t1, z);
      ssh_gf2n_init_inherit(&t2, z);
      ssh_gf2n_init_inherit(&t3, z);
      ssh_gf2n_init_inherit(&t4, z);

      while (1)
	{
	  ssh_gf2n_poor_rand(&t1);

	  ssh_gf2n_set_ui(z, 0);
	  ssh_gf2n_set(&t2, b);

	  for (i = 1; i < ssh_gf2n_deg_mod_inherit(z) - 1; i++)
	    {
	      ssh_gf2n_square(z, z);
	      ssh_gf2n_square(&t4, &t2);
	      ssh_gf2n_add(&t2, &t4, b);
	      ssh_gf2n_mul(&t3, &t4, &t1);
	      ssh_gf2n_add(z, z, &t3);
	    }

	  if (ssh_gf2n_cmp_ui(&t2, 0) != 0)
	    break;

	  /* Verify. */
	  ssh_gf2n_square(&t1, z);
	  ssh_gf2n_add(&t1, &t1, z);
	  
	  if (ssh_gf2n_cmp_ui(&t1, 0) != 0)
	    {
	      solution = TRUE;
	      break;
	    }
	}
      
      ssh_gf2n_clear(&t1);
      ssh_gf2n_clear(&t2);
      ssh_gf2n_clear(&t3);
      ssh_gf2n_clear(&t4);
    }

  return solution;
}

#if 1
void ssh_gf2n_hex_dump(const SshGF2nElement *e)
{
  unsigned int i, j;
  SshWord x;
  
  if (e->n == 0)
    {
      printf("0x0");
      return;
    }

  printf("0x");
  for (i = e->n; i; i--)
    {
      x = e->v[i - 1];
      for (j = SSH_WORD_BITS; j; j -= 8)
	printf("%02lx", (x >> (j - 8)) & 0xff);
    }
}

void ssh_gf2n_pretty_print(const SshGF2nElement *e)
{
  SshBPoly b;
  ssh_bpoly_init(&b);
  ssh_bpoly_set_gf2n(&b, e);
  ssh_bpoly_pretty_print(&b);
  ssh_bpoly_clear(&b);
}

void ssh_gf2n_mod_pretty_print(const SshGF2nModuli *m)
{
  SshBPoly b;
  ssh_bpoly_init(&b);
  ssh_bpoly_set_gf2n_mod(&b, m);
  ssh_bpoly_pretty_print(&b);
  ssh_bpoly_clear(&b);
}
#endif

/******************** Binary polynomials ************************/
/* Following routines are for the general binary polynomial case. */

/* Some of the most basic GF(2^n) routines. */

#define ssh_bpoly_memset  ssh_gf2n_memset
#define ssh_bpoly_memcpy  ssh_gf2n_memcpy
#define ssh_bpoly_memcmp  ssh_gf2n_memcmp

void ssh_bpoly_init(SshBPoly *e)
{
  e->n = 0;
  e->m = 0;
  e->v = NULL;
}

void ssh_bpoly_clear(SshBPoly *e)
{
  ssh_xfree(e->v);
  e->n = 0;
  e->m = 0;
  e->v = NULL;
}

void ssh_bpoly_realloc(SshBPoly *e, int new_size)
{
  SshWord *v;

  if (e->m < new_size)
    {
      v = ssh_xmalloc(sizeof(*v) * new_size);
      ssh_bpoly_memcpy(v, e->v, e->n);
      ssh_xfree(e->v);
      e->v = v;
      e->m = new_size;
    }
}

/* Zero the extended memory available. */
void ssh_bpoly_zero_extra(SshBPoly *e)
{
  ssh_bpoly_memset(e->v + e->n, 0, (e->m - e->n));
}

void ssh_bpoly_set_zero(SshBPoly *e)
{
  e->n = 0;
}

void ssh_bpoly_check_size(SshBPoly *e)
{
  if (e->n == 0)
    return;
  while (e->n && e->v[e->n - 1] == 0)
    e->n--;
}

unsigned int ssh_bpoly_deg(const SshBPoly *ret)
{
  int size = ret->n, r;
  SshWord v;

  if (size == 0)
    return 0;

  v = ret->v[size - 1];
  if (v == 0)
    r = SSH_WORD_BITS;
  else
    {
      r = 0;
      SSH_GF2N_COUNT_LEADING_ZEROS(r, v);
    }

  return size * SSH_WORD_BITS - r;
}

int ssh_bpoly_cmp_ui(const SshBPoly *e, unsigned int u)
{
  if (e->n == 0 && u == 0)
    return 0;

  if (e->n == 0)
    return -1;

  if (u == 0)
    return 1;

  if (e->n > 1)
    return 1;
  
  if (e->v[0] > (SshWord)u)
    return 1;

  if (e->v[0] == (SshWord)u)
    return 0;

  return -1;
}

int ssh_bpoly_cmp(const SshBPoly *a, const SshBPoly *b)
{
  unsigned int i;
  /* Check sizes. */
  if (ssh_bpoly_deg(a) != ssh_bpoly_deg(b))
    {
      if (ssh_bpoly_deg(a) > ssh_bpoly_deg(b))
	return 1;
      return -1;
    }

  /* Of equal size. */
  for (i = a->n; i; i--)
    {
      if (a->v[i - 1] != b->v[i - 1])
	{
	  if (a->v[i - 1] > b->v[i - 1])
	    return 1;
	  return -1;
	}
    }
  return 0;
}

/* Some conversion. */
void ssh_bpoly_set_gf2n_mod(SshBPoly *ret, const SshGF2nModuli *m)
{
  int i;
  /* Figure the size needed. */
  ssh_bpoly_realloc(ret, m->w[m->bits - 1] + 1);
  ssh_bpoly_memset(ret->v, 0, m->w[m->bits - 1] + 1);
  /* Copy. */
  for (i = 0; i < m->bits; i++)
    ret->v[m->w[i]] ^= ((SshWord)1 << m->b[i]);
  ret->n = m->w[m->bits - 1] + 1;
}

void ssh_bpoly_set_gf2n(SshBPoly *ret, const SshGF2nElement *e)
{
  /* Figure out the size needed. */
  ssh_bpoly_realloc(ret, e->n);
  /* Copy. */
  ssh_bpoly_memcpy(ret->v, e->v, e->n);
  ret->n = e->n;
}

void ssh_mp_set_bpoly(SshInt *ret, const SshBPoly *b)
{
  /* Figure out the size needed. */
  ssh_mp_realloc(ret, b->n);
  /* Copy. */
  ssh_bpoly_memcpy(ret->v, b->v, b->n);
  ret->n = b->n;
}

void ssh_bpoly_set_mp(SshBPoly *ret, const SshInt *mp)
{
  /* Figure out the size needed. */
  ssh_bpoly_realloc(ret, mp->n);
  /* Do a copy. */
  ssh_bpoly_memcpy(ret->v, mp->v, mp->n);
  ret->n = mp->n;
}

void ssh_bpoly_set(SshBPoly *dest, const SshBPoly *src)
{
  if (src->n == 0)
    {
      dest->n = 0;
      return;
    }
  if (dest == src)
    return;

  ssh_bpoly_realloc(dest, src->n);
  ssh_bpoly_memcpy(dest->v, src->v, src->n);
  dest->n = src->n;
}

void ssh_bpoly_set_ui(SshBPoly *ret, unsigned int u)
{
  if (u == 0)
    {
      ret->n = 0;
      return;
    }
  ssh_bpoly_realloc(ret, 1);
  ret->v[0] = (SshWord)u;
  ret->n = 1;
}

unsigned int ssh_bpoly_get_ui(const SshBPoly *op)
{
  if (op->n > 0)
    return op->v[0];
  return 0;
}

void ssh_bpoly_set_word(SshBPoly *ret, SshWord u)
{
  if (u == 0)
    {
      ret->n = 0;
      return;
    }
  ssh_bpoly_realloc(ret, 1);
  ret->v[0] = u;
  ret->n = 1;
}

SshWord ssh_bpoly_get_word(const SshBPoly *op)
{
  if (op->n > 0)
    return op->v[0];
  return 0;
}

/* Handle buffers. */
void ssh_bpoly_get_buf(unsigned char *buf, size_t buf_length,
		       const SshBPoly *op)
{
  int i;
  SshBPoly b;
  ssh_bpoly_init(&b);
  ssh_bpoly_set(&b, op);
  for (i = 0; i < buf_length; i++)
    {
      buf[buf_length - i - 1] = (ssh_bpoly_get_ui(&b) & 0xff);
      ssh_bpoly_div_2exp(&b, &b, 8);
    }
  ssh_bpoly_clear(&b);
}

void ssh_bpoly_set_buf(SshBPoly *ret, const unsigned char *buf,
		       size_t buf_length)
{
  int i;
  ssh_bpoly_set_ui(ret, 0);
  for (i = 0; i < buf_length; i++)
    {
      ssh_bpoly_mul_2exp(ret, ret, 8);
      ssh_bpoly_add_ui(ret, ret, buf[i]);
    }
}

/* Code for shifting. */
void ssh_bpoly_shift_up_words(SshBPoly *ret, unsigned int m)
{
  unsigned int i;

  if (m == 0 || ret->n == 0)
    return;
  
  ssh_bpoly_realloc(ret, ret->n + m);

  /* Lets do this manually. */
  for (i = ret->n; i; i--)
    ret->v[i + m - 1] = ret->v[i - 1];
  for (i = 0; i < m; i++)
    ret->v[i] = 0;

  ret->n += m;
}

void ssh_bpoly_shift_up_bits(SshBPoly *ret, unsigned int m)
{
  unsigned int i;

  if (m == 0 || ret->n == 0)
    return;

  ssh_bpoly_realloc(ret, ret->n + 1);
  ssh_bpoly_zero_extra(ret);
  
  for (i = ret->n; i; i--)
    ret->v[i] =
      (ret->v[i] << m) |
      (ret->v[i - 1] >> (SSH_WORD_BITS - m));
  ret->v[0] <<= m;

  ret->n++;

  /* Verify the length. */
  ssh_bpoly_check_size(ret);
}

void ssh_bpoly_shift_down_words(SshBPoly *ret, unsigned int m)
{
  unsigned int i;

  if (m == 0 || ret->n == 0)
    return;

  if (m > ret->n)
    {
      ret->n = 0;
      return;
    }

  for (i = 0; i < ret->n - m; i++)
    ret->v[i] = ret->v[i + m];

  ret->n -= m;
}

void ssh_bpoly_shift_down_bits(SshBPoly *ret, unsigned int m)
{
  unsigned int i;

  if (m == 0 || ret->n == 0)
    return;

  for (i = 0; i < ret->n - 1; i++)
    ret->v[i] = (ret->v[i] >> m) |
      (ret->v[i + 1] << (SSH_WORD_BITS - m));

  ret->v[ret->n - 1] >>= m;

  /* Recheck the size. */
  ssh_bpoly_check_size(ret);
}

void ssh_bpoly_mul_2exp(SshBPoly *ret, const SshBPoly *e, unsigned int m)
{
  unsigned int i;
  
  /* Copy first if not equal. */
  ssh_bpoly_set(ret, e);

  if (m == 0)
    return;

  i = m / SSH_WORD_BITS;
  m %= SSH_WORD_BITS;

  if (i)
    ssh_bpoly_shift_up_words(ret, i);

  /* Shift some bits. */
  if (m)
    ssh_bpoly_shift_up_bits(ret, m);
}

void ssh_bpoly_div_2exp(SshBPoly *ret, const SshBPoly *e, unsigned int m)
{
  unsigned int i;
  
  ssh_bpoly_set(ret, e);

  if (m == 0)
    return;

  i = m / SSH_WORD_BITS;
  m %= SSH_WORD_BITS;

  if (i)
    ssh_bpoly_shift_down_words(ret, i);

  if (m)
    ssh_bpoly_shift_down_bits(ret, m);
}

unsigned int ssh_bpoly_get_bit(const SshBPoly *ret, unsigned int m)
{
  unsigned int i;
  SshWord v;
  
  if (ret->n == 0)
    return 0;
  
  i = m / SSH_WORD_BITS;
  m %= SSH_WORD_BITS;

  if (i > ret->n - 1)
    return 0;
  
  v = ret->v[i];

  return (v >> m) & 0x1;
}

void ssh_bpoly_set_bit(SshBPoly *ret, unsigned int m)
{
  unsigned int i;

  i = m / SSH_WORD_BITS;
  m %= SSH_WORD_BITS;

  ssh_bpoly_realloc(ret, i + 1);
  ssh_bpoly_zero_extra(ret);
  
  ret->v[i] = (ret->v[i] | ((SshWord)1 << m));
  if (ret->n < i + 1)
    ret->n = i + 1;
}

void ssh_bpoly_add_ui(SshBPoly *ret, const SshBPoly *a, unsigned int u)
{
  ssh_bpoly_set(ret, a);
  ssh_bpoly_realloc(ret, 1);
  ssh_bpoly_zero_extra(ret);
  ret->v[0] ^= u;
  if (ret->n == 0)
    ret->n = 1;
}

void ssh_bpoly_add(SshBPoly *ret, const SshBPoly *a, const SshBPoly *b)
{
  unsigned int i;

  /* Copy. */
  ssh_bpoly_set(ret, a);

  /* Resize. */
  ssh_bpoly_realloc(ret, b->n);

  /* Zero the extra memory. */
  ssh_bpoly_zero_extra(ret);
  
  for (i = 0; i < b->n; i++)
    ret->v[i] ^= b->v[i];

  if (ret->n < b->n)
    ret->n = b->n;
  
  /* Check the size. */
  ssh_bpoly_check_size(ret);
}

#if 0
/* Very slow multiplication. */
void ssh_bpoly_mul(SshBPoly *ret, const SshBPoly *a, const SshBPoly *b)
{
  unsigned int i, zeros, size;
  SshBPoly tmp, shifted;

  ssh_bpoly_init(&tmp);
  ssh_bpoly_init(&shifted);
  
  /* Multiplication. */
  ssh_bpoly_realloc(&tmp, a->n + b->n);
  ssh_bpoly_set_ui(&tmp, 0);

  size = ssh_bpoly_deg(b);
  ssh_bpoly_set(&shifted, a);

  for (i = 0, zeros = 0; i < size; i++, zeros++)
    {
      if (ssh_bpoly_get_bit(b, i) == 1)
	{
	  ssh_bpoly_mul_2exp(&shifted, &shifted, zeros);
	  ssh_bpoly_add(&tmp, &tmp, &shifted);
#if 0
	  printf("s = ");
	  ssh_bpoly_hex_dump(&shifted);
	  printf("\n");
	  printf("a = ");
	  ssh_bpoly_hex_dump(&tmp);
	  printf("\n");
#endif
	  zeros = 0;
	}
    }
  
  ssh_bpoly_set(ret, &tmp);
  
  ssh_bpoly_clear(&tmp);
  ssh_bpoly_clear(&shifted);
}
#else
/* Reasonably fast multiplication. Not re-entrant! */
void ssh_bpoly_mul(SshBPoly *ret, const SshBPoly *a, const SshBPoly *b)
{
  int n;
  SshWord *r;
  static SshWord ut0[SSH_WORD_BITS], ut1[SSH_WORD_BITS];

  n = a->n + b->n + 1;
  ssh_bpoly_realloc(ret, n);
  if (ret != a && ret != b)
    r = ret->v;
  else
    r = ssh_xmalloc(sizeof(SshWord) * n);
  ssh_bpoly_memset(r, 0, n);

  if (a->n > b->n)
    ssh_gf2n_internal_mul(r, a->v, a->n, b->v, b->n,
			  ut0, ut1);
  else
    ssh_gf2n_internal_mul(r, b->v, b->n, a->v, a->n,
			  ut0, ut1);

  /* Figure out the correct size. */
  while (n && r[n - 1] == 0)
    n--;
  
  if (r != ret->v)
    {
      ssh_bpoly_memcpy(ret->v, r, n);
      ssh_xfree(r);
    }
 ret->n = n;
}
#endif

#if 0
/* It is unknown to me if this is faster than multiplying with this
   sort of implementation. */
void ssh_bpoly_square(SshBPoly *ret, const SshBPoly *a)
{
  unsigned int size, i;
  SshBPoly tmp;

  ssh_bpoly_init(&tmp);
  ssh_bpoly_set_ui(&tmp, 0);

  size = ssh_bpoly_deg(a);

  for (i = 0; i < size; i++)
    {
      if (ssh_bpoly_get_bit(a, i))
	ssh_bpoly_set_bit(&tmp, i << 1);
    }

  ssh_bpoly_set(ret, &tmp);
  ssh_bpoly_clear(&tmp);
}
#else
/* Reasonably fast squaring. */
void ssh_bpoly_square(SshBPoly *ret, const SshBPoly *a)
{
  SshWord *r;
  int n;

  n = a->n * 2 + 1;
  ssh_bpoly_realloc(ret, n);
  if (ret != a)
    r = ret->v;
  else
    r = ssh_xmalloc(sizeof(SshWord) * n);

  /* We want to clear the memory before filling it with squared octets. */
  ssh_bpoly_memset(r, 0, n);
  ssh_gf2n_internal_square(r, a->v, a->n);

  /* Figure out the correct length. */
  while (n && r[n - 1] == 0)
    n--;

  if (r != ret->v)
    {
      ssh_bpoly_memcpy(ret->v, r, n);
      ssh_xfree(r);
    }
  ret->n = n;
}
#endif

/* Very slow division. We don't want to spend the time to speed this up,
   because there is no use for general purpose division of binary polynomials
   in cryptography. Or is there? */
void ssh_bpoly_div(SshBPoly *q, SshBPoly *r,
		   const SshBPoly *a, const SshBPoly *b)
{
  unsigned int deg_b, deg_t, last_t, diff, shift;
  SshBPoly t1, t2, t3;

  if (b->n == 0)
    ssh_fatal("ssh_bpoly_div: division by zero.\n");
  
  if (ssh_bpoly_deg(a) < ssh_bpoly_deg(b))
    {
      ssh_bpoly_set(r, a);
      ssh_bpoly_set_ui(q, 0);
      return;
    }
  
  ssh_bpoly_init(&t1);
  ssh_bpoly_init(&t2);
  ssh_bpoly_init(&t3);

  ssh_bpoly_set(&t1, a);
  ssh_bpoly_set_ui(&t2, 0);

  deg_b  = ssh_bpoly_deg(b);
  deg_t  = ssh_bpoly_deg(&t1);
  last_t = deg_b;
  diff   = deg_t - deg_b;
  shift  = 0;

#if 0
  printf("\nDivision: \n");
#endif
  
  while (deg_t >= deg_b)
    {
      ssh_bpoly_mul_2exp(&t3, b, diff);

#if 0
      printf("remainder = ");
      ssh_bpoly_hex_dump(&t1);
      printf(" %d\n", ssh_bpoly_deg(&t1));
      printf("  divisor = ");
      ssh_bpoly_hex_dump(&t3);
      printf(" %d\n", ssh_bpoly_deg(&t3));
      printf(" original = ");
      ssh_bpoly_hex_dump(b);
      printf(" %d\n", ssh_bpoly_deg(b));
#endif
      
      ssh_bpoly_add(&t1, &t1, &t3);
      
      /* Move the quotient. */
      if (shift)
	ssh_bpoly_mul_2exp(&t2, &t2, shift);

      /* Add to the quotient. */
      ssh_bpoly_add_ui(&t2, &t2, 1);

      /* Recompute difference. */
      last_t = deg_t;
      deg_t  = ssh_bpoly_deg(&t1);
      diff   = deg_t - deg_b;
      shift  = last_t - deg_t;

#if 0
      printf("l: %d t: %d b: %d d: %d s: %d\n",
	     last_t, deg_t, deg_b, diff, shift);

      printf("quotient = ");
      ssh_bpoly_hex_dump(&t2);
      printf("\n");
#endif
    }

  /* Final corrections for the quotient. */
  if (last_t - deg_b)
    ssh_bpoly_mul_2exp(&t2, &t2, last_t - deg_b);
  
  ssh_bpoly_set(r, &t1);
  ssh_bpoly_set(q, &t2);

#if 0
  /* Testing. */
  
  ssh_bpoly_mul(&t1, q, b);
  ssh_bpoly_add(&t1, &t1, r);
  if (ssh_bpoly_cmp(&t1, a) != 0)
    {
      printf("error: division failed.\n");
      printf("t1 = ");
      ssh_bpoly_hex_dump(&t1);
      printf("\nq = ");
      ssh_bpoly_hex_dump(q);
      printf("\nr = ");
      ssh_bpoly_hex_dump(r);
      printf("\nb = ");
      ssh_bpoly_hex_dump(b);
      printf("\na = ");
      ssh_bpoly_hex_dump(a);
      printf("\n");
      abort();
    }
#endif
  
  ssh_bpoly_clear(&t1);
  ssh_bpoly_clear(&t2);
  ssh_bpoly_clear(&t3);
}

/* Very slow modulo. If doing a lot of these then use the ssh_gf2n_* set
   of routines. However, it of course would be sometimes advantageous to
   make this routine fast. I don't know any easy way to do so, though. */
void ssh_bpoly_mod(SshBPoly *r,
		   const SshBPoly *a, const SshBPoly *b)
{
  unsigned int deg_b, deg_t, last_t, diff;
  SshBPoly t1, t3;

  if (b->n == 0)
    {
      printf("gf2n_mod: division by zero.\n");
      abort();
    }
  
  if (ssh_bpoly_deg(a) < ssh_bpoly_deg(b))
    {
      ssh_bpoly_set(r, a);
      return;
    }
  
  ssh_bpoly_init(&t1);
  ssh_bpoly_init(&t3);

  ssh_bpoly_set(&t1, a);

  deg_b = ssh_bpoly_deg(b);
  deg_t = ssh_bpoly_deg(&t1);
  diff = deg_t - deg_b;
  
  while (deg_t >= deg_b)
    {
      ssh_bpoly_mul_2exp(&t3, b, diff);
      ssh_bpoly_add(&t1, &t1, &t3);

      /* Recompute difference. */
      last_t = deg_t;
      deg_t = ssh_bpoly_deg(&t1);
      diff = deg_t - deg_b;
    }

  ssh_bpoly_set(r, &t1);

#if 0
  ssh_bpoly_div(&t1, &t3, a, b);
  if (ssh_bpoly_cmp(&t3, r) != 0)
    {
      printf("error: modular operation failed.\n");
      abort();
    }
#endif
  
  
  ssh_bpoly_clear(&t1);
  ssh_bpoly_clear(&t3);
}

/* Euclidean algorithms for binary polynomials. */

void ssh_bpoly_gcd(SshBPoly *gcd, const SshBPoly *a, const SshBPoly *b)
{
  SshBPoly h, g, r, q;

  ssh_bpoly_init(&h);
  ssh_bpoly_init(&g);
  ssh_bpoly_init(&r);
  ssh_bpoly_init(&q);

  ssh_bpoly_set(&h, a);
  ssh_bpoly_set(&g, b);
  
  while (ssh_bpoly_deg(&h))
    {
      ssh_bpoly_div(&q, &r, &g, &h);
      ssh_bpoly_set(&g, &h);
      ssh_bpoly_set(&h, &r);
    }

  ssh_bpoly_set(gcd, &g);
  
  ssh_bpoly_clear(&h);
  ssh_bpoly_clear(&g);
  ssh_bpoly_clear(&r);
  ssh_bpoly_clear(&q);
}

void ssh_bpoly_gcdext(SshBPoly *gcd, SshBPoly *sx,
		      const SshBPoly *gx, const SshBPoly *hx)
{
  SshBPoly s, h, q, r, g, s1, s2;

  ssh_bpoly_init(&s);
  ssh_bpoly_init(&h);
  ssh_bpoly_init(&q);
  ssh_bpoly_init(&r);
  ssh_bpoly_init(&g);
  ssh_bpoly_init(&s1);
  ssh_bpoly_init(&s2);

  ssh_bpoly_set(&h, hx);
  ssh_bpoly_set(&g, gx);

  ssh_bpoly_set_ui(&s2, 1);
  ssh_bpoly_set_ui(&s1,0);

  while (ssh_bpoly_deg(&h))
    {
      ssh_bpoly_div(&q, &r, &g, &h);
      ssh_bpoly_mul(&s, &q, &s1);
      ssh_bpoly_add(&s, &s, &s2);
      ssh_bpoly_set(&g, &h);
      ssh_bpoly_set(&h, &r);
      ssh_bpoly_set(&s2, &s1);
      ssh_bpoly_set(&s1, &s);
    }

  ssh_bpoly_set(gcd, &g);
  ssh_bpoly_set(sx, &s2);
  
  ssh_bpoly_clear(&s);
  ssh_bpoly_clear(&q);
  ssh_bpoly_clear(&r);
  ssh_bpoly_clear(&h);
  ssh_bpoly_clear(&g);
  ssh_bpoly_clear(&s1);
  ssh_bpoly_clear(&s2);  
}

void ssh_bpoly_swap(SshBPoly *a, SshBPoly *b)
{
  int k;
  SshWord *v;

  /* First swap the pointers. */
  v = a->v;
  a->v = b->v;
  b->v = v;

  /* Then the control information. */
  k = a->n;
  a->n = b->n;
  b->n = k;

  k = a->m;
  a->m = b->m;
  b->m = k;

  /* Finished. */
}

#if 0
int ssh_bpoly_invert(SshBPoly *inv, const SshBPoly *a, const SshBPoly *b)
{
  SshBPoly g;

  ssh_bpoly_init(&g);

  ssh_bpoly_gcdext(&g, inv, a, b);
  if (ssh_bpoly_cmp_ui(&g, 1) == 0)
    return 0;
  return 1;
}
#else
#if 1
/* We recommend doing the inversion like this, or with the
   almost inverse routine. This method is direct translation of the
   method by Bosselaers et al.

   This might be slightly slower than the almost inverse algorithm. But
   use this with the general binary polynomials for reasons obvious. E.g.
   it is more meaningful to test between two different algorithms than
   between two versions of one algorithm, it means that we will with
   more probability find errors in test suites.
   */
int ssh_bpoly_invert(SshBPoly *inv, const SshBPoly *a, const SshBPoly *m)
{
  SshBPoly f, g, b, c, t1, t2;
  unsigned int j;

  if (ssh_bpoly_cmp_ui(a, 0) == 0)
    return 0;

  if (ssh_bpoly_deg(a) == 0)
    return 0;

  if (m->n == 0)
    {
      printf("ssh_bpoly_invert: divide by zero.\n");
      abort();
    }
        
  ssh_bpoly_init(&f);
  ssh_bpoly_init(&g);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);
  ssh_bpoly_init(&t1);
  ssh_bpoly_init(&t2);

  ssh_bpoly_set_ui(&b, 1);
  ssh_bpoly_set_ui(&c, 0);
  ssh_bpoly_set(&f, a);
  ssh_bpoly_set(&g, m);

  while (ssh_bpoly_cmp_ui(&f, 1) > 0)
    {
#if 0
      printf(" f = ");
      ssh_bpoly_hex_dump(&f);
      printf("\n g = ");
      ssh_bpoly_hex_dump(&g);
      printf("\n b = ");
      ssh_bpoly_hex_dump(&b);
      printf("\n c = ");
      ssh_bpoly_hex_dump(&c);
      printf("\n");
#endif
      
      if (ssh_bpoly_deg(&f) < ssh_bpoly_deg(&g))
	{
	  ssh_bpoly_swap(&f, &g);
	  ssh_bpoly_swap(&b, &c);
	}

      j = ssh_bpoly_deg(&f) - ssh_bpoly_deg(&g);

      ssh_bpoly_mul_2exp(&t1, &g, j);
      ssh_bpoly_mul_2exp(&t2, &c, j);

      ssh_bpoly_add(&f, &f, &t1);
      ssh_bpoly_add(&b, &b, &t2);
    }

  ssh_bpoly_set(inv, &b);

#if 0
  ssh_bpoly_mul(&c, &b, a);
  ssh_bpoly_mod(&c, &c, m);
  if (ssh_bpoly_cmp_ui(&c, 1) != 0)
    {
      printf("Failure in ssh_bpoly_invert!\n");
      printf("Input: ");
      ssh_bpoly_hex_dump(a);      
      printf("\nResult: ");
      ssh_bpoly_hex_dump(&c);
      printf("\nOutput: ");
      ssh_bpoly_hex_dump(inv);
      printf("\nModulus: ");
      ssh_bpoly_hex_dump(m);
      printf("\n");
    }
#endif
  
  ssh_bpoly_clear(&f);
  ssh_bpoly_clear(&g);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&c);
  ssh_bpoly_clear(&t1);
  ssh_bpoly_clear(&t2);  

  return 1;
}
#else

/* Almost inverse algorithm of Schroeppel et al. This is for testing
   purposes of the faster optimized version of gf2n! */
int ssh_bpoly_invert(SshBPoly *inv, const SshBPoly *a, const SshBPoly *m)
{
  SshBPoly f, g, b, c;
  int k = 0, i, j;
  SshWord mask, v;

  if (ssh_bpoly_cmp_ui(a, 0) == 0)
    {
      printf("error: division by zero.\n");
      return 1;
    }
  
  ssh_bpoly_init(&f);
  ssh_bpoly_init(&g);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&c);

  ssh_bpoly_set_ui(&b, 1);
  ssh_bpoly_set_ui(&c, 0);
  ssh_bpoly_set(&f, a);
  ssh_bpoly_set(&g, m);
  
  while (1)
    {
#if 0
      printf(" c = ");
      ssh_bpoly_hex_dump(&c);
      printf("\n f = ");
      ssh_bpoly_hex_dump(&f);
      printf("\n b = ");
      ssh_bpoly_hex_dump(&b);
      printf("\n g = ");
      ssh_bpoly_hex_dump(&g);
      printf("\n");
#endif

      while (!(ssh_bpoly_get_ui(&f) & 0x1))
	{
	  ssh_bpoly_div_2exp(&f, &f, 1);
	  ssh_bpoly_mul_2exp(&c, &c, 1);
	  k++;
	}

      if (ssh_bpoly_cmp_ui(&f, 1) == 0)
	break;

      if (ssh_bpoly_cmp(&f, &g) < 0)
	{
	  ssh_bpoly_swap(&f, &g);
	  ssh_bpoly_swap(&c, &b);
	}

      ssh_bpoly_add(&f, &f, &g);
      ssh_bpoly_add(&b, &b, &c);
    }

  ssh_bpoly_set(&f, m);

#if 0
  printf("\n b = ");
  ssh_bpoly_hex_dump(&b);
#endif

  /* Figure out the difference between two of the least significant
     modulus bits. This is rather ugly, but this version is used
     for testing only! */
  v = ssh_bpoly_get_word(m);
  v ^= 0x1;
  i = 0;
  if (v)
    {
      while ((v & 0x1) == 0)
	{
	  v >>= 1;
	  i++;
	}
    }
  else
    i = SSH_WORD_BITS;
  
  while (k >= SSH_WORD_BITS)
    {
      for (j = 0; j < SSH_WORD_BITS; j += i)
	{
	  ssh_bpoly_set_word(&c, ssh_bpoly_get_word(&b));
	  ssh_bpoly_mul(&g, &c, &f);
	  ssh_bpoly_add(&b, &b, &g);
	}
      ssh_bpoly_div_2exp(&b, &b, SSH_WORD_BITS);
      k -= SSH_WORD_BITS;
    }
#if 0
  printf("\n b = ");
  ssh_bpoly_hex_dump(&b);
  printf("\n");
#endif

  if (k)
    {
      mask = ((SshWord)1 << k) - 1;
      for (j = 0; j < k; j += i)
	{
	  ssh_bpoly_set_word(&c, ssh_bpoly_get_word(&b) & mask);
	  ssh_bpoly_mul(&g, &c, &f);
	  ssh_bpoly_add(&b, &b, &g);
	}
      ssh_bpoly_div_2exp(&b, &b, k);
    }

#if 0
  printf("\n b = ");
  ssh_bpoly_hex_dump(&b);
  printf("\n");
#endif
  
  ssh_bpoly_set(inv, &b);
  
  ssh_bpoly_clear(&f);
  ssh_bpoly_clear(&c);
  ssh_bpoly_clear(&g);
  ssh_bpoly_clear(&b);
  return 0;
}

#endif
#endif
#if 0
/* Testing. This function was used to test the inversion in this lower
   level. We'd better write some code for upper level testing. */
int ssh_bpoly_invert(SshBPoly *inv, const SshBPoly *a, const SshBPoly *m)
{
  SshBPoly b, t;
  int rv;
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&t);
  ssh_bpoly_invert_almost(&b, a, m);
  ssh_bpoly_mul(&t, &b, a);
  ssh_bpoly_mod(&t, &t, m);
  if (ssh_bpoly_cmp_ui(&t, 1) == 0)
    printf("Inversion 1 success.\n");
  else
    printf("Inversion 1 failed.\n");
  
  rv = ssh_bpoly_invert_basic(inv, a, m);
  ssh_bpoly_mul(&t, inv, a);
  ssh_bpoly_mod(&t, &t, m);
  if (ssh_bpoly_cmp_ui(&t, 1) == 0)
    printf("Inversion 2 success.\n");
  else
    printf("Inversion 2 failed.\n");
  if (ssh_bpoly_cmp(&b, inv) != 0)
    {
      printf("error: not equivalent.\n");
      printf("b = ");
      ssh_bpoly_hex_dump(&b);
      printf("\ninv = ");
      ssh_bpoly_hex_dump(inv);
      printf("\n");
    }
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&t);
  return 0;
}
#endif

void ssh_bpoly_trace(SshBPoly *trace, const SshBPoly *a, const SshBPoly *b)
{
  unsigned int len;
  SshBPoly tmp, t;

  ssh_bpoly_init(&tmp);
  ssh_bpoly_init(&t);
  ssh_bpoly_set_ui(&tmp, 0);
  ssh_bpoly_set(&t, a);

  for (len = 1; len < (ssh_bpoly_deg(b) - 1); len++)
    {
      ssh_bpoly_square(&tmp, &t);
      ssh_bpoly_mod(&tmp, &tmp, b);
      ssh_bpoly_add(&t, &tmp, a);
    }

  ssh_bpoly_set(trace, &t);
  
  ssh_bpoly_clear(&tmp);
  ssh_bpoly_clear(&t);
}

void ssh_bpoly_half_trace(SshBPoly *trace, const SshBPoly *a,
			  const SshBPoly *b)
{
  unsigned int len;
  SshBPoly tmp, t;

  ssh_bpoly_init(&tmp);
  ssh_bpoly_init(&t);
  ssh_bpoly_set_ui(&tmp, 0);
  ssh_bpoly_set(&t, a);

  /* Note that ssh_bpoly_deg(b) is actually one larger than the highest set
     bit. Thus this instead of (ssh_bpoly_deg(b) - 1)/2 + 1. */
  for (len = 1; len < ssh_bpoly_deg(b)/2; len++)
    {
      ssh_bpoly_square(&tmp, &t);
      ssh_bpoly_mod(&tmp, &tmp, b);
      ssh_bpoly_square(&t, &tmp);
      ssh_bpoly_mod(&t, &t, b);
      ssh_bpoly_add(&t, &t, a);
    }

  ssh_bpoly_set(trace, &t);
  
  ssh_bpoly_clear(&tmp);
  ssh_bpoly_clear(&t);
}

void ssh_bpoly_relative_trace(SshBPoly *trace, const SshBPoly *a,
			      unsigned int exp, const SshBPoly *m)
{
  unsigned int deg = ssh_bpoly_deg(m) - 1, i, j;
  SshBPoly tmp, t;

  ssh_bpoly_init(&tmp);
  ssh_bpoly_init(&t);

  ssh_bpoly_set(&t, a);

  /* The computation goes as:

     0 t = a
     1 t = a^(2^exp) + a
     2 t = a^(2^(2exp)) + a^(2^exp) + a
     ...
     */

  for (i = 1; i < deg/exp; i++)
    {
      /* compute a^(2^exp) */
      for (j = 0; j < exp; j++)
	{
	  ssh_bpoly_square(&tmp, &t);
	  ssh_bpoly_mod(&t, &tmp, m);
	}
      ssh_bpoly_add(&t, &t, a);
      ssh_bpoly_mod(&t, &t, m);
    }
	 
  ssh_bpoly_set(trace, &t);
  
  ssh_bpoly_clear(&tmp);
  ssh_bpoly_clear(&t);
  
}

void ssh_bpoly_powm_2exp(SshBPoly *a, const SshBPoly *b,
			 unsigned int e, const SshBPoly *m)
{
  SshBPoly t1;

  ssh_bpoly_init(&t1);

  ssh_bpoly_set(&t1, b);

  while (e)
    {
      ssh_bpoly_square(&t1, &t1);
      ssh_bpoly_mod(&t1, &t1, m);
      e--;
    }

  ssh_bpoly_set(a, &t1);
  ssh_bpoly_clear(&t1);
}
		    
void ssh_bpoly_powm(SshBPoly *a, const SshBPoly *b,
		    const SshInt *e, const SshBPoly *m)
{
  unsigned int i, size;
  SshBPoly t1;

  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_bpoly_set_ui(a, 1);
      return;
    }
  
  ssh_bpoly_init(&t1);

  ssh_bpoly_set(&t1, b);

  size = ssh_mp_get_size(e, 2) - 1;

  for (i = size; i; i--)
    {
      ssh_bpoly_square(&t1, &t1);
      ssh_bpoly_mod(&t1, &t1, m);

      if (ssh_mp_get_bit(e, i - 1))
	{
	  ssh_bpoly_mul(&t1, &t1, b);
	  ssh_bpoly_mod(&t1, &t1, m);
	}
    }
  
  ssh_bpoly_set(a, &t1);
  ssh_bpoly_clear(&t1);
}

void ssh_bpoly_poor_rand(SshBPoly *a, const SshBPoly *m)
{
  unsigned int size = m->n + 1, i;

  ssh_bpoly_realloc(a, size);
  for (i = 0; i < size; i++)
    a->v[i] = ssh_gf2n_random();
  a->n = size;
  
  ssh_bpoly_mod(a, a, m);
}

Boolean ssh_bpoly_quad_solve(SshBPoly *z, const SshBPoly *b,
			     const SshBPoly *m)
{
  SshBPoly t1, t2, t3, t4;
  Boolean solution = FALSE;
  unsigned int i;

#if 0
  printf("Degree %u\n", ssh_bpoly_deg(m) - 1);
  printf("Input: ");
  ssh_bpoly_hex_dump(b);
  printf("\nModuli: ");
  ssh_bpoly_hex_dump(m);
  printf("\n");
#endif
  
  if ((ssh_bpoly_deg(m) - 1) & 0x1)
    {
      /* Special case of size odd. */
      ssh_bpoly_init(&t1);
      ssh_bpoly_half_trace(z, b, m);

      /* Verify. */
      ssh_bpoly_square(&t1, z);
      ssh_bpoly_mod(&t1, &t1, m);
      ssh_bpoly_add(&t1, &t1, z);

      if (ssh_bpoly_cmp(&t1, b) == 0)
	solution = TRUE;

      ssh_bpoly_clear(&t1);
    }
  else
    {
      ssh_bpoly_init(&t1);
      ssh_bpoly_init(&t2);
      ssh_bpoly_init(&t3);
      ssh_bpoly_init(&t4);

      while (1)
	{
	  ssh_bpoly_poor_rand(&t1, m);

	  ssh_bpoly_set_ui(z, 0);
	  ssh_bpoly_set(&t2, b);

	  for (i = 1; i < ssh_bpoly_deg(m) - 1; i++)
	    {
	      ssh_bpoly_square(&t3, z);
	      ssh_bpoly_mod(z, &t3, m);

	      ssh_bpoly_square(&t4, &t2);
	      ssh_bpoly_mod(&t4, &t4, m);
	      ssh_bpoly_add(&t2, &t4, b);

	      ssh_bpoly_mul(&t3, &t4, &t1);
	      ssh_bpoly_mod(&t3, &t3, m);

	      ssh_bpoly_add(z, z, &t3);
	    }

	  if (ssh_bpoly_cmp_ui(&t2, 0) != 0)
	    break;

	  /* Verify. */
	  ssh_bpoly_square(&t1, z);
	  ssh_bpoly_mod(&t1, &t1, m);
	  ssh_bpoly_add(&t1, &t1, z);
	  
	  if (ssh_bpoly_cmp_ui(&t1, 0) != 0)
	    {
	      solution = TRUE;
	      break;
	    }
	}
      
      ssh_bpoly_clear(&t1);
      ssh_bpoly_clear(&t2);
      ssh_bpoly_clear(&t3);
      ssh_bpoly_clear(&t4);
    }

  return solution;
}

Boolean ssh_bpoly_is_irreducible(const SshBPoly *op)
{
  SshBPoly u, v, d, x;
  unsigned int i, deg = ssh_bpoly_deg(op) - 1;

  ssh_bpoly_init(&u);
  ssh_bpoly_init(&v);
  ssh_bpoly_init(&d);
  ssh_bpoly_init(&x);

  /* Set x */
  ssh_bpoly_set_ui(&x, 2);
  ssh_bpoly_set(&u, &x);

  for (i = 0; i < deg/2; i++)
    {
      ssh_bpoly_square(&v, &u);
      ssh_bpoly_mod(&v, &v, op);
      ssh_bpoly_set(&u, &v);
      ssh_bpoly_add(&v, &v, &x);
      ssh_bpoly_gcd(&d, op, &v);
      if (ssh_bpoly_cmp_ui(&d, 1) != 0)
	break;
    }

  ssh_bpoly_clear(&u);
  ssh_bpoly_clear(&v);
  ssh_bpoly_clear(&d);
  ssh_bpoly_clear(&x);

  if (i == deg/2)
    return TRUE;
  return FALSE;
}

/* Sometimes we only want to find a very small irreducible polynomial,
   of any number of terms. */
unsigned int ssh_bpoly_find_small_irreducible(unsigned int size)
{
  unsigned int i, p;
  SshBPoly a;

  ssh_bpoly_init(&a);

  /* Do a brute force search. Should not take too long for very small
     sizes. Notice, that we are only seeking for values that
     are odd. */
  for (i = 1; i < (1 << size); i += 2)
    {
      /* Set up the binary polynomial. */
      ssh_bpoly_set_ui(&a, i | (1 << size));
      if (ssh_bpoly_is_irreducible(&a) == TRUE)
	{
	  p = ssh_bpoly_get_ui(&a);
	  ssh_bpoly_clear(&a);
	  return p;
	}
    }
  /* Nothing found! Too bad. */
  ssh_bpoly_clear(&a);
  return 0;
}

/* Finds the irreducible with some specific number of terms. */
int ssh_bpoly_find_irreducible(unsigned int size, unsigned int first,
			       int *bits, unsigned int bits_count)
{
  int i, j;
  SshBPoly m;

  ssh_bpoly_init(&m);

  /* Cannot be irreducible if has even number of terms! */
  if (bits_count != 2 && (bits_count % 2) == 0)
    {
      ssh_bpoly_clear(&m);
      return 0;
    }

  /* If we are searching for the first, e.g. smallest, irreducible
     then set up with our own setup function. */
  if (first)
    {
      /* Least significant bit must always be set. */
      bits[0] = 0;
      /* As the most significant bit, because we are searching for
	 irreducible of this specific degree! */
      bits[bits_count - 1] = size;
      for (i = 1; i < bits_count - 1; i++)
	bits[i] = i;
    }

  /* Loop through the bits. */
  while (1)
    {
      /* Test phase. */
      ssh_bpoly_set_ui(&m, 0);
      for (i = 0; i < bits_count; i++)
	ssh_bpoly_set_bit(&m, bits[i]);
      if (ssh_bpoly_is_irreducible(&m) == TRUE)
	break;

      /* Advance phase. */
      for (i = 1; i < bits_count - 1; i++)
	if (bits[i] + 1 < bits[i + 1])
	  {
	    for (j = 1; j < i; j++)
	      bits[j] = j;
	    bits[i]++;
	    break;
	  }

      /* Stopping condition (we don't search for ever!). */
      if (i >= bits_count - 1)
	{
	  ssh_bpoly_clear(&m);
	  return 0;
	}
    }
  ssh_bpoly_clear(&m);
  return 1;
}

/* Checking whether op is primitive element modulo m. However, this
   will work only if m is small. */
Boolean ssh_bpoly_is_primitive(const SshBPoly *op, const SshBPoly *m)
{
  unsigned int deg = ssh_bpoly_deg(m) - 1, i, k, max;
  SshBPoly t1;
  SshInt e;

  if (deg > 32)
    {
      /* Cannot factor this large numbers. */
      return FALSE;
    }

  /* Compute the power. */
  if (deg == 32)
    k = ~(unsigned int)0;
  else
    k = (1 << deg) - 1;

  max = (1 << ((deg + 1)/2));
  
  ssh_bpoly_init(&t1);

  ssh_mp_init(&e);
  ssh_mp_set_ui(&e, k);
  
  ssh_bpoly_powm(&t1, op, &e, m);
  if (ssh_bpoly_cmp_ui(&t1, 1) != 0)
    {
      printf("Failure!\n");
      abort();
    }
  
  /* Simple trial division factorization and checking. */
  for (i = 2; i < max; i++)
    {
      if ((k % i) == 0)
	{
	  ssh_mp_set_ui(&e, k / i);
	  ssh_bpoly_powm(&t1, op, &e, m);
	  if (ssh_bpoly_cmp_ui(&t1, 1) == 0)
	    break;
	}
    }

  ssh_bpoly_clear(&t1);
  ssh_mp_clear(&e);

  if (i == max)
    return TRUE;
  return FALSE;
}

#if 1
void ssh_bpoly_hex_dump(const SshBPoly *e)
{
  unsigned int i, j;
  SshWord x;

  if (e->n == 0)
    {
      printf("0x0");
      return;
    }

  printf("0x");
  for (i = e->n; i; i--)
    {
      x = e->v[i - 1];
      for (j = SSH_WORD_BITS; j; j -= 8)
	printf("%02lx", (x >> (j - 8)) & 0xff);
    }
}

void ssh_bpoly_pretty_print(const SshBPoly *e)
{
  unsigned int i, prev;

  if (e->n == 0)
    {
      printf("(0)");
      return;
    }

  printf("(");
  for (prev = 0, i = ssh_bpoly_deg(e) + 1; i; i--)
    {
      if (ssh_bpoly_get_bit(e, i - 1) == 1)
	{
	  if (prev)
	    printf(" + ");
	  if (i == 1)
	    printf("1");
	  else
	    printf("x^%d", i - 1);
	  prev = 1;
	}
    }
  printf(")");
}
#endif

/********************* GF(2^n) Polynomials *********************/

/* Quick and dirty polynomial extension for gf2n. */

/* We don't use much comments. Everything you need to know is in some other
   file. Sorry. XXX This need to be fixed.  */

/* Initialize the polynomial. */
void ssh_gf2n_poly_init(SshGF2nPoly *p, const SshGF2nModuli *m)
{
  p->m = 0;
  p->n = 0;
  p->c = NULL;
  p->moduli = m;
}

void ssh_gf2n_poly_clear(SshGF2nPoly *p)
{
  unsigned int i;
  for (i = 0; i < p->m; i++)
    ssh_gf2n_clear(&p->c[i]);
  p->n =0;
  p->m = 0;
  ssh_xfree(p->c);
  p->c = NULL;
}

void ssh_gf2n_poly_realloc(SshGF2nPoly *p, unsigned int size)
{
  if (size > p->m)
    {
      SshGF2nElement *table;
      unsigned int i;

      table = ssh_xmalloc(sizeof(SshGF2nElement) * size);
      memcpy(table, p->c, sizeof(SshGF2nElement) * p->n);
      for (i = p->n; i < size; i++)
	{
	  ssh_gf2n_init(&table[i], p->moduli);
	  ssh_gf2n_set_ui(&table[i], 0);
	}
      ssh_xfree(p->c);
      p->c = table;
      p->m = size;
    }
}

int ssh_gf2n_poly_is_zero(const SshGF2nPoly *a)
{
  if (a->n == 0)
    return 1;
  return 0;
}

void ssh_gf2n_poly_set_zero(SshGF2nPoly *a)
{
  unsigned int i;
  if (a->c == NULL)
    return;
  for (i = 0; i < a->m; i++)
    ssh_gf2n_set_ui(&a->c[i], 0);
  a->n = 0;
}

void ssh_gf2n_poly_set(SshGF2nPoly *a, const SshGF2nPoly *b)
{
  unsigned int i;
  if (a == b)
    return;
  ssh_gf2n_poly_realloc(a, b->n);
  for (i = 0; i < b->n; i++)
    ssh_gf2n_set(&a->c[i], &b->c[i]);
  a->n = b->n;
}

/* Setall that can do wonders. */
void ssh_gf2n_poly_setall(SshGF2nPoly *a, ...)
{
  va_list ap;
  unsigned int format;
  SshGF2nElement k, *t;
  SshBPoly *tb;
  SshInt *tm;
  unsigned int pos;

  va_start(ap, a);
  ssh_gf2n_init(&k, a->moduli);
  
  for (; (format = va_arg(ap, unsigned int)) != SSH_GF2N_POLY_END;)
    {
      switch (format)
	{
	case SSH_GF2N_POLY_UI:
	  pos = va_arg(ap, unsigned int);
	  ssh_gf2n_set_ui(&k, va_arg(ap, unsigned int));

	  ssh_gf2n_poly_realloc(a, pos + 1);
	  
	  ssh_gf2n_set(&a->c[pos], &k);
	  if (a->n < pos + 1)
	    a->n = pos + 1;
	  break;
	case SSH_GF2N_POLY_GF2N:
	  pos = va_arg(ap, unsigned int);
	  t = va_arg(ap, SshGF2nElement *);

	  ssh_gf2n_poly_realloc(a, pos + 1);
	  ssh_gf2n_set(&a->c[pos], t);

	  if (a->n < pos + 1)
	    a->n = pos + 1;
	  break;
	case SSH_GF2N_POLY_BPOLY:
	  pos = va_arg(ap, unsigned int);
	  tb = va_arg(ap, SshBPoly *);

	  ssh_gf2n_poly_realloc(a, pos + 1);
	  ssh_gf2n_set_bpoly(&a->c[pos], tb);

	  if (a->n < pos + 1)
	    a->n = pos + 1;
	  break;
	case SSH_GF2N_POLY_MP:
	  pos = va_arg(ap, unsigned int);
	  tm = va_arg(ap, SshInt *);

	  ssh_gf2n_poly_realloc(a, pos + 1);
	  ssh_gf2n_set_mp(&a->c[pos], tm);

	  if (a->n < pos + 1)
	    a->n = pos + 1;
	  break;
	default:
	  ssh_fatal("ssh_gf2n_poly_setall: undefined format identifier %d.",
		    format);
	  break;
	}
    }
  ssh_gf2n_clear(&k);
  va_end(ap);
}

/* Setall that can do wonders. */
void ssh_gf2n_poly_getall(const SshGF2nPoly *a, ...)
{
  va_list ap;
  unsigned int format;
  SshGF2nElement *t;
  SshBPoly *tb;
  SshInt *tm;
  unsigned int pos, *val;

  va_start(ap, a);
  
  for (; (format = va_arg(ap, unsigned int)) != SSH_GF2N_POLY_END;)
    {
      switch (format)
	{
	case SSH_GF2N_POLY_UI:
	  pos = va_arg(ap, unsigned int);
	  val = va_arg(ap, unsigned int *);

	  if (a->n <= pos)
	    *val = 0;
	  else
	    *val = ssh_gf2n_get_ui(&a->c[pos]);
	  break;
	case SSH_GF2N_POLY_GF2N:
	  pos = va_arg(ap, unsigned int);
	  t = va_arg(ap, SshGF2nElement *);

	  if (a->n <= pos)
	    ssh_gf2n_set_ui(t, 0);
	  else
	    ssh_gf2n_set(t, &a->c[pos]);
	  break;
	case SSH_GF2N_POLY_BPOLY:
	  pos = va_arg(ap, unsigned int);
	  tb = va_arg(ap, SshBPoly *);

	  if (a->n <= pos)
	    ssh_bpoly_set_ui(tb, 0);
	  else
	    ssh_bpoly_set_gf2n(tb, &a->c[pos]);
	  break;
	case SSH_GF2N_POLY_MP:
	  pos = va_arg(ap, unsigned int);
	  tm = va_arg(ap, SshInt *);

	  if (a->n <= pos)
	    ssh_mp_set_ui(tm, 0);
	  else
	    ssh_mp_set_gf2n(tm, &a->c[pos]);
	  break;
	default:
	  ssh_fatal("ssh_gf2n_poly_getall: undefined format identifier %d.",
		    format);
	  break;
	}
    }
  va_end(ap);
}

#if 1
void ssh_gf2n_poly_print(const SshGF2nPoly *p)
{
  unsigned int i, j, fp;

  if (p->c == NULL)
    {
      printf("0");
      return;
    }
  
  for (i = p->n, j = 0; i; i--)
    {
      if (ssh_gf2n_cmp_ui(&p->c[i - 1], 0) != 0)
	{
	  if (j > 0)
	    printf(" + ");
	  fp = 0;
	  if (ssh_gf2n_cmp_ui(&p->c[i - 1], 1) != 0)
	    {
	      ssh_gf2n_hex_dump(&p->c[i - 1]);
	      fp = 1;
	    }
	  if ((i - 1) != 0)
	    {
	      if (fp)
		printf(" * ");
	      
	      if ((i - 1) == 1)
		printf("x");
	      else
		printf("x^%d", i - 1);
	    }
	  else
	    {
	      if (!fp)
		printf("1");
	    }
	  j++;
	}
    }

  if (j > 0)
    {
      printf(" (mod ");
      ssh_gf2n_mod_pretty_print(p->moduli);
      printf(")");
    }
  else
    {
      printf("0");
    }
}
#endif

/* Some basic operations that should be use for testing. */

void ssh_gf2n_poly_add(SshGF2nPoly *a, const SshGF2nPoly *b)
{
  unsigned int i;
  
  /* Extend if necessary. */
  ssh_gf2n_poly_realloc(a, b->n);

  for (i = 0; i < b->n; i++)
    ssh_gf2n_add(&a->c[i], &a->c[i], &b->c[i]);

  /* Set correct size. */
  if (a->n < b->n)
    a->n = b->n;

  while (a->n && ssh_gf2n_cmp_ui(&a->c[a->n - 1], 0) == 0)
    a->n--;
}

unsigned int ssh_gf2n_poly_deg(const SshGF2nPoly *a)
{
  return a->n;
}

/* This is given for compatibility. To what? XXX */
void ssh_gf2n_poly_sub(SshGF2nPoly *a, const SshGF2nPoly *b)
{
  unsigned int i;

  /* Extend if necessary. */
  ssh_gf2n_poly_realloc(a, b->n);

  for (i = 0; i < b->n; i++)
    ssh_gf2n_add(&a->c[i], &a->c[i], &b->c[i]);

  /* Set correct size. */
  if (a->n < b->n)
    a->n = b->n;

  while (a->n > 0 && ssh_gf2n_cmp_ui(&a->c[a->n - 1], 0) == 0)
    a->n--;
}

/* Compare two polynomials. */
int ssh_gf2n_poly_cmp(const SshGF2nPoly *a, const SshGF2nPoly *b)
{
  int i, s;
  
  if (a->n > b->n)
    return 1;
  if (a->n < b->n)
    return -1;

  for (i = a->n; i; i--)
    {
      s = ssh_gf2n_cmp(&a->c[i - 1], &b->c[i - 1]);
      if (s != 0)
	return s;
    }
  return 0;
}

void ssh_gf2n_poly_mulx(SshGF2nPoly *ret, unsigned int exp)
{
  unsigned int i;
  if (ret->n == 0 || exp == 0)
    return;
  ssh_gf2n_poly_realloc(ret, ret->n + exp);
  for (i = ret->n; i; i--)
    ssh_gf2n_set(&ret->c[i - 1 + exp], &ret->c[i - 1]);
  for (i = 0; i < exp; i++)
    ssh_gf2n_set_ui(&ret->c[i], 0);
  ret->n = ret->n + exp;
}

void ssh_gf2n_poly_divx(SshGF2nPoly *ret, unsigned int exp)
{
  unsigned int i;
  if (ret->n == 0 || exp == 0)
    return;
  if (ret->n <= exp)
    {
      ssh_gf2n_poly_set_zero(ret);
      return;
    }
  for (i = exp; i < ret->n; i++)
    ssh_gf2n_set(&ret->c[i - exp], &ret->c[i]);
  ret->n = ret->n - exp;
}

/* Plain multiplication, should only be used to test other multiplication
   routines. */
void ssh_gf2n_poly_mul_plain(SshGF2nPoly *ret, const SshGF2nPoly *a,
			     const SshGF2nPoly *b)
{
  unsigned int i, j;
  SshGF2nElement temp;

  if (a->n == 0 || b->n == 0)
    {
      ssh_gf2n_poly_set_zero(ret);
      return;
    }
  
  /* Extend if necessary. */
  ssh_gf2n_poly_realloc(ret, a->n + b->n);
  ssh_gf2n_poly_set_zero(ret);
  
  /* Temporary variable. */
  ssh_gf2n_init(&temp, ret->moduli);
  
  for (i = 0; i < b->n; i++)
    for (j = 0; j < a->n; j++)
      {
	ssh_gf2n_mul(&temp, &a->c[j], &b->c[i]);
	ssh_gf2n_add(&ret->c[i + j], &ret->c[i + j], &temp);
      }

  ssh_gf2n_clear(&temp);

  /* Compute correct size. */
  ret->n = a->n + b->n - 1;
  while (ret->n && ssh_gf2n_cmp_ui(&ret->c[ret->n - 1], 0) == 0)
    ret->n--;
}

void ssh_gf2n_poly_square_plain(SshGF2nPoly *ret, const SshGF2nPoly *a)
{
  unsigned int i;
  SshGF2nElement temp;

  if (a->n == 0)
    {
      ssh_gf2n_poly_set_zero(ret);
      return;
    }
  
  /* Extend if necessary. */
  ssh_gf2n_poly_realloc(ret, a->n * 2);
  ssh_gf2n_poly_set_zero(ret);
  
  /* Temporary variable. */
  ssh_gf2n_init(&temp, ret->moduli);
  
  for (i = 0; i < a->n; i++)
    {
      ssh_gf2n_square(&temp, &a->c[i]);
      ssh_gf2n_set(&ret->c[i*2], &temp);
    }

  ssh_gf2n_clear(&temp);

  /* Set correct size. */
  ret->n = a->n * 2 - 1;

  while (ret->n && ssh_gf2n_cmp_ui(&ret->c[ret->n - 1], 0) == 0)
    ret->n--;
}

void ssh_gf2n_poly_div_plain(SshGF2nPoly *q, SshGF2nPoly *r,
			     const SshGF2nPoly *a, const SshGF2nPoly *b)
{
  unsigned int i, j, k;
  SshGF2nElement inv, temp, temp2;

  /* And another. */
  if (b->n == 0)
    ssh_fatal("ssh_gf2n_poly_div_plain: divide by zero.");

  /* Trivial case. */
  if (a->n < b->n)
    {
      ssh_gf2n_poly_set_zero(q);
      ssh_gf2n_poly_set(r, a);
      return;
    }
  
  /* Extend if necessary. */
  ssh_gf2n_poly_realloc(q, a->n - b->n + 1);
  ssh_gf2n_poly_set_zero(q);
  ssh_gf2n_poly_set(r, a);
  
  /* Temporary variables. */
  ssh_gf2n_init(&temp, q->moduli);
  ssh_gf2n_init(&temp2, q->moduli);
  ssh_gf2n_init(&inv, q->moduli);

  /* Precompute inverse of divisors highest term. */
  ssh_gf2n_invert(&inv, &b->c[b->n - 1]);

  /* Main division loop.
   */
  for (i = r->n, q->n = 0; i >= b->n; i--, r->n--)
    {
      if (ssh_gf2n_cmp_ui(&r->c[i - 1], 0) == 0)
	continue;
      
      ssh_gf2n_mul(&temp, &inv, &r->c[i - 1]);

      /* Compute quotient. */
      ssh_gf2n_set(&q->c[i - b->n], &temp);
      if (q->n == 0)
	{
	  if (ssh_gf2n_cmp_ui(&temp, 0) != 0)
	    q->n = i - b->n + 1;
	}
      
      /* Clear highest. */
      ssh_gf2n_set_ui(&r->c[i - 1], 0);
      
      /* Loop through remainder. */
      for (j = i - 1, k = b->n - 1; k; j--, k--)
	{
	  ssh_gf2n_mul(&temp2, &temp, &b->c[k - 1]);
	  ssh_gf2n_add(&r->c[j - 1], &r->c[j - 1], &temp2);
	}
    }

  while (r->n && ssh_gf2n_cmp_ui(&r->c[r->n - 1], 0) == 0)
    r->n--;
  
  ssh_gf2n_clear(&temp2);
  ssh_gf2n_clear(&temp);
  ssh_gf2n_clear(&inv);

#if 0
  {
    SshGF2nPoly t1;

    ssh_gf2n_poly_init(&t1, q->moduli);
    ssh_gf2n_poly_mul(&t1, q, b);
    ssh_gf2n_poly_add(&t1, r);

    if (ssh_gf2n_poly_cmp(&t1, a) != 0)
      {
	printf("Division failed.\n");
	printf(" a(x) = ");
	ssh_gf2n_poly_print(a);
	printf("\n b(x) = ");
	ssh_gf2n_poly_print(b);
	printf("\n r(x) = ");
	ssh_gf2n_poly_print(r);
	printf("\n q(x) = ");
	ssh_gf2n_poly_print(q);
	printf("\n t1(x) = ");
	ssh_gf2n_poly_print(&t1);
	printf("\n");
      }
    ssh_gf2n_poly_clear(&t1);
  }
#endif

}

void ssh_gf2n_poly_mod_plain(SshGF2nPoly *r, const SshGF2nPoly *a,
			     const SshGF2nPoly *b)
{
  unsigned int i, j, k;
  SshGF2nElement inv, temp, temp2;

  /* And another. */
  if (b->n == 0)
    ssh_fatal("gf2n_poly_mod_plain: divide by zero.");

  /* Trivial case. */
  if (a->n < b->n)
    {
      if (r != a)
	ssh_gf2n_poly_set(r, a);
      return;
    }
  
  /* Extend if necessary. */
  if (r != a)
    ssh_gf2n_poly_set(r, a);
  
  /* Temporary variable. */
  ssh_gf2n_init(&temp, r->moduli);
  ssh_gf2n_init(&temp2, r->moduli);
  ssh_gf2n_init(&inv, r->moduli);
  
  /* Precompute inverse of divisors highest term. */
  ssh_gf2n_invert(&inv, &b->c[b->n - 1]);

  /* Main division loop.
   */
  for (i = r->n; i >= b->n; i--, r->n--)
    {
      if (ssh_gf2n_cmp_ui(&r->c[i - 1], 0) == 0)
	continue;

      /* Compute the multiplier. */
      ssh_gf2n_mul(&temp, &r->c[i - 1], &inv);
      
      /* Clear highest. */
      ssh_gf2n_set_ui(&r->c[i - 1], 0);
      
      /* Loop through remainder. */
      for (j = i - 1, k = b->n - 1; k; j--, k--)
	{
	  ssh_gf2n_mul(&temp2, &b->c[k - 1], &temp);
	  ssh_gf2n_add(&r->c[j - 1], &r->c[j - 1], &temp2);
	}
    }

  while (r->n && ssh_gf2n_cmp_ui(&r->c[r->n - 1], 0) == 0)
    r->n--;
  
  ssh_gf2n_clear(&inv);
  ssh_gf2n_clear(&temp);
  ssh_gf2n_clear(&temp2);
}

int ssh_gf2n_poly_weight(const SshGF2nPoly *a)
{
  int i, w;

  if (a->c == NULL)
    return 0;
  
  for (i = 0, w = 0; i < a->n; i++)
    if (ssh_gf2n_cmp_ui(&a->c[i], 0) != 0)
      w++;
  return w;
}

void ssh_gf2n_poly_monic(SshGF2nPoly *a)
{
  SshGF2nElement inv;
  unsigned int i;

  /* Trivial case. */
  if (a->n == 0)
    return;
  
  ssh_gf2n_init(&inv, a->moduli);

  ssh_gf2n_invert(&inv, &a->c[a->n - 1]);
  ssh_gf2n_set_ui(&a->c[a->n - 1], 1);
  
  for (i = 0; i < a->n - 1; i++)
    ssh_gf2n_mul(&a->c[i], &a->c[i], &inv);
  
  ssh_gf2n_clear(&inv);
}

void ssh_gf2n_poly_gcd(SshGF2nPoly *gcd, const SshGF2nPoly *p,
		       const SshGF2nPoly *q)
{
  SshGF2nPoly a, b, c;

  ssh_gf2n_poly_init(&a, gcd->moduli);
  ssh_gf2n_poly_init(&b, gcd->moduli);
  ssh_gf2n_poly_init(&c, gcd->moduli);

  ssh_gf2n_poly_set(&a, p);
  ssh_gf2n_poly_set(&b, q);

  while (ssh_gf2n_poly_deg(&b))
    {
#if 0
      printf(" gcd: b(x) = ");
      ssh_gf2n_poly_print(&b);
      printf("\n");
#endif
      ssh_gf2n_poly_mod(&c, &a, &b);
      ssh_gf2n_poly_set(&a, &b);
      ssh_gf2n_poly_set(&b, &c);
    }

  /* gf2n_poly_monic(&a, m); */
  ssh_gf2n_poly_set(gcd, &a);
  
  ssh_gf2n_poly_clear(&a);
  ssh_gf2n_poly_clear(&b);
  ssh_gf2n_poly_clear(&c);
}

void ssh_gf2n_poly_gcdext(SshGF2nPoly *g, SshGF2nPoly *s,
			  SshGF2nPoly *t,
			  const SshGF2nPoly *a, const SshGF2nPoly *b)
{
  SshGF2nPoly s0, s1, d0, d1, q, r, x, temp;

  ssh_gf2n_poly_init(&s0, g->moduli);
  ssh_gf2n_poly_init(&s1, g->moduli);
  ssh_gf2n_poly_init(&d0, g->moduli);
  ssh_gf2n_poly_init(&d1, g->moduli);
  ssh_gf2n_poly_init(&q, g->moduli);
  ssh_gf2n_poly_init(&x, g->moduli);
  ssh_gf2n_poly_init(&r, g->moduli);
  ssh_gf2n_poly_init(&temp, g->moduli);

  ssh_gf2n_poly_setall(&s0, SSH_GF2N_POLY_UI, 0, 1, SSH_GF2N_POLY_END);
  ssh_gf2n_poly_set_zero(&s1);
  
  ssh_gf2n_poly_set(&d0, a);
  ssh_gf2n_poly_set(&d1, b);

  while (ssh_gf2n_poly_deg(&d1))
    {
      ssh_gf2n_poly_div(&q, &r, &d0, &d1);
      
      ssh_gf2n_poly_set(&d0, &d1);
      ssh_gf2n_poly_set(&d1, &r);

      ssh_gf2n_poly_mul(&x, &s1, &q);
      ssh_gf2n_poly_sub(&s0, &x);
      ssh_gf2n_poly_set(&x, &s0);
      ssh_gf2n_poly_set(&s0, &s1);
      ssh_gf2n_poly_set(&s1, &x);
#if 0
      printf(" --- \n");
      printf(" q(x) = ");
      ssh_gf2n_poly_print(&q);
      printf("\n r(x) = ");
      ssh_gf2n_poly_print(&r);
      printf("\n d0(x) = ");
      ssh_gf2n_poly_print(&d0);
      printf("\n d1(x) = ");
      ssh_gf2n_poly_print(&d1);
      printf("\n s0(x) = ");
      ssh_gf2n_poly_print(&s0);
      printf("\n s1(x) = ");
      ssh_gf2n_poly_print(&s1);
      printf("\n");
#endif
    }

  ssh_gf2n_poly_mul(&x, &s0, a);
  ssh_gf2n_poly_set(&temp, &d0);
  ssh_gf2n_poly_sub(&temp, &x);
  ssh_gf2n_poly_set(&x, &temp);
  ssh_gf2n_poly_div(t, &temp, &x, b);

  ssh_gf2n_poly_set(s, &s0);
  ssh_gf2n_poly_set(g, &d0);

  ssh_gf2n_poly_clear(&s0);
  ssh_gf2n_poly_clear(&s1);
  ssh_gf2n_poly_clear(&d0);
  ssh_gf2n_poly_clear(&d1);
  ssh_gf2n_poly_clear(&q);
  ssh_gf2n_poly_clear(&x);
  ssh_gf2n_poly_clear(&r);
  ssh_gf2n_poly_clear(&temp);
}

int ssh_gf2n_poly_invert(SshGF2nPoly *inv, const SshGF2nPoly *p0,
			 const SshGF2nPoly *m)
{
  SshGF2nPoly gcd, t, t_inv;
  int found = 0;
  
  ssh_gf2n_poly_init(&gcd,   inv->moduli);
  ssh_gf2n_poly_init(&t,     inv->moduli);
  ssh_gf2n_poly_init(&t_inv, inv->moduli);

  ssh_gf2n_poly_gcdext(&gcd, &t_inv, &t, p0, m);

  if (ssh_gf2n_poly_deg(&gcd) == 1)
    found = 1;
  
  ssh_gf2n_poly_div(inv, &t, &t_inv, &gcd); 

  ssh_gf2n_poly_clear(&gcd);
  ssh_gf2n_poly_clear(&t);
  ssh_gf2n_poly_clear(&t_inv);

  return found;
}

void ssh_gf2n_poly_powm_plain(SshGF2nPoly *r, const SshGF2nPoly *g,
			      const SshInt *e, const SshGF2nPoly *p)
{
  SshGF2nPoly temp, t1, t2;
  unsigned int bit;

  ssh_gf2n_poly_init(&t1, r->moduli);
  ssh_gf2n_poly_init(&t2, r->moduli);
  ssh_gf2n_poly_init(&temp, r->moduli);
  
  ssh_gf2n_poly_set(&t1, g);

  for (bit = ssh_mp_get_size(e, 2) - 1; bit; bit--)
    {
      ssh_gf2n_poly_square(&temp, &t1);
      ssh_gf2n_poly_mod(&temp, &temp, p);
      
      if (ssh_mp_get_bit(e, bit - 1))
	{
	  ssh_gf2n_poly_mul(&t2, &temp, g);
	  ssh_gf2n_poly_mod(&t1, &t2, p);
	}
    }

  ssh_gf2n_poly_set(r, &t1);
  ssh_gf2n_poly_clear(&t1);
  ssh_gf2n_poly_clear(&t2);
  ssh_gf2n_poly_clear(&temp);
}

int ssh_gf2n_poly_is_irreducible(const SshGF2nPoly *f)
{
  SshGF2nPoly u, v, d, x;
  unsigned int i, deg = ssh_gf2n_poly_deg(f), r, j;

  ssh_gf2n_poly_init(&u, f->moduli);
  ssh_gf2n_poly_init(&v, f->moduli);
  ssh_gf2n_poly_init(&d, f->moduli);
  ssh_gf2n_poly_init(&x, f->moduli);

  r = ssh_gf2n_deg_mod(f->moduli) - 1;
  
  ssh_gf2n_poly_setall(&x, SSH_GF2N_POLY_UI, 1, 1, SSH_GF2N_POLY_END);
  ssh_gf2n_poly_set(&u, &x);

  for (i = 0; i < deg/2; i++)
    {
      for (j = 0; j < r; j++)
	{
	  ssh_gf2n_poly_square(&v, &u);
	  ssh_gf2n_poly_mod(&u, &v, f);
	}
      ssh_gf2n_poly_set(&v, &u);
      ssh_gf2n_poly_add(&v, &x);
      ssh_gf2n_poly_gcd(&d, f, &v);
      if (ssh_gf2n_poly_deg(&d) != 1)
	{
	  if (ssh_gf2n_poly_deg(&d) != 0)
	    goto reducible;
	}
    }
reducible:
  ssh_gf2n_poly_clear(&x);
  ssh_gf2n_poly_clear(&d);
  ssh_gf2n_poly_clear(&v);
  ssh_gf2n_poly_clear(&u);
  
  if (i >= deg/2)
    return 1;
  return 0;
}

/* Find the polynomial which represents all the roots of f. */
int ssh_gf2n_poly_roots(SshGF2nPoly *ret, const SshGF2nPoly *f)
{
  SshGF2nPoly x, u, v;
  int i, r;

  ssh_gf2n_poly_init(&x, ret->moduli);
  ssh_gf2n_poly_init(&u, ret->moduli);
  ssh_gf2n_poly_init(&v, ret->moduli);
  
  /* Set just x. */
  ssh_gf2n_poly_setall(&x, SSH_GF2N_POLY_UI, 1, 1, SSH_GF2N_POLY_END);

  r = ssh_gf2n_deg_mod(ret->moduli) - 1;
  ssh_gf2n_poly_set(&u, &x);
  for (i = 0; i < r; i++)
    {
      ssh_gf2n_poly_square(&v, &u);
      ssh_gf2n_poly_mod(&u, &v, f);
    }
  ssh_gf2n_poly_add(&u, &x);
  ssh_gf2n_poly_gcd(ret, &u, f);

  ssh_gf2n_poly_clear(&x);
  ssh_gf2n_poly_clear(&v);
  ssh_gf2n_poly_clear(&u);
  
  return ssh_gf2n_poly_deg(ret);
}

void ssh_gf2n_poly_factor(SshGF2nPoly *ret, const SshGF2nPoly *f,
			  int degree)
{
  SshGF2nPoly g, u, c, h, t, tx;
  int i;
  
  /* Trivial cases. */
  if (ssh_gf2n_poly_deg(f) == 0)
    {
      ssh_gf2n_poly_set_zero(ret);
      return;
    }
  if (degree == 0)
    {
      ssh_gf2n_poly_set_zero(ret);
      ssh_gf2n_poly_setall(ret, SSH_GF2N_POLY_UI, 0, 1, SSH_GF2N_POLY_END);
      return;
    }

  /* Initialize necessary variable amount. */
  ssh_gf2n_poly_init(&g, ret->moduli);
  ssh_gf2n_poly_init(&u, ret->moduli);
  ssh_gf2n_poly_init(&c, ret->moduli);
  ssh_gf2n_poly_init(&h, ret->moduli);
  ssh_gf2n_poly_init(&t, ret->moduli);
  ssh_gf2n_poly_init(&tx, ret->moduli);

  /* Main loop, this does the randomized search for a factor. */
  ssh_gf2n_poly_set(&g, f);
  while (ssh_gf2n_poly_deg(&g) - 1 > degree)
    {
      ssh_gf2n_poly_random(&u, 2*degree - 1);
      ssh_gf2n_poly_monic(&u);
      ssh_gf2n_poly_set(&c, &u);
      for (i = 1; i < degree; i++)
	{
	  ssh_gf2n_poly_square(&c, &c);
	  ssh_gf2n_poly_mod(&c, &c, &g);
	  ssh_gf2n_poly_add(&c, &u);
	}
      ssh_gf2n_poly_gcd(&h, &c, &g);
      /* If h is constant or deg(h) = deg(g). */
      if (ssh_gf2n_poly_deg(&h) < 2 ||
	  ssh_gf2n_poly_deg(&h) == ssh_gf2n_poly_deg(&g))
	continue;
      /* If 2*deg(h) > deg(g) */
      if (2*(ssh_gf2n_poly_deg(&h) - 1) > (ssh_gf2n_poly_deg(&g) - 1))
	{
	  ssh_gf2n_poly_div(&t, &tx, &g, &h);
	  ssh_gf2n_poly_set(&g, &t);
	}
      else
	ssh_gf2n_poly_set(&g, &h);
    }

  /* Handle output. */
  ssh_gf2n_poly_monic(&g);
  ssh_gf2n_poly_set(ret, &g);
  
  ssh_gf2n_poly_clear(&g);
  ssh_gf2n_poly_clear(&u);
  ssh_gf2n_poly_clear(&c);
  ssh_gf2n_poly_clear(&h);
  ssh_gf2n_poly_clear(&t);
  ssh_gf2n_poly_clear(&tx);
}

void ssh_gf2n_poly_random_root(SshGF2nElement *ret, const SshGF2nPoly *f)
{
  SshGF2nPoly g, u, c, h, t, tx;
  SshGF2nElement k;
  int i;
  
  /* Trivial cases. */
  if (ssh_gf2n_poly_deg(f) == 0)
    {
      ssh_gf2n_set_ui(ret, 0);
      return;
    }

  /* Initialize necessary variable amount. */
  ssh_gf2n_poly_init(&g, ret->m);
  ssh_gf2n_poly_init(&u, ret->m);
  ssh_gf2n_poly_init(&c, ret->m);
  ssh_gf2n_poly_init(&h, ret->m);
  ssh_gf2n_poly_init(&t, ret->m);
  ssh_gf2n_poly_init(&tx, ret->m);

  ssh_gf2n_init(&k, ret->m);
  
  /* Main loop, this does the randomized search for a factor. */
  ssh_gf2n_poly_set(&g, f);
  while (ssh_gf2n_poly_deg(&g) > 2)
    {
      ssh_gf2n_poor_rand(&k);
      ssh_gf2n_poly_set_zero(&u);
      ssh_gf2n_poly_setall(&u, SSH_GF2N_POLY_GF2N, 1, &k, SSH_GF2N_POLY_END);
      ssh_gf2n_poly_set(&c, &u);
      for (i = 1; i < ssh_gf2n_deg_mod(ret->m) - 1; i++)
	{
	  ssh_gf2n_poly_square(&t, &c);
	  ssh_gf2n_poly_mod(&c, &t, &g);
	  ssh_gf2n_poly_add(&c, &u);
	}
      ssh_gf2n_poly_gcd(&h, &c, &g);
      /* If h is constant or deg(h) = deg(g). */
      if (ssh_gf2n_poly_deg(&h) < 2 ||
	  ssh_gf2n_poly_deg(&h) == ssh_gf2n_poly_deg(&g))
	continue;
      /* If 2*deg(h) > deg(g) */
      if (2*(ssh_gf2n_poly_deg(&h) - 1) > (ssh_gf2n_poly_deg(&g) - 1))
	{
	  ssh_gf2n_poly_div(&t, &tx, &g, &h);
	  ssh_gf2n_poly_set(&g, &t);
	}
      else
	ssh_gf2n_poly_set(&g, &h);
    }

  /* Handle output. */
  ssh_gf2n_poly_monic(&g);
  ssh_gf2n_poly_getall(&g, SSH_GF2N_POLY_GF2N, 0, ret, SSH_GF2N_POLY_END);
  
  ssh_gf2n_poly_clear(&g);
  ssh_gf2n_poly_clear(&u);
  ssh_gf2n_poly_clear(&c);
  ssh_gf2n_poly_clear(&h);
  ssh_gf2n_poly_clear(&t);
  ssh_gf2n_poly_clear(&tx);

  ssh_gf2n_clear(&k);
}

void ssh_gf2n_poly_random(SshGF2nPoly *f, unsigned int deg)
{
  unsigned int i;
  SshGF2nElement k;

  /* Trivial case? */
  if (deg == 0)
    {
      ssh_gf2n_poly_set_zero(f);
      ssh_gf2n_init(&k, f->moduli);
      ssh_gf2n_poor_rand(&k);
      ssh_gf2n_poly_setall(f, SSH_GF2N_POLY_GF2N, 0, &k, SSH_GF2N_POLY_END);
      ssh_gf2n_clear(&k);
      return;
    }
  
  ssh_gf2n_init(&k, f->moduli);
  ssh_gf2n_poly_set_zero(f);
  
  for (i = 0; i < deg; i++)
    {
      ssh_gf2n_poor_rand(&k);
      if (ssh_gf2n_cmp_ui(&k, 0) != 0)
	ssh_gf2n_poly_setall(f, SSH_GF2N_POLY_GF2N, i, &k, SSH_GF2N_POLY_END);
    }
  ssh_gf2n_clear(&k);
}

void ssh_gf2n_poly_find_irreducible(SshGF2nPoly *f, unsigned int deg)
{
  if (deg == 0)
    {
      ssh_gf2n_poly_set_zero(f);
      return;
    }
  
  do
    {
      /* Generate a random polynomial of degree deg. */
      ssh_gf2n_poly_random(f, deg);
    }
  while (!ssh_gf2n_poly_is_irreducible(f));
}

void ssh_gf2n_poly_evaluate(SshGF2nElement *ret, const SshGF2nPoly *f,
			    const SshGF2nElement *v)
{
  SshGF2nElement u;
  unsigned int i;

  if (f->n == 0)
    {
      ssh_gf2n_set_ui(ret, 0);
      return;
    }
  
  /* Traditional way, i.e. using the Horner's rule.
    
    f(x) = x^n + x^{n-1} + .. + x + 1
          = (((x + 1)x + 1) ... + 1) */

  ssh_gf2n_init(&u, f->moduli);
  ssh_gf2n_set(&u, &f->c[f->n - 1]);
  for (i = f->n - 1; i; i--)
    {
      ssh_gf2n_mul(&u, &u, v);
      ssh_gf2n_add(&u, &u, &f->c[i - 1]);
    }

  ssh_gf2n_set(ret, &u);
  ssh_gf2n_clear(&u);
}

/* gf2n.c */
