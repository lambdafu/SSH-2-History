/*

  sshmp.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996-98 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Tue Oct 28 14:54:44 1997 [mkojo]

  SSH Multiple Precision arithmetic library with fast modular arithmetic
  interface. 

  This package is mainly intended to work as the core technology for
  public key cryptosystems. However, there might be other uses where
  this sort of package suits.

  If you want to learn how everything here works, you should have the
  references mentioned available to glance for detailed discussion. 

  References:

    The main references used were

      Handbook of Applied Cryptography, by Menezes, Oorschot, Vanstone.

        Which was used for elementary routines, such as division and
        Montgomery routines. All basic operations I first implemented
        as described in this book.
        
      A Course in Computation Algebraic Number Theory, by Henri Cohen.
      
        This book offered nice, and fast, approaches to several basic
        computations. Such as square roots, Rabin-Miller (or Miller-Rabin)
        tests etc. I have used some of them. 

    Also a lot of ideas and good approaches were drawn from several
    multiple precision implementations. In random order,

      GMP      package by Torbjorn Granlund
      FreeLIP  package by Arjen Lenstra
      BigNum   package by Francois Morain
      BnLib    package by Colin Plumb
      "BigNum" package by Eric Young
      Crypto++ package by Wei Dai

    as one easily finds out most routines are written to look like GMP
    functions. This is no coincidence. However, code here presented is
    original although sometimes it might be hard to tell. And yes,
    I have read through those packages to learn ideas of doing things
    better than I would have done by just myself.

    Montgomery routines pay debt to the package of Colin Plumb. Also
    squaring using Karatsuba is implemented along his ideas. Note,
    that I also implemented another Karatsuba squaring approach using
    Markku-Juhani Saarinen's idea.

  Future:

    Some future ideas might be:

      faster modular aritmetic for special moduli
      FFT and Newtons iteration methods (not very useful?)
      more number theoretic functions
      factorization functions 
      discrete log search functions (lambda, rho, bs-gs)
      rational arithmetic
      elliptic curves over rationals(?)
      floating point arithmetic
      complex arithmetic
      number field arithmetic(?)
      class group algorithms(?)
      polynomial algorithms over finite fields (perhaps also for rationals)
      (fourier) series algorithms over complex numbers 

      (?) cases are very hypothetical.
      
  */

/*
 * $Id: sshmp.c,v 1.35 1998/11/22 16:54:05 ylo Exp $
 *
 * Revision 1.31  1998/09/16 21:17:33  mkojo
 *      Modified some of the casts.
 *
 * Revision 1.30  1998/09/16 21:06:51  mkojo
 *      Added many casts.
 *
 * Revision 1.29  1998/08/30 22:51:04  mkojo
 *      Changes to many comments.
 *
 * Revision 1.28  1998/08/29 23:39:52  mkojo
 *      Added SSH_MP_LONG_SQUARE, and a some other minor changes.
 *
 * Revision 1.27  1998/08/29 20:25:05  mkojo
 *      Improved division and integer modular reduction by about 15
 *      percent on Alpha. This is a heuristic improvement, and might
 *      not allow faster computation on other platforms.
 *
 * Revision 1.26  1998/08/27 12:32:36  mkojo
 *      Organized the functions.
 *
 * Revision 1.25.2.2  1998/09/03 13:25:49  mkojo
 *      Merged new version to Ipsec 1.1 branch.
 *
 * Revision 1.25  1998/07/10 09:38:18  sjl
 *      Fixed case in $EndLog$
 *
 * Revision 1.24  1998/07/10 05:55:51  vsuontam
 * Added some more assembler macros (+ bug fixes)
 *
 * Revision 1.21  1998/06/11 19:35:30  mkojo
 *      Now it should be possible to do modular arithmetic without
 *      too much allocation. Also some other changes.
 *
 * Revision 1.20  1998/06/10 08:37:43  tmo
 *      Removed unused varibles by #ifdef'n them out to get rid of
 *      compilation warnings.
 *
 * Revision 1.19  1998/06/07 09:58:21  mkojo
 *      Some additions to arithmetic library. Added, for example,
 *      some speed-ups for elliptic curves such as ABC and Frobenius
 *      curve multiplication.
 *
 * Revision 1.18  1998/06/06 23:11:27  kivinen
 *      Changed SSHMATH_i386 to SSHMATH_I386.
 *
 * Revision 1.17  1998/06/06 18:46:56  mkojo
 *      Added freeing of moduli to ssh_powm_bsw_mont.
 *
 * Revision 1.16  1998/06/03 01:55:37  ylo
 *      Fixed some uninitialized memory accesses.
 *
 * Revision 1.15  1998/05/27  20:44:32  mkojo
 *      Modifications. For example, switched to faster elliptic curve
 *      multiplication.
 *
 * Revision 1.14  1998/05/27 00:50:36  mkojo
 *      Small changes to string conversion routines.
 *
 * Revision 1.13  1998/05/26  20:35:00  mkojo
 *      Numerous corrections and changes.
 *
 * Revision 1.12  1998/05/24 01:07:13  kivinen
 *      Changed lots of int / unsigned int to SshWord / SignedSshWord,
 *      because in alpha int is only 32 bit, and SshWord (unsigned
 *      long) is 64 bits. It assumed many places that the size of _ui
 *      argument is same as SshWord. Changed also all _ui, and _si
 *      arguments to SshWord/SignedSshWord. Fixed all printf("%08x" ...) to
 *      check the SIZEOF_LONG and if it is 8 then use printf("%16lx"
 *      ...). Changed all normalization code so that they will first
 *      check that the ret->n is > 0 before they try to access
 *      ret->v[ret->n - 1].
 *
 * Revision 1.11  1998/05/23  20:54:09  kivinen
 *      Changed ssh_mp_int_to_char to be unsigned.
 *
 * Revision 1.10  1998/05/14  17:45:29  mkojo
 *      Tested more, and added functions for modular square roots. Found
 *      few typos, now corrected.
 *
 * Revision 1.9  1998/05/12 20:18:24  mkojo
 *      New features and functions added. Tested a lot more.
 *
 * Revision 1.8  1998/05/11 19:43:50  mkojo
 *      Bug correction.
 *
 * Revision 1.7  1998/05/08 23:34:52  mkojo
 *      Modified and expanded the string handling so that it now
 *      handles the usual cases smoothly.
 *
 * Revision 1.6  1998/05/07 15:41:25  mkojo
 *      Added ssh_mp_get_si and some other small changes.
 *
 * Revision 1.5  1998/05/05 16:28:51  mkojo
 *      Back to using the previous defines.
 *
 * Revision 1.4  1998/05/05 14:12:17  mkojo
 *      Modified slightly.
 *
 * Revision 1.3  1998/03/28 23:44:21  ylo
 *      Changed to use SSHMATH_ASSEMBLER_SUBROUTINES instead of
 *      USE_ASSEMBLER_SUBROUTINES.
 *
 *      Removed kludge that defined USE_ASSEMBLER_SUBROUTINES; it is
 *      now determined by configure.
 *
 * Revision 1.2  1998/03/17 13:20:02  mkojo
 *      Removed an extra parenthesis from one of the macros.
 *
 * Revision 1.1  1998/03/17 11:48:37  mkojo
 *      Initial revision of SSH Multiple Precision library.
 *
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmath-types.h"
#include "sieve.h"
#include "sshmp.h" 

/* Some sign manipulation. */

/* Evaluate the sign, either to TRUE or FALSE. */
#define SSH_MP_GET_SIGN(x)      (((x)->sign) & TRUE)
/* Clear the sign, i.e. make positive. */
#define SSH_MP_NO_SIGN(x)       (((x)->sign) &= (~SSH_MP_GET_SIGN(x)))
/* Make negative. */
#define SSH_MP_SET_SIGN(x)      (((x)->sign) |= TRUE)
/* Copy sign from one integer to another. */
#define SSH_MP_COPY_SIGN(x,y)   (((x)->sign) = ((y)->sign))
/* Xor sign, negation. */
#define SSH_MP_XOR_SIGN(x)      (((x)->sign) ^= TRUE)
/* Xor signs together, useful in multiplication. */
#define SSH_MP_XOR_SIGNS(x,y,z) (((x)->sign) = ((y)->sign) ^ ((z)->sign))

/* Some kludges for starters. Write also C versions for later use. */

#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
/* Note: we give here only the most necessary routines, e.g. not additions
   etc. Those would speed computation slightly too, but might become
   burden also. There might be some changes within the library on the
   assembler interface. Idea is to use C as much as possible. */

#ifdef SSHMATH_I386
/* Fast trailing zero searching using i386 special instruction. */
#define SSH_MP_COUNT_TRAILING_ZEROS(count, x)  \
__asm__("bsfl %1,%0" : \
        "=r" (count) : "rm" ((SshWord)(x))); \

/* For leading zeros. */
#define SSH_MP_COUNT_LEADING_ZEROS(count, x) \
  __asm__("bsrl %1,%0; xorl $31, %0" : \
          "=r" (count) : "rm" ((SshWord)(x)));

/* Fast multiplication. */
#define SSH_MP_LONG_MUL(u, v, a, b)      \
__asm__("mull %3"                 \
        : "=a" ((SshWord)v), \
          "=d" ((SshWord)u)  \
        : "%0" ((SshWord)a), \
          "rm" ((SshWord)b))

/* Fast division. */
#define SSH_MP_LONG_DIV(q, r, d1, d0, d)  \
__asm__("divl %4"                  \
        : "=a" ((SshWord)q),  \
          "=d" ((SshWord)r)   \
        : "%0"  ((SshWord)d0), \
          "%1"  ((SshWord)d1), \
          "rm" ((SshWord)d))
#endif
     
/* Prototypes of assembler functions. */
/* Addition routines. Perform addition of equal length buffers, and
   addition by 1. */
SshWord ssh_mpn_add_n(SshWord *ret, SshWord *op1,
                      SshWord *op2, unsigned int len);
SshWord ssh_mpn_add_1(SshWord *ret, SshWord *op, unsigned int len);

/* Subtraction routines. Perform subtraction of equal length buffers, and
   subtraction by 1. */
SshWord ssh_mpn_sub_n(SshWord *ret,
                      SshWord *op1, SshWord *op2, unsigned int len);
SshWord ssh_mpn_sub_1(SshWord *ret,
                      SshWord *op, unsigned int len);

/* Standard style addition after multiplication by word. */
SshWord ssh_mpn_addmul(SshWord *ret, SshWord k,
                       SshWord *op, unsigned int len);
/* Standard style subtraction after multiplication by word. */
SshWord ssh_mpn_submul(SshWord *ret, SshWord k,
                       SshWord *op, unsigned int len);
/* Fast shift up by 1 bit. */
SshWord ssh_mpn_shift_up_1(SshWord *ret, unsigned int len);
/* Specialized routine for squaring all the words in the buffer, and
   adding to the result at new positions. */
SshWord ssh_mpn_square_words(SshWord *ret, SshWord *op, unsigned int len);
/* Montgomery style addition after multiplication by word. */
SshWord ssh_mpmn_addmul(SshWord *ret, SshWord mp, SshWord *op,
                        unsigned int len, SshWord carry);

#ifdef WIN32
/* The Window's kludge. This uses some code that I wrote before for
   GMP, but today use here. */

  #include "winasmmp.h"

  #define SSH_MP_COUNT_LEADING_ZEROS winasm_count_leading_zeros
  #define SSH_MP_COUNT_TRAILING_ZEROS winasm_count_trailing_zeros
  #define SSH_MP_LONG_MUL winasm_umul_ppmm 
  #define SSH_MP_LONG_DIV winasm_udiv_qrnnd

  #include "winasm.c"
#endif


/* Usually we don't have squaring routine in assembler, but in
   C language we can achieve better throughput with such a
   function. However, here we are happy with just multiplication. */
#define SSH_MP_LONG_SQUARE(u, v, a) SSH_MP_LONG_MUL(u, v, a, a)
 
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */

/* Define this additional macro for usage here. */
#define SSH_MP_LOW_BIT_MASK (((SshWord)1 << (SSH_WORD_BITS/2)) - 1)
#define SSH_MP_HIGH_OCTET   ((SshWord)0xff << (SSH_WORD_BITS - 8))

/* Table for trailing zero computations. This table could be
   removed with some extra work in actual computations (using the
   following table instead). */
static const unsigned char ssh_mp_trailing_zero_table[256] =
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
static const unsigned char ssh_mp_leading_zero_table[256] =
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

/* Compute trailing zeros with the table based approach. These will
   probably be move to some main header file of this library later,
   so that I don't have to duplicate all the code. */
#define SSH_MP_COUNT_TRAILING_ZEROS(count, x)                 \
{                                                             \
  SshWord __x = (x); int __count;                             \
  for (__count = 0; !(__x & 0xff); __x >>= 8, __count += 8)   \
    ;                                                         \
  (count) = __count + ssh_mp_trailing_zero_table[__x & 0xff]; \
}

/* Compute leading zeros. */
#define SSH_MP_COUNT_LEADING_ZEROS(count, x)                             \
{                                                                        \
  SshWord __x = (x); int __count;                                        \
  for (__count = 8; !(__x & SSH_MP_HIGH_OCTET); __x <<= 8, __count += 8) \
    ;                                                                    \
  (count) = __count -                                                    \
    ssh_mp_leading_zero_table[(__x >> (SSH_WORD_BITS - 8)) & 0xff];      \
}

/* Standard method of multiplication. One could try to use
   Karatsuba ideas here also. If assembler version exist one should
   use it rather. */
#define SSH_MP_LONG_MUL(u, v, a, b)                      \
{                                                        \
  SshWord __a = (a), __b = (b), __al, __ah, __bl, __bh;  \
  SshWord __rl, __rh;                                    \
                                                         \
  /* Break the inputs into halves. */                    \
  __al = (__a) & SSH_MP_LOW_BIT_MASK;                    \
  __bl = (__b) & SSH_MP_LOW_BIT_MASK;                    \
  __ah = ((__a) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK; \
  __bh = ((__b) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK; \
                                                         \
  /* Multiplication of parts. */                         \
  __rl = __al * __bl;                                    \
  __rh = __ah * __bh;                                    \
  __al *= __bh;                                          \
  __ah *= __bl;                                          \
                                                         \
  /* Add together middle parts.       */                 \
  __al += __ah;                                          \
  /* Now we create parts for following addition.         \
     I.e. we take halves of 'al' and position them correctly. */  \
  __bh = ((__al & SSH_MP_LOW_BIT_MASK) << (SSH_WORD_BITS/2)); \
  __bl = ((__al >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK); \
                                                         \
  /* Perform the final addition.                     */  \
  __rl += __bh;                                          \
  __rh += __bl;                                          \
                                                         \
  /* Handle carry, and add it to the high word.      */  \
  if (__al < __ah)                                       \
    __rh += ((SshWord)1 << (SSH_WORD_BITS/2));           \
  if (__rl < __bh)                                       \
    __rh++;                                              \
                                                         \
  /* Finished.    */                                     \
  (v) = __rl;                                            \
  (u) = __rh;                                            \
}

#if 1
/* Standard method of multiplication. One could try to use
   Karatsuba ideas here also. If assembler version exist one should
   use it rather.

   This amounts to negligible savings, I'm afraid. 
   */
#define SSH_MP_LONG_SQUARE(u, v, a)                      \
{                                                        \
  SshWord __a = (a), __al, __ah, __bl, __bh;             \
  SshWord __rl, __rh;                                    \
                                                         \
  /* Break the input into halves. */                     \
  __al = (__a) & SSH_MP_LOW_BIT_MASK;                    \
  __ah = ((__a) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK; \
                                                         \
  /* We get around with only 3 multiplications. */       \
  __rl = __al * __al;                                    \
  __rh = __ah * __ah;                                    \
  __al *= __ah;                                          \
                                                         \
  /* Fix the high carry, add to the correct position. */ \
  if (__al & ((SshWord)1 << (SSH_WORD_BITS - 1)))        \
    __rh += ((SshWord)1 << (SSH_WORD_BITS/2));           \
  /* Perform the multiplication by 2. */                 \
  __al <<= 1;                                            \
                                                         \
  /* Glue together the parts. */                         \
  __bh = ((__al & SSH_MP_LOW_BIT_MASK) << (SSH_WORD_BITS/2)); \
  __bl = ((__al >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK); \
                                                         \
  /* Add finally together to get the result. */          \
  __rl += __bh;                                          \
  __rh += __bl;                                          \
                                                         \
  /* Final carry correction. */                          \
  if (__rl < __bh)                                       \
    __rh++;                                              \
                                                         \
  /* Finished. */                                        \
  (v) = __rl;                                            \
  (u) = __rh;                                            \
}
#else
/* In case you don't like to do squaring with special macro. */
#define SSH_MP_LONG_SQUARE(u, v, a) SSH_MP_LONG_MUL(u, v, a, a)
#endif

#if 0
/* This macro (older version though) has gained a lot of fame, because
   it is very close to the one in GMP by Torbjorn Granlund and in
   BnLib by Colin Plumb.

   Where has this code come from? Basically this is derivation of the
   algorithm D by Knuth (in Seminumerical Algorithms section
   4.3.1). This has been optimized for the task. The correction phase
   with the tests can be done in another way, but that would (as far
   as I can see) demand also few instructions more (basically that
   would slow down the code).

   The input should be given so that (d1*b + d0) / d < b. I.e. the
   quotient is in between b - 1 and 0. This restriction is
   taken care in the code that follows.
   */
#define SSH_MP_LONG_DIV(q, r, d1, d0, d)                     \
{                                                            \
  SshWord __d1, __d0, __q1, __q0, __rr, __m;                 \
  /* Break the divisor into two.                       */    \
  __d1 = ((d) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK;   \
  __d0 = (d) & SSH_MP_LOW_BIT_MASK;                          \
                                                             \
  /* Compute the first case, a la Knuth.               */    \
  __q1 = (d1) / __d1;                                        \
  __rr = (d1) %__d1;                                         \
  __m  = __q1 * __d0;                                        \
                                                             \
  /* Build up rr = rb + d0.                            */    \
  __rr = (__rr  << (SSH_WORD_BITS/2)) |                      \
           (((d0) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK); \
                                                             \
  /* Error correction. At this point it is well-known that   \
     q is only upto 2 too large, we want correct that.  */   \
  if (__rr < __m)                                            \
    {                                                        \
      __q1--;                                                \
      __rr += (d);                                           \
                                                             \
      /* rr = rb + d0 - d, and now by Knuth we are interested\
         in r + v1 < b, it holds that if rr >= d then        \
         r + v1 < b. */                                      \
      if (__rr >= (d) && __rr < __m)                         \
        {                                                    \
          __q1--;                                            \
          __rr += (d);                                       \
        }                                                    \
    }                                                        \
  /* Finish up the remainder of the first division.     */   \
  __rr -= __m;                                               \
                                                             \
  /* Second case a la Knuth. This is equivalent to the       \
     previous case, now we are working from the              \
     remainder. */                                           \
  __q0 = __rr / __d1;                                        \
  __rr = __rr % __d1;                                        \
  __m  = __q0 * __d0;                                        \
  __rr = (__rr << (SSH_WORD_BITS/2)) |                       \
           ((d0) & SSH_MP_LOW_BIT_MASK);                     \
  if (__rr < __m)                                            \
    {                                                        \
      __q0--;                                                \
      __rr += (d);                                           \
      if (__rr >= (d) && __rr < __m)                         \
        {                                                    \
          __q0--;                                            \
          __rr += (d);                                       \
        }                                                    \
    }                                                        \
  __rr -= __m;                                               \
                                                             \
  /* Finish up the division by building up the quotient,     \
     and the remainder. */                                   \
  (q) = (__q1 << (SSH_WORD_BITS/2)) | __q0;                  \
  (r) = __rr;                                                \
}
#elif 1

/* This implements heuristic improvement, it simply computes the
   remainder part with multiplication. In Alpha this seems to be
   somewhat faster.

   In general this is faster than the above if the machine has
   faster multiplication than division and the compiler doesn't
   really care about speeding things up (e.g. it is not very smart).

   This should be default, because usually division is slower
   than multiplication and some compilers just don't optimize
   the divisions (or can't optimize them due hardware).  */
#define SSH_MP_LONG_DIV(q, r, d1, d0, d)                     \
{                                                            \
  SshWord __d1, __d0, __q1, __q0, __rr, __m;                 \
  /* Break the divisor into two.                       */    \
  __d1 = ((d) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK;   \
  __d0 = (d) & SSH_MP_LOW_BIT_MASK;                          \
                                                             \
  /* Compute the first case, a la Knuth.               */    \
  __q1 = (d1) / __d1;                                        \
  /* Here we use multiplication to simply reduce number      \
     of divisions needed. */                                 \
  __rr = (d1) - __q1 *__d1;                                  \
  __m  = __q1 * __d0;                                        \
  __rr = (__rr  << (SSH_WORD_BITS/2)) |                      \
         (((d0) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK); \
  if (__rr < __m)                                            \
    {                                                        \
      __q1--;                                                \
      __rr += (d);                                           \
      if (__rr >= (d) && __rr < __m)                         \
        {                                                    \
          __q1--;                                            \
          __rr += (d);                                       \
        }                                                    \
    }                                                        \
  __rr -= __m;                                               \
                                                             \
  /* Second case a la Knuth. This is equivalent to the       \
     previous case, now we are working from the              \
     remainder. */                                           \
  __q0 = __rr / __d1;                                        \
  __rr = __rr - __q0 * __d1;                                 \
  __m  = __q0 * __d0;                                        \
  __rr = (__rr << (SSH_WORD_BITS/2)) |                       \
           ((d0) & SSH_MP_LOW_BIT_MASK);                     \
  if (__rr < __m)                                            \
    {                                                        \
      __q0--;                                                \
      __rr += (d);                                           \
      if (__rr >= (d) && __rr < __m)                         \
        {                                                    \
          __q0--;                                            \
          __rr += (d);                                       \
        }                                                    \
    }                                                        \
  __rr -= __m;                                               \
                                                             \
  /* Finish up the division by building up the quotient,     \
     and the remainder. */                                   \
  (q) = (__q1 << (SSH_WORD_BITS/2)) | __q0;                  \
  (r) = __rr;                                                \
}

#elif 0

/* This implements "another" heuristic improvement. Sadly, this
   doesn't work on Alpha where this would have been interesting.

   On 32-bit processors with fast double arithmetic you could
   probably get away with this. It takes some time to convert
   into double etc. but over all this has some chance of being
   faster on some platforms.

   XXX Haven't yet tested this one. 
   */

#define SSH_MP_LONG_DIV(q, r, d1, d0, d)                     \
{                                                            \
  SshWord __d1, __d0, __q1, __q0, __rr, __m;                 \
  double  __d;                                               \
  /* Break the divisor into two.                       */    \
  __d1 = ((d) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK;   \
  __d0 = (d) & SSH_MP_LOW_BIT_MASK;                          \
                                                             \
  /* Compute the first case, a la Knuth.               */    \
                                                             \
  /* Instead of using integer division, we try to get by     \
     with floating division. It should work a ok when        \
     word size is less than 32-bits. E.g. 32 bits can be     \
     extracted directly from the double. For 64 bit          \
     machines this sadly doesn't work. And yet more sadly    \
     long double isn't always 80 bits, thus we couldn't      \
     try that either. */                                     \
  __d = 1.0/(double)__d1;                                    \
  __q1 = (SshWord) \
         (((d1) & (SSH_MP_LOW_BIT_MASK << SSH_WORD_BITS/2)) * __d + \
          ((d1) & (SSH_MP_LOW_BIT_MASK)) * __d); \
  __rr = (d1) - __q1 *__d1;                                  \
  __m  = __q1 * __d0;                                        \
  __rr = (__rr  << (SSH_WORD_BITS/2)) |                      \
         (((d0) >> (SSH_WORD_BITS/2)) & SSH_MP_LOW_BIT_MASK); \
  if (__rr < __m)                                            \
    {                                                        \
      __q1--;                                                \
      __rr += (d);                                           \
      if (__rr >= (d) && __rr < __m)                         \
        {                                                    \
          __q1--;                                            \
          __rr += (d);                                       \
        }                                                    \
    }                                                        \
  __rr -= __m;                                               \
                                                             \
  /* Second case a la Knuth. This is equivalent to the       \
     previous case, now we are working from the              \
     remainder. */                                           \
  __q1 = (SshWord) \
         ((__rr & (SSH_MP_LOW_BIT_MASK << SSH_WORD_BITS/2)) * __d + \
          (__rr & (SSH_MP_LOW_BIT_MASK)) * __d); \
  __rr = __rr - __q0 * __d1;                                 \
  __m  = __q0 * __d0;                                        \
  __rr = (__rr << (SSH_WORD_BITS/2)) |                       \
           ((d0) & SSH_MP_LOW_BIT_MASK);                     \
  if (__rr < __m)                                            \
    {                                                        \
      __q0--;                                                \
      __rr += (d);                                           \
      if (__rr >= (d) && __rr < __m)                         \
        {                                                    \
          __q0--;                                            \
          __rr += (d);                                       \
        }                                                    \
    }                                                        \
  __rr -= __m;                                               \
                                                             \
  /* Finish up the division by building up the quotient,     \
     and the remainder. */                                   \
  (q) = (__q1 << (SSH_WORD_BITS/2)) | __q0;                  \
  (r) = __rr;                                                \
}
#endif

#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */

/* Routines for handling unsigned integers. These could be written
   in assembler, if more speed would be required. However, insignificant
   things should not be optimized. */

#ifndef SSHMATH_FAST_MEM_ROUTINES
/* C versions. */
void ssh_mpn_memcopy(SshWord *d, SshWord *s, unsigned int len)
{
  int i, j;
  /* Run the buffers two words at a time if possible. This should
     lower the overhead. */
  for (j = 0, i = len >> 1; i; j += 2, i--)
    {
      d[j    ] = s[j    ];
      d[j + 1] = s[j + 1];
    }
  if (len & 0x1)
    d[j] = s[j];
}
 
void ssh_mpn_memzero(SshWord *d, unsigned int len)
{
  int i, j;
  /* Run the buffers two words at a time if possible. This should
     lower the overhead. */
  for (j = 0, i = len >> 1; i; j += 2, i--)
    {
      d[j    ] = 0;
      d[j + 1] = 0;
    }
  if (len & 0x1)
    d[j] = 0;
}
#else /* SSHMATH_FAST_MEM_ROUTINES */

/* Wrappers for memory copy. */

void ssh_mpn_memcopy(SshWord *d, SshWord *s, unsigned int len)
{
  memcpy(d, s, len * sizeof(SshWord));
}

void ssh_mpn_memzero(SshWord *d, unsigned int len)
{
  memset(d, 0, len * sizeof(SshWord));
}
#endif /* SSHMATH_FAST_MEM_ROUTINES */

/************* Basic arithmetical operations. *****************/

/* Following routines are the core of basic operation, these do not check
   for anything and need an upper layer which implements nice application
   interface. */

/* Some bit level operations. */

/* Shifting, that is dividing and multiplying with 2^n's.*/

int ssh_mpn_shift_up_bits(SshWord *op, unsigned int ssh_mp_n,
                          unsigned int bits)
{
  unsigned int i;
  /* Nothing to do if zero integer. */
  if (!ssh_mp_n)
    return 0;

  /* We need a simple macro to make life easier. I.e. other wise
     we would have to dublicate it for all the cases. */
  
#define UP_SHIFT_MACRO(__bits__)                  \
  for (i = ssh_mp_n - 1; i; i--)                  \
    op[i] = (op[i] << (__bits__)) | (op[i - 1] >> \
            (SSH_WORD_BITS - __bits__));          \
  op[0] <<= __bits__;

  /* It is not of course necessarily best to do things this way,
     but in princible the shifting with just some variable is
     slower than by fixed value. At least this is so in Intel
     Pentiums. */
  switch (bits)
    {
    case 0:
      break;
    case 1:
      UP_SHIFT_MACRO(1);
      break;
    case 2:
      UP_SHIFT_MACRO(2);
      break;
    case 3:
      UP_SHIFT_MACRO(3);
      break;
    default:
      UP_SHIFT_MACRO(bits);
      break;
    }
#undef UP_SHIFT_MACRO

  if (op[ssh_mp_n - 1])
    ssh_mp_n++;
  return ssh_mp_n;
}

int ssh_mpn_shift_down_bits(SshWord *op, SshWord ssh_mp_n,
                            SshWord bits)
{
  unsigned int i;
  
  /* Nothing to do if zero integer. */
  if (!ssh_mp_n)
    return 0;

  /* We need a simple macro to make life easier. I.e. other wise
     we would have to dublicate it for all the cases. */

#define DOWN_SHIFT_MACRO(__bits__)                \
  for (i = 0; i < ssh_mp_n - 1; i++)              \
    op[i] = (op[i] >> (__bits__)) | (op[i + 1] << \
            (SSH_WORD_BITS - __bits__));          \
    op[ssh_mp_n - 1] >>= __bits__;
  
  /* It is not of course necessarily best to do things this way,
     but in princible the shifting with just some variable is
     slower than by fixed value. At least this is so in Intel
     Pentiums. */
  switch (bits)
    {
    case 0:
      break;
    case 1:
      DOWN_SHIFT_MACRO(1);
      break;
    case 2:
      DOWN_SHIFT_MACRO(2);
      break;
    case 3:
      DOWN_SHIFT_MACRO(3);
      break;
    default:
      DOWN_SHIFT_MACRO(bits);
      break;
    }
#undef DOWN_SHIFT_MACRO
  if (op[ssh_mp_n - 1])
    ssh_mp_n--;
  return ssh_mp_n;
}

/* Compute the size of the input word array in base 2. Fast. */
unsigned int ssh_mpn_size_in_bits(SshWord *op, unsigned int op_n)
{
  SshWord t;
  unsigned int r;
  
  if (op_n == 0)
    return 0;

  t = op[op_n - 1];
  r = 0;
  SSH_MP_COUNT_LEADING_ZEROS(r, t);
  
  return op_n * SSH_WORD_BITS - r;
}

/* Comparison of integers routines. */

/* Comparison of unsigned integer with an large integer. */
int ssh_mpn_cmp_ui(SshWord *op, unsigned int op_n, SshWord u)
{
  /* First check if values are both zero. */
  if (op_n == 0 && u == 0)
    return 0;

  /* If large integer is zero. */
  if (op_n == 0)
    return -1;

  /* If integer is zero. */
  if (u == 0)
    return 1;

  /* If large integer is larger than just one integer. */
  if (op_n > 1)
    return 1;

  /* If both are of roughly equal size. */
  if (op[0] > u)
    return 1;
  if (op[0] < u)
    return -1;

  /* Must be equal then. */
  return 0;
}

/* General compare with two large natural integers given as arrays. This
   should be written so that it is usually faster than running through
   all words of an integer array. */
int ssh_mpn_cmp(SshWord *op1, unsigned int op1_n,
                SshWord *op2, unsigned int op2_n)
{
  unsigned int i;

  /* Both might be zero? */
  if (op1_n == 0 && op2_n == 0)
    return 0;

  /* We may check just their sizes, because they are supposed to be
     kept updated. */
  if (op1_n > op2_n)
    return 1;
  if (op1_n < op2_n)
    return -1;

  /* Check whether the words are equal and if not which is larger. */
  for (i = op2_n; i; i--)
    {
      if (op1[i - 1] != op2[i - 1])
        {
          if (op1[i - 1] > op2[i - 1])
            return 1;
          return -1;
        }
    }

  /* Must be totally equal. Sadly in this case we have runned the loop
     in full, no other way I guess. */
  return 0;
}

/* We assume that op1_n > op2_n and that ret_n >= op1_n. */

SshWord ssh_mpn_add(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n)
{
  SshWord c;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int i;
  SshWord t, k;
#endif

  /* Addition in two phases. First we add the buffers up to the
     smallest. This ensures simplicity in the inner loop. */

#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
  /* Assembler routine for fast unsigned addition of two
     buffers of equal length. */
  c = ssh_mpn_add_n(ret, op1, op2, op2_n);
  if (op2_n < op1_n)
    {
      /* Check the carry and act accordingly. */
      if (c)
        c = ssh_mpn_add_1(ret + op2_n, op1 + op2_n, op1_n - op2_n);
      else
        ssh_mpn_memcopy(ret + op2_n, op1 + op2_n, op1_n - op2_n);
    }
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
  
  /* Add two buffers of equal length. */
  for (i = 0, c = 0; i < op2_n; i++)
    {
      /* Do the standard addition procedure. We assume that the word
         size is correct, and no additional bits are available for
         the word. This assumption is used throughout this code. */
      k = op1[i] + c;
      if (k < c)
        c = 1;
      else
        c = 0;
      t = k + op2[i];
      if (t < k)
        c++;
      ret[i] = t;
    }
  /* Check the carry and act accordingly. */
  if (c)
    {
      /* Add carries. */
      for (; i < op1_n; i++)
        {
          /* Simpler addition sequence, we can bail out if the carrying
             ends. */
          k = op1[i];
          t = k + 1;
          ret[i] = t;
          if (t > k)
            {
              c = 0;
              i++;
              break;
            }
        }
    }
  for (; i < op1_n; i++)
    ret[i] = op1[i];
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */
  return c;
}

/* We assume that op1_n > op2_n and op1 > op2 in absolute value. */

SshWord ssh_mpn_sub(SshWord *ret,
                    SshWord *op1, unsigned int op1_n,
                    SshWord *op2, unsigned int op2_n)
{
  SshWord c;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int i;
  SshWord t, k, j;
#endif

  /* Subtraction in two phases. */
  
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
  /* Assembler subtraction with buffers of equal length. */
  c = ssh_mpn_sub_n(ret, op1, op2, op2_n);
  if (op2_n < op1_n)
    {
      /* Handle the issue of carry. */
      if (c)
        c = ssh_mpn_sub_1(ret + op2_n, op1 + op2_n, op1_n - op2_n);
      else
        ssh_mpn_memcopy(ret + op2_n, op1 + op2_n, op1_n - op2_n);
  } 
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */

  /* Subtraction with buffers of equal length. */
  for (i = 0, c = 0; i < op2_n; i++)
    {
      /* Standard subtraction. Assumes same things as addition. */
      k = op1[i];
      j = op2[i] + c;
      if (j < c)
        c = 1;
      else
        c = 0;
      t = k - j;
      if (t > k)
        c++;
      ret[i] = t;
    }
  if (c)
    {
      /* Subtract carries. */
      for (; i < op1_n; i++)
        {
          /* Note the bail out similarity to addition. */
          k = op1[i];
          t = k - 1;
          ret[i] = t;
          if (t < k)
            {
              c = 0;
              i++;
              break;
            }
        }
    }
  for (; i < op1_n; i++)
    ret[i] = op1[i];
#endif
  
  return c;
}

/* The school multiplication method. */

void ssh_mpn_mul(SshWord *ret, unsigned int ret_n,
                 SshWord *op1, unsigned int op1_n,
                 SshWord *op2, unsigned int op2_n)
{
  unsigned int i;
  SshWord c;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord k, n1, n2, t1, t2;
  SshWord *tmp;
#endif

  /* Loop through the multiplier. We assume usually that the multiplier
     is shorter, thus there will probably exists slightly less
     overhead. */
  for (i = 0; i < op1_n; i++)
    {
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
      /* Assembler addmul, standard way to doing it. */
      c = ssh_mpn_addmul(ret + i, op1[i], op2, op2_n);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
      for (j = 0, c = 0, tmp = ret + i, k = op1[i]; j < op2_n; j++)
        {
          /* For each pair of words multiply and add to the
             return array. Handle the carries with an extra carry word. */
          SSH_MP_LONG_MUL(n2, n1, k, op2[j]);
          t1 = tmp[j] + n1;
          t2 = n2;
          if (t1 < n1)
            t2++;
          t1 += c;
          if (t1 < c)
            t2++;
          tmp[j] = t1;
          c = t2;
        }
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */
      /* Set the carry word on top. */
      ret[i + op2_n] = c;
    }
}

/* Faster version for specific multiplication by just single digit. This case
   cannot be speeded up asymptotically. */

void ssh_mpn_mul_ui(SshWord *ret, unsigned int ret_n,
                    SshWord *op,  unsigned int op_n,
                    SshWord u)
{
  unsigned int i;
  SshWord c, n1, n2, t1, t2;

  /* XXX Make use of the assembler version. */
  for (i = 0, c = 0; i < op_n; i++)
    {
      /* Simplied from above. */
      SSH_MP_LONG_MUL(n2, n1, u, op[i]);
      t1 = n1 + c;
      t2 = n2;
      if (t1 < c)
        t2++;
      ret[i] = t1;
      c = t2;
    }
  /* Set the carry. */
  if (c)
    ret[i] = c;
}

/* Rather quick squaring. However, we need even faster!

   Note:

     (a b c d)^2 =

     aa ab ac ad
        ba bb bc bd
           ca cb cc cd
              da db dc dd

     we get an algorithm:

     for i = 0 to op_n
       ret[i*2] += op[i]*op[i]
       for j = i + 1 to op_n
         ret[j + i] += 2*op[j]*op[i]

     which outputs:
         
     aa
     ab*2 
     ac*2 bb
     ad*2 bc*2
     bd*2 cc
     cd*2
     dd

   This squaring is given in HAC. Rather odd, it is not best way to
   do this? Or is it...
 */

#if 0
/* This squaring is older and slower (hopefully). Don't use but for
   testing, and timing. This implementation might be removed later. */
void ssh_mpn_square(SshWord *ret, unsigned int ret_n,
                    SshWord *op,  unsigned int op_n)
{
  unsigned int i, j;
  SshWord c1, c2, n1, n2, n3, t, k, high_carry;

  for (i = 0, high_carry = 0; i < op_n; i++)
    {
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
      high_carry = ssh_mpn_addsq(ret + i * 2, op + i, op_n - (i + 1),
                             high_carry);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */

      /* Initial multiplication in loop. */
      k = op[i];
      SSH_MP_LONG_MUL(n2, n1, k, k);
      t = ret[i * 2];
      n1 += t;
      if (n1 < t)
        n2++;

      /* Set */
      ret[i * 2] = n1;
      c1 = n2;
      c2 = 0;

      for (j = i + 1; j < op_n; j++)
        {
          SSH_MP_LONG_MUL(n2, n1, op[j], k);
          /* Shift up by 1. I.e. Multiply by 2. On some processors
             this might become very slow, so XXX. */
          n3 = n2 >> (SSH_WORD_BITS - 1);
          n2 = (n2 << 1) | (n1 >> (SSH_WORD_BITS - 1));
          n1 <<= 1;

          /* Add with ret. */
          t = ret[i + j];
          n1 += t;
          /* Handle carry. We can accumulate the carry to c2, because
             c2 is generally very small. In fact, this seems to be
             a bit nicer than by the more direct way. */
          if (n1 < t)
            c2++;

          /* Add with carry. */
          n1 += c1;
          if (n1 < c1)
            c2++;

          /* Handle the "excess" values. */
          n2 += c2;
          if (n2 < c2)
            n3++;

          /* Set for the following round. */
          ret[i + j] = n1;
          c1 = n2;
          c2 = n3;
        }

      c1 += high_carry;
      if (c1 < high_carry)
        c2++;
      
      ret[i + op_n]     = c1;
      ret[i + op_n + 1] = c2;

      high_carry = c2;
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */
    }
}
#else

/* This squaring routine is much faster than the above one. Using the
   straight-forward idea, without so much excessive shifting.

   Above one interleaves everything, however, it will be faster to
   compute it uninterleaved as is usually the case. (However, I was
   rather happy to notice this one night.)

   Following snipnet will do the job:

   for i = 0 to op_n - 1
     for j = i + 1 to op_n - 1
       ret[j + i] += op[j] * op[i]

   ret = ret*2

   for i = 0 to op_n - 1
     ret[i*2] += op[i]*op[i]

   Notice the elegance of this approach. It is easy to see that the first
   part does op_n*(op_n - 1)/2 operations. That is less than half of
   the standard school multiplication. Then the multiplication by two
   is insignificant, and can be performed quickly. The last step
   takes op_n operations, that is the full computation takes
   op_n*(op_n + 1)/2 multiplications, 1 shift, lots of additions. The
   version above takes op_n*(op_n + 1)/2 multiplications, op_n*(op_n - 1)/2
   shifts and lots of additions.

   And infact, this way the computation is clearly faster.
   */

void ssh_mpn_square(SshWord *ret, int ret_n,
                    SshWord *op,  int op_n)
{
  unsigned int i;
  SshWord c;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord k, t1, t2, n1, n2;
#endif
  
  /* First do the almost ordinary looking multiplication phase. */
  for (i = 0; i < op_n; i++)
  {
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
    /* Handle multiplication (and addition) with just one
       call to assembler routine. This is same what is used in
       multiplication. Makes this interface very nice. */
    c = ssh_mpn_addmul(ret + 2*i + 1, op[i], op + i + 1, op_n - i - 1);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
      for (j = i + 1, k = op[i], c = 0; j < op_n; j++)
        {
          /* Same routine as the one given above. */
          SSH_MP_LONG_MUL(n2, n1, k, op[j]);
          t1 = ret[j + i] + n1;
          t2 = n2;
          if (t1 < n1)
            t2++;
          t1 += c;
          if (t1 < c)
            t2++;
          ret[j + i] = t1;
          c = t2;
        }
#endif
      /* Handle the carry as usual. */
      ret[i + op_n] = c;
    }
 
  /* Now shift up by 1 bit. */
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
  /* Assembler shifter for just one bit. Not very useful? I have not
     ran any tests for this one, but do assume that it makes everything
     worthwhile. */
  ssh_mpn_shift_up_1(ret, op_n*2);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
  /* Shifting in C. Possibly a bit slow. */
  for (i = op_n * 2; i; i--)
    ret[i] = (ret[i] << 1) | (ret[i - 1] >> (SSH_WORD_BITS - 1));
  ret[0] <<= 1;
#endif
   
  /* Last, but not least, add the squared values. Here we are in a bit
     of a trouble. The assembler version is a lot faster. */
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
  /* Square words quickly with assembler. Handles also the difficult
     addition procedure. */
  ssh_mpn_square_words(ret, op, op_n);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
  for (i = 0, c = 0; i < op_n; i++)
    {
      k = op[i];
      /* Use the square macro, which is slightly faster (possibly)
         than the multiply macro. */
      SSH_MP_LONG_SQUARE(n2, n1, k);

      /* Start the complicated addition sequence. As you might have
         noted we need to do rather much of comparing. */
      t1 = ret[i*2] + n1;
      t2 = n2;
      if (t1 < n1)
        t2++;
      t1 = t1 + c;
      if (t1 < c)
        t2++;
      ret[i*2] = t1;
      
      /* Add to the following word. */ 
      k = ret[i*2 + 1];
      c = 0;
      t2 += k;
      if (t2 < k)
        c++;
      ret[i*2 + 1] = t2;
    }
  /* Handle the addition of the carry and the top word thus far. */
  k = ret[op_n * 2] + c;
  if (k < c)
    c = 1;
  else
    c = 0;

  /* Set the highest words correctly. */
  ret[op_n * 2] = k;
  ret[op_n * 2 + 1] = c;
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */
}

#endif

/* Standard Karatsuba multiplying and non-standard squaring. 

   Following formulas are used in following:

   Multiplication with Karatsuba's idea:

   Let

     u = u0 + u1*b
     v = v0 + v1*b
     b is the word size (e.g. 2^32)

   Karatsuba multiplication algorithm:
     
     u * v = (b^2 + b) * u1 * v1 + b*(u1 - u0)*(v0 - v1) + (b + 1) * v0 * u0

   Squaring algorithm 1 (due to Markku-Juhani Saarinen):

   Let

     x = (u1 + u0)^2
     y = (u1 - u0)^2
     z = u1^2

   then
     
     u^2 = z*b^2 + ((x - y)*b + (x + y))/2 - z

   Squaring algorithm 2 (due to Colin Plumb):

     (u*b + v)^2 = u^2*(b^2 + b) + v^2 * (b + 1) - (u - v)^2 * b

   Saarinen's method uses 3 squaring's, 4 additions and 3
   subtractions. 
   
   Plumb's method uses 3 squaring's, 3 additions and 2 subtractions. 

   Both can be reasonably efficiently implemented. Note that squaring
   such as (u - v)^2 forgets the sign of the u - v computation, which
   makes implementation nicer.
     
   */

/* A threshold for estimating when these divide and conquer methods should be
   used. A nice configuration system would allow searching (with binary
   search etc.) the best possible thresholds for your system.
   */
   
#define SSH_MPN_MUL_KARATSUBA_THRESHOLD 28
#define SSH_MPN_SQUARE_KARATSUBA_THRESHOLD 60

#if 0
/* Some test code, to be removed. */
void ssh_mpn_print(char *str, SshWord *op, int op_n)
{
  SshInt t;
  char *buf;
  int i;
  
  t.v = op;
  t.n = op_n;
  t.m = op_n;
  t.sign = 0;

  buf = ssh_mp_get_str(NULL, 10, &t);
  printf("%s %s\n", str, buf);
  ssh_xfree(buf);

  printf("in hex = ");
  for (i = op_n; i; i--)
#if SIZEOF_LONG==4
    printf("%08lx ", op[i - 1]);
#else
    printf("%16lx ", op[i - 1]);
#endif /* SIZEOF_LONG==4 */
  printf("\n");
}
#endif

#if 1

/* Compute the needed memory for the Karatsuba squaring. */
unsigned int ssh_mpn_square_karatsuba_needed_memory(unsigned int op_n)
{
  unsigned int work_n, div_n;
  
  /* If smaller than the threshold. */
  if (op_n < SSH_MPN_SQUARE_KARATSUBA_THRESHOLD)
    return 0;

  /* Select nearly optimal sizes. */
  div_n = op_n/2;
  work_n = ((div_n + 1) * 2 + 1)*4;

  /* Compute recursively the amount of memory needed! */
  work_n += ssh_mpn_square_karatsuba_needed_memory(div_n);
  work_n += ssh_mpn_square_karatsuba_needed_memory(op_n - div_n);
  work_n += ssh_mpn_square_karatsuba_needed_memory(op_n - div_n);

  return work_n;
}

/* This is the algorithm of Plumb's. As one can see this falls in place
   quite nicely. */

/* Original idea was to do all this in data recursion rather than the
   more easier code recursion. But that would mean some allocation,
   and might not be too much faster. 
   */
void ssh_mpn_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space,
                              unsigned int work_space_n)
{
  if (op_n < SSH_MPN_SQUARE_KARATSUBA_THRESHOLD)
    {
      /* If the compiler is smart it probably will inline this function
         here. */
      ssh_mpn_square(ret, ret_n, op, op_n);
    }
  else
    {
      SshWord *u0, *u1, *x, *y, *z, *t, *work;
      unsigned int u0_n, u1_n, x_n, y_n, z_n, work_n, div_n, t_n;
      Boolean work_allocated;
      
      /* (u*b + v)^2 = u^2*(b^2 + b) + v^2 * (b + 1) - (u - v)^2 * b

         x = u1^2
         y = u0^2
         t = u1 - u0
         z = t^2
       */
      
      /* Select nearly optimal sizes. */
      div_n = op_n / 2;

      /* Compute divided parts. */
      u1 = op + div_n;
      u1_n = op_n - div_n;
      u0 = op;
      u0_n = div_n;

      /* Compute lengths for partial values. */
      x_n = (div_n + 1) * 2 + 1;
      y_n = (div_n + 1) * 2 + 1;
      z_n = (div_n + 1) * 2 + 1;
      t_n = (div_n + 1) * 2 + 1;
      work_n = x_n + y_n + z_n + t_n;

      /* Allocate working space. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_xmalloc(work_n * sizeof(SshWord));
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          /* Advance the working space. */
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      x = work;
      y = x + x_n;
      z = y + y_n;
      t = z + z_n;

      /* Compute x = u1^2 */
      x_n = u1_n * 2 + 1;
      ssh_mpn_memzero(x, x_n);
      ssh_mpn_square_karatsuba(x, x_n, u1, u1_n,
                               work_space, work_space_n);
      /* Check size. */
      while (x_n && x[x_n - 1] == 0)
        x_n--;
      
      /* Compute y = u0^2 */
      y_n = u0_n * 2 + 1;
      ssh_mpn_memzero(y, y_n);
      ssh_mpn_square_karatsuba(y, y_n, u0, u0_n,
                               work_space, work_space_n);
      /* Check size. */
      while (y_n && y[y_n - 1] == 0)
        y_n--;
      
      /* Compute t = u1 - u0. Note that we do not need to remember the
         sign of this computation.

         It should be reasonably rare occurance that u1 < u0, but
         there is really no need to try to avoid it by selecting the
         division point "better".
         */
      t_n = u1_n;
      ssh_mpn_memzero(t, t_n);
      if (ssh_mpn_cmp(u1, u1_n, u0, u0_n) >= 0)
        ssh_mpn_sub(t, u1, u1_n, u0, u0_n);
      else
        ssh_mpn_sub(t, u0, u0_n, u1, u1_n);
      /* Check size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;
      
      /* Compute z = u1^2 */
      z_n = t_n * 2 + 1;
      ssh_mpn_memzero(z, z_n);
      ssh_mpn_square_karatsuba(z, z_n, t, t_n,
                               work_space, work_space_n);
      /* Check size. */
      while (z_n && z[z_n - 1] == 0)
        z_n--;

      /* (u1*b + u0)^2 = u1^2*(b^2 + b) + u0^2 * (b + 1) - (u1 - u0)^2 * b

         x = u1^2
         y = u0^2
         t = u1 - u0
         z = t^2
       */

      /* Copy the x up there. */
      ssh_mpn_memcopy(ret + div_n * 2, x, x_n);
      ssh_mpn_add(ret + div_n, ret + div_n, ret_n - div_n,
              x, x_n);
      ssh_mpn_add(ret + div_n, ret + div_n, ret_n - div_n,
              y, y_n);
      ssh_mpn_add(ret, ret, ret_n,
              y, y_n);

      /* Subtract last to be assured that we cannot get negative. */
      ssh_mpn_sub(ret + div_n, ret + div_n, ret_n - div_n,
              z, z_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_xfree(work); 
    }
}

#else 

/* Compute amount of memory needed for the Karatsuba squaring to
   work. This is recursive, but could be written out probably as
   a simple formula. */
unsigned int ssh_mpn_square_karatsuba_needed_memory(unsigned int op_n)
{
  unsigned int work_n, div_n;
  
  /* If smaller than the threshold. */
  if (op_n < SSH_MPN_SQUARE_KARATSUBA_THRESHOLD)
    return 0;

  /* Select nearly optimal sizes. */
  div_n = op_n/2;
  work_n = ((div_n + 1) * 2 + 1)*4;

  /* Compute recursively the amount of memory needed! */
  work_n += ssh_mpn_square_karatsuba_needed_memory((op_n - div_n) + 1);
  work_n += ssh_mpn_square_karatsuba_needed_memory(op_n - div_n);
  work_n += ssh_mpn_square_karatsuba_needed_memory(op_n - div_n);

  return work_n;
}

/* This is the algorithm due to Saarinen. */
void ssh_mpn_square_karatsuba(SshWord *ret, unsigned int ret_n,
                              SshWord *op,  unsigned int op_n,
                              SshWord *work_space, unsigned int work_space_n)
{
  if (op_n < SSH_MPN_SQUARE_KARATSUBA_THRESHOLD)
    {
      /* Lets call the school squaring algorithm. */
      ssh_mpn_square(ret, ret_n, op, op_n);
    }
  else
    {
      SshWord *u0, *u1, *x, *y, *z, *t, *work, c;
      unsigned int u0_n, u1_n, x_n, y_n, z_n, work_n, div_n, t_n;
      Boolean work_allocated;
      
      /* Select nearly optimal sizes. */
      div_n = op_n / 2;

      /* Compute divided parts. */
      u1 = op + div_n;
      u1_n = op_n - div_n;
      u0 = op;
      u0_n = div_n;

      /* Compute lengths for partial values. */
      x_n = (div_n + 1) * 2 + 1;
      y_n = (div_n + 1) * 2 + 1;
      z_n = (div_n + 1) * 2 + 1;
      t_n = (div_n + 1) * 2 + 1;
      work_n = x_n + y_n + z_n + t_n;

      /* Allocate working space. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_xmalloc(work_n * sizeof(SshWord));
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      x = work;
      y = x + x_n;
      z = y + y_n;
      t = z + z_n;

      /* Compute x = (u1 + u0)^2 */
      t_n = u1_n;
      ssh_mpn_memzero(t, t_n);
      c = ssh_mpn_add(t, u1, u1_n, u0, u0_n);
      if (c)
        {
          t[t_n] = 1;
          t_n++;
        }
      else
        /* Check size. */
        while (t_n && t[t_n - 1] == 0)
          t_n--;

      x_n = t_n * 2 + 1;
      ssh_mpn_memzero(x, x_n);
      ssh_mpn_square_karatsuba(x, x_n, t, t_n,
                               work_space, work_space_n);
      
      /* Compute y = (u1 - u0)^2 */
      t_n = u1_n;
      ssh_mpn_memzero(t, u1_n);
      if (ssh_mpn_cmp(u1, u1_n, u0, u0_n) >= 0)
        ssh_mpn_sub(t, u1, u1_n, u0, u0_n);
      else
        ssh_mpn_sub(t, u0, u0_n, u1, u1_n);
      /* Check size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      y_n = t_n * 2 + 1;
      ssh_mpn_memzero(y, y_n);
      ssh_mpn_square_karatsuba(y, y_n, t, t_n,
                               work_space, work_space_n);
      
      /* Compute z = u1^2 */
      z_n = u1_n * 2 + 1;
      ssh_mpn_memzero(z, z_n);
      ssh_mpn_square_karatsuba(z, z_n, u1, u1_n,
                               work_space, work_space_n);

      /* Add things up. Clean this! XXX */
     
      /* u^2 = z*b^2 + ((x - y)/2)*b + ((x + y)/2 - z) */

      /* Check sizes. */
      while (x_n && x[x_n - 1] == 0)
        x_n--;
      while (y_n && y[y_n - 1] == 0)
        y_n--;
      while (z_n && z[z_n - 1] == 0)
        z_n--;

      /* Compute t = (x + y)/2 and x = (x - y)/2. */
      t_n = x_n;
      c = ssh_mpn_add(t, x, x_n, y, y_n);
      ssh_mpn_sub(x, x, x_n, y, y_n);

      /* Handle possible carry. And correct sizes. */
      if (c)
        {
          t[t_n] = 1;
          t_n++;
        }
      else
        while (t_n && t[t_n - 1] == 0)
          t_n--;
      
      while (x_n && x[x_n - 1] == 0)
        x_n--;

      /* u^2 = z*b^2 + x*b + (t - z) */

      /* Shift down, that is divide by 2. */
      ssh_mpn_memcopy(ret + div_n, x, x_n);
      ssh_mpn_add(ret, ret, div_n + x_n, t, t_n);

      /* Correct the size. */
      t_n = div_n + x_n + 1;
      while (t_n && ret[t_n - 1] == 0)
        t_n--;

      /* Divide by 2. */
      ssh_mpn_shift_down_bits(ret, t_n, 1);

      /* Compute the rest. */
      
      /* Add and subtract z. */
      ssh_mpn_add(ret + div_n * 2, ret + div_n * 2, ret_n - div_n * 2,
              z, z_n);
      ssh_mpn_sub(ret, ret, ret_n, z, z_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_xfree(work); 
    }
}

#endif

/* Compute the needed memory for the Karatsuba multiplication. */
unsigned int ssh_mpn_mul_karatsuba_needed_memory(unsigned int op1_n,
                                                 unsigned int op2_n)
{
  unsigned int u0_n, u1_n, v0_n, v1_n, work_n, div_n, uv1_n, uv0_n,
    um_n, vm_n, vum_n;
  
  /* Check for threshold. */
  if (op1_n < SSH_MPN_MUL_KARATSUBA_THRESHOLD ||
      op2_n < SSH_MPN_MUL_KARATSUBA_THRESHOLD)
    return 0;

  if (op1_n < op2_n)
    div_n = op1_n / 2;
  else
    div_n = op2_n / 2;

  /* Compute sizes and positions to make things much clearer later.
     Compiler will interleave these if it is any good? */
  u0_n = div_n;
  u1_n = op1_n - div_n;
  v0_n = div_n;
  v1_n = op2_n - div_n;
  
  /* We need some working space. */
  uv1_n = u1_n + v1_n + 1;
  uv0_n = u0_n + u0_n + 1;
  um_n  = u1_n + 1;
  vm_n  = v1_n + 1;
  vum_n = um_n + vm_n + 1;
  
  /* Add up all sizes. */
  work_n = uv1_n + uv0_n + um_n + vm_n + vum_n;

  /* Compute the recursive effect! */
  work_n += ssh_mpn_mul_karatsuba_needed_memory(u1_n, v1_n);
  work_n += ssh_mpn_mul_karatsuba_needed_memory(u0_n, v0_n);
  work_n += ssh_mpn_mul_karatsuba_needed_memory(um_n, vm_n);

  /* Return the amount of memory used in total. */
  return work_n;
}

/* Karatsuba multiplication. This is basically a recursive function, which
   divides each input into two and calls itself until ready for
   school multiplication. */
void ssh_mpn_mul_karatsuba(SshWord *ret, unsigned int ret_n,
                           SshWord *op1, unsigned int op1_n,
                           SshWord *op2, unsigned int op2_n,
                           SshWord *work_space, unsigned int work_space_n)
{
  if (op1_n < SSH_MPN_MUL_KARATSUBA_THRESHOLD ||
      op2_n < SSH_MPN_MUL_KARATSUBA_THRESHOLD)
    {
      /* Call ssh_mpn_mul in such a way that the faster loop runs longer. */
      if (op1_n < op2_n)
        ssh_mpn_mul(ret, ret_n, op1, op1_n,
                op2, op2_n);
      else
        ssh_mpn_mul(ret, ret_n, op2, op2_n,
                op1, op1_n);
    }
  else
    {
      SshWord *u0, *u1, *v0, *v1, *work;
      unsigned int u0_n, u1_n, v0_n, v1_n, work_n, div_n, uv1_n, uv0_n,
        um_n, vm_n, vum_n;
      SshWord *uv1, *uv0, *um, *vm, *vum;
      Boolean vm_sign = FALSE, um_sign = FALSE, vum_sign, work_allocated;
      
      /*
        Let

        u = u0 + u1*b
        v = v0 + v1*b
        b is the word size (e.g. 2^32)
        
        Karatsuba multiplication algorithm:
        
        u * v = (b^2 + b) * u1 * v1 + b*(u1 - u0)*(v0 - v1) + (b + 1) * v0 * u0

     */

      if (op1_n < op2_n)
        div_n = op1_n / 2;
      else
        div_n = op2_n / 2;

      /* Compute sizes and positions to make things much clearer later.
         Compiler will interleave these if it is any good? */
      u0   = op1;
      v0   = op2;
      u1   = op1 + div_n;
      v1   = op2 + div_n;
      u0_n = div_n;
      u1_n = op1_n - div_n;
      v0_n = div_n;
      v1_n = op2_n - div_n;

      /* We need some working space. */
      uv1_n = u1_n + v1_n + 1;
      uv0_n = u0_n + v0_n + 1;
      um_n  = u1_n + 1;
      vm_n  = v1_n + 1;
      vm_sign = FALSE;
      vum_n = um_n + vm_n + 1;

      /* Add up all sizes. */
      work_n = uv1_n + uv0_n + vum_n + vm_n + um_n;

      /* Allocate space with ssh_xmalloc which should be fast enough. */
      if (work_space == NULL || work_space_n < work_n)
        {
          work_allocated = TRUE;
          work           = ssh_xmalloc(sizeof(SshWord) * work_n);
        }
      else
        {
          work_allocated = FALSE;
          work           = work_space;
          work_space    += work_n;
          work_space_n  -= work_n;
        }

      /* Divide amongst the intermediate variables. */
      uv1 = work;
      uv0 = uv1 + uv1_n;
      um  = uv0 + uv0_n;
      vm  = um  + um_n;
      vum = vm  + vm_n;
      
      /* Compute u1 * v1 */
      ssh_mpn_memzero(uv1, uv1_n);
      ssh_mpn_mul_karatsuba(uv1, uv1_n, u1, u1_n, v1, v1_n,
                            work_space, work_space_n);

      /* Compute u0 * v0 */
      ssh_mpn_memzero(uv0, uv0_n);
      ssh_mpn_mul_karatsuba(uv0, uv0_n, u0, u0_n, v0, v0_n,
                            work_space, work_space_n);
      
      /* Compute (u1 - u0) * (v0 - v1) */
      if (ssh_mpn_cmp(u1, u1_n, u0, u0_n) >= 0)
        {
          ssh_mpn_sub(um, u1, u1_n, u0, u0_n);
          um_n = u1_n;
          um_sign = FALSE;
        }
      else
        {
          ssh_mpn_sub(um, u0, u0_n, u1, u1_n);
          um_n = u0_n;
          um_sign = TRUE;
        }

      /* Check size. */
      while (um_n && um[um_n - 1] == 0)
        um_n--;
      
      if (ssh_mpn_cmp(v0, v0_n, v1, v1_n) >= 0)
        {
          ssh_mpn_sub(vm, v0, v0_n, v1, v1_n);
          vm_n = v0_n;
          vm_sign = FALSE;
        }
      else
        {
          ssh_mpn_sub(vm, v1, v1_n, v0, v0_n);
          vm_n = v1_n;
          vm_sign = TRUE;
        }
      
      /* Check size. */
      while (vm_n && vm[vm_n - 1] == 0)
        vm_n--;
      
      /* Multiply. */
      vum_n = um_n + vm_n + 1;
      ssh_mpn_memzero(vum, vum_n);
      ssh_mpn_mul_karatsuba(vum, vum_n, um, um_n, vm, vm_n,
                            work_space, work_space_n);
      vum_sign = um_sign ^ vm_sign;

      /* Check size. */
      while (vum_n && vum[vum_n - 1] == 0)
        vum_n--;
      
      /*
        u * v = (b^2 + b) * u1 * v1 + b*(u1 - u0)*(v0 - v1) + (b + 1) * v0 * u0
        */

      /* Add up. */
      
      ssh_mpn_memcopy(ret + div_n * 2, uv1, uv1_n);
      ssh_mpn_add(ret + div_n, ret + div_n, ret_n - div_n,
              uv0, uv0_n);
      ssh_mpn_add(ret + div_n, ret + div_n, ret_n - div_n,
              uv1, uv1_n);
      ssh_mpn_add(ret, ret, ret_n, uv0, uv0_n);

      /* The middle place with either subtraction or addition. */
      if (vum_sign)
        ssh_mpn_sub(ret + div_n, ret + div_n, ret_n - div_n,
                vum, vum_n);
      else
        ssh_mpn_add(ret + div_n, ret + div_n, ret_n - div_n,
                vum, vum_n);

      /* Finished. */
      if (work_allocated == TRUE)
        ssh_xfree(work);
    }
}

/* Compute the number of leading zero bits. This is useful with
   division, especially when needing normalization. */
unsigned int ssh_mpn_leading_zeros(SshWord *d, unsigned int d_n)
{
  SshWord r, v;

  /* Quick check. */
  v = d[d_n - 1];
  if (v & ((SshWord)1 << (SSH_WORD_BITS - 1)))
    return 0;

  r = 0;
  SSH_MP_COUNT_LEADING_ZEROS(r, v);
  return r;
}

/* Basic division of an large integer. Returns quotient in q and
   remainder in r. r should be set to the dividend when called.
   This algorithm is derived from HAC. */
void ssh_mpn_div(SshWord *q, unsigned int q_n,
                 SshWord *r, unsigned int r_n,
                 SshWord *d, unsigned int d_n)
{
  unsigned int i;
  SshWord div, divl, rem, quot, c2, c1, c, rh, rl, rll;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord *tmp, k, t;
#endif

  /* We'd like to have optimized cases for all lengths of divisor, but
     that's impossible. Instead we have separated the trivial cases,
     and we'll do most of the work in the default case. */
  switch (d_n)
    {
    case 0:
      /* Divide by zero. */
      ssh_fatal("ssh_mpn_div: divide by zero.");
      break;

      /* This should be very fast, one could even check for some
         special divisors. Same algorithm is basically used later
         in some functions. */
    case 1:
      div = d[0];
      rem = 0;
      for (i = r_n; i; i--)
        SSH_MP_LONG_DIV(q[i - 1], rem, rem, r[i - 1], div);
      r[0] = rem;
      break;

      /* Other small cases? 2, 3, 4, ... would these speed things up
         in some particular cases? Probably, considering that some of
         our applications use integers of size 200 bits, and 64*4 >
         200. */
      
      /* General case, with very large divisors. */
    default:
      
      /* Reduce n such that n < d_n*b^(n_n - d_n). This step should be
         performed only once if everything goes nicely. Notice that
         this step also ensures that our macro for division
         will work. */

      if (ssh_mpn_cmp(r + (r_n - d_n), d_n, d, d_n) >= 0)
        {
          ssh_mpn_sub(r + (r_n - d_n), r + (r_n - d_n), d_n, d, d_n);
          q[r_n - d_n] = 1;
        }

      /* Main loop of division code. */
      for (i = r_n, div = d[d_n - 1], divl = d[d_n - 2]; i > d_n; i--)
        {
          rh = r[i - 1];
          rl = r[i - 2];

          /* This test makes it possible to use this loop for division
             of less than 3 word numbers. Otherwise we'd need to write
             special case routine. Which would be faster though. */
            
          if (i >= 3)
            rll = r[i - 3];
          else
            rll = 0;
          
          if (rh == div)
            quot = -1;
          else
            {
              /* Idea here is to compute:

                 quot = (xh*b + xl) / yh
                 rem  = (xh*b + xl) % yh

                 then

                 c = quot * yl

                 now we can check if

                 quot * (yh*b + yl) > xh*b^2 + xl*b + xll

                 by checking when

                 quot*yl + quot * yh*b > xh*b^2 + xl*b + xll

                 <=>

                 c + xh*b^2 + xl*b - rem*b > xh*b^2 + xl*b + xll

                 <=>

                 c - rem*b > xll

                 Now we can easily work with only one division and
                 one multiplication to get the quot correct.
                 
                 */

              SSH_MP_LONG_DIV(quot, rem, rh, rl, div);
              SSH_MP_LONG_MUL(c2, c1, quot, divl);

              /* Now reduce quot, until it is correct. This loop is
                 correct, because c - rem*b > xll iff c2 > rem or
                 c2 == rem and c1 > n[i - 2], otherwise c - rem*b is equal
                 or less than xll.

                 The reduction of c and rem can be performed without slow
                 arithmetic because

                 c = quot*yh

                 that is

                 c = (quot - 1)*yl =  quot * yl - yl

                 and

                 rem = (xh*b + xl) % yh

                 thus

                 rem = xh*b + xl - quot*yh

                 now 

                     rem = xh*b + xl - (quot - 1)*yh
                 <=> rem = xh*b + xl - quot*yh + yh
                 <=> rem = rem + yh

                 which is what we are after.
                 */

              while (c2 > rem || (c2 == rem && c1 > rll))
                {
                  quot--;

                  rem += div;
                  if (rem < div)
                    break;

                  if (c1 < divl)
                    c2--;
                  c1 -= divl;
                }
            }
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
          c = ssh_mpn_submul(r + i - d_n - 1, quot, d, d_n);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
          
          /* Now we have a "quot" which is almost correct (possibly 1
             too large). And can thus compute quickly a suitable
             multiple of d such that we can reduce the dividend.  */

          for (j = 0, c = 0, tmp = r + i - d_n - 1; j < d_n; j++)
            {
              SSH_MP_LONG_MUL(c2, c1, d[j], quot);

              /* We use here the carry along the way. That is we don't need
                 to loop at all, but just to keep track of the carry
                 until the end of the run. */
              c1 += c;
              if (c1 < c)
                c2++;
              c = c2;

              /* Now compute the actual word to place in appropriate place. */
              k = tmp[j];
              t = k - c1;
              if (t > k)
                c++;
              tmp[j] = t;
            }
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */

          /* Add if negative to make positive. E.g. this is the
             final correction phase, after the "quot" must be correct. */
          if (rh < c)
            {
              ssh_mpn_add(r + (i - d_n - 1), r + (i - d_n - 1), d_n, d, d_n);
              quot--;
            }
          
          q[i - d_n - 1] = quot;
        }
      break;
    }
}

/* Simple proof for the following algorithm (we have used it before already). 

   input: k of n words

   Computation:
     q * d + r = k
   where r is a one word remainder.

   Now, k - q*d = r and given division of 2 word by 1 word we can compute

       div(q_0, r_0, 0, k_n-1, d)
   <=> k_n-1 = q_0*d + r_0

   then
   
       div(q_1, r_1, r_0, k_n-2, d)
   <=> r_0*b + k_n-2 = q_1*d + r_1

   and thus

       (k_n-1 - q_0*d)*b + k_n-2 = q_1*d + r_1
   <=> k_n-1*b + k_n-2 = (q_0*b + q_1)*d + r_1

   now by induction this holds until the end. That is, we get the
   remainder as r_n-1 and quotients in (wrong) order q_0...q_n-1.
 */

/* Note, the 'r' here is not altered, although it basically would
   contain the remainder if computed in above way. */
SshWord ssh_mpn_div_ui(SshWord *q, unsigned int q_n,
                       SshWord *r, unsigned int r_n,
                       SshWord d)
{
  unsigned int i;
  SshWord rem;
  
  rem = 0;
  for (i = r_n; i; i--)
    SSH_MP_LONG_DIV(q[i - 1], rem, rem, r[i - 1], d);
  return rem;
}

/* This works as the one above. */
SshWord ssh_mpn_mod_ui(SshWord *r, unsigned int r_n,
                       SshWord d)
{
  unsigned int i;
  SshWord rem, t;
  
  rem = 0;
  for (i = r_n; i; i--)
    SSH_MP_LONG_DIV(t, rem, rem, r[i - 1], d);
  return rem;  
}

/* Computation of the remainder in a way that ignores the quotient altogether.
   Makes allocation easier for the ssh_mp_mod. Might be a bit faster than
   the ssh_mpn_div however, main point is to reduce allocation. */
void ssh_mpn_mod(SshWord *r, unsigned int r_n,
                 SshWord *d, unsigned int d_n)
{
  unsigned int i;
  SshWord div, divl, rem, quot, c2, c1, c, t, rh, rl, rll;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord *tmp, k;
#endif

  /* We'd like to have optimized cases for all lengths of divisor. */
  switch (d_n)
    {
    case 0:
      /* Divide by zero. */
      ssh_fatal("ssh_mpn_mod: divide by zero.");
      break;

      /* This should be very fast, one could even check for some
         special divisors. */
    case 1:
      div = d[0];
      rem = 0;
      for (i = r_n; i; i--)
        SSH_MP_LONG_DIV(t, rem, rem, r[i - 1], div);
      r[0] = rem;
      break;

      /* Other small cases? 2, 3, 4, ... would these speed things
         up in some particular cases. */
      
      /* General case, with very large divisors. */
    default:
      /* Reduce n such that n < d_n*b^(n_n - d_n). This step should be
         performed only once if everything goes nicely. */

      if (ssh_mpn_cmp(r + (r_n - d_n), d_n, d, d_n) >= 0)
        ssh_mpn_sub(r + (r_n - d_n), r + (r_n - d_n), d_n, d, d_n);

      for (i = r_n, div = d[d_n - 1], divl = d[d_n - 2]; i > d_n; i--)
        {
          rh = r[i - 1];
          rl = r[i - 2];
            
          if (i >= 3)
            rll = r[i - 3];
          else
            rll = 0;
          
          if (rh == div)
            quot = -1;
          else
            {
              /* See ssh_mpn_div for further comments. */
                 
              SSH_MP_LONG_DIV(quot, rem, rh, rl, div);
              SSH_MP_LONG_MUL(c2, c1,  quot, divl);
              
              while (c2 > rem || (c2 == rem && c1 > rll))
                {
                  quot--;
                  
                  rem += div;
                  if (rem < div)
                    break;

                  if (c1 < divl)
                    c2--;
                  c1 -= divl;
                }
            }

#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
          c = ssh_mpn_submul(r + i - d_n - 1, quot, d, d_n);
#else /* SSHMATH_ASSEMBLER_SUBROUTINES */
          
          /* Use assembler subroutine here if possible. */
          
          for (j = 0, c = 0, tmp = r + i - d_n - 1; j < d_n; j++)
            {
              SSH_MP_LONG_MUL(c2, c1, d[j], quot);

              c1 += c;
              if (c1 < c)
                c2++;
              c = c2;

              /* Now compute the actual word to place in appropriate place. */
              k = tmp[j];
              t = k - c1;
              if (t > k)
                c++;
              tmp[j] = t;
            }
#endif /* SSHMATH_ASSEMBLER_SUBROUTINES */

          /* Add if negative to make positive. */
          if (rh < c)
            ssh_mpn_add(r + (i - d_n - 1), r + (i - d_n - 1), d_n, d, d_n);
        }
      break;
    }
}

#if 0

/* These functions are not yet written, due they are of lesser importance.
   However, they are important in many applications, and should probably
   be included to future versions. */

/* XXX We implement these as special functions because we are after optimal
   speed. */

int ssh_mpn_mod_fermat(SshWord *r,
                       SshWord *op, int op_n,
                       SshWord n)
{
}

int ssh_mpn_mod_mersenne(SshWord *r,
                         SshWord *op, int op_n,
                         SshWord n)
{
}

int ssh_mpn_mod_special(SshWord *r,
                        SshWord *op, int op_n,
                        SshWord n, SshWord c,
                        Boolean sign)
{
}

/* The standard binary GCD. XXX */
void ssh_mpn_gcd(SshWord *gcd, unsigned int gcd_n,
                 SshWord *x,   unsigned int x_n,
                 SshWord *y,   unsigned int y_n)
{
  unsigned int g;
  /* Divide with two if both are even. */

  g = 0;
  while ((x[0] & 0x1) == 0 && (y[0] & 0x1) == 0)
    {
      ssh_mpn_shift_down_bits(x, x_n, 1);
      ssh_mpn_shift_down_bits(y, y_n, 1);
      g++;
    }
  
  while (ssh_mpn_cmp_ui(x, x_n, 0) != 0)
    {
      if (!(x[0] & 0x1))
        ssh_mpn_shift_down_bits(x, x_n, 1);
      if (!(y[0] & 0x1))
        ssh_mpn_shift_down_bits(y, y_n, 1);

      /* We want to compute:

         t = |x - y|/2

         and then set

         x = t

         or

         y = t, depending which is larger. */
         
      if (ssh_mpn_cmp(x, x_n, y, y_n) >= 0)
        {
          /* This was easy. */
          ssh_mpn_sub(x, x, x_n, y, y_n);
          ssh_mpn_shift_down_bits(x, x_n, 1);
        }
      else
        {
          /* Now the other way around. */
          ssh_mpn_sub(y, y, y_n, x, x_n);
          ssh_mpn_shift_down_bits(y, y_n, 1);
        }
    }
  
  /* Result is in y. Shift it up a bit. */
  while (g)
    {
      ssh_mpn_shift_up_bits(y, y_n, 1);
      g--;
    }

  /* Set to ret. */
  ssh_mpn_memcopy(gcd, y, y_n);
}

/* Fast inversion... */
void ssh_mpn_invert()
{
}

#endif

/********** Routines for handling variable length integers *****/

/* Routines for allocating and expanding SshInt's. */

SshInt *ssh_mp_malloc(void)
{
  SshInt *op;
  op = ssh_xmalloc(sizeof(*op));

  /* Initialize the SshInt. */
  op->m = 0;
  op->n = 0;
  op->sign = FALSE;
  op->v = NULL;
  return op;
}

void ssh_mp_free(SshInt *op)
{
  ssh_xfree(op->v);
  ssh_xfree(op);
}

void ssh_mp_realloc(SshInt *op, unsigned int new_size)
{
  if (new_size > op->m)
    {
      SshWord *nv;

      /* Allocate, copy and clear the rest. */
      nv = ssh_xmalloc((size_t)new_size * sizeof(SshWord));
      ssh_mpn_memcopy(nv, op->v, op->n);

      /* Free the old one. */
      ssh_xfree(op->v);

      /* Set the new one. */
      op->v = nv;
      op->m = new_size;
    }
}

/* Clear the upper (part which is not used) part of the
   integer. This allows us to sometimes use the integer's own
   data area for computations. */
void ssh_mp_clear_extra(SshInt *op)
{
  unsigned int i;
  for (i = op->n; i < op->m; i++)
    op->v[i] = 0;
}

/****************** The integer interface. ******************/

/* Initialize the integer. */
void ssh_mp_init(SshInt *op)
{
  op->m = 0;
  op->n = 0; 
  op->sign = 0;
  op->v = NULL;
}

/* Clear the integer up, free the space occupied, but don't free the
   integer context. */
void ssh_mp_clear(SshInt *op)
{
  ssh_xfree(op->v);
  op->n = 0;
  op->m = 0;
  op->sign = 0;
  op->v = NULL;
}

SshWord ssh_mp_get_ui(const SshInt *op)
{
  if (op->n == 0)
    return 0;
  return op->v[0];
}

SignedSshWord ssh_mp_get_si(const SshInt *op)
{
  SignedSshWord si;
  if (op->n == 0)
    return 0;
  /* Figure the bits that can be used. */
  si = (SignedSshWord)(op->v[0] & (SSH_WORD_MASK >> 1));
  if (op->sign)
    return -si;
  return si;
}

void ssh_mp_set(SshInt *ret, const SshInt *op)
{
  /* Check that pointers are not equal, in which case, anything more
     would be stupid. */
  if (ret == op)
    return;

  ssh_mp_realloc(ret, op->n);

  /* Copy */
  ssh_mpn_memcopy(ret->v, op->v, op->n);
  ret->n = op->n;
  SSH_MP_COPY_SIGN(ret, op);
}

void ssh_mp_set_ui(SshInt *op, SshWord n)
{
  if (n == 0)
    {
      op->n = 0;
      SSH_MP_NO_SIGN(op);
      return;
    }
  
  /* Check that we have enough space. */
  ssh_mp_realloc(op, 1);

  /* Set the integer. */
  op->v[0] = (SshWord)n;
  op->n = 1;
  SSH_MP_NO_SIGN(op);
}

void ssh_mp_set_si(SshInt *op, SignedSshWord n)
{
  if (n == 0)
    {
      op->n = 0;
      SSH_MP_NO_SIGN(op);
      return;
    }
  
  /* Check that we have enough space. */
  ssh_mp_realloc(op, 1);

  if (n < 0)
    {
      SSH_MP_SET_SIGN(op);
      n = -n;
    }
  else
    SSH_MP_NO_SIGN(op);
  /* Set the integer. */
  op->v[0] = (SshWord)n;
  op->n = 1;
}

/* Init and assign. */
void ssh_mp_init_set(SshInt *ret, const SshInt *op)
{
  ssh_mp_init(ret);
  ssh_mp_set(ret, op);
}

int ssh_mp_init_set_str(SshInt *ret, const char *str, unsigned int base)
{
  ssh_mp_init(ret);
  return ssh_mp_set_str(ret, str, base);
}

void ssh_mp_init_set_ui(SshInt *ret, SshWord u)
{
  ssh_mp_init(ret);
  ssh_mp_set_ui(ret, u);
}

void ssh_mp_init_set_si(SshInt *ret, SignedSshWord s)
{
  ssh_mp_init(ret);
  ssh_mp_set_si(ret, s);
}

/* Negate an integer. This is very easy operation. */
void ssh_mp_neg(SshInt *ret, const SshInt *op)
{
  ssh_mp_set(ret, op);
  if (ret->n)
    SSH_MP_XOR_SIGN(ret);
}

/* Get the absolute of an integer, basically a distance in Z. */
void ssh_mp_abs(SshInt *ret, const SshInt *op)
{
  ssh_mp_set(ret, op);
  SSH_MP_NO_SIGN(ret);
}

/* The sign of an integer. We follow here the standard practice of
   naming the function. However, some call it just sign, but in
   number theory I have read about it as signum. */
int ssh_mp_signum(const SshInt *op)
{
  if (SSH_MP_GET_SIGN(op))
    return -1;
  return 1;
}

/* These routines are written to be quick enough to be used in general.
   In some particular cases faster ways might be available. */

void ssh_mp_mul_2exp(SshInt *ret, const SshInt *op, unsigned int bits)
{
  unsigned int k, i;

  /* Check if no need to to anything. */
  if (op->n == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }

  if (bits == 0)
    {
      ssh_mp_set(ret, op);
      return;
    }
  
  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  /* Move from op to ret. */
  ssh_mp_set(ret, op);

  /* Allocate new space. */
  ssh_mp_realloc(ret, k + 1 + ret->n);
  
  /* Move words first. */
  if (k)
    {
      for (i = ret->n; i; i--)
        ret->v[i + k - 1] = ret->v[i - 1];
      for (i = 0; i < k; i++)
        ret->v[i] = 0;
    }

  /* Set the possible highest word to zero. */
  ret->v[k + ret->n] = 0;
  ssh_mpn_shift_up_bits(ret->v + k, ret->n + 1, bits);

  /* Compute the correct size. */
  ret->n = ret->n + k + 1;
  
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  /* Remember the sign thing. */
  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}
 
void ssh_mp_div_2exp(SshInt *ret, const SshInt *op, unsigned int bits)
{
  unsigned int k, i;

  /* Check sizes. */
  if (op->n == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }

  if (bits == 0)
    {
      ssh_mp_set(ret, op);
      return;
    }
  
  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  if (k > op->n)
    {
      ret->n = 0;
      return;
    }
  
  /* Move from op to ret. */
  ssh_mp_set(ret, op);
  
  /* Move down. */
  if (k)
    for (i = 0; i < ret->n - k; i++)
      ret->v[i] = ret->v[i + k];

  ssh_mpn_shift_down_bits(ret->v, ret->n - k, bits);

  /* Compute new size. */
  ret->n = ret->n - k;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

void ssh_mp_mod_2exp(SshInt *ret, const SshInt *op, unsigned int bits)
{
  unsigned int k;

  /* Check for trivial cases. */
  if (op->n == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }

  if (bits == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }
  
  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  /* Now copy to the ret. This might not be the optimal way but easy.  */
  ssh_mp_set(ret, op);

  /* Check yet one more trivial case. We might be done already. */
  if (ret->n < k)
    return;

  /* Now we have to do the very hard part. */
  ret->v[k] = (ret->v[k] & (((SshWord)1 << bits) - 1));
  
  /* Check sizes. */
  ret->n = k + 1;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Comparison function which use directly the ssh_mpn_* functions. */
int ssh_mp_cmp(const SshInt *op1, const SshInt *op2)
{
  /* Handle signs. */
  if (SSH_MP_GET_SIGN(op1) || SSH_MP_GET_SIGN(op2))
    {
      if (SSH_MP_GET_SIGN(op1) && !SSH_MP_GET_SIGN(op2))
        return -1;
      if (!SSH_MP_GET_SIGN(op1) && SSH_MP_GET_SIGN(op2))
        return 1;
    }
  return ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n);
}

int ssh_mp_cmp_ui(const SshInt *op, SshWord u)
{
  if (SSH_MP_GET_SIGN(op))
    return -1;
  return ssh_mpn_cmp_ui(op->v, op->n, u);
}

int ssh_mp_cmp_si(const SshInt *op, SignedSshWord s)
{
  if (SSH_MP_GET_SIGN(op) || (s < 0))
    {
      if (SSH_MP_GET_SIGN(op) && (s >= 0))
        return -1;
      if (!SSH_MP_GET_SIGN(op) && (s < 0))
        return 1;
      /* Make s positive. */
      if (s < 0)
        s = -s;
    }
  return ssh_mpn_cmp_ui(op->v, op->n, (SshWord)s);
}

/* Addition routine which handles signs. */

void ssh_mp_add(SshInt *ret, const SshInt *op1, const SshInt *op2)
{
  SshWord c;

  if (op1->n == 0)
    {
      ssh_mp_set(ret, op2);
      return;
    }

  if (op2->n == 0)
    {
      ssh_mp_set(ret, op1);
      return;
    }
    
  
  /* Make op1 > op2 in absolute value. Also enlarge ret so that the
     result fits into it. */

  if (op1->n < op2->n)
    {
      const SshInt *t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  if (op1->n + 1 > ret->n)
    ssh_mp_realloc(ret, op1->n + 1);
  
  /* Then figure out which case it really is. This idea of
     switching cames from my small floating point library that I
     wrote year ago. */

  switch ((SSH_MP_GET_SIGN(op1) << 1) + SSH_MP_GET_SIGN(op2))
    {
    case 0:
      c = ssh_mpn_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      SSH_MP_NO_SIGN(ret);
      break;
    case 1:
      if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpn_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_NO_SIGN(ret);
        }
      else
        {
          ssh_mpn_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_SET_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 2:
      if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpn_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_SET_SIGN(ret);
        }
      else
        {
          ssh_mpn_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_NO_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 3:
      c = ssh_mpn_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      SSH_MP_SET_SIGN(ret);
      break;
    }

  /* Following code should be place into either a macro or a function. */
  
  /* Correct the size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Subtraction routine which handles signs. */

void ssh_mp_sub(SshInt *ret, const SshInt *op1, const SshInt *op2)
{
  SshWord c;
  unsigned int signs;
  
  if (op2->n == 0)
    {
      ssh_mp_set(ret, op1);
      return;
    }

  if (op1->n == 0)
    {
      ssh_mp_neg(ret, op2);
      return;
    }
  
  /* Make op1 > op2 in absolute value. Also enlarge ret so that the
     result fits in it. */

  if (op1->n < op2->n)
    {
      const SshInt *t;

      t = op1;
      op1 = op2;
      op2 = t;

      signs = ((SSH_MP_GET_SIGN(op1) ^ 0x1) << 1) + SSH_MP_GET_SIGN(op2);
    }
  else
    signs = (SSH_MP_GET_SIGN(op1) << 1) + (SSH_MP_GET_SIGN(op2) ^ 0x1);
  
  if (op1->n + 1 > ret->n)
    ssh_mp_realloc(ret, op1->n + 1);
  
  /* Then figure out which case it really is. Note the difference between
     addition and subtraction. */

  switch (signs)
    {
    case 0:
      c = ssh_mpn_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      /* No sign for ret. */
      SSH_MP_NO_SIGN(ret);
      break;
    case 1:
      if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpn_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_NO_SIGN(ret);
        }
      else
        {
          ssh_mpn_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_SET_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 2:
      if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
        {
          ssh_mpn_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
          SSH_MP_SET_SIGN(ret);
        }
      else
        {
          ssh_mpn_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
          SSH_MP_NO_SIGN(ret);
        }
      ret->n = op1->n;
      break;
    case 3:
      c = ssh_mpn_add(ret->v, op1->v, op1->n, op2->v, op2->n);
      if (c)
        {
          ret->v[op1->n] = c;
          ret->n = op1->n + 1;
        }
      else
        ret->n = op1->n;
      SSH_MP_SET_SIGN(ret);
      break;
    }

  /* Following code should be place into either a macro or a function. */
  
  /* Correct the size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Addition of a SshInt and an SshWord. */
void ssh_mp_add_ui(SshInt *ret, const SshInt *op, SshWord u)
{
  SshWord c;

  if (op->n == 0)
    {
      ssh_mp_set_ui(ret, u);
      return;
    }
  
  ssh_mp_realloc(ret, op->n + 1);

  switch (SSH_MP_GET_SIGN(op))
    {
    case 0:
      c = ssh_mpn_add(ret->v, op->v, op->n, &u, 1);
      if (c)
        {
          ret->v[op->n] = c;
          ret->n = op->n + 1;
        }
      else
        ret->n = op->n;
      SSH_MP_NO_SIGN(ret);
      break;
    case 1:
      if (ssh_mpn_cmp_ui(op->v, op->n, u) > 0)
        {
          ssh_mpn_sub(ret->v, op->v, op->n, &u, 1);
          SSH_MP_SET_SIGN(ret);
        }
      else
        {
          ssh_mpn_sub(ret->v, &u, 1, op->v, op->n);
          SSH_MP_NO_SIGN(ret);
        }
      ret->n = op->n;
      break;
    }

  /* Check size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);
}

/* Subtraction of an unsigned integer from a SshInt. */
void ssh_mp_sub_ui(SshInt *ret, const SshInt *op, SshWord u)
{
  SshWord c;

  if (op->n == 0)
    {
      ssh_mp_set_ui(ret, u);
      return;
    }
  
  ssh_mp_realloc(ret, op->n + 1);

  switch (SSH_MP_GET_SIGN(op))
    {
    case 0:
      if (ssh_mpn_cmp_ui(op->v, op->n, u) > 0)
        {
          ssh_mpn_sub(ret->v, op->v, op->n, &u, 1);
          SSH_MP_NO_SIGN(ret);
        }
      else
        {
          ssh_mpn_sub(ret->v, &u, 1, op->v, op->n);
          SSH_MP_SET_SIGN(ret);
        }
      ret->n = op->n;
      break;
    case 1:
      c = ssh_mpn_add(ret->v, op->v, op->n, &u, 1);
      if (c)
        {
          ret->v[op->n] = c;
          ret->n = op->n + 1;
        }
      else
        ret->n = op->n;
      SSH_MP_SET_SIGN(ret);
      break;
    }

  /* Check size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  if (ret->n == 0)
    SSH_MP_NO_SIGN(ret);  
}

/* Multiplication routine (future work karatsuba and fft) */

void ssh_mp_mul(SshInt *ret, const SshInt *op1, const SshInt *op2)
{
  SshWord *temp;
  unsigned int temp_n;

  /* Check the inputs. */
  if (op1->n == 0 || op2->n == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }
  
  /* Allocate some temporary memory. */
  temp_n = op1->n + op2->n + 1;
  ssh_mp_realloc(ret, temp_n);

  if (op1->v == ret->v || op2->v == ret->v)
    temp = ssh_xmalloc(temp_n * sizeof(SshWord));
  else
    temp = ret->v;

  ssh_mpn_memzero(temp, temp_n);
  
  /* Do the multiplication. */
  ssh_mpn_mul_karatsuba(temp, temp_n, op1->v, op1->n, op2->v, op2->n,
                        NULL, 0);
  
  /* Check the exact length of the result. */

  while (temp_n && temp[temp_n - 1] == 0)
    temp_n--;

  /* Check the sign. */
  SSH_MP_XOR_SIGNS(ret, op1, op2);
  
  /* Finish by copying result to ret. */
  if (ret->v != temp)
    {
      ssh_mpn_memcopy(ret->v, temp, temp_n);
      ssh_xfree(temp);
    }
  
  ret->n = temp_n;
}

/* Multiplication routine (future work karatsuba and fft) */

void ssh_mp_square(SshInt *ret, const SshInt *op)
{
  SshWord *temp;
  unsigned int temp_n;

  /* Check the inputs. */
  if (op->n == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }
  
  /* Allocate some temporary memory. */
  temp_n = op->n * 2 + 2;
  ssh_mp_realloc(ret, temp_n);

  if (op->v == ret->v)
    temp = ssh_xmalloc(temp_n * sizeof(SshWord));
  else
    temp = ret->v;

  ssh_mpn_memzero(temp, temp_n);
  
  /* Do the multiplication. */
  ssh_mpn_square_karatsuba(temp, temp_n, op->v, op->n,
                           NULL, 0);

  /* Check the exact length of the result. */

  while (temp_n && temp[temp_n - 1] == 0)
    temp_n--;

  /* Squaring, thus no sign! */
  SSH_MP_NO_SIGN(ret);
  
  /* Finish by copying result to ret. */
  if (ret->v != temp)
    {
      ssh_mpn_memcopy(ret->v, temp, temp_n);
      ssh_xfree(temp);
    }
  
  ret->n = temp_n;
}

/* Division routine. Future work Newton reciprocal computation. */

void ssh_mp_div(SshInt *q, SshInt *r, const SshInt *op1, const SshInt *op2)
{
  SshWord *rem, *quot, *div;
  unsigned int rem_n, quot_n, bits;

  /* Check sizes first. */
  if (op1->n < op2->n)
    {
      ssh_mp_set_ui(q, 0);
      ssh_mp_set(r, op1);
      return;
    }

  if (op1->n == op2->n)
    {
      if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) < 0)
        {
          ssh_mp_set_ui(q, 0);
          ssh_mp_set(r, op1);
          return;
        }
    }
  
  rem_n = op1->n + 1;
  quot_n = op1->n - op2->n + 1;
  
  /* Do some reallocation. */
  ssh_mp_realloc(q, op1->n - op2->n + 1);
  ssh_mp_realloc(r, op2->n);

  /* Allocate temporary space. */
  rem  = ssh_xmalloc(sizeof(SshWord) * (rem_n + quot_n + op2->n));
  quot = rem + rem_n;
  div  = quot + quot_n; 

  /* Clear and copy. */
  ssh_mpn_memzero(quot, quot_n);
  ssh_mpn_memcopy(rem, op1->v, op1->n);
  rem[op1->n] = 0;

  /* Normalize, this can be optimized. XXX */
  ssh_mpn_memcopy(div, op2->v, op2->n);

  bits = ssh_mpn_leading_zeros(div, op2->n);
  ssh_mpn_shift_up_bits(div, op2->n, bits);
  ssh_mpn_shift_up_bits(rem, rem_n, bits);

  /* Certify the length. */
  if (rem[rem_n - 1] == 0)
    rem_n--;

  /* Do the division iteration. */
  ssh_mpn_div(quot, quot_n, rem, rem_n, div, op2->n);

  /* Quotient is immediately correct. However, remainder must be
     denormalized. */
  ssh_mpn_shift_down_bits(rem, op2->n, bits);

  /* Now set the quotient. */
  ssh_mpn_memcopy(q->v, quot, quot_n);
  q->n = quot_n;
  
  /* Set the remainder. */
  ssh_mpn_memcopy(r->v, rem, op2->n);
  r->n = op2->n;

  /* Figure out quotient sign. */
  SSH_MP_XOR_SIGNS(q, op1, op2);

  /* Check sizes. */
  while (q->n && q->v[q->n - 1] == 0)
    q->n--;

  while (r->n && r->v[r->n - 1] == 0)
    r->n--;

  /* Handle the sign of the remainder. */
  if (SSH_MP_GET_SIGN(op1))
    SSH_MP_SET_SIGN(r);
  else
    SSH_MP_NO_SIGN(r);

  /* Make sure that zeros are positive :) */
  if (r->n == 0)
    SSH_MP_NO_SIGN(r);
  if (q->n == 0)
    SSH_MP_NO_SIGN(q);

  /* Free temporary storage. */
  ssh_xfree(rem);
}

/* Compute the remainder i.e. op1 (mod op2). */
void ssh_mp_mod(SshInt *r, const SshInt *op1, const SshInt *op2)
{
  SshWord *rem, *div;
  unsigned int rem_n, bits, div_n;

  /* Check sizes first. */
  if (op1->n == 0)
    {
      ssh_mp_set_ui(r, 0);
      return;
    }

  if (op1->n < op2->n)
    {
      if (SSH_MP_GET_SIGN(op1))
        {
          ssh_mp_add(r, op2, op1);
          return;
        }
      ssh_mp_set(r, op1);
      return;
    }

  if (op1->n == op2->n)
    {
      if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) < 0)
        {
          if (SSH_MP_GET_SIGN(op1))
            {
              ssh_mp_add(r, op2, op1);
              return;
            }
          ssh_mp_set(r, op1);
          return;
        }
    }
  
  rem_n = op1->n + 1;
  div_n = op2->n;
  
  /* Do some reallocation. */
  ssh_mp_realloc(r, op2->n);

  /* Allocate temporary space. */
  rem  = ssh_xmalloc(sizeof(SshWord) * (rem_n + div_n));
  div  = rem + rem_n; 

  /* Clear and copy. */
  ssh_mpn_memcopy(rem, op1->v, op1->n);
  rem[op1->n] = 0;

  /* Normalize, this can be optimized. XXX */
  ssh_mpn_memcopy(div, op2->v, op2->n);

  bits = ssh_mpn_leading_zeros(div, op2->n);
  ssh_mpn_shift_up_bits(div, op2->n, bits);
  ssh_mpn_shift_up_bits(rem, rem_n, bits);

  /* Certify the length. */
  if (rem[rem_n - 1] == 0)
    rem_n--;

  /* Do the division iteration. */
  ssh_mpn_mod(rem, rem_n, div, op2->n);

  /* Quotient is immediately correct. However, remainder must be
     denormalized. */
  ssh_mpn_shift_down_bits(rem, op2->n, bits);

  /* Set the remainder. */
  ssh_mpn_memcopy(r->v, rem, op2->n);
  ssh_xfree(rem);
  
  /* Check sizes. */
  r->n = op2->n;
  while (r->n && r->v[r->n - 1] == 0)
    r->n--;
  
  /* Handle possible negative input here. */
  if (SSH_MP_GET_SIGN(op1))
    {
      ssh_mpn_sub(r->v, op2->v, op2->n, r->v, r->n);

      /* Check size again. */
      r->n = op2->n;
      while (r->n && r->v[r->n - 1] == 0)
        r->n--;
    }

  /* Remainder has no sign (it is always positive). */
  SSH_MP_NO_SIGN(r);
}

/* Extra routines for special numbers. */

void ssh_mp_mul_ui(SshInt *ret, const SshInt *op, SshWord u)
{
  SshWord *temp;
  unsigned int temp_n;
  
  if (u == 0 || op->n == 0)
    {
      ssh_mp_set_ui(ret, 0);
      return;
    }
  
  temp_n = op->n + 1;
  ssh_mp_realloc(ret, temp_n);
  
  if (op->v != ret->v)
    temp = ret->v;
  else
    temp = ssh_xmalloc(sizeof(SshWord) * temp_n);

  ssh_mpn_memzero(temp, temp_n);

  /* Multiply. */
  ssh_mpn_mul_ui(temp, temp_n, op->v, op->n, u);

  /* Finish the management. */
  if (temp != ret->v)
    {
      ssh_mpn_memcopy(ret->v, temp, temp_n);
      ssh_xfree(temp);
    }

  ret->n = temp_n;

  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;

  SSH_MP_COPY_SIGN(ret, op);
}

/* Just for compatibility with GMP. */
void ssh_mp_div_q(SshInt *q, const SshInt *op1, const SshInt *op2)
{
  SshInt t;
  ssh_mp_init(&t);
  ssh_mp_div(q, &t, op1, op2);
  ssh_mp_clear(&t);
}

SshWord ssh_mp_div_ui(SshInt *q, const SshInt *op, SshWord u)
{
  SshWord *temp, *norm, t, rem;
  unsigned int temp_n, r;
  
  if (u == 0)
    ssh_fatal("ssh_mp_div_ui: division by zero.");

  if (op->n == 0)
    {
      ssh_mp_set_ui(q, 0);
      return 0;
    }

  /* Figure out the normalization of 'u'. */
  t = u;
  r = 0;
  SSH_MP_COUNT_LEADING_ZEROS(r, t);
  t <<= r;

  /* Enlarge integers. */
  temp_n = op->n + 1;
  
  ssh_mp_realloc(q, temp_n);
  if (q->v != op->v)
    temp = q->v;
  else
    temp = ssh_xmalloc(sizeof(SshWord) * temp_n);

  /* Normalize. */
  norm = ssh_xmalloc(sizeof(SshWord) * (op->n + 1));
  ssh_mpn_memcopy(norm, op->v, op->n);
  norm[op->n] = 0;
  
  ssh_mpn_shift_up_bits(norm, op->n + 1, r);
  
  rem = ssh_mpn_div_ui(temp, temp_n, norm, op->n + 1, t);

  ssh_xfree(norm);
  
  /* Correct remainder. */
  rem >>= r;

  /* Quotient is correct. */
  if (temp != q->v)
    {
      ssh_mpn_memcopy(q->v, temp, temp_n);
      ssh_xfree(temp);
    }

  /* Set the size. */
  q->n = temp_n;

  while (q->n && q->v[q->n - 1] == 0)
    q->n--;

  if (q->n == 0)
    SSH_MP_NO_SIGN(q);
      
  return rem;
}

SshWord ssh_mp_mod_ui(const SshInt *op, SshWord u)
{
  SshWord *norm, rem, t;
  unsigned int r;
  
  if (u == 0)
    ssh_fatal("ssh_mp_div_ui: division by zero.");

  if (op->n == 0)
    return 0;

  /* Handle the normalization of 'u'. */
  t = u;
  r = 0;
  SSH_MP_COUNT_LEADING_ZEROS(r, t);
  t <<= r;

  /* Allocate and normalize. */
  norm = ssh_xmalloc(sizeof(SshWord) * (op->n + 1));
  ssh_mpn_memcopy(norm, op->v, op->n);
  norm[op->n] = 0;
  
  ssh_mpn_shift_up_bits(norm, op->n + 1, r);
  rem = ssh_mpn_mod_ui(norm, op->n + 1, t);
  ssh_xfree(norm);
  
  /* Correct remainder. */
  rem >>= r;

  return rem;
}

/* GMP like interface to mod_ui. Just for compatibility. */
SshWord ssh_mp_mod_ui2(SshInt *ret, const SshInt *op, SshWord u)
{
  SshWord t;
  t = ssh_mp_mod_ui(op, u);
  ssh_mp_set_ui(ret, t);
  return t;
}
     
#if 1
/* Useful but messy dump function for integers. Can be used for
   debugging, but probably will be removed later. */
void ssh_mp_dump(const SshInt *op)
{
  int i;
  printf("op: size = %u, allocated = %u, sign = %08x, words = \n",
         op->n, op->m, op->sign);
  printf("  ");
  for (i = op->n; i; i--)
    {
#if SIZEOF_LONG==4
      printf("%08lx ", op->v[i - 1]);
#else
      printf("%16lx ", op->v[i - 1]);
#endif /* SIZEOF_LONG==4 */
    }
  printf("\n");
  printf("  (0 ");
  for (i = op->n; i; i--)
    {
      printf("+ %lu*2^%u ", (unsigned long)op->v[i - 1],
             sizeof(unsigned long)*8*(i - 1));
    }
  printf(")\n");
#if 0
  {
    SshInt temp;
    
    /* Use this only if you know that division by small integer works. */
    printf("backwards: ");
    ssh_mp_init(&temp);
    ssh_mp_set(&temp, op);
    while (ssh_mp_cmp_ui(&temp, 0) != 0)
      {
        printf("%lu", ssh_mp_div_ui(&temp, &temp, 10));
      }
    printf("\n");
  }
#endif
}
#else /* dump */
void ssh_mp_dump(const SshInt *op)
{
  /* Do nothing. */
}
#endif

/* Miscellaneous, these will be useful later. */

/* Get a bit at position 'bit'. Returns thus either 1 or 0. */
unsigned int ssh_mp_get_bit(const SshInt *op, unsigned int bit)
{
  unsigned int i;
  
  if (op->n == 0)
    return 0;

  /* Find out the amount of words. */
  i = bit / SSH_WORD_BITS;
  bit %= SSH_WORD_BITS;

  /* Too large. */
  if (i >= op->n)
    return 0;

  return (op->v[i] >> bit) & 0x1;
}

/* Compatibility with GMP, don't use for anything other. These are
   slow. */
unsigned int ssh_mp_scan0(const SshInt *op, unsigned int bit)
{
  while (ssh_mp_get_bit(op, bit) == 1)
    bit++;
  return bit;
}

unsigned int ssh_mp_scan1(const SshInt *op, unsigned int bit)
{
  while (ssh_mp_get_bit(op, bit) == 0)
    bit++;
  return bit;
}

/* Set a bit at position 'bit'. */
void ssh_mp_set_bit(SshInt *op, unsigned int bit)
{
  unsigned int i;
  
  /* Find out the amount of words. */
  i = bit / SSH_WORD_BITS;
  bit %= SSH_WORD_BITS;

  /* Allocate some new space and clear the extra space. */
  ssh_mp_realloc(op, i + 1);
  ssh_mp_clear_extra(op);

  op->v[i] |= ((SshWord)1 << bit);

  if (op->n < i + 1)
    op->n = i + 1;
}

/* Clear a bit at position 'bit'. */
void ssh_mp_crl_bit(SshInt *op, unsigned int bit)
{
  unsigned int i;
  
  /* Find out the amount of words. */
  i = bit / SSH_WORD_BITS;
  bit %= SSH_WORD_BITS;

  /* Allocate some new space and clear the extra space. */
  ssh_mp_realloc(op, i + 1);
  ssh_mp_clear_extra(op);

  op->v[i] &= (~((SshWord)1 << bit));

  if (op->n < i + 1)
    op->n = i + 1;
}

/* Compute the size of integer 'op' in base 'base'. Slow in many cases,
   but fast in base 2.  */
unsigned int ssh_mp_get_size(const SshInt *op, SshWord base)
{
  unsigned int digits;
  SshInt temp;
  
  switch (base)
    {
    case 0:
    case 1:
      return 0;
    case 2:
      /* Exact bit size quickly. */
      return ssh_mpn_size_in_bits(op->v, op->n);
    default:
      /* XXX Use division to divide to the base. Clearly this is slow, but
         this will be used only rarely. */
      ssh_mp_init(&temp);
      ssh_mp_set(&temp, op);
      if (ssh_mp_cmp_ui(&temp, 0) < 0)
        ssh_mp_neg(&temp, &temp);
      for (digits = 0; temp.n; digits++)
        ssh_mp_div_ui(&temp, &temp, base);
      ssh_mp_clear(&temp);
      return digits;
    }
}

/* Print routine. */

/* These are useful for hex and less bases. */
const unsigned char ssh_mp_int_to_char[16] =
{ "0123456789abcdef" };

const unsigned char ssh_mp_char_to_int[128] =
{
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255,  62, 255, 255, 255,  63, 
    0,   1,   2,   3,   4,   5,   6,   7,
    8,   9, 255, 255, 255, 255, 255, 255, 
  255,  10,  11,  12,  13,  14,  15, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255,  10,  11,  12,  13,  14,  15, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
};

/* These are useful for bases upto hexes, that is most
   importantly base 64. */
const unsigned char ssh_mp_int_to_base64[64] =
{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };

const unsigned char ssh_mp_base64_to_int[128] =
{
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 
  255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255,  62, 255, 255, 255,  63, 
   52,  53,  54,  55,  56,  57,  58,  59,
   60,  61, 255, 255, 255, 255, 255, 255, 
  255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14, 
   15,  16,  17,  18,  19,  20,  21,  22,
   23,  24,  25, 255, 255, 255, 255, 255, 
  255,  26,  27,  28,  29,  30,  31,  32,
   33,  34,  35,  36,  37,  38,  39,  40, 
   41,  42,  43,  44,  45,  46,  47,  48,
   49,  50,  51, 255, 255, 255, 255, 255,
};

/* Transform the integer into a string format in base 'base'. */
char *ssh_mp_get_str(char *ret_str, SshWord base, const SshInt *op)
{
  SshInt temp;
  unsigned int digits, real_digits, i, j, l;
  SshWord k, d; 
  char *str;
  const unsigned char *table;
  Boolean sign = FALSE;

  /* Cannot handle larger than base 64 numbers nor smaller than 2. */
  if (base > 64 || base < 2)
    return NULL;

  if (base <= 16)
    table = ssh_mp_int_to_char;
  else
    table = ssh_mp_int_to_base64;
  
  if (ssh_mp_cmp_ui(op, 0) == 0)
    {
      if (ret_str == NULL)
        str = ssh_xmalloc(2);
      else
        str = ret_str;

      if (base <= 16)
        {
          str[0] = '0';
          str[1] = '\0';
        }
      else
        {
          str[0] = 'A';
          str[1] = '\0';
        }
      return str;
    }
  
  ssh_mp_init(&temp);
  ssh_mp_set(&temp, op);

  real_digits = digits = ssh_mp_get_size(op, base);

  if (ssh_mp_cmp_ui(&temp, 0) < 0)
    {
      digits++;
      sign = TRUE;
      ssh_mp_neg(&temp, &temp);
    }

  switch (base)
    {
    case 8:
      digits++;
      break;
    case 16:
      digits += 2;
      break;
    case 64:
      digits++;
      break;
    default:
      break;
    }
  
  if (ret_str == NULL)
    str = ssh_xmalloc(digits + 1);
  else
    str = ret_str;

  /* This is a very slow way to compute. We should atleast optimize this
     to take care of cases when base = 2^n. */

  for (j = 1, d = base; ;
       d = k, j++)
    {
      k = d * base;
      if (k / base != d)
        break;
    }
  
  for (i = 0; i < real_digits && temp.n; i += j)
    {
      k = ssh_mp_div_ui(&temp, &temp, d);
      
      if (j + i > real_digits)
        j = real_digits - i;
      
      for (l = 0; l < j; l++)
        {
          str[(digits - (1 + i + l))] = table[k % base];
          k /= base;
        }
    }
  
  ssh_mp_clear(&temp);

  /* Set the beginning to indicate the sign and base. */
  i = 0;
  if (sign)
    {
      str[0] = '-';
      i = 1;
    }

  switch (base)
    {
    case 8:
      str[i] = '0';
      break;
    case 16:
      str[i] = '0';
      str[i + 1] = 'x';
      break;
    case 64:
      str[i] = '#';
      break;
    default:
      break;
    }

  str[digits] = '\0';
  return str;
}

/* Convert a string into an integer in base 'base'. */
int ssh_mp_set_str(SshInt *op, const char *str, SshWord base)
{
  size_t size = strlen(str);
  size_t i;
  const unsigned char *table;
  Boolean sign = FALSE;
  SshWord k, d, s;
  unsigned int j, l;

  /* Init with zero. */
  ssh_mp_set_ui(op, 0);

  /* Skip leading whitespace and signs. */
  for (i = 0; i < size; i++)
    {
      switch (str[i])
        {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
          break;
        case '-':
          if (!sign)
            {
              sign = TRUE;
              break;
            }
          return 0;
          break;
        case '0':
          /* Either base 8 or base 16. */
          if (tolower(str[i + 1]) == 'x')
            {
              /* Base-16. */
              if (base == 16 || base == 0)
                {
                  table = ssh_mp_char_to_int;
                  base = 16;
                  i += 2;
                  goto read_number;
                }
            }
          if (isdigit(str[i + 1]))
            {
              /* Base-8 */
              if (base == 8 || base == 0)
                {
                  table = ssh_mp_char_to_int;
                  base = 8;
                  i++;
                  goto read_number;
                }
            }
          if (base == 0)
            return 0;
          if (base <= 16)
            table = ssh_mp_char_to_int;
          else
            table = ssh_mp_base64_to_int;
          goto read_number;
          break;
        case '#':
          /* Base-64. */
          if (base == 64 || base == 0)
            {
              table = ssh_mp_base64_to_int;
              base = 64;
              i++;
              goto read_number;
            }
          return 0;
          break;
        default:
          /* Any base or base-10 */
          if (base == 0)
            base = 10;
          if (base <= 16)
            table = ssh_mp_char_to_int;
          else
            table = ssh_mp_base64_to_int;
          goto read_number;
          break;
        }
    }

  /* No number to read. */
  return 0;

read_number:

  /* Generate large divisor. */
  for (j = 1, d = base;;
       d = k, j++)
    {
      k = d * base;
      if ((k / base) != d)
        break;
    }
  
  /* Loop through the string. */
  for (l = 0, k = 0; i <= size; i++)
    {
      switch (str[i])
        {
        case '\t':
        case ' ':
        case '\n':
          continue;
        }
          
      s = table[(unsigned char)(str[i] & 127)];
      if (s == 255)
        break;
      if (s >= base)
        break;
      
      k *= base;
      k += s;

      l++;
      if (l == j)
        {
          ssh_mp_mul_ui(op, op, d);
          ssh_mp_add_ui(op, op, k);
          l = 0;
          k = 0;
        }
    }

  /* Finish it off. */
  if (l)
    {
      for (i = 1, d = base; i < l; i++)
        d *= base;

      ssh_mp_mul_ui(op, op, d);
      ssh_mp_add_ui(op, op, k);
    }
  
  if (sign)
    ssh_mp_neg(op, op);

  /* Return the number of limbs used. */
  return 1;
}

#if 1
/* Out integer to a stream. */
void ssh_mp_out_str(FILE *fp, unsigned int base, const SshInt *op)
{
  char *str;

  str = ssh_mp_get_str(NULL, base, op);
  if (fp == NULL)
    fputs(str, stdout);
  else
    fputs(str, fp);
  ssh_xfree(str);
}
#endif

/* Quick and dirty implementations of buffer routines.
   TODO: write optimized versions of these. */

/* Make a buffer. */
void ssh_mp_get_buf(unsigned char *buf, size_t buf_length,
                    const SshInt *op)
{
  int i;
  SshInt t;

  /* Run through byte at a time, this is not very optimal. */
  ssh_mp_init_set(&t, op);
  for (i = 0; i < buf_length; i++)
    {
      buf[buf_length - 1 - i] = (ssh_mp_get_ui(&t) & 0xff);
      ssh_mp_div_2exp(&t, &t, 8);
    }
  ssh_mp_clear(&t);
}

/* Make an integer out of a buffer. */
void ssh_mp_set_buf(SshInt *ret, const unsigned char *buf,
                    size_t buf_length)
{
  int i;
  /* Run through a byte at a time. Not very optimal. */
  ssh_mp_set_ui(ret, 0);
  for (i = 0; i < buf_length; i++)
    {
      ssh_mp_mul_2exp(ret, ret, 8);
      ssh_mp_add_ui(ret, ret, buf[i]);
    }
}

/* Random number routines. */

/* Our own reasonably well balanced random number generator based on the
   enhanced random number generator around Unix systems. */
SshWord ssh_mp_word_rand(void)
{
  unsigned int i;
  SshWord v;
  /* Fill up the SshWord! Assume that the lowest 16 bits have the most
     random quality (although in general random() does a good job for
     all bits, except perhaps the highest). */
  for (i = 0, v = 0; i < SSH_WORD_BITS; i += 16)
    v ^= ((SshWord)random()) << i; 
  
  return v;
}

/* 'Find' a random number of 'bits' bits. */
void ssh_mp_rand(SshInt *op, unsigned int bits)
{
  unsigned int i, k;

  /* Compute the word and bit positions. */
  k = bits / SSH_WORD_BITS;
  bits %= SSH_WORD_BITS;

  ssh_mp_realloc(op, k + 1);

  /* Generate enough random bits. */
  for (i = 0; i < k + 1; i++)
    op->v[i] = ssh_mp_word_rand();

  /* Don't do any shifting? */
  if (bits == 0)
    {
      op->n = k;
      while (op->n && op->v[op->n - 1] == 0)
        op->n--;
      SSH_MP_NO_SIGN(op);
      return;
    }

  /* Trivial shifting, masking... */
  op->v[k] = op->v[k] & (((SshWord)1 << bits) - 1);
  op->n = k + 1;

  while (op->n && op->v[op->n - 1] == 0)
    op->n--;
  SSH_MP_NO_SIGN(op);
}

/* Slow but allows one to build either very sparse (in 2-adic sense :) or
   very dense random numbers. */
void ssh_mp_rand_w(SshInt *op, unsigned int bits, unsigned int weigth)
{
  unsigned int i, j;
  SshWord k, n0, n1;

  /* Clear the number before anything else. */
  ssh_mp_set_ui(op, 0);
  ssh_mp_clear_extra(op);
  
  /* We need some kind of an algorithm, which reasonably well builds
     sparse random numbers. They should be almost uniformly
     distributed. */

  /* One easy algorithm is to consider the probability that a bit is
     set, denoted by p = weigth/bits. However, we cannot work with
     floats so we have to do some tricks. */

  for (i = 0, j = 0; i < bits; i++)
    {
      /* Get a value from 0 <= k < 2^32. */
      k = ssh_mp_word_rand();

      /* Convert k to comparable value. */

      SSH_MP_LONG_MUL(n1, n0, k, (SshWord)bits);
      if (n1 <= (SshWord)weigth)
        ssh_mp_set_bit(op, i);
    }
}

/* Slow, but so simple to write that I had to do it. */
void ssh_mp_pow(SshInt *ret, const SshInt *g, const SshInt *e)
{
  SshInt temp;
  unsigned int bits, i;

  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_set(ret, g);
      return;
    }
  
  ssh_mp_init(&temp);
  ssh_mp_set(&temp, g);

  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);
  
  for (i = bits - 1; i; i--)
    {
      ssh_mp_square(&temp, &temp);
      if (ssh_mp_get_bit(e, i - 1))
        ssh_mp_mul(&temp, &temp, g);
    }

  ssh_mp_set(ret, &temp);
  ssh_mp_clear(&temp);
}

/* XXX Write optimized binary versions of the next two routines. That is,
   implement the binary gcd routines. They are reasonably simple, but
   I don't think they will be much faster thus it's easier to get
   along with these. */

/* Naive versions of these routines, which are fairly rarely used. */
void ssh_mp_gcd(SshInt *d, const SshInt *a, const SshInt *b)
{
  SshInt a0, b0, r;

  ssh_mp_init(&a0);
  ssh_mp_init(&b0);
  ssh_mp_init(&r);

  ssh_mp_set(&a0, a);
  ssh_mp_set(&b0, b);

  /* Standard gcd, however, we should implemented much faster ways also. */
  while (ssh_mp_cmp_ui(&b0, 0) != 0)
    {
      ssh_mp_mod(&r, &a0, &b0);
      ssh_mp_set(&a0, &b0);
      ssh_mp_set(&b0, &r);
    }

  ssh_mp_set(d, &a0);
  
  ssh_mp_clear(&a0);
  ssh_mp_clear(&b0);
  ssh_mp_clear(&r);
}

/* Compute (d, u, v) given (a, b) such that au + bv = d. */
void ssh_mp_gcdext(SshInt *d, SshInt *u, SshInt *v,
                   const SshInt *a, const SshInt *b)
{
  SshInt v1, v3, t1, t3, d0, u0, x;

  if (ssh_mp_cmp_ui(b, 0) == 0)
    {
      ssh_mp_set(d, a);
      ssh_mp_set_ui(v, 0);
      ssh_mp_set_ui(u, 1);
    }
  
  ssh_mp_init(&v1);
  ssh_mp_init(&v3);
  ssh_mp_init(&t1);
  ssh_mp_init(&t3);
  ssh_mp_init(&u0);
  ssh_mp_init(&d0);
  ssh_mp_init(&x);
  
  ssh_mp_set_ui(&u0, 1);
  ssh_mp_set(&d0, a);
  ssh_mp_set_ui(&v1, 0);
  ssh_mp_set(&v3, b);

  /* Check for zero value using the internal size, which is bit ugly. */
  while (v3.n != 0)
    {
      /* Standard extended GCD algorithm inner loop. See for example
         Cohen's book. */
      ssh_mp_div(&x, &t3, &d0, &v3);
      ssh_mp_mul(&t1, &x, &v1);
      ssh_mp_sub(&t1, &u0, &t1);
      ssh_mp_set(&u0, &v1);
      ssh_mp_set(&d0, &v3);
      ssh_mp_set(&v1, &t1);
      ssh_mp_set(&v3, &t3);
    }

  /* Compute v. */
  ssh_mp_mul(&t1, a, &u0);
  ssh_mp_sub(&t1, &d0, &t1);
  ssh_mp_div(&v1, &v3, &t1, b);
  
  ssh_mp_set(d, &d0);
  ssh_mp_set(u, &u0);
  ssh_mp_set(v, &v1);

  ssh_mp_clear(&v1);
  ssh_mp_clear(&v3);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t3);
  ssh_mp_clear(&d0);
  ssh_mp_clear(&u0);
  ssh_mp_clear(&x);
}

/* Inversion routine, slow one, but fast enough. In particalar, we could
   write a specialized routine for this along the binary extended GCD
   or other variations. But the point is how often do we need this? Not
   very. */
Boolean ssh_mp_invert(SshInt *inv, const SshInt *op, const SshInt *m)
{
  SshInt g, v, t;
  Boolean rv = TRUE;
  
  ssh_mp_init(&g);
  ssh_mp_init(&v);
  ssh_mp_init(&t);

  /* Make sure that the input will lead to correct answer. */
  if (ssh_mp_cmp_ui(op, 0) < 0)
    ssh_mp_mod(&t, op, m);
  else
    ssh_mp_set(&t, op);

  /* Compute with extented euclidean algorithm. */
  ssh_mp_gcdext(&g, inv, &v, &t, m);

  /* Now, did we succeed? */
  if (ssh_mp_cmp_ui(&g, 1) != 0)
    rv = FALSE;

  /* If we did, we don't want to return negative values. */
  if (rv == TRUE)
    {
      /* Return only values which are positive. */
      if (ssh_mp_cmp_ui(inv, 0) < 0)
        ssh_mp_add(inv, inv, m);
    }
  
  ssh_mp_clear(&g);
  ssh_mp_clear(&v);
  ssh_mp_clear(&t);
  
  return rv;
}

/* We follow here Henri Cohen's naming. All ideas in this function are
   basically standard, but optimizations are all from Cohen's book. */
int ssh_mp_kronecker(const SshInt *a, const SshInt *b)
{
  int tab2[8] = { 0, 1, 0, -1, 0, -1, 0, 1};
  int v, k;
  SshInt b0, a0, r;
  
  /* The initial test. */
  if (ssh_mp_cmp_ui(b, 0) == 0)
    {
      ssh_mp_init(&a0);
      ssh_mp_abs(&a0, a);
      if (ssh_mp_cmp_ui(&a0, 1) != 0)
        {
          ssh_mp_clear(&a0);
          return 0;
        }
      ssh_mp_clear(&a0);
      return 1;
    }

  /* Check if both a and b are even. */
  if ((ssh_mp_get_ui(b) & 0x1) == 0 &&
      (ssh_mp_get_ui(a) & 0x1) == 0)
    return 0;

  ssh_mp_init(&b0);
  ssh_mp_init(&a0);
  ssh_mp_init(&r);
  
  ssh_mp_set(&b0, b);
  ssh_mp_set(&a0, a);

  /* Removal of 2's from b. */
  v = 0;
  while ((ssh_mp_get_ui(&b0) & 0x1) == 0)
    {
      ssh_mp_div_2exp(&b0, &b0, 1);
      v++;
    }

  /* Alter the k accordingly. */
  if ((v & 0x1) == 0)
    k = 1;
  else
    k = tab2[ssh_mp_get_ui(&a0) & 0x7];

  /* Handle negative values. */
  if (ssh_mp_cmp_ui(&b0, 0) < 0)
    {
      ssh_mp_neg(&b0, &b0);
      if (ssh_mp_cmp_ui(&a0, 0) < 0)
        k = -k;
    }

  /* Loop until done. */
  while (ssh_mp_cmp_ui(&a0, 0) != 0)
    {
      /* This loop could be optimized significantly. */
      v = 0;
      while ((ssh_mp_get_ui(&a0) & 0x1) == 0)
        {
          ssh_mp_div_2exp(&a0, &a0, 1);
          v++;
        }

      if (v & 0x1)
        {
          /* This is crude, but works. */
          if (k < 0)
            k = -tab2[ssh_mp_get_ui(&b0) & 0x7];
          else
            k = tab2[ssh_mp_get_ui(&b0) & 0x7];
        }

      /* This is a funny invention by Cohen. The quadratic reciprocity
         in very simplicity. */
      if (ssh_mp_get_ui(&b0) & ssh_mp_get_ui(&a0) & 0x2)
        k = -k;

      ssh_mp_abs(&r, &a0);
      ssh_mp_mod(&a0, &b0, &r);
      ssh_mp_set(&b0, &r);
    }

  if (ssh_mp_cmp_ui(&b0, 1) > 0)
    k = 0;
  
  ssh_mp_clear(&a0);
  ssh_mp_clear(&b0);
  ssh_mp_clear(&r);

  return k;
}

int ssh_mp_jacobi(const SshInt *op1, const SshInt *op2)
{
  return ssh_mp_kronecker(op1, op2);
}

/* We can actually compute Legendre symbol faster with Jacobi's symbol
   and with the known rules. */
int ssh_mp_legendre(const SshInt *op1, const SshInt *op2)
{
  return ssh_mp_kronecker(op1, op2);
}

/* Simple, but hopefully reasonably efficient. This is almost directly
   from Cohen's book. Improve if more speed is needed, one could open
   things up a bit, but this seems reasonably efficient. */
void ssh_mp_sqrt(SshInt *sqrt_out, const SshInt *op)
{
  SshInt x, y, r, t;
  int bits;

  /* Check impossible cases. */
  if (ssh_mp_cmp_ui(op, 0) <= 0)
    {
      /* Should we terminate? Perhaps we return the integer part of this
         operation. */
      ssh_mp_set_ui(sqrt_out, 0);
      return;
    }
  
  ssh_mp_init(&x);
  ssh_mp_init(&y);
  ssh_mp_init(&r);
  ssh_mp_init(&t);

  /* Find a nice estimate for n. */
  bits = ssh_mpn_size_in_bits(op->v, op->n);

  /* This should be fairly correct estimate. */
  ssh_mp_set_bit(&x, (bits + 2)/2);
  
  /* Loop until a nice value found. */
  while (1)
    {
      /* Compute the newtonian step. */
      ssh_mp_div(&t, &r, op, &x);
      ssh_mp_add(&t, &t, &x);
      ssh_mp_div_2exp(&y, &t, 1);
      
      if (ssh_mp_cmp(&y, &x) < 0)
        ssh_mp_set(&x, &y);
      else
        break;
    }

  /* Finished. */
  ssh_mp_set(sqrt_out, &x);
  
  ssh_mp_clear(&x);
  ssh_mp_clear(&y);
  ssh_mp_clear(&r);
  ssh_mp_clear(&t);
}

/* Montgomery routines. */

/* Montgomery representation routines. */

/* Compute x*R^-1 (mod M), that is reduce in Montgomery representation.
   This algorithm is basically from HAC. */
void ssh_mpmn_reduce(SshWord *ret, unsigned int ret_n,
                     SshWord *op,  unsigned int op_n,
                     SshWord mp,
                     SshWord *m,   unsigned int m_n)
{
  unsigned int i;
  SshWord high_carry;
#ifndef SSHMATH_ASSEMBLER_SUBROUTINES
  unsigned int j;
  SshWord t, u, a2, a1, c;
#endif
  
  ssh_mpn_memcopy(ret, op, op_n);
  
  for (high_carry = 0, i = 0; i < m_n; i++)
    {
#ifdef SSHMATH_ASSEMBLER_SUBROUTINES
      high_carry = ssh_mpmn_addmul(ret + i, mp, m, m_n, high_carry);
#else
      SSH_MP_LONG_MUL(t, u, ret[i], mp);
      for (j = 0, c = 0; j < m_n; j++)
        {
          SSH_MP_LONG_MUL(a2, a1, u, m[j]);

          /* Add the carry. */
          a1 += c;
          if (a1 < c)
            a2++;
          c = a2;

          /* Add to the result. */
          t = ret[j + i] + a1;
          if (t < a1)
            c++;
          ret[j + i] = t;
        }
      c = c + high_carry;
      if (c < high_carry)
        high_carry = 1;
      else
        high_carry = 0;
      t = ret[j + i] + c;
      if (t < c)
        high_carry++;
      ret[j + i] = t;
#endif
    }

  /* Remove this shift down later. */
  for (i = 0; i < m_n; i++)
    ret[i] = ret[i + m_n];
  
  if (high_carry)
    {
      ret[m_n] = high_carry;
      ret_n = m_n + 1;
    }
  else
    {
      ret_n = m_n;
      while (ret_n && ret[ret_n - 1] == 0)
        ret_n--;
    }

  if (ssh_mpn_cmp(ret, ret_n, m, m_n) >= 0)
    ssh_mpn_sub(ret, ret, ret_n, m, m_n);
}

#if 0
/* Coarsely integrated operand scanning as described by Kaliski et al.
   However, we don't use this because it's faster to multiply with
   karatsuba when values are reasonably large. And with smaller values
   it really doesn't matter anyway, anymore.

   NOTE: with elliptic curves there might be slight speed difference
   noticeable, however, it would not probably be that much we should
   be implementing this for some lengths.

   Do not use, this is just for reference, and has not been tested. And
   probably never will, because this will NOT be fast(er) for large
   inputs.

   XXX Do not try this, has NEVER been tested.
   */
void ssh_mpmn_mul(SshWord *ret, SshWord ret_n,
                  SshWord *op1, SshWord op1_n,
                  SshWord *op2, SshWord op2_n,
                  SshWord mp,
                  SshWord *m,   SshWord m_n)
{
  SshWord i, j, k, t, u, c, a1, a2;

  for (i = 0; i < m_n; i++)
    {
      for (j = 0, c = 0, k = op1[i]; j < m_n; j++)
        {
          SSH_MP_LONG_MUL(a2, a1, k, op2[i]);

          /* Add carry. */
          a1 += c;
          if (a1 < c)
            a2++;
          c = a2;

          /* Add to ret. */
          t = ret[j] + a1;
          if (t < a1)
            c++;
          ret[j] = t;
        }
      t = ret[m_n] + c;
      if (t < c)
        ret[m_n + 1] = 1;
      else
        ret[m_n + 1] = 0;
      ret[m_n] = t;

      k = ret[0];
      SSH_MP_LONG_MUL(t, u, k, mp);

      /* Multiply and add */
      SSH_MP_LONG_MUL(a2, a1, u, m[0]);

      t = a1 + ret[0];
      if (t < a1)
        a2++;
      c = a2;
      
      for (j = 1; j < m_n; j++)
        {
          SSH_MP_LONG_MUL(a2, a1, u, m[j]);

          a1 += c;
          if (a1 < c)
            a2++;
          c = a2;

          t = a2 + ret[j];
          if (t < a2)
            c++;
          ret[j - 1] = t;
        }
      t = ret[m_n] + c;
      if (t < c)
        c = 1;
      else
        c = 0;
      ret[m_n - 1] = t;
      ret[m_n] = ret[m_n + 1] + c;
    }
}
#endif

/* Compute x^-1 == a (mod 2^SSH_WORD_BITS). Please, use the Newton
   iteration method. It is fastest and easily proven to be correct. */

#if 0
/* NOTE: this implementation is for testing only. */
SshWord ssh_mpmn_small_inv(SshWord a)
{
  SshWord t, ignore, k;

  /* It gets too complicated to implement extended euclidean
     algorithm, so we just exponentiate. That is, we all know from
     basic algebra that

     phi(2^n) = (2^n - 2^(n - 1))

     then with Fermat's theorem we get

     a^-1 = a^(phi(2^n) - 1) (mod 2^n)

     Clearly this is a very slow algorithm. Taking time for each of those
     multiplications of which there shall be 2*(n - 1) - 1.
     */

  t = a;
  k = SSH_WORD_BITS - 1;
  while (k)
    {
      SSH_MP_LONG_MUL(ignore, t, t, t);
      SSH_MP_LONG_MUL(ignore, t, t, a);
      k--;
    }
  return t;
}
#else
SshWord ssh_mpmn_small_inv(SshWord a)
{
  SshWord ignore, t, k;

  /* Using the standard Newton's iteration. This should be significantly
     faster than the above.

     Why does this work, you ask. Well, I was amazed too, but it does. And
     very amazingly fast. Colin Plumb was the first I have seen using
     this, although, there probably are others. The proof for the success
     of this can be easily seen by considering the error which _grows_
     in each iteration leaving the least significant bits correct.
     It can easily be seen that this is quadratically convergent.

     Exercise: Prove that this sequence (x_n+1 = x_n*(2 - a*x_n) (mod 2^k))
               converges quadratically, iff a == a^-1 (mod 2).
     Hint:     Follow the steps

               1. Obtain an expression for the error e_i+1 in terms of
                  error e_i.
               2. Use the expression to show that e_k -> 0.
               3. Now as the sequence converges determine the speed.

               as given by G.W. Stewart in his
               Afternotes on Numerical Analysis.

     You can also prove it for the more general case (mod p^k) as easily.
     */
  t = a;
  while (1)
    {
      SSH_MP_LONG_MUL(ignore, k, t, a);
      if (k == 1)
        break;
      k = 2 - k;
      SSH_MP_LONG_MUL(ignore, t, k, t);
    }
  return t;
}     
#endif

/* Very quick initialization! */
Boolean ssh_mpm_init_m(SshIntModuli *m, const SshInt *op)
{
  unsigned int temp_n;

  /* If op < 3 or op % 2 == 0 we cannot work in Montgomery
     representation. */
  if (ssh_mp_cmp_ui(op, 3) < 0 || (ssh_mp_get_ui(op) & 0x1) == 0)
    return FALSE;

  /* Compute mp = -op^-1 (mod 2^SSH_WORD_BITS).
 
     XXX This is not a good way to do it, because we now alarm a
     warning.
   */
  m->mp = -ssh_mpmn_small_inv(op->v[0]);

  /* Set the modulus up, also in normalized form. */
  m->m = ssh_xmalloc(sizeof(SshWord) * (op->n + op->n));
  m->d = m->m + op->n;
  m->m_n = op->n;
  ssh_mpn_memcopy(m->m, op->v, m->m_n);
  ssh_mpn_memcopy(m->d, op->v, m->m_n);
  m->shift = ssh_mpn_leading_zeros(m->d, m->m_n);
  ssh_mpn_shift_up_bits(m->d, m->m_n, m->shift);

#ifdef SSHMATH_USE_WORKSPACE
  /* Determine how much memory we want to keep in reserve as working
     space. */
  temp_n =
    ssh_mpn_square_karatsuba_needed_memory(m->m_n);
  m->karatsuba_work_space_n =
    ssh_mpn_mul_karatsuba_needed_memory(m->m_n, m->m_n);
  if (m->karatsuba_work_space_n < temp_n)
    m->karatsuba_work_space_n = temp_n;
  /* Note that it is still possible that no extra memory is needed! */
  if (m->karatsuba_work_space_n)
    m->karatsuba_work_space = ssh_xmalloc(sizeof(SshWord) *
                                          m->karatsuba_work_space_n);
  else
    m->karatsuba_work_space = NULL;
  
  /* Now allocate the extra higher level working space. */

  /* The amount of memory for multiplication and squaring! */
  m->work_space_n = (m->m_n * 2 + 1) * 2;
  m->work_space   = ssh_xmalloc(sizeof(SshWord) * m->work_space_n);
#else /* SSHMATH_USE_WORKSPACE */
  m->karatsuba_work_space   = NULL;
  m->karatsuba_work_space_n = 0;
  m->work_space             = NULL;
  m->work_space_n           = 0;
#endif /* SSHMATH_USE_WORKSPACE */
    
  return TRUE;
}

/* Clean up the used moduli space. */
void ssh_mpm_clear_m(SshIntModuli *m)
{
  /* Free. */
  ssh_xfree(m->m);
  ssh_xfree(m->karatsuba_work_space);
  ssh_xfree(m->work_space);

  /* Clean. */
  m->mp = 0;
  m->m_n = 0;
  m->shift = 0;
  m->m = NULL;
  m->d = NULL;
  m->work_space           = NULL;
  m->karatsuba_work_space = NULL;
}

void ssh_mp_set_m(SshInt *ret, const SshIntModuli *m)
{
  ssh_mp_realloc(ret, m->m_n);
  ssh_mpn_memcopy(ret->v, m->m, m->m_n);
  ret->n = m->m_n;
  /* Our moduli cannot be negative! */
  SSH_MP_NO_SIGN(ret);
}

void ssh_mpm_init(SshIntModQ *op, const SshIntModuli *m)
{
  op->n = 0;
  op->v = ssh_xmalloc(sizeof(SshWord) * (m->m_n + 1));
  op->m = m;
}

void ssh_mpm_clear(SshIntModQ *op)
{
  ssh_xfree(op->v);
  op->n = 0;
  op->m = NULL;
}

void ssh_mpm_set(SshIntModQ *ret, const SshIntModQ *op)
{
  if (ret == op)
    return;

  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }
  ssh_mpn_memcopy(ret->v, op->v, op->n);
  ret->n = op->n;
}

void ssh_mpm_set_mp(SshIntModQ *ret, const SshInt *op)
{
  SshWord *t;
  unsigned int t_n;

  /* Trivial case. */
  if (op->n == 0)
    {
      /* Return zero also. */
      ret->n = 0;
      return;
    }

  /* If the input op != 0 then we will necessarily need some modular
     reduction. Thus the following doesn't need checks for the size
     of the input. */
  
  /* Compute R*op = ret (mod m) */

  /* Allocate some temporary space. */
  t = ssh_xmalloc(sizeof(SshWord) * (op->n + 1 + ret->m->m_n));
  
  /* Multiply by R the remainder. */
  ssh_mpn_memzero(t, ret->m->m_n);
  ssh_mpn_memcopy(t + ret->m->m_n, op->v, op->n);
  t_n = op->n + ret->m->m_n + 1;
  t[t_n - 1] = 0;

  /* Normalize. */
  ssh_mpn_shift_up_bits(t + ret->m->m_n, op->n + 1, ret->m->shift);

  /* Validate that length is correct. */
  if (t[t_n - 1] == 0)
    t_n--;
  
  /* Modular operations. */
  ssh_mpn_mod(t, t_n, ret->m->d, ret->m->m_n);

  /* Denormalize the remainder. */
  ssh_mpn_shift_down_bits(t, ret->m->m_n, ret->m->shift);

  /* Compute exact size. */
  t_n = ret->m->m_n;
  while (t_n && t[t_n - 1] == 0)
    t_n--;
  
  /* Copy into ret. */
  ssh_mpn_memcopy(ret->v, t, t_n);
  ret->n = t_n;

#if 0
  printf("Monty: \n"
         "0 ");
  for (bits = 0; bits < t_n; bits++)
    printf(" + %lu * (2^%u) ", t[bits], 32*bits);
  printf("\n");
#endif
  
  ssh_xfree(t);
}

void ssh_mp_set_mpm(SshInt *ret, const SshIntModQ *op)
{
  SshWord *t;
  unsigned int t_n;
  
  /* Allocate enough space for reduction to happen. */
  t_n = op->m->m_n * 2 + 1;
  t = ssh_xmalloc(sizeof(SshWord) * t_n);
  ssh_mpn_memzero(t, t_n);

  /* Reduce. */
  ssh_mpmn_reduce(t, t_n,
                  op->v, op->n,
                  op->m->mp,
                  op->m->m, op->m->m_n);

  /* Compute exact length. */
  t_n = op->m->m_n;
  while (t_n && t[t_n - 1] == 0)
    t_n--;
  
  /* Copy the result into ret. */
  ssh_mp_realloc(ret, t_n);
  ssh_mpn_memcopy(ret->v, t, t_n);
  ret->n = t_n;

  /* Free temporary storage. */
  ssh_xfree(t);
  
  SSH_MP_NO_SIGN(ret);
}

/* This is a simple wrapper but rather useful in many occasions. */
int ssh_mpm_cmp(SshIntModQ *op1, SshIntModQ *op2)
{
  return ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n);
}

/* Addition is easy with Montgomery representation. */
void ssh_mpm_add(SshIntModQ *ret, const SshIntModQ *op1,
                 const SshIntModQ *op2)
{
  SshWord c;

  if (op1->n < op2->n)
    {
      const SshIntModQ *t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Perform the addition. */
  c = ssh_mpn_add(ret->v, op1->v, op1->n, op2->v, op2->n);
  if (c)
    {
      ret->v[op1->n] = c;
      ret->n = op1->n + 1;
    }
  else
    ret->n = op1->n;

  /* Do modular reduction. */
  if (ssh_mpn_cmp(ret->v, ret->n, ret->m->m, ret->m->m_n) > 0)
    {
      ssh_mpn_sub(ret->v, ret->v, ret->n, ret->m->m, ret->m->m_n);
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
}

/* Subtraction is a bit more difficult. */
void ssh_mpm_sub(SshIntModQ *ret, const SshIntModQ *op1,
                 const SshIntModQ *op2)
{
  if (ssh_mpn_cmp(op1->v, op1->n, op2->v, op2->n) >= 0)
    {
      ssh_mpn_sub(ret->v, op1->v, op1->n, op2->v, op2->n);
      ret->n = op1->n;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
  else
    {
      ssh_mpn_sub(ret->v, op2->v, op2->n, op1->v, op1->n);
      ret->n = op2->n;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;

      /* Do modular reduction. */
      ssh_mpn_sub(ret->v, ret->m->m, ret->m->m_n, ret->v, ret->n);
      ret->n = ret->m->m_n;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
}

void ssh_mpm_mul(SshIntModQ *ret, const SshIntModQ *op1,
                 const SshIntModQ *op2)
{
  SshWord *t, *r;
  unsigned int t_n, r_n;

  if (op1->n == 0 || op2->n == 0)
    {
      ret->n = 0;
      return;
    }
  
  /* Allocate some temporary space. */
  t_n = op1->n + op2->n + 1;
  r_n = ret->m->m_n*2 + 1;
  if (ret->m->work_space == NULL)
    t = ssh_xmalloc(sizeof(SshWord) * (t_n + r_n));
  else
    t = ret->m->work_space;
  r = t + t_n;

  /* Clear temporary space. */
  ssh_mpn_memzero(t, t_n);
  ssh_mpn_mul_karatsuba(t, t_n, op1->v, op1->n, op2->v, op2->n,
                        ret->m->karatsuba_work_space,
                        ret->m->karatsuba_work_space_n);

  /* Find the exact length. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Do the reduction step. */
  ssh_mpn_memzero(r, r_n);
  ssh_mpmn_reduce(r, r_n,
                  t, t_n,
                  ret->m->mp,
                  ret->m->m, ret->m->m_n);

  /* Compute exact length. */
  r_n = ret->m->m_n;
  while (r_n && r[r_n - 1] == 0)
    r_n--;

  /* Copy to destination. */
  ssh_mpn_memcopy(ret->v, r, r_n);
  ret->n = r_n;

  /* Free temporary storage. */
  if (ret->m->work_space == NULL)
    ssh_xfree(t);
}

/* This should work, because op = x*R (mod N) and we can just
   compute op*u = x*R*u (mod N) as before. This should be much
   faster than standard multiplication. */
void ssh_mpm_mul_ui(SshIntModQ *ret, const SshIntModQ *op, SshWord u)
{
  SshWord *t;
  int t_n;

  /* Handle the trivial case. */
  if (op->n == 0 || u == 0)
    {
      ret->n = 0;
      return;
    }

  /* Another trivial case. */
  if (u == 1)
    {
      ssh_mpm_set(ret, op);
      return;
    }

  /* Multiply first. */
  t_n = op->n + 2;
  if (ret->m->work_space == NULL)
    t = ssh_xmalloc(sizeof(SshWord) * t_n);
  else
    t = ret->m->work_space;
  ssh_mpn_memzero(t, t_n);
  ssh_mpn_mul_ui(t, t_n, op->v, op->n, u);

  /* Correct the size. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Do a compare, which determines whether the modular reduction
     is necessary. */
  if (ssh_mpn_cmp(t, t_n, ret->m->m, ret->m->m_n) >= 0)
    {
      /* Allow growing a bit. */
      t_n ++;
      
      /* Now reduce (mod N). */

      /*The normalization first. */
      ssh_mpn_shift_up_bits(t, t_n, ret->m->shift);
      
      /* Check the size again. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;

      /* Reduction function. */
      ssh_mpn_mod(t, t_n, ret->m->d, ret->m->m_n);
      t_n = ret->m->m_n;
  
      ssh_mpn_shift_down_bits(t, t_n, ret->m->shift);
      
      /* Correct the size. */
      while (t_n && t[t_n - 1] == 0)
        t_n--;
    }

  ssh_mpn_memcopy(ret->v, t, t_n);
  ret->n = t_n;

  /* Free if necessary. */
  if (ret->m->work_space == NULL)
    ssh_xfree(t);
}

void ssh_mpm_square(SshIntModQ *ret, const SshIntModQ *op)
{
  SshWord *t, *r;
  unsigned int t_n, r_n;
  
  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }
  
  /* Allocate some temporary space. */
  t_n = op->n * 2 + 1;
  r_n = ret->m->m_n*2 + 1;
  if (ret->m->work_space == NULL)
    t = ssh_xmalloc(sizeof(SshWord) * (t_n + r_n));
  else
    t = ret->m->work_space;
  r = t + t_n;

  /* Clear temporary space. */
  ssh_mpn_memzero(t, t_n + r_n);
  ssh_mpn_square_karatsuba(t, t_n, op->v, op->n,
                           ret->m->karatsuba_work_space,
                           ret->m->karatsuba_work_space_n);

  /* Find the exact length. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Do the reduction step. */
  ssh_mpn_memzero(r, r_n);
  ssh_mpmn_reduce(r, r_n,
                  t, t_n,
                  ret->m->mp,
                  ret->m->m, ret->m->m_n);

  /* Compute exact length. */
  r_n = ret->m->m_n;
  while (r_n && r[r_n - 1] == 0)
    r_n--;

  /* Copy to destination. */
  ssh_mpn_memcopy(ret->v, r, r_n);
  ret->n = r_n;

  /* Free temporary storage. */
  if (ret->m->work_space == NULL)
    ssh_xfree(t);  
}

void ssh_mpm_mul_2exp(SshIntModQ *ret, const SshIntModQ *op,
                      unsigned int exp)
{
  unsigned int k;
  SshWord *t;
  int t_n;
  
  /* Check if no need to to anything. */
  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }

  /* Handle some special number of bits here. */
  switch (exp)
    {
    case 0:
      ssh_mpm_set(ret, op);
      return;
    case 1:
    case 2:
    case 3:
      /* Copy to ret. */
      ssh_mpm_set(ret, op);
      /* This can be done, because ret has always one extra word. */
      ret->v[ret->n] = 0;
      ssh_mpn_shift_up_bits(ret->v, ret->n + 1, exp);
      /* Figure the correct length. */
      ret->n++;
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
      /* Compute the modulus by number of subtractions. */
      while (ssh_mpn_cmp(ret->v, ret->n, ret->m->m, ret->m->m_n) > 0)
        {
          ssh_mpn_sub(ret->v, ret->v, ret->n, ret->m->m, ret->m->m_n);
          /* Correct the size once again. */
          while (ret->n && ret->v[ret->n - 1] == 0)
            ret->n--;
        }
      return;
    default:
      break;
    }

  /* The standard way of doing the same thing. */
  exp += ret->m->shift;
  k = exp / SSH_WORD_BITS;
  exp %= SSH_WORD_BITS;

  /* Allocate new space. */
  t_n = k + 2 + op->n;
  t = ssh_xmalloc(sizeof(SshWord) * t_n);
  
  /* Move from op to ret. */
  ssh_mpn_memzero(t, t_n);
  ssh_mpn_memcopy(t + k, op->v, op->n);
  ssh_mpn_shift_up_bits(t + k, op->n + 1, exp);

  /* Figure out the correct size here. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Compute the modulus. */
  ssh_mpn_mod(t, t_n, ret->m->d, ret->m->m_n);
  t_n = ret->m->m_n;
  ssh_mpn_shift_down_bits(t, t_n, ret->m->shift);

  /* Figure out the correct size. */
  while (t_n && t[t_n - 1] == 0)
    t_n--;

  /* Now copy to the ret. */
  ssh_mpn_memcopy(ret->v, t, t_n);
  ret->n = t_n;
  ssh_xfree(t);
}

void ssh_mpm_div_2exp(SshIntModQ *ret, const SshIntModQ *op,
                      unsigned int exp)
{
  int i;
  SshWord c;
  
  /* Handle trivial cases first. */
  if (op->n == 0)
    {
      ret->n = 0;
      return;
    }

  if (exp == 0)
    {
      ssh_mpm_set(ret, op);
      return;
    }
  
  /* Now handle the main iteration, notice that dividing by very
     large values this way isn't very fast! */

  /* Set up the return integer. */
  ssh_mpn_memzero(ret->v, ret->m->m_n + 1);
  ssh_mpm_set(ret, op);

  /* Loop until done, might take a while. */
  for (i = 0; i < exp; i++)
    {
      if (ret->v[0] & 0x1)
        {
          if (ret->n < ret->m->m_n)
            ret->n = ret->m->m_n;
          c = ssh_mpn_add(ret->v, ret->v, ret->n, ret->m->m, ret->m->m_n);
          if (c)
            {
              ret->v[ret->n] = c;
              ret->n++;
            }
        }
      ssh_mpn_shift_down_bits(ret->v, ret->n, 1);
      while (ret->n && ret->v[ret->n - 1] == 0)
        ret->n--;
    }
}

/* This will be needed in some future time. E.g. when writing fast
   polynomial arithmetic modulo large integer. Although, one should
   then also implement some other routines which would be of lots of
   use. */
Boolean ssh_mpm_invert(SshIntModQ *ret, const SshIntModQ *op)
{
  SshInt t, q;
  Boolean rv;
  ssh_mp_init(&t);
  ssh_mp_init(&q);
  /* Convert into basic integers. */
  ssh_mp_set_mpm(&t, op);
  ssh_mp_set_m(&q, ret->m);
  rv = ssh_mp_invert(&t, &t, &q);
  ssh_mpm_set_mp(ret, &t);
  ssh_mp_clear(&t);
  ssh_mp_clear(&q);
  return rv;
}

#if 0
/* Simple dumping code for monty values. */
void ssh_mpm_dump(const SshIntModQ *op)
{
  int i;

  printf("ssh_mpm_dump: \n  ");
  for (i = op->n; i; i--)
#if SIZEOF_LONG==4
    printf("%08lx ", op->v[i-1]);
#else
    printf("%16lx ", op->v[i-1]);
#endif /* SIZEOF_LONG==4 */

  printf("\n (0 ");
  for (i = 0; i < op->n; i++)
    printf("+ %lu*2^%u", op->v[i], i*32);
  printf(")\n");
}
#else
void ssh_mpm_dump(const SshIntModQ *op)
{
  /* Do nothing. */
}
#endif

/* Simple Montgomery representation based exponentiation method.
   Cannot work with even moduli (it is an error anyway in our usual
   applications). */
void ssh_mp_powm_naive_mont(SshInt *ret, const SshInt *g,
                            const SshInt *e, const SshInt *m)
{
  SshIntModuli mod;
  SshIntModQ   temp, x;
  unsigned int bits, i;
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_mod(ret, g, m);
      return;
    }

  if (ssh_mpm_init_m(&mod, m) == FALSE)
    {
      /* Later one could implement switch to standard method of
         exponentiation, but for now lets die. */
      ssh_fatal("ssh_mp_powm: montgomery representation demands odd moduli.");
    }
  ssh_mpm_init(&temp, &mod);
  ssh_mpm_init(&x,    &mod);

  ssh_mpm_set_mp(&x, g);
  ssh_mpm_set(&temp, &x);
  
  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mpm_square(&temp, &temp);
      if (ssh_mp_get_bit(e, i - 1))
        ssh_mpm_mul(&temp, &temp, &x);
    }
  
  ssh_mp_set_mpm(ret, &temp);
  ssh_mpm_clear(&temp);
  ssh_mpm_clear(&x);
  ssh_mpm_clear_m(&mod);
}

/* Simple Montgomery representation based exponentiation method.
   Cannot work with even moduli. */
void ssh_mp_powm_naive_mont_ui(SshInt *ret, SshWord g,
                               const SshInt *e, const SshInt *m)
{
  SshIntModuli mod;
  SshIntModQ   temp, x;
  SshInt       gg;
  unsigned int bits, i;
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  ssh_mp_init(&gg);
  ssh_mp_set_ui(&gg, g);
  
  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_mod(ret, &gg, m);
      ssh_mp_clear(&gg);
      return;
    }

  if (ssh_mpm_init_m(&mod, m) == FALSE)
    {
      /* Later one could implement switch to standard method of
         exponentiation, but for now lets die. */
      ssh_fatal("ssh_mp_powm: montgomery representation demands odd moduli.");
    }
  ssh_mpm_init(&temp, &mod);
  ssh_mpm_init(&x,    &mod);

  ssh_mpm_set_mp(&x, &gg);
  ssh_mpm_set(&temp, &x);
  
  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mpm_square(&temp, &temp);
      if (ssh_mp_get_bit(e, i - 1))
        ssh_mpm_mul_ui(&temp, &temp, g);
    }
  
  ssh_mp_set_mpm(ret, &temp);
  ssh_mp_clear(&gg);
  ssh_mpm_clear(&temp);
  ssh_mpm_clear(&x);
  ssh_mpm_clear_m(&mod);
}

/* Following routine implements 2^k-ary binary sliding window method
   with Montgomery representation.

   The window length will be selected as a function of the exponent
   length in bits. Following values are for most conservative
   implementations. 

   window length        exponent bits

   2                    < 24
   3                    < 88
   4                    < 277
   5                    < 798
   6                    < 2173
   7                    < 5678
   8                    < 14373
   9                    for the rest

   As for theoretical consideration we can see that the number of
   multiplications and squarings is about

   f(n,k) = 2^(k - 1) + n/k + n 

   where n denotes the exponent bit size, and k the window length in
   bits. In fact, we are trying to find a k such that

   f(n,k) < f(n, k+-1),

   in this quest we can compute

   Df(n,k) = 2^(k - 1)*ln(2) - n/k^2

   and thus

   n = k^2 * 2^(k - 1) * ln(2).

   This formula f is not exactly correct. It gives just a rough figure
   for which is reasonable window selection. There are ways go beyond
   these figures.

   This is the preferred method of exponentiation. However, cannot
   work with even moduli. 
   
   */
   
void ssh_mp_powm_bsw_mont(SshInt *ret, const SshInt *g,
                          const SshInt *e, const SshInt *m)
{
  SshIntModuli mod;
  unsigned int ssh_mp_table_bits, ssh_mp_table_size;
  SshIntModQ temp, x, *table;
  unsigned int bits, i, j, mask, end_square, first;
  unsigned int tab[] =
  { 24, 88, 277, 798, 2173, 5678, 14373, 0 };
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_mod(ret, g, m);
      return;
    }

  if (ssh_mpm_init_m(&mod, m) == FALSE)
    {
      /* Implement some fallback mechanism to switch into some
         slower, but standard exponentiation method. */
      ssh_fatal("ssh_mp_powm: montgomery representation demands odd moduli.");
    }

  ssh_mpm_init(&temp, &mod);
  ssh_mpm_init(&x,    &mod);

  /* Initialize the generator (in Montgomery representation). */
  ssh_mpm_set_mp(&x, g);
  
  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);

  /* Select a reasonable window size. */
  for (i = 0; tab[i]; i++)
    {
      if (bits < tab[i])
        break;
    }
  ssh_mp_table_bits = i + 2;
  ssh_mp_table_size = ((SshWord)1 << (ssh_mp_table_bits - 1));

  /* Allocate the table. */
  table = ssh_xmalloc(sizeof(SshIntModQ) * ssh_mp_table_size);

  /* Start computing the table. */
  ssh_mpm_init(&table[0], &mod);
  ssh_mpm_set(&table[0], &x);

  /* Compute g^2 into temp. */
  ssh_mpm_set(&temp, &table[0]);
  ssh_mpm_square(&temp, &temp);
  
  /* Compute the small table of powers. */
  for (i = 1; i < ssh_mp_table_size; i++)
    {
      ssh_mpm_init(&table[i], &mod);
      ssh_mpm_mul(&table[i], &table[i - 1], &temp);
    }

  for (first = 1, i = bits; i;)
    {
      for (j = 0, mask = 0; j < ssh_mp_table_bits && i; j++, i--)
        {
          mask <<= 1;
          mask |= ssh_mp_get_bit(e, i - 1);
        }

      for (end_square = 0; (mask & 0x1) == 0;)
        {
          mask >>= 1;
          end_square++;
        }

      if (!first)
        {
          /* First square. */
          for (j = mask; j; j >>= 1)
            ssh_mpm_square(&temp, &temp);
          
          ssh_mpm_mul(&temp, &temp, &table[(mask - 1)/2]);
        }
      else
        {
          ssh_mpm_set(&temp, &table[(mask - 1)/2]);
          first = 0;
        }

      /* Get rid of zero bits... */
      while (end_square)
        {
          ssh_mpm_square(&temp, &temp);
          end_square--;
        }

      while (i && ssh_mp_get_bit(e, i - 1) == 0)
        {
          ssh_mpm_square(&temp, &temp);
          i--;
        }
    }

  /* Clear and free the table. */
  for (i = 0; i < ssh_mp_table_size; i++)
    ssh_mpm_clear(&table[i]);
  ssh_xfree(table);
  
  ssh_mp_set_mpm(ret, &temp);
  ssh_mpm_clear(&temp);
  ssh_mpm_clear(&x);
  ssh_mpm_clear_m(&mod);
}

/* Slow, but so simple to write that I had to do it. This will be
   optimized a lot in near future. */
void ssh_mp_powm_naive(SshInt *ret, const SshInt *g, const SshInt *e,
                       const SshInt *m)
{
  SshInt temp;
  unsigned int bits, i;
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_mod(ret, g, m);
      return;
    }
  
  ssh_mp_init(&temp);
  ssh_mp_set(&temp, g);

  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mp_square(&temp, &temp);
      ssh_mp_mod(&temp, &temp, m);

      if (ssh_mp_get_bit(e, i - 1))
        {
          ssh_mp_mul(&temp, &temp, g);
          ssh_mp_mod(&temp, &temp, m);
        }
    }
  
  ssh_mp_set(ret, &temp);
  ssh_mp_clear(&temp);
}

/* Rather fast exponentiation for small base values. */
void ssh_mp_powm_naive_ui(SshInt *ret, SshWord g, const SshInt *e,
                          const SshInt *m)
{
  SshInt temp;
  unsigned int bits, i;
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_init(&temp);
      ssh_mp_set_ui(&temp, g);
      ssh_mp_mod(ret, &temp, m);
      ssh_mp_clear(&temp);
      return;
    }
  
  ssh_mp_init(&temp);
  ssh_mp_set_ui(&temp, g);

  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);

  for (i = bits - 1; i; i--)
    {
      ssh_mp_square(&temp, &temp);
      ssh_mp_mod(&temp, &temp, m);

      if (ssh_mp_get_bit(e, i - 1))
        {
          ssh_mp_mul_ui(&temp, &temp, g);
          ssh_mp_mod(&temp, &temp, m);
        }
    }
  
  ssh_mp_set(ret, &temp);
  ssh_mp_clear(&temp);
}

/* Rather fast exponentiation for small exponent values. */
void ssh_mp_powm_naive_expui(SshInt *ret, const SshInt *g, SshWord e,
                             const SshInt *m)
{
  SshInt temp;
  unsigned int i, bits;

  /* Trivial cases. */
  if (e == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (e == 1)
    {
      ssh_mp_mod(ret, g, m);
      return;
    }
  
  ssh_mp_init(&temp);
  ssh_mp_set(&temp, g);

  bits = 0;
  SSH_MP_COUNT_LEADING_ZEROS(bits, e);
  bits = SSH_WORD_BITS - bits;
  
  for (i = ((SshWord)1 << (bits - 1)); i; i >>= 1)
    {
      ssh_mp_square(&temp, &temp);
      ssh_mp_mod(&temp, &temp, m);

      if (e & i)
        {
          ssh_mp_mul(&temp, &temp, g);
          ssh_mp_mod(&temp, &temp, m);
        }
    }
  
  ssh_mp_set(ret, &temp);
  ssh_mp_clear(&temp);
}

#if 0
/* under construction XXX */

/* It is quite unlikely that this would be much faster, because in
   general the exponents are very uniformly distributed. */
void ssh_mp_powm_bsw2(SshInt *ret, const SshInt *g, const SshInt *e,
                      const SshInt *m)
{
#define SSH_MP_TABLE_BITS 7
#define SSH_MP_TABLE_SIZE ((SshWord)1 << (SSH_MP_TABLE_BITS - 1))
  SshInt temp, table[SSH_MP_TABLE_SIZE];
  unsigned char tk[SSH_MP_TABLE_SIZE];
#define SSH_MP_POW_NUM    4
  SshInt pow[SSH_MP_POW_NUM];
  unsigned int bits, i, j, mask, end_square, last;
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_mod(ret, g, m);
      return;
    }

  ssh_mp_init(&table[0]);
  ssh_mp_set(&table[0], g);
  ssh_mp_mod(&table[0], &table[0], m);
  
  ssh_mp_init(&temp);
  ssh_mp_set(&temp, &table[0]);
  ssh_mp_square(&temp, &temp);
  ssh_mp_mod(&temp, &temp, m);

  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);

  /* Compute g^2, g^4, g^6, g^8, ... */
  ssh_mp_init(&pow[0]);
  ssh_mp_set(&pow[0], &temp);
  for (i = 1; i < SSH_MP_POW_NUM; i++)
    {
      ssh_mp_init(&pow[i]);
      ssh_mp_mul(&pow[i], &pow[i - 1], &temp);
      ssh_mp_mod(&pow[i], &pow[i], m);
    }
  
  /* Clear the computed table. */
  tk[0] = 1;
  for (i = 1; i < SSH_MP_TABLE_SIZE; i++)
    tk[i] = 0;
  
  /* Figure out which are to be used. This should be very fast. */
  for (i = bits - 1; i;)
    {
      while (i && ssh_mp_get_bit(e, i - 1) == 0)
        i--;

      if (i == 0)
        break;
      
      for (j = 0, mask = 0; j < SSH_MP_TABLE_BITS && i; j++, i--)
        {
          mask <<= 1;
          mask |= ssh_mp_get_bit(e, i - 1);
        }

      for (end_square = 0; (mask & 0x1) == 0;)
        {
          mask >>= 1;
          end_square++;
        }

      tk[(mask - 1)/2] = 1;
    }

  /* Now figure out which of the places are needed to be actually
     computed. */
  
  /* This algorithm is very simple one, but still should be reasonably
     efficient. */

  /* This works as:

     0  g^1
     1  g^3  -- 1 - 0 - 1 = 0 -- g^2*g^1 
     2  g^5  -- 2 - 0 - 1 = 1 -- g^4*g^1
     3  g^7  -- 3 - 0 - 1 = 2 -- g^6*g^1
     4  g^9  -- 4 - 0 - 1 = 3 -- g^8*g^1
     
   */
  
  for (i = 1, last = 0; i < SSH_MP_TABLE_SIZE; i++)
    {
      if (tk[i] == 1 || (i - last - 1) >= (SSH_MP_POW_NUM - 1))
        {
          ssh_mp_init(&table[i]);
          ssh_mp_mul(&table[i], &table[last], &pow[i - last - 1]);
          ssh_mp_mod(&table[i], &table[i], m);
          last = i;

          /* Make sure that this is taken as initialized. */
          tk[i] = 1;
        }
    }

  for (i = 0; i < SSH_MP_POW_NUM; i++)
    ssh_mp_clear(&pow[i]);
  
  /* Start the actual exponentiation. */
  ssh_mp_set(&temp, &table[0]);

  /* Note that we recompute all the windows. This is stupid in a way, but
     still doesn't slow things down much. */
  for (i = bits - 1; i;)
    {
      while (i && ssh_mp_get_bit(e, i - 1) == 0)
        {
          ssh_mp_square(&temp, &temp);
          ssh_mp_mod(&temp, &temp, m);
          i--;
        }

      if (i == 0)
        break;
      
      for (j = 0, mask = 0; j < SSH_MP_TABLE_BITS && i; j++, i--)
        {
          mask <<= 1;
          mask |= ssh_mp_get_bit(e, i - 1);
        }

      for (end_square = 0; (mask & 0x1) == 0;)
        {
          mask >>= 1;
          end_square++;
        }

      /* First square. */
      for (j = mask; j; j >>= 1)
        {
          ssh_mp_square(&temp, &temp);
          ssh_mp_mod(&temp, &temp, m);
        }

      if (tk[(mask - 1)/2] == 0)
        ssh_fatal("ssh_mp_powm:"
                  " set up incorrect, appropriate mask not found.");
      ssh_mp_mul(&temp, &temp, &table[(mask - 1)/2]);
      ssh_mp_mod(&temp, &temp, m);

      while (end_square)
        {
          ssh_mp_square(&temp, &temp);
          ssh_mp_mod(&temp, &temp, m);
          end_square--;
        }
    }

  for (i = 0; i < SSH_MP_TABLE_SIZE; i++)
    {
      if (tk[i])
        ssh_mp_clear(&table[i]);
    }
  
  ssh_mp_set(ret, &temp);
  ssh_mp_clear(&temp);
#undef SSH_MP_TABLE_SIZE
#undef SSH_MP_TABLE_BITS
#undef SSH_MP_POW_NUM
  
}

#endif

/* 2^k-ary Binary sliding window method of exponentiation for standard
   algorithms. */
void ssh_mp_powm_bsw(SshInt *ret, const SshInt *g, const SshInt *e,
                     const SshInt *m)
{
#define SSH_MP_TABLE_BITS 6
#define SSH_MP_TABLE_SIZE ((SshWord)1 << (SSH_MP_TABLE_BITS - 1))
  SshInt temp, table[SSH_MP_TABLE_SIZE];
  unsigned int bits, i, j, mask, end_square, first;
  
  /* Trivial cases. */
  if (ssh_mp_cmp_ui(e, 0) == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }

  if (ssh_mp_cmp_ui(e, 1) == 0)
    {
      ssh_mp_mod(ret, g, m);
      return;
    }

  ssh_mp_init(&table[0]);
  ssh_mp_set(&table[0], g);
  ssh_mp_mod(&table[0], &table[0], m);
  
  ssh_mp_init(&temp);
  ssh_mp_set(&temp, &table[0]);
  ssh_mp_square(&temp, &temp);
  ssh_mp_mod(&temp, &temp, m);
  
  /* Compute the size of the exponent. */
  bits = ssh_mpn_size_in_bits(e->v, e->n);
  
  for (i = 1; i < SSH_MP_TABLE_SIZE; i++)
    {
      ssh_mp_init(&table[i]);
      ssh_mp_mul(&table[i], &table[i - 1], &temp);
      ssh_mp_mod(&table[i], &table[i], m);
    }

  for (first = 1, i = bits; i;)
    {
      for (j = 0, mask = 0; j < SSH_MP_TABLE_BITS && i; j++, i--)
        {
          mask <<= 1;
          mask |= ssh_mp_get_bit(e, i - 1);
        }

      for (end_square = 0; (mask & 0x1) == 0;)
        {
          mask >>= 1;
          end_square++;
        }

      if (!first)
        {
          /* First square. */
          for (j = mask; j; j >>= 1)
            {
              ssh_mp_square(&temp, &temp);
              ssh_mp_mod(&temp, &temp, m);
            }
          
          ssh_mp_mul(&temp, &temp, &table[(mask - 1)/2]);
          ssh_mp_mod(&temp, &temp, m);
        }
      else
        {
          ssh_mp_set(&temp, &table[(mask - 1)/2]);
          first = 0;
        }

      /* Get rid of zero bits... */
      while (end_square)
        {
          ssh_mp_square(&temp, &temp);
          ssh_mp_mod(&temp, &temp, m);
          end_square--;
        }

      while (i && ssh_mp_get_bit(e, i - 1) == 0)
        {
          ssh_mp_square(&temp, &temp);
          ssh_mp_mod(&temp, &temp, m);
          i--;
        }
    }

  for (i = 0; i < SSH_MP_TABLE_SIZE; i++)
    ssh_mp_clear(&table[i]);
  
  ssh_mp_set(ret, &temp);
  ssh_mp_clear(&temp);
#undef SSH_MP_TABLE_SIZE
#undef SSH_MP_TABLE_BITS
}

#if 0
/* A optimized exponentiation method which avoid much of the allocation
   etc. However, doesn't use Karatsuba methods at the moment and thus
   is rather slowish. It seems that allocation is not that slow, and
   one could always use stack allocation in most of the routines. 
   */
void ssh_mp_powm_optimized_naive(SshInt *ret, const SshInt *g,
                                 const SshInt *e, const SshInt *m)
{
  SshWord *div;
  SshWord *gen1, *gen2, *gen3;
  SshWord *exp, *tp;
  SshWord v, k;
  unsigned int exp_n, gen_n, gen1_n, gen2_n, gen3_n, bits, r, t;

  /* Check the trivial cases. */
  if (e->n == 0)
    {
      ssh_mp_set_ui(ret, 1);
      return;
    }
  /* This seems to be too fancy stuff. */
  if (e->n == 1)
    {
      switch (e->v[0])
        {
        case 1:
          ssh_mp_mod(ret, g, m);
          return;
        case 2:
          ssh_mp_square(ret, g);
          ssh_mp_mod(ret, ret, m);
          return;
        default:
          break;
        }
    }

  if (g->n > m->n * 2)
    gen_n = g->n + 1;
  else
    gen_n = m->n * 2 + 1;

  /* Allocate. */
  div  = ssh_xmalloc((m->n * 2 + gen_n * 2) * sizeof(SshWord));
  gen1 = div  + m->n;
  gen2 = gen1 + gen_n;
  gen3 = gen2 + gen_n;
  ssh_mpn_memcopy(gen1, g->v, g->n);
  ssh_mpn_memzero(gen1 + g->n, gen_n - g->n);
  
  /* Compute the normalization degree. */
  bits = ssh_mpn_leading_zeros(m->v, m->n);
  ssh_mpn_memcopy(div, m->v, m->n);

  /* Normalize. */
  ssh_mpn_shift_up_bits(div, m->n, bits);

  gen1_n = g->n + 1;
  
  /* Shift up i.e. normalize. */
  ssh_mpn_shift_up_bits(gen1, gen_n, bits);

  if (gen1[gen1_n - 1])
    gen1_n++;
  
  /* Figure exp out. No need to allocate. */
  exp = e->v;
  exp_n = e->n;

  /* Reduce gen first before starting something stupid. */
  if (gen1_n > m->n || (gen1_n == m->n && gen1[gen1_n - 1] >= m->v[m->n - 1]))
    {
      ssh_mpn_mod(gen1, gen1_n, div, m->n);
      gen1_n = m->n;
      while (gen1_n && gen1[gen1_n - 1] == 0)
        gen1_n--;
    }

  /* Copy and move back down (denormalize). */
  ssh_mpn_memcopy(gen3, gen1, gen1_n);
  gen3_n = gen1_n;
  ssh_mpn_shift_down_bits(gen3, gen3_n, bits);
  if (gen3[gen3_n - 1] == 0)
    gen3_n--;

  /* Compute the first msbit position. */
  r = 0;
  v = exp[exp_n - 1];
  SSH_MP_COUNT_LEADING_ZEROS(r, v);
  v = exp[exp_n - 1];
  r = (SSH_WORD_BITS - r) - 2;
  while (1)
    {
      if (r < SSH_WORD_BITS)
        for (k = (SshWord)1 << r; k; k >>= 1)
          {
            gen2_n = gen1_n * 2 + 1;
            ssh_mpn_memzero(gen2, gen2_n);
            ssh_mpn_square(gen2, gen2_n, gen1, gen1_n);
            ssh_mpn_shift_down_bits(gen2, gen2_n, bits);
            
            /* Correct the size. */
            if (gen2[gen2_n - 1] == 0)
              gen2_n--;
            
            ssh_mpn_mod(gen2, gen2_n, div, m->n);
            gen2_n = m->n;
            /* Correct the size. */
            while (gen2_n && gen2[gen2_n - 1] == 0)
              gen2_n--;

            if (k & v)
              {
                gen1_n = gen2_n + gen3_n + 1;
                ssh_mpn_memzero(gen1, gen1_n);
                ssh_mpn_mul(gen1, gen1_n, gen2, gen2_n, gen3, gen3_n);
                ssh_mpn_mod(gen1, gen1_n, div, m->n);
                gen1_n = m->n;
                /* Correct the size. */
                while (gen1_n && gen1[gen1_n - 1] == 0)
                  gen1_n--;
              }
            else
              {
                /* Swap. */
                tp = gen1;
                gen1 = gen2;
                gen2 = tp;
                
                t = gen1_n;
                gen1_n = gen2_n;
                gen2_n = t;
              }
          }
      exp_n--;
      if (exp_n == 0)
        break;
      
      v = exp[exp_n - 1];
      r = SSH_WORD_BITS - 1;
    }
  ssh_mpn_shift_down_bits(gen1, gen1_n, bits);

  ssh_mp_realloc(ret, gen1_n);
  ssh_mpn_memcopy(ret->v, gen1, gen1_n);
  ret->n = gen1_n;

  ssh_xfree(div);
  
  /* Correct the size. */
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  
  SSH_MP_NO_SIGN(ret);
}
#endif

/* Basic bit operations, for integers. These are simple, but useful
   sometimes. */
void ssh_mp_and(SshInt *ret, const SshInt *op1, const SshInt *op2)
{
  unsigned int i;

  /* Swap. */
  if (op1->n > op2->n)
    {
      const SshInt *t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Reallocate. */
  ssh_mp_realloc(ret, op1->n);

  /* This can be written more optimally. */
  for (i = 0; i < op1->n; i++)
    ret->v[i] = op1->v[i] & op2->v[i];

  ret->n = op1->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

void ssh_mp_or(SshInt *ret, const SshInt *op1, const SshInt *op2)
{
  unsigned int i;

  /* Swap. */
  if (op1->n > op2->n)
    {
      const SshInt *t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Reallocate. */
  ssh_mp_realloc(ret, op2->n);

  /* This can be written more optimally. */
  for (i = 0; i < op1->n; i++)
    ret->v[i] = op1->v[i] | op2->v[i];
  for (; i < op2->n; i++)
    ret->v[i] = op2->v[i];

  ret->n = op2->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

void ssh_mp_xor(SshInt *ret, const SshInt *op1, const SshInt *op2)
{
  unsigned int i;

  /* Swap. */
  if (op1->n > op2->n)
    {
      const SshInt *t;
      t = op1;
      op1 = op2;
      op2 = t;
    }

  /* Reallocate. */
  ssh_mp_realloc(ret, op1->n);

  /* This can be written more optimally. */
  for (i = 0; i < op1->n; i++)
    ret->v[i] = op1->v[i] ^ op2->v[i];
  for (; i < op2->n; i++)
    ret->v[i] = op2->v[i];
  
  ret->n = op2->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

void ssh_mp_not(SshInt *ret, const SshInt *op)
{
  unsigned int i;

  /* Reallocate. */
  ssh_mp_realloc(ret, op->n);

  /* This can be written more optimally. */
  for (i = 0; i < op->n; i++)
    ret->v[i] = ~op->v[i];

  ret->n = op->n;
  while (ret->n && ret->v[ret->n - 1] == 0)
    ret->n--;
  SSH_MP_NO_SIGN(ret);
}

int ssh_mp_miller_rabin(const SshInt *op, unsigned int limit)
{
  SshInt q, a, b, op_1;
  int rv;
  unsigned int t, k, e;
  
  /* Assume primes are larger than 1. */
  if (ssh_mp_cmp_ui(op, 1) <= 0)
    return 0;

  ssh_mp_init(&q);
  ssh_mp_init(&op_1);
  ssh_mp_set(&q, op);
  ssh_mp_sub_ui(&q, &q, 1);
  ssh_mp_set(&op_1, &q);
  t = 0;
  while ((ssh_mp_get_ui(&q) & 0x1) == 0)
    {
      ssh_mp_div_2exp(&q, &q, 1);
      t++;
    }

  ssh_mp_init(&a);
  ssh_mp_init(&b);

  rv = 1;
  /* To the witness tests. */
  for (; limit; limit--)
    {
      /* We want to be fast, thus we use 0 < a < 2^(SSH_WORD_BITS). */
      do 
        k = ssh_mp_word_rand();
      while (k == 0);

      /* Exponentiate. XXX Speed this later. */
      ssh_mp_powm_ui(&b, k, &q, op);
      if (ssh_mp_cmp_ui(&b, 1) != 0)
        {
          e = 0;
          while (ssh_mp_cmp_ui(&b, 1) != 0 &&
                 ssh_mp_cmp(&b, &op_1) != 0 &&
                 e <= t - 2)
            {
              ssh_mp_square(&b, &b);
              ssh_mp_mod(&b, &b, op);
              e++;
            }
          
          if (ssh_mp_cmp(&b, &op_1) != 0)
            {
              rv = 0;
              break;
            }
        }
    }
  ssh_mp_clear(&q);
  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&op_1);

  return rv;
}

/* Following routine decides, if given value is very likely a prime or not. */
int ssh_mp_is_probable_prime(const SshInt *op, unsigned int limit)
{
  SshInt temp;

  /* Check for trivial cases. */
  if (ssh_mp_cmp_ui(op, 2) < 0)
    return 0;
  if (ssh_mp_cmp_ui(op, 2) == 0)
    return 1;
  if ((ssh_mp_get_ui(op) & 0x1) == 0)
    return 0;
  
  /* Test first with Fermat's test with witness 2. */
  ssh_mp_init(&temp);
  ssh_mp_powm_ui(&temp, 2, op, op);
  if (ssh_mp_cmp_ui(&temp, 2) != 0)
    {
      ssh_mp_clear(&temp);
      return 0;
    }
  ssh_mp_clear(&temp);

  /* Finally try Miller-Rabin test. */
  if (ssh_mp_miller_rabin(op, limit) == 1)
    return 1;
  return 0;
}

/* Square tables. We follow Henri Cohen very closely here. */
const unsigned char ssh_mp_sq11[11] = 
{ 1,1,0,1,1,1,0,0,0,1,0, };
const unsigned char ssh_mp_sq63[63] = 
{ 1,1,0,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,0,0,0,1,0,0,1,0,0,1,0,0,0,
  0,0,0,0,1,1,0,0,0,0,0,1,0,0,1,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0 };
const unsigned char ssh_mp_sq64[64] =
{ 1,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,
  0,1,0,0,1,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0 };
const unsigned char ssh_mp_sq65[65] = 
{ 1,1,0,0,1,0,0,0,0,1,1,0,0,0,1,0,1,0,0,0,0,0,0,0,0,1,1,0,0,1,1,0,
  0,0,0,1,1,0,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,0,1,1,0,0,0,0,1,0,0,
  1 };

int ssh_mp_is_perfect_square(const SshInt *op)
{
  int r;
  SshInt t;
  
  /* Quick check for case op is a square. */
  if (ssh_mp_sq64[ssh_mp_get_ui(op) & 63] == 0)
    return 0;

  /* Other Quick tests. */
  r = ssh_mp_mod_ui(op, 45045);
  if (ssh_mp_sq63[r % 63] == 0)
    return 0;
  if (ssh_mp_sq65[r % 65] == 0)
    return 0;
  if (ssh_mp_sq11[r % 11] == 0)
    return 0;

  /* We have now no other choice but to compute the square root. */
  ssh_mp_init(&t);
  ssh_mp_sqrt(&t, op);
  ssh_mp_square(&t, &t);

  /* Lets expect failure. */
  r = 0;
  if (ssh_mp_cmp(&t, op) == 0)
    r = 1;

  ssh_mp_clear(&t);

  return r;
}

void ssh_mp_sqrtrem(SshInt *sqrt_out, SshInt *rem, const SshInt *op)
{
  SshInt r, t;

  /* Lets have some temporary variables. */
  ssh_mp_init(&r);
  ssh_mp_init(&t);

  /* Compute square root and then square it. */
  ssh_mp_sqrt(&t, op);
  ssh_mp_square(&r, &t);

  /* Find the remainder. */
  ssh_mp_sub(rem, op, &r);
  ssh_mp_set(sqrt_out, &t);
  
  /* Clear temporary space. */
  ssh_mp_clear(&r);
  ssh_mp_clear(&t);
}

/* Algorithm for computing a = b^(1/2) (mod p), the general case.
   Note: we are using mostly integers, and not the values in
   modular representation, which might be nicer. This means, that
   we have to do mods, but also its easier to compare values etc. */
Boolean ssh_mp_tonelli_shanks(SshInt *sqrt_out, const SshInt *op,
                              const SshInt *p)
{
  SshInt n, q, x, y, b, t;
  unsigned int counter, e, r, m, size;
  Boolean rv = FALSE;
  
  /* We are assuming that the input prime (it should be prime), is
     larger or equal to 2. */
  if (ssh_mp_cmp_ui(p, 1) <= 0)
    return rv;

  /* Get good size. */
  size = ssh_mp_get_size(p, 2);
  
  ssh_mp_init(&n);
  ssh_mp_init(&q);
  ssh_mp_init(&x);
  ssh_mp_init(&y);
  ssh_mp_init(&b);
  ssh_mp_init(&t);
  
  /* Find q */
  ssh_mp_sub_ui(&q, p, 1);
  e = 0;
  while ((ssh_mp_get_ui(&q) & 0x1) == 0)
    {
      e++;
      ssh_mp_div_2exp(&q, &q, 1);
    }
  
  /* This loop might take forever, though, it should not. */
  for (counter = 0; counter < 0xffff; counter++)
    {
      ssh_mp_rand(&n, size);
      if (ssh_mp_kronecker(&n, p) == -1)
        break;
    }
  if (counter >= 0xffff)
    ssh_fatal("ssh_mp_tonelli_shanks: could not find quadratic non-residue!");

  /* Initialize, as Cohen says. */

  /* Compute y = n^q (mod p). */
  ssh_mp_powm(&y, &n, &q, p);
  r = e;

  /* (q - 1)/2 */
  ssh_mp_sub_ui(&t, &q, 1);
  ssh_mp_div_2exp(&t, &t, 1);

  ssh_mp_powm(&x, op, &t, p);

  ssh_mp_square(&b, &x);
  ssh_mp_mul(&b, &b, op);
  ssh_mp_mod(&b, &b, p);
  ssh_mp_mul(&x, &x, op);
  ssh_mp_mod(&x, &x, p);

  /* Now start the main loop. This should be deterministic, and thus
     finish is reasonable time. */
  while (ssh_mp_cmp_ui(&b, 1) != 0)
    {
      ssh_mp_set(&t, &b);
      for (m = 1; m < r; m++)
        {
          ssh_mp_square(&t, &t);
          ssh_mp_mod(&t, &t, p);
          if (ssh_mp_cmp_ui(&t, 1) == 0)
            break;
        }

      /* We are finished, not a quadratic residue. */
      if (m >= r)
        goto failed;

      /* Compute y^(2^(r - m - 1)) (mod p). */
      ssh_mp_powm_expui(&t, &y, ((SshWord)1 << (r - m - 1)), p); 
      ssh_mp_square(&y, &t);
      ssh_mp_mod(&y, &y, p);
      r = m;

      /* x = xt (mod p) */
      ssh_mp_mul(&x, &x, &t);
      ssh_mp_mod(&x, &x, p);

      /* b = by (mod p) */
      ssh_mp_mul(&b, &b, &y);
      ssh_mp_mod(&b, &b, p);
    }

  /* The result. */
  ssh_mp_set(sqrt_out, &x);
  
  rv = TRUE;
  
failed:
  ssh_mp_clear(&n);
  ssh_mp_clear(&q);
  ssh_mp_clear(&x);
  ssh_mp_clear(&y);
  ssh_mp_clear(&b);
  ssh_mp_clear(&t);

  return rv;
}

/* Algorithm for computing the above one in all cases where p is prime,
   optimized for some specific cases. */

Boolean ssh_mp_mod_sqrt(SshInt *sqrt_out, const SshInt *op, const SshInt *p)
{
  SshInt in;
  Boolean rv = FALSE;
  
  ssh_mp_init(&in);
  ssh_mp_mod(&in, op, p);
  
  /* First we want to know if the given op is quadratic residue, and
     we can use the Kronecker method. */
  if (ssh_mp_kronecker(&in, p) != 1)
    goto failed;
  
  /* Handle case p == 3 (mod 4) */
  if ((ssh_mp_get_ui(p) & 3) == 3)
    {
      SshInt t;
      ssh_mp_init(&t);
      ssh_mp_add_ui(&t, p, 1);
      ssh_mp_div_2exp(&t, &t, 2);
      ssh_mp_powm(sqrt_out, &in, &t, p);
      ssh_mp_clear(&t);

      rv = TRUE;
      goto failed;
    }
  
  /* Handle case p == 5 (mod 8).
     Here we don't do it as Henri Cohen suggest because better method
     with just one exponentiation is available. It is described for
     example in P1363. Proof follows easily, along the lines that Cohen
     does. 
   */
  if ((ssh_mp_get_ui(p) & 7) == 5)
    {
      SshInt t, h, k;
      ssh_mp_init(&t);
      ssh_mp_init(&h);
      ssh_mp_init(&k);

      /* First compute (p - 5)/8. */
      ssh_mp_sub_ui(&k, p, 5);
      ssh_mp_div_2exp(&k, &k, 3);

      /* Now t = (2*op)^k (mod p). */
      ssh_mp_mul_2exp(&t, &in, 1);
      ssh_mp_mod(&t, &t, p);
      ssh_mp_powm(&t, &t, &k, p);

      /* Then h = 2*op*t^2 (mod p). */
      ssh_mp_square(&h, &t);
      ssh_mp_mod(&h, &h, p);
      ssh_mp_mul_2exp(&h, &h, 1);
      ssh_mp_mul(&h, &h, &in);
      ssh_mp_mod(&h, &h, p);

      /* Now the final computation. */
      ssh_mp_sub_ui(&h, &h, 1);
      ssh_mp_mul(&h, &h, &t);
      ssh_mp_mul(&h, &h, &in);
      ssh_mp_mod(sqrt_out, &h, p);
      
      ssh_mp_clear(&t);
      ssh_mp_clear(&h);
      ssh_mp_clear(&k);

      rv = TRUE;
      goto failed;
    }
  /* Use the algorithm of Tonelli-Shanks in remaining cases. */

  if (ssh_mp_tonelli_shanks(sqrt_out, &in, p) == FALSE)
    ssh_fatal("ssh_mp_mod_sqrt: quadratic residue test failed!");

  /* Consider using Lucas functions as P1363 does. I have tried the
     method in past and it works nicely. However, this version here is
     more self-contained, and theoretically easier. */

  rv = TRUE;
failed:
  ssh_mp_clear(&in);
  return rv;
}

/* Routine which seeks next prime starting from start. This routine
   is closely related to the previous function written to SSH
   Cryptolibrary by Antti Huima, and then revised by me. This version
   is somewhat different.

   This function does work for every start value, although, clearly
   very large values might make things difficult. 
   */
Boolean ssh_mp_next_prime(SshInt *p, const SshInt *start)
{
  SshInt s;
  SshSieve sieve;
  SshWord *moduli, m;
  unsigned char *diffs;
  unsigned long difference;
  Boolean divisible;
  unsigned int i, j, k, prime, bits, max, count;
  Boolean rv;
  /* XXX Following tables are not the best possible. I have not done
     any analysis on the best possible tables. These are tables that
     seem almost sensible, although better ones could be computed. */
  unsigned int ssh_mp_table_bits[8] =
  { 16, 64, 256, 1024, 2048, 4192, 16384, 0 };
  unsigned int ssh_mp_table_size[9] =
  { 64, 256, 512, 1024, 2*1024, 4*1024, 6*1024, 8 * 1024,
    10 * 1024 };
  
  /* Check for very small inputs. */
  if (ssh_mp_cmp_ui(start, 3) <= 0)
    {
      /* Handle trivial cases. */
      switch (ssh_mp_get_ui(start))
        {
        case 0:
        case 1:
          ssh_mp_set_ui(p, 2);
          return TRUE;
        case 2:
          ssh_mp_set_ui(p, 3);
          return TRUE;
        case 3:
          ssh_mp_set_ui(p, 5);
          return TRUE;
        default:
          break;
        }
      ssh_mp_set_ui(p, 0);
      return FALSE;
    }
      
  /* XXX Progress monitoring! */

  ssh_mp_init_set(&s, start);
  if (!(ssh_mp_get_ui(&s) & 0x1))
    ssh_mp_add_ui(&s, &s, 1);
  
  /* Compute reasonable amount of small primes.
   */

  bits = ssh_mp_get_size(&s, 2);

  /* This limit can be changed quite a lot higher, although, probably
     32 is the limit? */
  if (bits < 16)
    {
      max = ssh_mp_get_ui(&s);
      if (max < 1024)
        max = 1024;
      
      /* We can do the job with one large table. This proves that
         we actually have a prime. */
      ssh_sieve_allocate_ui(&sieve, max, 100000);

      /* Trivial case. */
      if (ssh_sieve_last_prime(&sieve) > ssh_mp_get_ui(&s))
        {
          k = ssh_sieve_next_prime(ssh_mp_get_ui(&s) - 1, &sieve);
          ssh_mp_set_ui(p, k);
          ssh_sieve_free(&sieve);
          ssh_mp_clear(&s);
          return TRUE;
        }
      
      for (k = ssh_mp_get_ui(&s); k; k += 2)
        {
          for (i = 2; i; i = ssh_sieve_next_prime(i, &sieve))
            if ((k % i) == 0)
              break;
          if (i == 0)
            break;
        }
      ssh_mp_set_ui(p, k);
      ssh_sieve_free(&sieve);
      ssh_mp_clear(&s);
      return TRUE;
    }

  /* Find the max for this bit size. */
  for (i = 0, max = 0; ssh_mp_table_bits[i]; i++)
    if (bits > ssh_mp_table_bits[i])
      max = i + 1;
  max = ssh_mp_table_size[max];
  ssh_sieve_allocate(&sieve, max);

  /* Count the primes (actually they have already been counted). */
  count = ssh_sieve_prime_count(&sieve);

  /* Allocate some space for us to work on. */
  moduli = ssh_xmalloc(count * sizeof(SshWord));
  diffs  = ssh_xmalloc(count);

  /* Set up the tables. E.g. the moduli table and the
     table which contains the prime gaps. */
  prime = 3;
  moduli[0] = ssh_mp_mod_ui(&s, prime);
  for (i = 1, j = ssh_sieve_next_prime(prime, &sieve);
       i < count && j; i++, j = ssh_sieve_next_prime(j, &sieve))
    {
      moduli[i] = ssh_mp_mod_ui(&s, j);
      if (j - prime > 0xff)
        break;
      diffs[i - 1]  = j - prime;      
      prime = j;
    }

  /* Set the correct size, might be slightly off in the first guess. */
  count = i;
  
  /* Free the sieve, we'll work with the tables. */
  ssh_sieve_free(&sieve);

  /* Start the main search iteration. */
  rv = FALSE;
  for (difference = 0; ; difference += 2)
    {
      /* We can assume that the largest prime gap is less than this,
         if not then better to try again. */
      if (difference > (unsigned int)((SshWord)1 << 20))
        goto failed;

      for (i = 0, divisible = FALSE, prime = 3; i < count;
           prime += diffs[i], i++)
        {
          m = moduli[i];
          while (m + difference >= prime)
            m -= prime;
          moduli[i] = m;
          if (m + difference == 0)
            break;
        }

      /* Multiple of a known prime. */
      if (i < count)
        continue;

      /* XXX Progress monitoring! */

      /* Compute the number in question. */
      ssh_mp_add_ui(p, &s, difference);

      /* Now do the good probable prime testing that we have
         implemented above! Note that this routine has been optimized
         and thus we don't need to do anything special here. */
      if (ssh_mp_is_probable_prime(p, 20))
        break;

      /* Was not a prime! */
    }
  /* Success! */
  rv = TRUE;
failed:

  ssh_xfree(moduli);
  ssh_xfree(diffs);
  ssh_mp_clear(&s);

  /* Finished. */
  return rv;
}

#if 0
/* Computation of Lucas numbers with fast exponentiation
   method. This of course also goes for Fibonacci numbers. */
void ssh_mp_lucas(SshInt *ret, const SshInt *l1, const SshInt *l2,
                  const SshInt *k, const SshInt *m)
{
}
/* Search for Sophie Germain primes e.g. primes p = q*2 + 1, where p and q
   are both primes. */
Boolean ssh_mp_next_sophie_germain_prime(SshInt *p, const SshInt *start)
{
}
/* Search for prime p = q*c + 1, where q and p are both primes. This
   should probably allow for searching of safer primes p = q1*q2 + 1,
   where all p, q1 and q2 are primes. These are harder to find though. */
Boolean ssh_mp_next_safe_prime(SshInt *p, const SshInt *start,
                               int small_size)
{
}
/* Function to factor large numbers (fastest for numbers less than
   40 digits long). Should at first use only ECM. */
Boolean ssh_mp_factor(SshInt *composite, SshInt *factor)
{
}
/* Function for index computations modulo p. Even if not very useful
   for general audience, has the advantage of allowing users to get
   a feel for the difficulty of index computation. */
Boolean ssh_mp_index(SshInt *index, SshInt *g, SshInt *q, SshInt *p)
{
}
#endif

/* sshmp.c */

