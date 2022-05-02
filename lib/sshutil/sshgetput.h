/*

sshgetput.h

Author: Tatu Ylonen <ylo@cs.hut.fi>
        Mika Kojo <mkojo@ssh.fi>

Copyright (c) 1995-1998 SSH Communications Security, Finland
                   All rights reserved

Created: Wed Jun 28 22:36:30 1995 ylo

Macros for storing and retrieving integers in msb first and lsb first order.

*/

/*
 * $Id: sshgetput.h,v 1.6 1998/12/04 23:29:57 kivinen Exp $
 * $Log: sshgetput.h,v $
 * $EndLog$
 */

#ifndef SSHGETPUT_H
#define SSHGETPUT_H

#define SSH_GET_8BIT(cp) (*(unsigned char *)(cp))
#define SSH_PUT_8BIT(cp, value) (*(unsigned char *)(cp)) = \
  (unsigned char)(value)
#define SSH_GET_4BIT_LOW(cp) (*(unsigned char *)(cp) & 0x0f)
#define SSH_GET_4BIT_HIGH(cp) ((*(unsigned char *)(cp) >> 4) & 0x0f)
#define SSH_PUT_4BIT_LOW(cp, value) (*(unsigned char *)(cp) = \
  (unsigned char)((*(unsigned char *)(cp) & 0xf0) | ((value) & 0x0f)))
#define SSH_PUT_4BIT_HIGH(cp, value) (*(unsigned char *)(cp) = \
  (unsigned char)((*(unsigned char *)(cp) & 0x0f) | (((value) & 0x0f) << 4)))

#ifdef SSHUINT64_IS_64BITS
#define SSH_GET_64BIT(cp) (((SshUInt64)SSH_GET_32BIT((cp)) << 32) | \
                           ((SshUInt64)SSH_GET_32BIT((cp) + 4)))
#define SSH_PUT_64BIT(cp, value) do { \
  SSH_PUT_32BIT((cp), (SshUInt32)((value) >> 32)); \
  SSH_PUT_32BIT((cp) + 4, (SshUInt32)(value)); } while (0)
#define SSH_GET_64BIT_LSB_FIRST(cp) \
     (((SshUInt64)SSH_GET_32BIT_LSB_FIRST((cp))) | \
      ((SshUInt64)SSH_GET_32BIT_LSB_FIRST((cp) + 4) << 32))
#define SSH_PUT_64BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (SshUInt32)(value)); \
  SSH_PUT_32BIT_LSB_FIRST((cp) + 4, (SshUInt32)((value) >> 32)); } while (0)
#else /* SSHUINT64_IS_64BITS */
#define SSH_GET_64BIT(cp) ((SshUInt64)SSH_GET_32BIT((cp) + 4))
#define SSH_PUT_64BIT(cp, value) do { \
  SSH_PUT_32BIT((cp), 0L); \
  SSH_PUT_32BIT((cp) + 4, (SshUInt32)(value)); } while (0)
#define SSH_GET_64BIT_LSB_FIRST(cp) ((SshUInt64)SSH_GET_32BIT((cp)))
#define SSH_PUT_64BIT_LSB_FIRST(cp, value) do { \
  SSH_PUT_32BIT_LSB_FIRST((cp), (SshUInt32)(value)); \
  SSH_PUT_32BIT_LSB_FIRST((cp) + 4, 0L); } while (0)
#endif /* SSHUINT64_IS_64BITS */

#if defined(NO_INLINE_GETPUT) || !defined(__i386__) || !defined(__GNUC__)

/* Generic code. */

/*------------ macros for storing/extracting msb first words -------------*/

#define SSH_GET_32BIT(cp) \
  ((((unsigned long)((unsigned char *)(cp))[0]) << 24) | \
   (((unsigned long)((unsigned char *)(cp))[1]) << 16) | \
   (((unsigned long)((unsigned char *)(cp))[2]) << 8) | \
   ((unsigned long)((unsigned char *)(cp))[3]))

#define SSH_GET_16BIT(cp) \
     ((SshUInt16) ((((unsigned long)((unsigned char *)(cp))[0]) << 8) | \
      ((unsigned long)((unsigned char *)(cp))[1])))
     
#define SSH_PUT_32BIT(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 24); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 16); \
  ((unsigned char *)(cp))[2] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[3] = (unsigned char)(value); } while (0)
     
#define SSH_PUT_16BIT(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[1] = (unsigned char)(value); } while (0)
     
/*------------ macros for storing/extracting lsb first words -------------*/

     
#define SSH_GET_32BIT_LSB_FIRST(cp) \
  (((unsigned long)((unsigned char *)(cp))[0]) | \
  (((unsigned long)((unsigned char *)(cp))[1]) << 8) | \
  (((unsigned long)((unsigned char *)(cp))[2]) << 16) | \
  (((unsigned long)((unsigned char *)(cp))[3]) << 24))

#define SSH_GET_16BIT_LSB_FIRST(cp) \
  ((SshUInt16) (((unsigned long)((unsigned char *)(cp))[0]) | \
  (((unsigned long)((unsigned char *)(cp))[1]) << 8)))

#define SSH_PUT_32BIT_LSB_FIRST(cp, value) do { \
  ((unsigned char *)(cp))[0] = (unsigned char)(value); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 8); \
  ((unsigned char *)(cp))[2] = (unsigned char)((value) >> 16); \
  ((unsigned char *)(cp))[3] = (unsigned char)((value) >> 24); } while (0)

#define SSH_PUT_16BIT_LSB_FIRST(cp, value) do { \
  ((unsigned char *)(cp))[0] = (value); \
  ((unsigned char *)(cp))[1] = (unsigned char)((value) >> 8); } while (0)

#else /* Special code for i386 with gcc */

/* Intel i386 processor, using AT&T syntax for gcc compiler. */

/* Lsb first cases could be done efficiently also with just C-definitions
   to just copy values.  i386 has no alignment restrictions. */

#define SSH_GET_32BIT_LSB_FIRST(cp) (*(SshUInt32 *)(cp))
#define SSH_GET_16BIT_LSB_FIRST(cp) (*(SshUInt16 *)(cp))
#define SSH_PUT_32BIT_LSB_FIRST(cp,x) (*(SshUInt32 *)(cp)) = (x)
#define SSH_PUT_16BIT_LSB_FIRST(cp,x) (*(SshUInt16 *)(cp)) = (x)

/* Getting bytes msb first */

#define SSH_GET_32BIT(cp) \
({  \
  SshUInt32 __v__; \
  __asm__ ("movl (%1), %0; rolw $8, %0; roll $16, %0; rolw $8, %0;" \
          : "=&r" (__v__) \
          : "r" (cp)); \
  __v__; \
})

#define SSH_GET_16BIT(cp) \
({ \
  SshUInt16 __v__; \
  __asm__ ("movw (%1), %0; rolw $8, %0;" \
          : "=&r" (__v__) \
          : "r" (cp)); \
  __v__; \
})

#define SSH_PUT_32BIT(cp, v) \
__asm__ ("movl %1, %%ecx; rolw $8, %%cx; roll $16, %%ecx; rolw $8, %%cx;" \
         "movl %%ecx, (%0);" \
         : : "S" (cp), "a" (v) : "%ecx") \

#define SSH_PUT_16BIT(cp,v)  \
__asm__("movw %%ax, %%cx; rolw $8, %%cx; movw %%cx, (%0);"\
        : : "S" (cp), "a" (v) : "%cx") \

#endif /* __i386__ */

#endif /* GETPUT_H */
