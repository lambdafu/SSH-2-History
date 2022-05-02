/*

crc32.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1992 Tatu Ylonen, Espoo, Finland
                   All rights reserved

Created: Tue Feb 11 14:37:27 1992 ylo

Functions for computing 32-bit CRC.

*/

/*
 * $Id: crc32.h,v 1.4 1998/07/20 16:38:04 mkojo Exp $
 * $Log: crc32.h,v $
 * $EndLog$
 */

#ifndef CRC32_H
#define CRC32_H

/* This computes a 32 bit CRC of the data in the buffer, and returns the
   CRC.  The polynomial used is 0xedb88320. */

unsigned long crc32_buffer(const unsigned char *buf, unsigned int len);

/* This computes a 32 bit 'modified' CRC of the data in the buffer,
   and returns the CRC.  The polynomial used is 0xedb88320.

   As a matter of fact, there is a reason why this function exists. Given
   simple CRC function (of any bit length) there is a significant weakness
   that makes it vulnerable to some input buffers. That is, the CRC
   is defined in GF(2^n) as

      b(x) (mod f(x)) = crc

   where b(x) is the buffer and f(x) the polynomial mentioned before. That
   is we compute the remainder of division of polynomials with coefficients
   having values 0 or 1.

   It follows that if the buffer starts with zeroes (zero bits) the
   resulting CRC will match a CRC of the buffer without those leading
   zero bits.

   This function removes that problem by inserting the length of the
   buffer into the CRC state variable before CRC computation. It doesn't
   follow any standard so use with caution in protocols etc.

   Now the main purpose of this change for me is that when I'm using
   CRC as a hash function, it is good to handle all cases well, also
   those that might have the first bits equal to zero. There are other
   good hash functions but CRC is provably able to detect even one bit
   differences in long periods thus making it particularly well suited
   to some applications.  */

unsigned long crc32_buffer_altered(const unsigned char *buf, unsigned int len);

/* Once in a while one has to compute CRC's of very long buffers.
   Indeed, of so long that one doesn't even want to do that very
   often, but for some reason needs to do. Thus it would be nice to
   have a function that would allow a short cut, and update the CRC
   with indirect computations.

   And lo and behold, one can do it pretty easily. Following few
   functions give access to CRC's innerworlds. One shall be able to
   alter contents of a buffer and compute the corresponding CRC without
   having to run the whole buffer through a CRC routine.

   Although these routines are rather cumbersome in many ways, they
   work in polynomial time (O(log(n)^k), where n is the length of the
   buffer and k is some small integer) and thus are rather efficient
   and suitable for manipulation of very large buffers. */

/* We first present the masking function. This allows one to select a
   suitable mask which xored onto the buffer will yield a desired
   result buffer. One needs to know the previous CRC value and the
   total size of the buffer, and the offset where the mask shall be
   placed. No access to the buffer is needed. This function cannot
   alter the length of the buffer. Mask can be of any length that is
   smaller or equal to the length of the buffer.
     
   */

unsigned long crc32_mask(const unsigned char *mask, unsigned int mask_len,
			 unsigned int offset,
			 unsigned int total_len,
			 unsigned long prev_crc32);

/* A function that allows one to enlarge the buffer and keep the CRC
   still correct, without computing it by brute force in exponential
   time.  This function can be used when expanding the buffer with a
   number of zero octets. 

   Note: using this function and the masking function one can indeed
   append new data to a buffer without having to compute the CRC all
   over again. */

unsigned long crc32_extend(unsigned long prev_crc32, unsigned int len);

/* A function that allows one to truncate, or shorten, the buffer, while
   keeping the CRC correct. Unfortunately this is not a general purpose
   in a sense that one needs to use this in conjunction with the masking
   method to zero the number of octets wanted to truncate and only
   after that truncate. However, all things considered this seems
   reasonable. */

unsigned long crc32_truncate(unsigned long prev_crc32,
			     unsigned int len);
     

#if 0
/* Test code. */
void gf_division_test(void);
#endif

#endif /* CRC32_H */
