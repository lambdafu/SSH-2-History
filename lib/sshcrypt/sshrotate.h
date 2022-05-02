/*

  sshrotate.h

  Author: Markku-Juhani Saarinen <mjos@math.jyu.fi>

  Copyright (C) 1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  (cyclic) rotations of words

 */

#ifndef SSHROTATE_H
#define SSHROTATE_H

/* -- look for platform specific rotation primitives -- */

#ifdef _MSC_VER
#include <stdlib.h>

#undef SSH_ROL32
#undef SSH_ROR32

#pragma intrinsic(_lrotl,_lrotr)
#define SSH_ROL32(x, n) _lrotl(x, n)                     
#define SSH_ROR32(x, n) _lrotr(x, n)
#endif /* _MSC_VER */


/* -- fall back to generic ANSI C rotations -- */

/* cyclic shift left */

#ifndef SSH_ROL16
#define SSH_ROL16(x, y) (((x) << ((y) & 15)) | ((x) >> (16 - ((y) & 15))))
#endif /* SSH_ROL16 */

#ifndef SSH_ROL32
#define SSH_ROL32(x, y) (((x) << ((y) & 31)) | ((x) >> (32 - ((y) & 31))))
#endif /* SSH_ROL32 */


/* cyclic shift right */

#ifndef SSH_ROR16
#define SSH_ROR16(x, y) (((x) >> ((y) & 15)) | ((x) << (16 - ((y) & 15))))
#endif /* SSH_ROR16 */

#ifndef SSH_ROR32
#define SSH_ROR32(x, y) (((x) >> ((y) & 31)) | ((x) << (32 - ((y) & 31))))
#endif /* SSH_ROR32 */

#endif /* SSHROTATE_H */
