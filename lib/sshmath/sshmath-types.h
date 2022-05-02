/*

  sshmath-types.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Apr 27 20:07:29 1998 [mkojo]

  Definitions for types and definitions that are often used in
  SSH arithmetic library components.

  */

/*
 * $Id: sshmath-types.h,v 1.4 1998/06/24 13:26:35 kivinen Exp $
 * $Log: sshmath-types.h,v $
 * $EndLog$
 */

#ifndef SSHMATH_TYPES_H
#define SSHMATH_TYPES_H

/* XXX One should build a way to define these things automagically.
   This is something that should be done in future. */

/* This is the current word used internally, however, one should build
   a better system later for deducing the fastest available word size. */
typedef unsigned long SshWord;
typedef long          SignedSshWord;

#define SSH_WORD_BITS (sizeof(SshWord)*8)
#define SSH_WORD_MASK (~(SshWord)0)

#endif /* SSHMATH_TYPES_H */
