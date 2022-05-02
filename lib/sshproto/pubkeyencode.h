/*
  
  pubkeyencode.h

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Encode and decode public key blobs.
  
*/

#ifndef PUBKEYENCODE_H
#define PUBKEYENCODE_H

#include "sshcrypt.h"

/* Encode a public key into a SSH2 format blob. Return size or 0 on
   failure. */

size_t ssh_encode_pubkeyblob(SshPublicKey pubkey, unsigned char **blob);

/* Decode a public key blob. Return NULL on failure. */

SshPublicKey ssh_decode_pubkeyblob(unsigned char *blob, size_t bloblen);

/* Type of the encoded public key in blob.  Have to be freed with ssh_xfree. */
char *ssh_pubkeyblob_type(unsigned char *blob, size_t bloblen);

#endif /* PUBKEYENCODE_H */
