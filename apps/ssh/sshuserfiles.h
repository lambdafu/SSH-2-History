/*

  sshuserfiles.h

  Authors:
        Tatu Ylönen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Simple functions that update user's files.

*/

/* 
 * $Log: sshuserfiles.h,v $
 * $EndLog$
 */

#ifndef SSHUSERFILES_H
#define SSHUSERFILES_H

#include "sshcrypt.h"
#include "sshuser.h"
#include "sshconfig.h"

/* the name of the random seed directory under the user's home directory. */

#ifndef SSH_USER_DIR
#define SSH_USER_DIR ".ssh2"
#endif /* SSH_USER_DIR */

/* the random seed file */

#ifndef SSH_RANDSEED_FILE
#ifndef SSHDIST_WINDOWS
#  define SSH_RANDSEED_FILE "random_seed"
#else /* SSHDIST_WINDOWS */

#endif /* SSHDIST_WINDOWS */
#endif /* SSH_RANDSEED_FILE */

/* the size of the random seed file (in bytes) */

#ifndef SSH_RANDSEED_LEN
#define SSH_RANDSEED_LEN 512
#endif /* SSH_RANDSEED_LEN */

/* the standard cipher used for passphrase encryption */

#ifndef SSH_PASSPHRASE_CIPHER
#define SSH_PASSPHRASE_CIPHER "3des-cbc"
#endif /* SSH_PASSPHRASE_CIPHER */

/* the standard "authorization" file */

#ifndef SSH_AUTHORIZATION_FILE
#define SSH_AUTHORIZATION_FILE "authorization"
#endif /* SSH_AUTHORIZATION_FILE */

/* the separator for forced commands in the users
   "authorization" file.*/
#ifndef FORCED_COMMAND_ID
#define FORCED_COMMAND_ID "command"
#endif /* FORCED_COMMAND_ID */

/* the standard "identification" file */

#ifndef SSH_IDENTIFICATION_FILE
#define SSH_IDENTIFICATION_FILE "identification"
#endif /* SSH_IDENTIFICATION_FILE */

/* the standard "hostkey" file */
#ifndef SSHDIST_WINDOWS
#  ifndef SSH_HOSTKEY_FILE
#    define SSH_HOSTKEY_FILE "hostkey"
#  endif /* SSH_HOSTKEY_FILE */
#  ifndef SSH_PUBLIC_HOSTKEY
#    define SSH_PUBLIC_HOSTKEY "hostkey.pub"
#  endif
#else /* SSHDIST_WINDOWS */






#endif /* SSHDIST_WINDOWS */
/* server directory */

#ifndef SSH_SERVER_DIR
#define SSH_SERVER_DIR "/etc/ssh2"
#endif /* SSH_SERVER_DIR */

/* global configuration file for the client */

#ifndef SSH_CLIENT_GLOBAL_CONFIG_FILE
#define SSH_CLIENT_GLOBAL_CONFIG_FILE "/etc/ssh2/ssh2_config"
#endif /* SSH_CLIENT_GLOBAL_CONFIG_FILE */

/* configuration file for the client */

#ifndef SSH_CLIENT_CONFIG_FILE
#define SSH_CLIENT_CONFIG_FILE "ssh2_config"
#endif /* SSH_CLIENT_CONFIG_FILE */

/* configuration file for the server */

#ifndef SSH_SERVER_CONFIG_FILE
#define SSH_SERVER_CONFIG_FILE "sshd2_config"
#endif /* SSH_SERVER_CONFIG_FILE */

#ifdef SSHDIST_WINDOWS







#endif /* SSHDIST_WINDOWS */

/* Magic identifying codes for private and public key files. */

#define SSH_KEY_MAGIC_FAIL              0
#define SSH_KEY_MAGIC_PUBLIC            0x73736801
#define SSH_KEY_MAGIC_PRIVATE           0x73736802
#define SSH_KEY_MAGIC_PRIVATE_ENCRYPTED 0x73736803

#ifndef SSHDIST_WINDOWS
/* Return a pointer to user's ssh2 directory.
   The directory is created if `create_if_needed' is TRUE. 
   Return NULL on failure.  The returned value has been allocated with ssh_xmalloc,
   and the caller is responsible for freeing it with ssh_xfree when no longer
   needed. */
char *ssh_userdir(SshUser user, Boolean create_if_needed);

/* Make sure that the random seed file exists and return a pointer to it. 
   return NULL on failure. The file name is found from `config'. 
   If `config' is NULL, use the standard SSH_RANDSEED_FILE.

   The caller is responsible for freeing the returned value with ssh_xfree 
   when no longer needed. */
char *ssh_randseed_file(SshUser user, SshConfig config);

/* Get the random state from the file.  This loads and merges any data
   in the seed file into the generator. */

void ssh_randseed_load(SshUser user, SshRandomState random_state,
		       SshConfig config);

#endif /* SSHDIST_WINDOWS */

/* Reads a blob into a buffer. Return TRUE on failure.  The caller must free
   `*blob' with ssh_xfree when no longer needed. */
Boolean ssh_blob_read(SshUser user, const char *fname, unsigned char **blob, 
		      size_t *bloblen, void *context);

/* Write a blob. Return TRUE on failure. */
Boolean ssh_blob_write(SshUser user, const char *fname, mode_t mode,
		       const unsigned char *blob, size_t bloblen, 
		       void *context);

/* Read a public/private key blob from a file. Return the magic code
   or SSH_KEY_MAGIC_FAIL on failure.  The caller should free comment
   with ssh_xfree when no longer needed. */
unsigned long ssh_key_blob_read(SshUser user, const char *fname, 
				char **comment,
				unsigned char **blob,
				size_t *bloblen, void *context);

/* Write a key blob. Return TRUE on failure. */
Boolean ssh_key_blob_write(SshUser user, const char *fname, mode_t mode,
			   unsigned long magic,
			   const char *comment, const unsigned char *key,
			   size_t keylen, void * context);

/* Get the random state from the file.  The caller is responsible for
   freeing the random number generator with ssh_random_free, or closing and
   updating to the seed file with ssh_randseed_close (recommended) when no
   longer needed. */
SshRandomState ssh_randseed_open(SshUser user, SshConfig config);

/* Updates the random seed file with information from the random
   number generator.  Information from the old random seed file and
   the generator is mixed, so that the new random seed file will
   contain traces of both the generator state and the old seed
   file. */
void ssh_randseed_update(SshUser user, SshRandomState rs, SshConfig config);

/* Read a public key from a file. Return NULL on failure.  The caller is
   responsible for freeing `comment' with ssh_xfree when no longer needed.
   `comment' can be NULL. */
SshPublicKey ssh_pubkey_read(SshUser user, const char *fname, char **comment, 
			     void * context);

/* Write a public key to a file. Returns TRUE on error. */
Boolean ssh_pubkey_write(SshUser user, const char *fname, const char *comment,
			 SshPublicKey key, void *context);

/* Read a private key from a file. Return NULL on failure.  The caller should
   free `comment' with ssh_xfree when no longer needed.  `comment' can be NULL. */
SshPrivateKey ssh_privkey_read(SshUser user, const char *fname,
			       const char *passphrase, 
			       char **comment, void *context);

/* Write a private key to a file with a passphrase. Return TRUE on error. */
Boolean ssh_privkey_write(SshUser user,
			  const char *fname, const char *passphrase,
			  const char *comment,
			  SshPrivateKey key, SshRandomState rand,
			  void *context);

/* build a list of private key files that should be tried when
   logging into `host'.  The list's last entry is NULL.
   The caller should free the array and all strings in it with ssh_xfree when 
   no longer needed. */
char **ssh_privkey_list(SshUser user, char *host, SshConfig config);

#endif /* SSHUSERFILES_H */
