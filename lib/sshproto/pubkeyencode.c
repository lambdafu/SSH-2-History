/*
  
  pubkeyencode.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Encodes and decodes ssh2-format public key blobs.
  
*/

#include "sshincludes.h"
#include "sshauth.h"
#include "gmp.h"
#include "sshcrypt.h"
#include "sshencode.h"
#include "bufaux.h"
#include "sshdebug.h"
#include "sshcipherlist.h"

/* define this to dump all keys encoded/decoded */
#undef DUMP_KEYS

/* define this to dump key blobs going in/out */
#undef DUMP_BLOBS

/* Encode a public key into a SSH2 format blob. Return size or 0 on
   failure. */

size_t ssh_encode_pubkeyblob(SshPublicKey pubkey, unsigned char **blob)
{
  mpz_t p, q, g, y;  /* DSS public parameters */
#ifdef SSHDIST_CRYPT_RSA



#endif /* SSHDIST_CRYPT_RSA */
  SshBuffer *buf;
  size_t len;
  char *keytype;

 /* try to determine the exact type of the public key */

  if ((keytype = ssh_public_key_name(pubkey)) == NULL)
    {
      ssh_debug("ssh_encode_pubkeyblob: failed to extract "
                "key type information.");
      return 0;
    }

  /* -- DSS key type -- */

  /* this is sort of kludge-ish */
  if (strstr(keytype, "sign{dsa-nist") != NULL)
    {
      /* dig out the public parameters */

      mpz_init(p);
      mpz_init(q);
      mpz_init(g);
      mpz_init(y);

      if (ssh_public_key_get_info(pubkey, 
				  SSH_PKF_PRIME_P, p,
				  SSH_PKF_PRIME_Q, q,
				  SSH_PKF_GENERATOR_G, g, 
				  SSH_PKF_PUBLIC_Y, y,
				  SSH_PKF_END) 
	  != SSH_CRYPTO_OK)
	{
	  ssh_debug("ssh_encode_pubkeyblob: failed to get "
                    "internal parameters from a DSS public key.");
	  return 0;
	}

      /* construct the public key string */

      buf = ssh_buffer_allocate();

      buffer_put_uint32_string(buf, SSH_SSH_DSS, strlen(SSH_SSH_DSS));
      buffer_put_mp_int_ssh2style(buf, p);
      buffer_put_mp_int_ssh2style(buf, q);
      buffer_put_mp_int_ssh2style(buf, g);
      buffer_put_mp_int_ssh2style(buf, y);

#ifdef DUMP_KEYS
      printf("encode:\n p = ");
      mpz_out_str(stdout, 16, p);
      printf("\n q = ");    
      mpz_out_str(stdout, 16, q);
      printf("\n g = ");    
      mpz_out_str(stdout, 16, g);
      printf("\n y = ");    
      mpz_out_str(stdout, 16, y);
      printf("\n\n");
#endif

      mpz_clear(p);
      mpz_clear(q);
      mpz_clear(g);
      mpz_clear(y);

#ifdef DUMP_BLOBS
      ssh_debug("ssh_decode_pubkeyblob:");
      buffer_dump(buf);
#endif

      len = ssh_buffer_len(buf);
      *blob = ssh_xmalloc(len);
      memcpy(*blob, ssh_buffer_ptr(buf), len);
      ssh_buffer_free(buf);

      return len;
    }

#ifdef SSHDIST_CRYPT_RSA


















































#endif /* SSHDIST_CRYPT_RSA */

  ssh_debug("ssh_encode_pubkeyblob: unrecognized key type %s", keytype);
  return 0;
}


/* Decode a public key blob. Return NULL on failure. */

SshPublicKey ssh_decode_pubkeyblob(unsigned char *blob, size_t bloblen)
{
  unsigned char *keytype;
  SshPublicKey pubkey;
  mpz_t p, q, g, y;  /* DSS public parameters */
#ifdef SSHDIST_CRYPT_RSA



#endif /* SSHDIST_CRYPT_RSA */
  SshCryptoStatus code;
  SshBuffer *buf;

#ifdef DUMP_BLOBS
  ssh_debug("ssh_decode_pubkeyblob:");
  ssh_debug_hexdump(0, blob, bloblen);
#endif

  buf = ssh_buffer_allocate();
  ssh_buffer_append(buf, blob, bloblen);
  
  if (ssh_decode_buffer(buf,
			SSH_FORMAT_UINT32_STR, &keytype, NULL,
			SSH_FORMAT_END) == 0)
    return NULL;
  
  /* -- DSS key type -- */

  if (strcmp(SSH_SSH_DSS, (char *) keytype) == 0)
    { 
      mpz_init(p);
      mpz_init(q);
      mpz_init(g);
      mpz_init(y);

      buffer_get_mp_int_ssh2style(buf, p);
      buffer_get_mp_int_ssh2style(buf, q);
      buffer_get_mp_int_ssh2style(buf, g);
      buffer_get_mp_int_ssh2style(buf, y);
      
      /* ok, construct the public key */
      
      code = ssh_public_key_define(&pubkey,
				   SSH_CRYPTO_DSS,
				   SSH_PKF_PRIME_P, p,
				   SSH_PKF_PRIME_Q, q,
				   SSH_PKF_GENERATOR_G, g, 
				   SSH_PKF_PUBLIC_Y, y,
				   SSH_PKF_END);
#ifdef DUMP_KEYS
      printf("decode:\n p = ");
      mpz_out_str(stdout, 16, p);
      printf("\n q = ");    
      mpz_out_str(stdout, 16, q);
      printf("\n g = ");    
      mpz_out_str(stdout, 16, g);
      printf("\n y = ");    
      mpz_out_str(stdout, 16, y);
      printf("\n\n");
#endif

      mpz_clear(p);
      mpz_clear(q);
      mpz_clear(g);
      mpz_clear(y);

      if (code != SSH_CRYPTO_OK)
	{
	  ssh_debug("ssh_decode_pubkeyblob: failed to set the "
		    "parameters of an DSS public key.");
	  goto fail1;
	}
    
      ssh_buffer_free(buf);
      ssh_xfree(keytype);
      return pubkey;
    }

#ifdef SSHDIST_CRYPT_RSA








































#endif /* SSHDIST_CRYPT_RSA */

  /* could not identify key type */

  ssh_debug("ssh_decode_pubkeyblob: unrecognized key type %s", 
	    keytype);  

fail1:
  ssh_buffer_free(buf);
  ssh_xfree(keytype);

  return NULL;
}

char *ssh_pubkeyblob_type(unsigned char *blob, size_t bloblen)
{
  unsigned char *keytype;
  SshBuffer *buf;

  buf = ssh_buffer_allocate();
  ssh_buffer_append(buf, blob, bloblen);
  ssh_decode_buffer(buf,
		    SSH_FORMAT_UINT32_STR, &keytype, NULL,
		    SSH_FORMAT_END);
  ssh_buffer_free(buf);
     
  return ((char *)keytype);
}
