/*
    Author: Mika Kojo <mkojo@ssh.fi>

    Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
    All rights reserved.

    Created: Mon Oct 28 06:41:24 1996 [mkojo]

    */

/*
 * $Id: genciph.c,v 1.29 1998/08/11 19:18:10 mjos Exp $
 * $Log: genciph.c,v $
 * $EndLog$
 */


#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "sshbuffer.h"
#include "sshgetput.h"
#include "nociph.h"
#include "sha.h"
#ifdef SSHDIST_CRYPT_DES
#include "des.h"
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_BLOWFISH
#include "blowfish.h"
#endif /* SSHDIST_CRYPT_BLOWFISH */
#ifdef SSHDIST_CRYPT_CAST

#endif /* SSHDIST_CRYPT_CAST */

#ifdef SSHDIST_CRYPT_ARCFOUR
#include "arcfour.h"
#endif /* SSHDIST_CRYPT_ARCFOUR */

#ifdef SSHDIST_CRYPT_SEAL

#endif /* SSHDIST_CRYPT_SEAL */

#ifdef SSHDIST_CRYPT_IDEA



#endif /* SSHDIST_CRYPT_IDEA */

#ifdef SSHDIST_CRYPT_SAFER

#endif /* SSHDIST_CRYPT_SAFER */

#ifdef SSHDIST_CRYPT_TWOFISH

#endif /* SSHDIST_CRYPT_TWOFISH */

#ifdef SSHDIST_CRYPT_RC5

#endif /* SSHDIST_CRYPT_RC5 */

#ifdef SSHDIST_CRYPT_RC6

#endif /* SSHDIST_CRYPT_RC6 */

#ifdef SSHDIST_CRYPT_SKIPJACK

#endif /* SSHDIST_CRYPT_SKIPJACK */

#ifdef SSHDIST_CRYPT_MARS

#endif /* SSHDIST_CRYPT_MARS */

/* Algorithm definitions */

static const SshCipherDef ssh_cipher_algorithms[] =
{
#ifdef SSHDIST_CRYPT_DES
  { "3des-ecb", 8, 24, des3_ctxsize, des3_init, des3_ecb,
    des3_set_iv, des3_get_iv },
  { "3des-cbc", 8, 24, des3_ctxsize, des3_init, des3_cbc,
    des3_set_iv, des3_get_iv },
  { "3des-cfb", 8, 24, des3_ctxsize, des3_init, des3_cfb,
    des3_set_iv, des3_get_iv },    
  { "3des-ofb", 8, 24, des3_ctxsize, des3_init, des3_ofb,
    des3_set_iv, des3_get_iv },
#endif /* SSHDIST_CRYPT_DES */

#ifdef SSHDIST_CRYPT_CAST













#endif /* SSHDIST_CRYPT_CAST */
  
#ifdef SSHDIST_CRYPT_BLOWFISH
  { "blowfish-ecb", 8, 0,
    blowfish_ctxsize, blowfish_init,
    blowfish_ecb, blowfish_set_iv, blowfish_get_iv },
  { "blowfish-cbc", 8, 0,
    blowfish_ctxsize, blowfish_init,
    blowfish_cbc, blowfish_set_iv, blowfish_get_iv },
  { "blowfish-cfb", 8, 0,
    blowfish_ctxsize, blowfish_init,
    blowfish_cfb, blowfish_set_iv, blowfish_get_iv },
  { "blowfish-ofb", 8, 0,
    blowfish_ctxsize, blowfish_init,
    blowfish_ofb, blowfish_set_iv, blowfish_get_iv },
#endif /* SSHDIST_CRYPT_BLOWFISH */
    
#ifdef SSHDIST_CRYPT_DES
  { "des-ecb", 8, 8, des_ctxsize, des_init, des_ecb, des_set_iv, des_get_iv },
  { "des-cbc", 8, 8, des_ctxsize, des_init, des_cbc, des_set_iv, des_get_iv },
  { "des-cfb", 8, 8, des_ctxsize, des_init, des_cfb, des_set_iv, des_get_iv },
  { "des-ofb", 8, 8, des_ctxsize, des_init, des_ofb, des_set_iv, des_get_iv },
#endif /* SSHDIST_CRYPT_DES */
  
#ifdef SSHDIST_CRYPT_IDEA










#endif /* SSHDIST_CRYPT_IDEA */
  
#ifdef SSHDIST_CRYPT_SAFER  



































#endif /* SSHDIST_CRYPT_SAFER */

#ifdef SSHDIST_CRYPT_ARCFOUR
  { "arcfour", 1, 0, arcfour_ctxsize, arcfour_init, arcfour_transform,
    NULL, NULL },
#endif /* SSHDIST_CRYPT_ARCFOUR */

#ifdef SSHDIST_CRYPT_SEAL

#endif /* SSHDIST_CRYPT_SEAL */

#ifdef SSHDIST_CRYPT_TWOFISH












#endif /* SSHDIST_CRYPT_TWOFISH */

#ifdef SSHDIST_CRYPT_RC5


























#endif /* SSHDIST_CRYPT_RC5 */

#ifdef SSHDIST_CRYPT_RC6








#endif /* SSHDIST_CRYPT_RC6 */

#ifdef SSHDIST_CRYPT_SKIPJACK








#endif /* SSHDIST_CRYPT_SKIPJACK */
  
#ifdef SSHDIST_CRYPT_MARS








#endif /* SSHDIST_CRYPT_MARS */

  { "none", 1, 0, NULL, NULL, none_transform, NULL, NULL },
  
  { NULL }
};

/* Mapping from common cipher names to `canonical' ones. */
struct SshCipherAliasRec {
  char *name;
  char *real_name;
};

/* Common cipher names. */
struct SshCipherAliasRec ssh_cipher_aliases[] =
{
#ifdef SSHDIST_CRYPT_DES
  { "des", "des-cbc" },
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_DES
  { "3des", "3des-cbc" },
#endif /* SSHDIST_CRYPT_DES */
#ifdef SSHDIST_CRYPT_CAST

#endif /* SSHDIST_CRYPT_CAST */
#ifdef SSHDIST_CRYPT_BLOWFISH
  { "blowfish", "blowfish-cbc" },
#endif /* SSHDIST_CRYPT_BLOWFISH */
#ifdef SSHDIST_CRYPT_IDEA

#endif /* SSHDIST_CRYPT_IDEA */
#ifdef SSHDIST_CRYPT_SAFER

#endif /* SSHDIST_CRYPT_SAFER */
#ifdef SSHDIST_CRYPT_TWOFISH

#endif /* SSHDIST_CRYPT_TWOFISH */
#ifdef SSHDIST_CRYPT_RC5

#endif /* SSHDIST_CRYPT_RC5 */
#ifdef SSHDIST_CRYPT_RC6

#endif /* SSHDIST_CRYPT_RC6 */
#ifdef SSHDIST_CRYPT_SKIPJACK

#endif /* SSHDIST_CRYPT_SKIPJACK */
  { NULL, NULL }
};

struct SshCipherRec {
  const SshCipherDef *ops;
  void *context;
};

/* Get corresponding cipher def record by cipher name */
static const SshCipherDef *ssh_cipher_get_cipher_def_internal(const char *name)
{
  int i, j;

  if (name == NULL)
    return NULL;

  for (i = 0; ssh_cipher_algorithms[i].name; i++)
    {
      if (strcmp(ssh_cipher_algorithms[i].name, name) == 0)
	{
	  return &(ssh_cipher_algorithms[i]);
	}
    }
  for (i = 0; ssh_cipher_aliases[i].name; i++)
    {
      if (strcmp(ssh_cipher_aliases[i].name, name) == 0)
	{
	  name = ssh_cipher_aliases[i].real_name;
	  for (j = 0; ssh_cipher_algorithms[j].name; j++)
	    {
	      if (strcmp(ssh_cipher_algorithms[j].name, name) == 0)
		{
		  return &(ssh_cipher_algorithms[j]);
		}
	    }
	}
    }
  return NULL;
}

/* Get the native name of the cipher. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_native_name(const char *name)
{
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);

  if (cipher_def == NULL)
    return NULL;

  return ssh_xstrdup(cipher_def->name);
}

/* Check if given cipher name belongs to the set of supported ciphers
   and is not an alias. */

static Boolean ssh_cipher_supported_native(const char *name)
{
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);

  if (cipher_def == NULL)
    return FALSE;


  if (strcmp(name, cipher_def->name) != 0)
    return FALSE;

  return TRUE;
}

/* Check if given cipher name belongs to the set of supported ciphers
   aliases included. */

DLLEXPORT Boolean DLLCALLCONV
ssh_cipher_supported(const char *name)
{
  if (ssh_cipher_get_cipher_def_internal(name) != NULL)
    return TRUE;

  return FALSE;
}

/* Return a comma-separated list of supported native cipher algorithm names. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_supported_native(void)
{
  int i;
  SshBuffer buf;
  char *list;

  ssh_buffer_init(&buf);
  for (i = 0; ssh_cipher_algorithms[i].name != NULL; i++)
    {
      if (ssh_buffer_len(&buf) != 0)
	ssh_buffer_append(&buf, (unsigned char *) ",", 1);
      ssh_buffer_append(&buf, (unsigned char *) ssh_cipher_algorithms[i].name,
		    strlen(ssh_cipher_algorithms[i].name));
    }
  ssh_buffer_append(&buf, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buf));
  ssh_buffer_uninit(&buf);
  return list;
}

/* Return a comma-separated list of supported cipher algorithm names
   alias names included. */

DLLEXPORT char * DLLCALLCONV
ssh_cipher_get_supported(void)
{
  int i;
  SshBuffer buf;
  char *list;

  ssh_buffer_init(&buf);
  list = ssh_cipher_get_supported_native();
  ssh_buffer_append(&buf, (unsigned char *)list, strlen(list));
  ssh_xfree(list);

  for (i = 0; ssh_cipher_aliases[i].name != NULL; i++)
    {
      if (ssh_cipher_supported_native(ssh_cipher_aliases[i].real_name))
	{
	  if (ssh_buffer_len(&buf) != 0)
	    ssh_buffer_append(&buf, (unsigned char *) ",", 1);
	  ssh_buffer_append(&buf, 
			    (unsigned char *) ssh_cipher_aliases[i].name,
			    strlen(ssh_cipher_aliases[i].name));
	}
    }
  ssh_buffer_append(&buf, (unsigned char *) "\0", 1);
  list = ssh_xstrdup(ssh_buffer_ptr(&buf));
  ssh_buffer_uninit(&buf);
  return list;
}

/* Allocates and initializes a cipher of the specified name. */

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_internal(const char *name,
			     const unsigned char *key,
			     size_t keylen,
			     Boolean for_encryption,
			     SshCipher *cipher,
			     Boolean expand,
			     Boolean test_weak_keys)
{
  unsigned char *expanded_key;
  unsigned int expanded_key_len;
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return SSH_CRYPTO_UNSUPPORTED;

  if (keylen == 0 && expand == FALSE)
    return SSH_CRYPTO_KEY_TOO_SHORT;
  
  if (expand)
    {
      expanded_key_len = cipher_def->key_length;
      if (expanded_key_len == 0)
	expanded_key_len = SSH_CIPHER_MINIMAL_KEY_LENGTH;
      
      expanded_key = ssh_xmalloc(expanded_key_len);
      ssh_hash_expand_key_internal(expanded_key, expanded_key_len,
				   key, keylen,
				   NULL, 0,
				   &ssh_hash_sha_def);
    }
  else
    {
      expanded_key_len = keylen;
      expanded_key = (unsigned char *)key;
    }
  
  if (expanded_key_len < cipher_def->key_length)
    {
      if (expand)
	ssh_fatal("internal error: key expansion corrupted.");
      
      return SSH_CRYPTO_KEY_TOO_SHORT;
    }
  
  *cipher = ssh_xmalloc(sizeof(**cipher));
  (*cipher)->ops = cipher_def;
  if (cipher_def->ctxsize)
    {
      (*cipher)->context =
	ssh_xmalloc((*cipher_def->ctxsize)());
      (*cipher_def->init)((*cipher)->context,
			  expanded_key,
			  expanded_key_len,
			  for_encryption);
    }
  else
    {
      (*cipher)->context = NULL;
    }
  
  if (expand)
    ssh_xfree(expanded_key);
  
  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate(const char *name,
		    const unsigned char *key,
		    size_t keylen,
		    Boolean for_encryption,
		    SshCipher *cipher)
{
  return ssh_cipher_allocate_internal(name, key, keylen, for_encryption,
				      cipher, FALSE, FALSE);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_with_passphrase(const char *name,
				    const char *passphrase,
				    Boolean for_encryption,
				    SshCipher *cipher)
{
  return ssh_cipher_allocate_internal(name, (unsigned char *) passphrase,
				      strlen(passphrase),
				      for_encryption, cipher, TRUE, FALSE);
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_allocate_and_test_weak_keys(const char *name,
				       const unsigned char *key,
				       size_t keylen,
				       Boolean for_encryption,
				       SshCipher *cipher)
{
  return ssh_cipher_allocate_internal(name, key, keylen,
				      for_encryption, cipher,
				      FALSE, TRUE);
}

/* Free the cipher context */

DLLEXPORT void DLLCALLCONV
ssh_cipher_free(SshCipher cipher)
{
  ssh_xfree(cipher->context);
  ssh_xfree(cipher);
}

DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_key_length(const char *name)
{
  const SshCipherDef *cipher_def;

  cipher_def = ssh_cipher_get_cipher_def_internal(name);
  if (cipher_def == NULL)
    return 0;

  return cipher_def->key_length;
}

DLLEXPORT size_t DLLCALLCONV
ssh_cipher_get_block_length(SshCipher cipher)
{
  return cipher->ops->block_length;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_set_iv(SshCipher cipher,
		  const unsigned char *iv)
{
  if (cipher->ops->set_iv == NULL)
    return SSH_CRYPTO_UNSUPPORTED;
     
  (*cipher->ops->set_iv)(cipher->context, iv);

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_get_iv(SshCipher cipher,
		  unsigned char *iv)
{
  if (cipher->ops->get_iv == NULL)
    return SSH_CRYPTO_UNSUPPORTED;
     
  (*cipher->ops->get_iv)(cipher->context, iv);

  return SSH_CRYPTO_OK;
}

DLLEXPORT SshCryptoStatus DLLCALLCONV
ssh_cipher_transform(SshCipher cipher,
		     unsigned char *dest,
		     const unsigned char *src,
		     size_t len)
{
  /* Check that the src length is divisible by block length of the cipher. */
  if (len % cipher->ops->block_length == 0)
    (*cipher->ops->transform)(cipher->context, dest, src, len);
  else
    return SSH_CRYPTO_BLOCK_SIZE_ERROR;

  return SSH_CRYPTO_OK;
}
