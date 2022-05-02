/*

  dlglue.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu May 22 16:27:34 1997 [mkojo]

  Discrete logarithm based public key routines.

  */

/*
 * $Id: dlglue.c,v 1.15 1998/06/15 19:20:59 mkojo Exp $
 * $Log: dlglue.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "gmp.h"
#include "sshcrypt.h"
#include "sshcrypti.h"
#include "genmp.h"
#include "sshgetput.h"
#include "cstack.h"
#include "dlfix.h"
#include "dlglue.h"
#include "sshencode.h"

/********************** Stack routines ************************/

#define SSH_DLP_STACK_RANDOMIZER  0x1
  
/* Randomizer */
  
SSH_CSTACK_BEGIN( SshDLStackRandomizer )
  MP_INT k;
  MP_INT gk;
SSH_CSTACK_END( SshDLStackRandomizer );
  
/* Allocation and deletion of stack elements. */
    
/* Randomizer */

SSH_CSTACK_DESTRUCTOR_BEGIN( SshDLStackRandomizer, stack )
  mpz_clear(&stack->k);
  mpz_clear(&stack->gk);
SSH_CSTACK_DESTRUCTOR_END( SshDLStackRandomizer, stack )

SSH_CSTACK_CONSTRUCTOR_BEGIN( SshDLStackRandomizer, stack, context,
			      SSH_DLP_STACK_RANDOMIZER )
  mpz_init(&stack->k);
  mpz_init(&stack->gk); 
SSH_CSTACK_CONSTRUCTOR_END( SshDLStackRandomizer, stack )

/********************** Discrete Logarithm ********************/

/* Discrete Logarithm parameter structures. */

/*
   Parameters are in a list, and contain the stack used in many
   operations. 
  
   p - prime
   g - generator
   q - order of g (prime)
   */
typedef struct SshDLParamRec
{
  struct SshDLParamRec *next, *prev;
  SshCStack *stack;
  unsigned int reference_count;

  /* Predefined parameter sets have this defined. */
  const char *predefined;

  /* Actual parameter information. */
  MP_INT p;
  MP_INT g;
  MP_INT q;

  /* Information about the policy when generating random numbers. */
  unsigned int exponent_entropy;
} SshDLParam;

/* Global parameter list. This will contain only _unique_ parameters,
   allowing the generation of randomizers in transparent way. */

SshDLParam *ssh_dlp_param_list = NULL;

/* Routines for parameter handling. */

void ssh_dlp_init_param(SshDLParam *param)
{
  param->next = NULL;
  param->prev = NULL;
  param->stack = NULL;
  param->reference_count = 0;

  /* We assume that this parameter set is not predefined. */
  param->predefined = NULL;
  
  mpz_init(&param->p);
  mpz_init(&param->g);
  mpz_init(&param->q);

  /* Handle the entropy! Lets denote by zero that most secure settings
     should be used. */
  param->exponent_entropy = 0;
}

/* Free parameter set only if reference count tells so. */
void ssh_dlp_clear_param(SshDLParam *param)
{
  /* Keep the linked list updated. */
  if (param->prev)
    param->prev->next = param->next;
  else
    {
      /* In this case we might have the first entry in the
	 parameter list either different or equal to the parameters
	 in question. */
      if (ssh_dlp_param_list == param)
	ssh_dlp_param_list = param->next;
    }
  if (param->next)
    param->next->prev = param->prev;
  
  /* Free stack. */
  ssh_cstack_free(param->stack);
  
  mpz_clear(&param->p);
  mpz_clear(&param->g);
  mpz_clear(&param->q);

  /* Clean pointers. */
  param->next  = NULL;
  param->prev  = NULL;
  param->stack = NULL;
}

SshDLParam *ssh_dlp_param_list_add(SshDLParam *param)
{
  SshDLParam *temp;

  temp = ssh_dlp_param_list;
  while (temp)
    {
      if (mpz_cmp(&temp->p, &param->p) == 0 &&
	  mpz_cmp(&temp->q, &param->q) == 0 &&
	  mpz_cmp(&temp->g, &param->g) == 0 &&

	  /* Must also check the policies! */
	  temp->exponent_entropy == param->exponent_entropy)
	{
	  temp->reference_count++;
	  return temp;
	}
      temp = temp->next;
    }
  
  /* Make first, that is this is the first incarnation of a
     parameter set with these settings. */
  param->next = ssh_dlp_param_list;
  if (ssh_dlp_param_list)
    ssh_dlp_param_list->prev = param;
  param->reference_count++;
  ssh_dlp_param_list = param;
  return NULL;
}

/* Decode one parameter blob. */
size_t ssh_dlp_param_decode(const unsigned char *buf, size_t len,
			    va_list *ap)
{
  unsigned int *value;
  SshDLParam *param;
  size_t ret_value;
  char *predefined;

  if (buf == SSH_DECODE_FREE)
    return 0;

  param = va_arg(*ap, SshDLParam *);
  value = va_arg(*ap, unsigned int *);

  if (*value == 0)
    {
      return ssh_decode_array(buf, len,
			      SSH_FORMAT_MP_INT, &param->p,
			      SSH_FORMAT_MP_INT, &param->g,
			      SSH_FORMAT_MP_INT, &param->q,
			      SSH_FORMAT_END);
    }
  else
    {
      ret_value = ssh_decode_array(buf, len,
				   SSH_FORMAT_UINT32_STR, &predefined,
				   SSH_FORMAT_END);
      if (ret_value != 0)
	{
	  if (ssh_dlp_set_param(predefined, &param->predefined,
				&param->p, &param->q,
				&param->g) == FALSE)
	    {
	      ssh_xfree(predefined);
	      return 0;
	    }
	}
      else
	return ret_value;
      ssh_xfree(predefined);
      return ret_value;
    }
}

Boolean ssh_dlp_param_import(const unsigned char *buf,
			     size_t len, 
			     void **parameters)
{
  SshDLParam *param, *temp;
  unsigned int value;
  
  param = ssh_xmalloc(sizeof(*param));
  ssh_dlp_init_param(param);

  /* Decode */
  if (ssh_decode_array(buf, len,
		       SSH_FORMAT_UINT32, &value,
		       SSH_FORMAT_EXTENDED,
		       ssh_dlp_param_decode, param, &value,
		       SSH_FORMAT_END) == 0)
    {
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      return FALSE;
    }

  /* Check the global parameter list, if already exists then
     just use reference counting. */
  temp = ssh_dlp_param_list_add(param);
  if (temp)
    {
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      param = temp;
    }
  
  /* Reading was successful. */
  *parameters = (void *)param;
  
  return TRUE;
}

void ssh_dlp_param_encode(SshBuffer *buffer, va_list *ap)
{
  SshDLParam *param = va_arg(*ap, SshDLParam *);

  if (param->predefined)
    {
      ssh_encode_buffer(buffer,
			SSH_FORMAT_UINT32, 1,
			SSH_FORMAT_UINT32_STR, param->predefined,
			strlen(param->predefined),
			SSH_FORMAT_END);
    }
  else
    {
      ssh_encode_buffer(buffer,
			SSH_FORMAT_UINT32, 0,
			SSH_FORMAT_MP_INT, &param->p,
			SSH_FORMAT_MP_INT, &param->g,
			SSH_FORMAT_MP_INT, &param->q,
			SSH_FORMAT_END);
    }
}

Boolean ssh_dlp_param_export(const void *parameters,
			     unsigned char **buf,
			     size_t *length_return)
{
  const SshDLParam *param = parameters;

  *length_return =
    ssh_encode_alloc(buf,
		     SSH_FORMAT_EXTENDED, ssh_dlp_param_encode, param,
		     SSH_FORMAT_END);
  
  return TRUE;
}

void ssh_dlp_param_free(void *parameters)
{
  SshDLParam *param = parameters;

  if (param->reference_count == 0)
    ssh_fatal("ssh_dlp_param_free: reference counting failed.");
  
  if (--param->reference_count > 0)
    return;
  
  ssh_dlp_clear_param(param);
  ssh_xfree(parameters);
}

void ssh_dlp_param_copy(void *param_src, void **param_dest)
{
  SshDLParam *param = param_src;
  param->reference_count++;
  *param_dest = param_src;
}

void *ssh_dlp_param_generate(int bits, int small_bits, SshRandomState state)
{
  SshDLParam *param = ssh_xmalloc(sizeof(*param)), *temp;
  
  ssh_dlp_init_param(param);

retry:
  ssh_mp_random_strong_prime(&param->p, &param->q, bits, small_bits, state);

  if (ssh_mp_random_generator(&param->g, &param->q, &param->p, state) != TRUE)
    {
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      return NULL;
    }

  /* Check the parameter list for completeness, if these parameters
     happen to be there everything could blow up. */
  temp = ssh_dlp_param_list_add(param);
  if (temp)
    {
      /* XXX */
      ssh_dlp_param_free(temp);
      goto retry;
    }

  return (void *)param;
}

/* Discrete Logarithm key structures. */

/* Public key:

   parameters and
   y - public key (g^x mod p)
   */

typedef struct SshDLPublicKeyRec
{
  SshDLParam *param;
  MP_INT y;
} SshDLPublicKey;

/* Private key:

   parameters and
   y - public key (g^x mod p)
   x - private key
   */

typedef struct SshDLPrivateKeyRec
{
  SshDLParam *param;
  MP_INT x;
  MP_INT y;
} SshDLPrivateKey;

/* Discrete Logarithms key control functions. */

void ssh_dlp_init_public_key(SshDLPublicKey *pub_key, SshDLParam *param)
{
  /* Reference count, parameter indexed from here also. */
  param->reference_count++;
  pub_key->param = param;
  mpz_init(&pub_key->y);
}

void ssh_dlp_clear_public_key(SshDLPublicKey *pub_key)
{
  mpz_clear(&pub_key->y);
  ssh_dlp_param_free(pub_key->param);
}

void ssh_dlp_init_private_key(SshDLPrivateKey *prv_key, SshDLParam *param)
{
  /* Reference count, parameter indexed from here also. */
  param->reference_count++;
  prv_key->param = param;
  mpz_init(&prv_key->y);
  mpz_init(&prv_key->x);
}

void ssh_dlp_clear_private_key(SshDLPrivateKey *prv_key)
{
  mpz_clear(&prv_key->y);
  mpz_clear(&prv_key->x);
  ssh_dlp_param_free(prv_key->param);
}

/* Public key primitives. */

Boolean ssh_dlp_public_key_import(const unsigned char *buf,
				  size_t len,
				  void **public_key)
{
  SshDLPublicKey *pub_key;
  SshDLParam *param, *temp;
  MP_INT y;
  unsigned int value;

  param = ssh_xmalloc(sizeof(*param));
  ssh_dlp_init_param(param);
  mpz_init(&y);
  
  if (ssh_decode_array(buf, len,
		       SSH_FORMAT_UINT32, &value,
		       SSH_FORMAT_EXTENDED,
		       ssh_dlp_param_decode, param, &value,
		       SSH_FORMAT_MP_INT, &y,
		       SSH_FORMAT_END) == 0)
    {
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      return FALSE;
    }
  
  /* Verify that this is unique parameter set. */
  temp = ssh_dlp_param_list_add(param);
  if (temp)
    {
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      param = temp;
    }

  pub_key = ssh_xmalloc(sizeof(*pub_key));
  ssh_dlp_init_public_key(pub_key, param);

  mpz_set(&pub_key->y, &y);
  mpz_clear(&y);
  
  /* Reading was successful. */
  *public_key = (void *)pub_key;
  
  return TRUE;
}

Boolean ssh_dlp_public_key_export(const void *public_key,
				  unsigned char **buf,
				  size_t *length_return)
{
  const SshDLPublicKey *pub_key = public_key;

  *length_return =
    ssh_encode_alloc(buf,
		     SSH_FORMAT_EXTENDED,
		     ssh_dlp_param_encode, pub_key->param,
		     SSH_FORMAT_MP_INT, &pub_key->y,
		     SSH_FORMAT_END);
  return TRUE;
}

void ssh_dlp_public_key_free(void *public_key)
{
  ssh_dlp_clear_public_key((SshDLPublicKey *)public_key);
  ssh_xfree(public_key);
}

void ssh_dlp_public_key_copy(void *public_key_src, void **public_key_dest)
{
  SshDLPublicKey *pub_src = public_key_src;
  SshDLPublicKey *pub_dest = ssh_xmalloc(sizeof(*pub_dest));

  ssh_dlp_init_public_key(pub_dest, pub_src->param);
  
  mpz_set(&pub_dest->y, &pub_src->y);
  *public_key_dest = (void *)pub_dest;
}

/* Derive parameters from public key. */
void ssh_dlp_public_key_derive_param(void *public_key,
				     void **parameters)
{
  SshDLPublicKey *pub_key = public_key;
  SshDLParam *param = pub_key->param;

  /* Reference count... */
  param->reference_count++;

  *parameters = (void *)param;
}

/* Private key primitives. */

Boolean ssh_dlp_private_key_import(const unsigned char *buf,
			      size_t len,
			      void **private_key)
{
  SshDLPrivateKey *prv_key;
  SshDLParam *param, *temp;
  MP_INT x, y;
  unsigned int value;

  /* Temporary variables. */
  mpz_init(&x);
  mpz_init(&y);
  
  param = ssh_xmalloc(sizeof(*param));
  ssh_dlp_init_param(param);

  if (ssh_decode_array(buf, len,
		       SSH_FORMAT_UINT32, &value,
		       SSH_FORMAT_EXTENDED,
		       ssh_dlp_param_decode, param, &value,
		       SSH_FORMAT_MP_INT, &y,
		       SSH_FORMAT_MP_INT, &x,
		       SSH_FORMAT_END) == 0)
    {
      mpz_clear(&x);
      mpz_clear(&y);
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      return FALSE;
    }

  /* Check that param is unique and add to list or output param set
     that is equal and already exists in the list. */
  temp = ssh_dlp_param_list_add(param);
  if (temp)
    {
      ssh_dlp_clear_param(param);
      ssh_xfree(param);
      param = temp;
    }

  prv_key = ssh_xmalloc(sizeof(*prv_key));
  ssh_dlp_init_private_key(prv_key, param);

  mpz_set(&prv_key->x, &x);
  mpz_set(&prv_key->y, &y);
  mpz_clear(&x);
  mpz_clear(&y);
  
  /* Reading was successful. */
  *private_key = (void *)prv_key;
  
  return TRUE;
}

Boolean ssh_dlp_private_key_export(const void *private_key,
				   unsigned char **buf,
				   size_t *length_return)
{
  const SshDLPrivateKey *prv_key = private_key;

  *length_return =
    ssh_encode_alloc(buf,
		     SSH_FORMAT_EXTENDED,
		     ssh_dlp_param_encode, prv_key->param,
		     SSH_FORMAT_MP_INT, &prv_key->y,
		     SSH_FORMAT_MP_INT, &prv_key->x,
		     SSH_FORMAT_END);

  return TRUE;
}

void ssh_dlp_private_key_free(void *private_key)
{
  ssh_dlp_clear_private_key((SshDLPrivateKey *)private_key);
  ssh_xfree(private_key);
}

void ssh_dlp_private_key_copy(void *private_key_src, void **private_key_dest)
{
  SshDLPrivateKey *prv_src = private_key_src;
  SshDLPrivateKey *prv_dest = ssh_xmalloc(sizeof(*prv_dest));

  ssh_dlp_init_private_key(prv_dest, prv_src->param);
  mpz_set(&prv_dest->x, &prv_src->x);
  mpz_set(&prv_dest->y, &prv_src->y);

  *private_key_dest = (void *)prv_dest;
}

void ssh_dlp_private_key_derive_public_key(const void *private_key,
					   void **public_key)
{
  SshDLPublicKey *pub_key = ssh_xmalloc(sizeof(*pub_key));
  const SshDLPrivateKey *prv_key = private_key;

  ssh_dlp_init_public_key(pub_key, prv_key->param);
  mpz_set(&pub_key->y, &prv_key->y);

  *public_key = (void *)pub_key;
}

/* Derive parameters from a private key. */
void ssh_dlp_private_key_derive_param(void *private_key,
				      void **parameters)
{
  SshDLPrivateKey *prv_key = private_key;
  SshDLParam *param = prv_key->param;

  param->reference_count++;
  
  *parameters = (void *)param;
}

/* Finally something that can use our nice ;) stack approach. */

unsigned int ssh_dlp_param_count_randomizers(void *parameters)
{
  return ssh_cstack_count(&((SshDLParam*)parameters)->stack,
			  SSH_DLP_STACK_RANDOMIZER);
}

/* Precompute randomizer with parameters only, private key and public key. */

Boolean ssh_dlp_param_generate_randomizer(void *parameters,
					  SshRandomState state)
{
  /* Allocate stack element with constructor! */
  SshDLStackRandomizer *stack =
    ssh_cstack_SshDLStackRandomizer_constructor(NULL);
  SshDLParam *param = parameters;

retry:
  /* Add information to stack. */
  if (param->exponent_entropy)
    ssh_mp_mod_random_entropy(&stack->k, &param->q, state,
			      param->exponent_entropy);
  else
    ssh_mp_mod_random(&stack->k, &param->q, state);
  if (mpz_cmp_ui(&stack->k, 0) == 0)
    goto retry;
  mpz_powm(&stack->gk, &param->g, &stack->k, &param->p);

  /* Push to stack list, in parameter context. No it is visible for
     all, private keys, public keys and parameters. */
  ssh_cstack_push(&param->stack, stack);
  return TRUE;
}

Boolean ssh_dlp_param_export_randomizer(void *parameters,
					unsigned char **buf,
					size_t *length_return)
{
  SshDLStackRandomizer *stack;
  SshDLParam *param = parameters;

  stack = (SshDLStackRandomizer *)ssh_cstack_pop(&param->stack,
						 SSH_DLP_STACK_RANDOMIZER);
  if (stack)
    {
      *length_return =
	ssh_encode_alloc(buf,
			 SSH_FORMAT_MP_INT, &stack->k,
			 SSH_FORMAT_MP_INT, &stack->gk,
			 SSH_FORMAT_END);
      return TRUE;
    }
  *buf = NULL;
  *length_return = 0;

  return FALSE;  
}

Boolean ssh_dlp_param_import_randomizer(void *parameters,
					unsigned char *buf, size_t length)
{
  SshDLStackRandomizer *stack =
    ssh_cstack_SshDLStackRandomizer_constructor(NULL);
  SshDLParam *param = parameters;

  if (ssh_decode_array(buf, length,
		       SSH_FORMAT_MP_INT, &stack->k,
		       SSH_FORMAT_MP_INT, &stack->gk,
		       SSH_FORMAT_END) == 0)
    {
      ssh_cstack_free(stack);
      return FALSE;
    }

  ssh_cstack_push(&param->stack, stack);
  return TRUE;
}

/********************** Actions ************************/

/* XXX We should do here something like we have done with the
   elliptic curve stuff, that is set the action_* routines into one
   function and as well as the makes. Would make things easier. */

typedef struct SshDlpInitCtxRec
{
  SshRandomState state;
  MP_INT p, g, q, x, y;
  unsigned int size;
  unsigned int exponent_entropy;
  const char *predefined;
  unsigned int flag;
#define DLP_FLAG_IGNORE 0
#define DLP_FLAG_DSA    1
} SshDLPInitCtx;

void *ssh_dlp_action_init(SshRandomState state)
{
  SshDLPInitCtx *ctx = ssh_xmalloc(sizeof(*ctx));
  ctx->state = state;
  ctx->size = 0;
  ctx->exponent_entropy = 0;
  ctx->flag = DLP_FLAG_IGNORE;
  ctx->predefined = NULL;
  
  mpz_init_set_ui(&ctx->p, 0);
  mpz_init_set_ui(&ctx->g, 0);
  mpz_init_set_ui(&ctx->q, 0);
  mpz_init_set_ui(&ctx->x, 0);
  mpz_init_set_ui(&ctx->y, 0);

  return (void *)ctx;
}

void *ssh_dlp_action_public_key_init(void)
{
  return ssh_dlp_action_init(NULL);
}

void ssh_dlp_action_free(void *context)
{
  SshDLPInitCtx *ctx = context;
  mpz_clear(&ctx->p);
  mpz_clear(&ctx->q);
  mpz_clear(&ctx->g);
  mpz_clear(&ctx->x);
  mpz_clear(&ctx->y);
  ssh_xfree(ctx);
}

unsigned int ssh_dlp_action_put(void *context, va_list *ap,
				void *input_context,
				SshCryptoType   type,
				SshPkFormat format)
{
  
  SshDLPInitCtx *ctx = context;
  SshDLParam *param;
  MP_INT *temp;
  switch (format)
    {
    case SSH_PKF_SIZE:
      if (type & SSH_CRYPTO_TYPE_PUBLIC_KEY)
	return 0;
      ctx->size = va_arg(*ap, unsigned int);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      ctx->exponent_entropy = va_arg(*ap, unsigned int);
      /* In case the application suggests too small entropy value
	 lets force the maximum. Clearly the application didn't know
	 what it was doing. */
      if (ctx->exponent_entropy < SSH_RANDOMIZER_MINIMUM_ENTROPY)
	ctx->exponent_entropy = 0;
      break;
    case SSH_PKF_PRIME_P:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(&ctx->p, temp);
      break;
    case SSH_PKF_PRIME_Q:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(&ctx->q, temp);
      break;
    case SSH_PKF_GENERATOR_G:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(&ctx->g, temp);
      break;
    case SSH_PKF_SECRET_X:
      if (type & (SSH_CRYPTO_TYPE_PUBLIC_KEY | SSH_CRYPTO_TYPE_PK_GROUP))
	return 0;
      temp = va_arg(*ap, MP_INT *);
      mpz_set(&ctx->x, temp);
      break;
    case SSH_PKF_PUBLIC_Y:
      if (type & SSH_CRYPTO_TYPE_PK_GROUP)
	return 0;
      temp = va_arg(*ap, MP_INT *);
      mpz_set(&ctx->y, temp);
      break;
    case SSH_PKF_GROUP:
      /* Check that wrapper was used. */
      if (input_context == NULL)
	return 0;
      param = (SshDLParam *)input_context;
      mpz_set(&ctx->p, &param->p);
      mpz_set(&ctx->g, &param->g);
      mpz_set(&ctx->q, &param->q);
      break;
    case SSH_PKF_PREDEFINED_GROUP:
      ctx->predefined = va_arg(*ap, const char *);
      break;
    default:
      return 0;
      break;
    }
  return 1;
}

unsigned int ssh_dlp_action_private_key_put(void *context, va_list *ap,
					    void *input_context,
					    SshPkFormat format)
{
  return ssh_dlp_action_put(context, ap,
			    input_context,
			    SSH_CRYPTO_TYPE_PRIVATE_KEY,
			    format);
}

unsigned int ssh_dlp_action_private_key_get(void *context, va_list *ap,
					    void **output_context,
					    SshPkFormat format)
{
  SshDLPrivateKey *prv = context;
  MP_INT *temp;
  unsigned int *size;
  switch (format)
    {
    case SSH_PKF_SIZE:
      size = va_arg(*ap, unsigned int *);
      *size = ssh_mp_bit_size(&prv->param->p);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      size = va_arg(*ap, unsigned int *);
      if (!prv->param->exponent_entropy)
	/* In case the entropy is the maximal possible, lets fool the
	   application to think that we really think in terms of
	   bits for this case also. */
	*size = ssh_mp_byte_size(&prv->param->q);
      else
	/* Otherwise lets just give the real value used. */
	*size = prv->param->exponent_entropy;
      break;
    case SSH_PKF_PRIME_P:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &prv->param->p);
      break;
    case SSH_PKF_PRIME_Q:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &prv->param->q);
      break;
    case SSH_PKF_GENERATOR_G:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &prv->param->g);
      break;
    case SSH_PKF_SECRET_X:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &prv->x);
      break;
    case SSH_PKF_PUBLIC_Y:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &prv->y);
      break;
    default:
      return 0;
      break;
    }
  return 1;
}

unsigned int ssh_dlp_action_public_key_put(void *context, va_list *ap,
					   void *input_context,
					   SshPkFormat format)
{
  return ssh_dlp_action_put(context, ap,
			    input_context,
			    SSH_CRYPTO_TYPE_PUBLIC_KEY,
			    format);
}

unsigned int ssh_dlp_action_public_key_get(void *context, va_list *ap,
					   void **output_context,
					   SshPkFormat format)
{
  SshDLPublicKey *pub = context;
  MP_INT *temp;
  unsigned int *size;
  switch (format)
    {
    case SSH_PKF_SIZE:
      size = va_arg(*ap, unsigned int *);
      *size = ssh_mp_bit_size(&pub->param->p);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      size = va_arg(*ap, unsigned int *);
      if (!pub->param->exponent_entropy)
	/* In case the entropy is the maximal possible, lets fool the
	   application to think that we really think in terms of
	   bits for this case also. */
	*size = ssh_mp_byte_size(&pub->param->q);
      else
	/* Otherwise lets just give the real value used. */
	*size = pub->param->exponent_entropy;
      break;
    case SSH_PKF_PRIME_P:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &pub->param->p);
      break;
    case SSH_PKF_PRIME_Q:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &pub->param->q);
      break;
    case SSH_PKF_GENERATOR_G:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &pub->param->g);
      break;
    case SSH_PKF_PUBLIC_Y:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &pub->y);
      break;
    default:
      return 0;
      break;
    }
  return 1;
}

unsigned int ssh_dlp_action_param_put(void *context, va_list *ap,
				      void *input_context,
				      SshPkFormat format)
{
  return ssh_dlp_action_put(context, ap,
			    input_context,
			    SSH_CRYPTO_TYPE_PK_GROUP,
			    format);
}

unsigned int ssh_dlp_action_param_get(void *context, va_list *ap,
				      void **output_context,
				      SshPkFormat format)
{
  SshDLParam *param = context;
  MP_INT *temp;
  unsigned int *size;
  switch (format)
    {
    case SSH_PKF_SIZE:
      size = va_arg(*ap, unsigned int *);
      *size = ssh_mp_bit_size(&param->p);
      break;
    case SSH_PKF_RANDOMIZER_ENTROPY:
      size = va_arg(*ap, unsigned int *);
      if (!param->exponent_entropy)
	/* In case the entropy is the maximal possible, lets fool the
	   application to think that we really think in terms of
	   bits for this case also. */
	*size = ssh_mp_byte_size(&param->q);
      else
	/* Otherwise lets just give the real value used. */
	*size = param->exponent_entropy;
      break;
    case SSH_PKF_PRIME_P:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &param->p);
      break;
    case SSH_PKF_PRIME_Q:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &param->q);
      break;
    case SSH_PKF_GENERATOR_G:
      temp = va_arg(*ap, MP_INT *);
      mpz_set(temp, &param->g);
      break;
    default:
      return 0;
      break;
    }
  return 1;
}

#ifdef SSHDIST_CRYPT_DSA
void ssh_dlp_dsa_nist(void *context)
{
  SshDLPInitCtx *ctx = context;
  ctx->flag |= DLP_FLAG_DSA;
}
#endif /* SSHDIST_CRYPT_DSA */

void *ssh_dlp_action_make(void *context, int type)
{
  SshDLPInitCtx *ctx = context;
  SshDLParam *param, *temp;
  SshDLPrivateKey *prv_key;
  SshDLPublicKey *pub_key;
  unsigned int q_size;

  /* Check flags. */
  if ((ctx->flag & DLP_FLAG_DSA) == DLP_FLAG_DSA)
    {
      /* Force subprime size to 160 bits. */
      q_size = 160;
    }
  else
    /* XXX This should depend on policy selected too! Although,
       generally this seems a pretty good tradeoff. */
    q_size = ctx->size / 2;

  /* Check constraints of type. */
  switch (type)
    {
    case 0:
      /* None. */
      break;
    case 1:
      /* Verify that the public key was really given! */
      if (mpz_cmp_ui(&ctx->y, 0) == 0)
	return NULL;
      break;
    case 2:
      /* None. */
      break;
    }

  if (ctx->predefined == NULL)
    {
      /* Set parameters. */
      if (mpz_cmp_ui(&ctx->p, 0) == 0 ||
	  mpz_cmp_ui(&ctx->q, 0) == 0 ||
	  mpz_cmp_ui(&ctx->g, 0) == 0)
	{
	  if (ctx->size)
	    param = ssh_dlp_param_generate(ctx->size, q_size,
					   ctx->state);
	  else
	    return NULL;
	}
      else
	{
	  param = ssh_xmalloc(sizeof(*param));
	  ssh_dlp_init_param(param);
	  mpz_set(&param->p, &ctx->p);
	  mpz_set(&param->q, &ctx->q);
	  mpz_set(&param->g, &ctx->g);
	  
	  temp = ssh_dlp_param_list_add(param);
	  if (temp)
	    {
	      ssh_dlp_clear_param(param);
	      ssh_xfree(param);
	      param = temp;
	    }
	}
    }
  else
    {
      param = ssh_xmalloc(sizeof(*param));
      ssh_dlp_init_param(param);

      if (ssh_dlp_set_param(ctx->predefined, &param->predefined,
			    &param->p, &param->q, &param->g) == FALSE)
	{
	  ssh_dlp_clear_param(param);
	  ssh_xfree(param);
	  return NULL;
	}
      temp = ssh_dlp_param_list_add(param);
      if (temp)
	{
	  ssh_dlp_clear_param(param);
	  ssh_xfree(param);
	  param = temp;
	}
    }

  /* Finish the parameter generation with setting the policy information. */
  if (ctx->exponent_entropy > ssh_mp_bit_size(&param->q))
    ctx->exponent_entropy = ssh_mp_bit_size(&param->q);
  param->exponent_entropy = (ctx->exponent_entropy + 7) / 8;

  /* Handle the cases for private and public keys. */
  switch (type)
    {
    case 0:
      /* Nothing. */
      break;
    case 1:
      /* The public key stuff. */
      pub_key = ssh_xmalloc(sizeof(*pub_key));
      ssh_dlp_init_public_key(pub_key, param);
      mpz_set(&pub_key->y, &ctx->y);
      return (void *)pub_key;
      break;
    case 2:
      /* The private key stuff. */
      prv_key = ssh_xmalloc(sizeof(*prv_key));
      ssh_dlp_init_private_key(prv_key, param);
      
      /* Set private and public keys. */
      if (mpz_cmp_ui(&ctx->x, 0) == 0 ||
	  mpz_cmp_ui(&ctx->y, 0) == 0)
	{
	  /* Generate secret key. Note, here we definitely don't want to
	     use the restriction of random number size for the exponent.
	     It would be a poor practice, some attack could find the
	     discrete log faster that way. Well, that isn't the main point
	     however, just that in Diffie-Hellman and signatures you
	     are mainly using for short term security, but private keys
	     might last for a long while. Thus for sake of clarity
	     we don't do any restrictions here. */
	  ssh_mp_mod_random(&prv_key->x, &prv_key->param->q, ctx->state);
	  
	  /* Compute public key. */
	  mpz_powm(&prv_key->y, &prv_key->param->g, &prv_key->x,
		   &prv_key->param->p);
	}
      else
	{
	  /* Well, happily we were given both of them. This might be
	     because some application thinks it can generate better
	     keys than us. Well, we're not too proud, thus lets use
	     them as is. XXX No checking is performed here. */
	  mpz_set(&prv_key->x, &ctx->x);
	  mpz_set(&prv_key->y, &ctx->y);
	}
      return (void *)prv_key;
      break;
    }

  return (void *)param;  
}

void *ssh_dlp_private_key_action_make(void *context)
{
  return ssh_dlp_action_make(context, 2);
}

void *ssh_dlp_public_key_action_make(void *context)
{
  return ssh_dlp_action_make(context, 1);
}

void *ssh_dlp_param_action_make(void *context)
{
  return ssh_dlp_action_make(context, 0);
}

/********************** Schemes ************************/

#if 0
void hexdump(const unsigned char *buf, size_t len)
{
  size_t i, my_len;
  printf("hexdump: ");
  if (len > 25)
    my_len = 25;
  else
    my_len = len;
  for (i = 0; i < my_len; i++)
    printf("%02x", buf[i]);
  if (my_len < len)
    printf("...");
  printf("\n");
}
#endif
#if 0
void mprint(const char *str, MP_INT *n)
{
  printf("%s : ", str);
  mpz_out_str(NULL, 10, n);
  printf("\n");
  printf("%s : 0x", str);
  mpz_out_str(NULL, 16, n);
  printf("\n");
}
#endif

#ifdef SSHDIST_CRYPT_DSA

/* DSA - Digital Signature Algorithm XXX */

Boolean ssh_dlp_dsa_public_key_verify(const void *public_key,
				      const unsigned char *signature,
				      size_t signature_len,
				      Boolean need_hashing,
				      const unsigned char *data,
				      size_t data_len,
				      const SshHashDef *hash_def)
{
  const SshDLPublicKey *pub_key = public_key;
  unsigned int len = ssh_mp_byte_size(&pub_key->param->q);
  MP_INT v, w, s, r, e, invs, u1, u2;
  void *hash_context;
  unsigned char *digest;
  /* Assume failure. */
  Boolean rv = FALSE;

  if (signature_len < len * 2)
    return FALSE;

  mpz_init(&v);
  mpz_init(&w);
  mpz_init(&e);
  mpz_init(&s);
  mpz_init(&r);
  mpz_init(&u1);
  mpz_init(&u2);
  mpz_init(&invs);

  /* Verify the signature. */

  if (need_hashing)
    {
      /* Hash function (this will be moved later to allow computation of
	 signature of very large blobs). */
      digest = ssh_xmalloc(hash_def->digest_length);
      hash_context = ssh_xmalloc((*hash_def->ctxsize)());
      (*hash_def->reset_context)(hash_context);
      (*hash_def->update)(hash_context, data, data_len);
      (*hash_def->final)(hash_context, digest);
      ssh_xfree(hash_context);
    }
  else
    {
      digest = (unsigned char *)data;
      if (data_len != hash_def->digest_length)
	{
	  rv = FALSE;
	  goto failed;
	}
    }
  
  /* Reduce to correct length. */
  ssh_buf_to_mp(&e, digest, hash_def->digest_length);
  mpz_mod(&e, &e, &pub_key->param->q);

  if (need_hashing)
    {
      /* Free allocated hash information. */
      ssh_xfree(digest);
    }

  /* Convert and reduce signature. */
  ssh_buf_to_mp(&r, signature, len);
  if (mpz_cmp(&r, &pub_key->param->q) >= 0 ||
      mpz_cmp_ui(&r, 0) <= 0)
    {
      rv = FALSE;
      goto failed;
    }
  
  ssh_buf_to_mp(&s, signature + len, len);
  if (mpz_cmp(&s, &pub_key->param->q) >= 0 ||
      mpz_cmp_ui(&s, 0) <= 0)
    {
      rv = FALSE;
      goto failed;
    }
  
  /* Compute verification parameters:

     g^(k(m + rx)^-1 * m) * g^(x*k(m + rx)^-1 * r)) =
     g^k((m + rx)^-1 * m + (m + rx)^-1 * x * r) =
     g^k((m + rx)^-1 * (m + rx)) = g^k.
     
   */

  ssh_mp_mod_invert(&invs, &s, &pub_key->param->q);
  mpz_mul(&u1, &invs, &e);
  mpz_mod(&u1, &u1, &pub_key->param->q);
  mpz_mul(&u2, &invs, &r);
  mpz_mod(&u2, &u2, &pub_key->param->q);

  /* Exponentiate (GMP unfortunately doesn't allow some optimizations
     which could take place here). */
  mpz_powm(&v, &pub_key->param->g, &u1, &pub_key->param->p);
  mpz_powm(&w, &pub_key->y, &u2, &pub_key->param->p);
 
  mpz_mul(&v, &v, &w);
  mpz_mod(&v, &v, &pub_key->param->p);
  mpz_mod(&v, &v, &pub_key->param->q);
  
  /* Check validy. If and only if v = r then successful. */
  if (mpz_cmp(&v, &r) == 0)
    rv = TRUE;

failed:
  /* Clean memory. */
  mpz_clear(&v);
  mpz_clear(&w);
  mpz_clear(&e);
  mpz_clear(&s);
  mpz_clear(&r);
  mpz_clear(&invs);
  mpz_clear(&u1);
  mpz_clear(&u2);

  return rv;
}

size_t
ssh_dlp_dsa_private_key_max_signature_input_len(const void *private_key)
{
  return (size_t)-1;
}

size_t
ssh_dlp_dsa_private_key_max_signature_output_len(const void *private_key)
{
  const SshDLPrivateKey *prv_key = private_key;
  return ssh_mp_byte_size(&prv_key->param->q) * 2;
}

Boolean ssh_dlp_dsa_private_key_sign(const void *private_key,
				     Boolean need_hashing,
				     const unsigned char *data,
				     size_t data_len,
				     unsigned char *signature_buffer,
				     size_t ssh_buffer_len,
				     size_t *signature_length_return,
				     SshRandomState state,
				     const SshHashDef *hash_def)
{
  const SshDLPrivateKey *prv_key = private_key;
  SshDLStackRandomizer *stack;
  MP_INT k, e, r, invk, s;
  unsigned int len = ssh_mp_byte_size(&prv_key->param->q);
  unsigned char *digest;
  void *hash_context;
  
  if (ssh_buffer_len < len * 2)
    return FALSE;

  if (need_hashing)
    {
      /* Compute hash of the input data. */
      digest = ssh_xmalloc(hash_def->digest_length);
      hash_context = ssh_xmalloc((*hash_def->ctxsize)());
      (*hash_def->reset_context)(hash_context);
      (*hash_def->update)(hash_context, data, data_len);
      (*hash_def->final)(hash_context, digest);
      ssh_xfree(hash_context);
    }
  else
    {
      digest = (unsigned char *)data;
      if (data_len != hash_def->digest_length)
	return FALSE;
    }

  mpz_init(&k);
  mpz_init(&e);
  mpz_init(&r);
  mpz_init(&invk);
  mpz_init(&s);
      
  /* Reduce */
  ssh_buf_to_mp(&e, digest, hash_def->digest_length);
  mpz_mod(&e, &e, &prv_key->param->q);

  if (need_hashing)
    {
      /* Free hash contexts. */
      ssh_xfree(digest);
    }

retry0:
  
  stack = (SshDLStackRandomizer *)ssh_cstack_pop(&prv_key->param->stack,
						 SSH_DLP_STACK_RANDOMIZER);
  /* Check if in stack. */
  if (!stack)
    {
      /* In case we hit to failure cases. */
    retry1:

      /* Find the randomizer. The use of restrictions for the size of
	 the exponent work here. However, you should be very careful
	 with it. */
      if (prv_key->param->exponent_entropy)
	ssh_mp_mod_random_entropy(&k, &prv_key->param->q, state,
				  prv_key->param->exponent_entropy);
      else
	ssh_mp_mod_random(&k, &prv_key->param->q, state);
      
      if (mpz_cmp_ui(&k, 0) == 0)
	goto retry1;
      mpz_powm(&r, &prv_key->param->g, &k, &prv_key->param->p);
    }
  else
    {
      mpz_set(&k, &stack->k);
      mpz_set(&r, &stack->gk);
      /* This is legal, uses the destructor we have defined. */
      ssh_cstack_free(stack);
    }
	
  /* Compute: r = (g^(k mod q) mod p) mod q */
  mpz_mod(&r, &r, &prv_key->param->q);
  if (mpz_cmp_ui(&r, 0) == 0)
    goto retry0;
  
  /* Invert. */
  ssh_mp_mod_invert(&invk, &k, &prv_key->param->q);
  
  /* Compute signature s = k^-1(e + xr). */
  mpz_mul(&s, &r, &prv_key->x);
  mpz_add(&s, &s, &e);
  mpz_mul(&s, &s, &invk);
  mpz_mod(&s, &s, &prv_key->param->q);

  if (mpz_cmp_ui(&s, 0) == 0)
    goto retry0;
  
  /* Linearize signature. */
  ssh_mp_to_buf(signature_buffer, len, &r);
  ssh_mp_to_buf(signature_buffer + len, len, &s);
  *signature_length_return = len * 2;

  /* Clear temps. */
  mpz_clear(&k);
  mpz_clear(&e);
  mpz_clear(&r);
  mpz_clear(&invk);
  mpz_clear(&s);

  return TRUE;
}

#endif /* SSHDIST_CRYPT_DSA */

/************************ Key exchange **************************/

#ifdef SSHDIST_CRYPT_DH

void *ssh_dlp_mp_out(MP_INT *k)
{
  unsigned char *buf;
  unsigned int len = ssh_mp_byte_size(k);
  buf = ssh_xmalloc(len + 4);
  SSH_PUT_32BIT(buf, len);
  ssh_mp_to_buf(buf + 4, len, k);
  return buf;
}

void ssh_dlp_mp_in(MP_INT *k, void *ptr)
{
  unsigned char *buf = ptr;
  unsigned int len;
  len = SSH_GET_32BIT(buf);
  ssh_buf_to_mp(k, buf + 4, len);
}


/* Diffie-Hellman */

size_t
ssh_dlp_diffie_hellman_exchange_length(const void *parameters)
{
  const SshDLParam *param = parameters;
  return ssh_mp_byte_size(&param->p);
}

size_t
ssh_dlp_diffie_hellman_shared_secret_length(const void *parameters)
{
  const SshDLParam *param = parameters;
  return ssh_mp_byte_size(&param->p);
}

void ssh_dlp_diffie_hellman_internal_generate(MP_INT *ret,
					      SshDLParam *param,
					      MP_INT *k,
					      SshRandomState state)
{
  SshDLStackRandomizer *stack_r;

  stack_r = (SshDLStackRandomizer *)ssh_cstack_pop(&param->stack,
						   SSH_DLP_STACK_RANDOMIZER);
  if (!stack_r)
    {
      /* This is the main place where the entropy limitation will
	 be very useful. Usually Diffie-Hellman session keys are for
	 short term use, and are not used for stuff that needs to
	 be secure forever. Thus smaller amount of entropy is suitable. */
      if (param->exponent_entropy)
	ssh_mp_mod_random_entropy(k, &param->q,
				  state, param->exponent_entropy);
      else
	ssh_mp_mod_random(k, &param->q, state);
      mpz_powm(ret, &param->g, k, &param->p);
    }
  else
    {
      mpz_set(ret, &stack_r->gk);
      mpz_set(k, &stack_r->k);
      ssh_cstack_free(stack_r);
    }
}

Boolean ssh_dlp_diffie_hellman_generate(void *parameters,
					void **diffie_hellman,
					unsigned char *exchange,
					size_t exchange_length,
					size_t *return_length,
					SshRandomState state)
{
  const SshDLParam *param = parameters;
  MP_INT e;
  MP_INT k;
  unsigned int len = ssh_mp_byte_size(&param->p);
  
  if (exchange_length < len)
    return FALSE;

  mpz_init(&k);
  mpz_init(&e);
  
  ssh_dlp_diffie_hellman_internal_generate(&e, (SshDLParam *)param,
					   &k, state);

#if 0
  mprint("  p = ", &((DLParam *)param)->p);
  mprint("  q = ", &((DLParam *)param)->q);
  mprint("  g = ", &((DLParam *)param)->g);
  mprint("  k = ", &k);
#endif

  /* Linearize. */
  ssh_mp_to_buf(exchange, len, &e);
  *return_length = len;

  mpz_clear(&e);

  *diffie_hellman = ssh_dlp_mp_out(&k);
  mpz_clear(&k);
  
  return TRUE;
}

Boolean ssh_dlp_diffie_hellman_internal_final(MP_INT *ret,
					      MP_INT *input,
					      const SshDLParam *param,
					      MP_INT *k)
					      
{
  /* Reduce. */
  mpz_mod(ret, input, &param->p);
  /* Diffie-Hellman part. */
  mpz_powm(ret, ret, k, &param->p);
  return TRUE;
}

Boolean ssh_dlp_diffie_hellman_final(void *parameters,
				     void *diffie_hellman,
				     unsigned char *exchange,
				     size_t exchange_length,
				     unsigned char *secret,
				     size_t secret_length,
				     size_t *return_length)
{
  const SshDLParam *param = parameters;
  MP_INT v, k;
  unsigned int len = ssh_mp_byte_size(&param->p);
  
#if 0
  if (exchange_length < len)
    return FALSE;
#endif
  if (secret_length < len)
    return FALSE;

  mpz_init(&v);
  mpz_init(&k);

  /* Import the secret. */
  ssh_dlp_mp_in(&k, diffie_hellman);
  ssh_buf_to_mp(&v, exchange, exchange_length);

#if 0
  mprint("  v = ", &v);
  mprint("  p = ", &((DLParam *)param)->p);
  mprint("  q = ", &((DLParam *)param)->q);
  mprint("  g = ", &((DLParam *)param)->g);
  mprint("  k = ", &k);
#endif

  /* Compute v further. */
  if (ssh_dlp_diffie_hellman_internal_final(&v, &v, param, &k) == FALSE)
    {
      mpz_clear(&v);
      return FALSE;
    }

#if 0
  mprint("  v = ", &v);
#endif
  
  ssh_xfree(diffie_hellman);
  mpz_clear(&k);
  
  /* Linearize. */
  ssh_mp_to_buf(secret, len, &v);
  *return_length = len;

  /* Clear memory. */
  mpz_clear(&v);
  return TRUE;
}

/* Unified Diffie-Hellman (used after first part of standard Diffie-Hellman) */

size_t
ssh_dlp_unified_diffie_hellman_shared_secret_length(const void *parameters)
{
  const SshDLParam *param = parameters;
  return ssh_mp_byte_size(&param->p) * 2;
}

Boolean ssh_dlp_unified_diffie_hellman_final(const void *public_key,
					     const void *private_key,
					     void *diffie_hellman,
					     unsigned char *exchange,
					     size_t exchange_length,
					     unsigned char *secret,
					     size_t secret_length,
					     size_t *return_length)
{
  const SshDLPrivateKey *prv_key = private_key;
  const SshDLPublicKey *pub_key = public_key;
  MP_INT v, w, k;
  unsigned int len = ssh_mp_byte_size(&prv_key->param->p);

  if (exchange_length < len)
    return FALSE;
  if (secret_length < len)
    return FALSE;
  
  mpz_init(&v);
  mpz_init(&k);

  ssh_dlp_mp_in(&k, diffie_hellman);
  
  /* Diffie-Hellman in its basic form. */
  ssh_buf_to_mp(&v, exchange, len);
  
  if (ssh_dlp_diffie_hellman_internal_final(&v, &v, 
					    prv_key->param,
					    &k) != TRUE)
    {
      mpz_clear(&v);
      return FALSE;
    }

  ssh_xfree(diffie_hellman);
  mpz_clear(&k);

  mpz_init(&w);
  
  /* Unified Diffie-Hellman part. */
  mpz_powm(&w, &pub_key->y, &prv_key->x, &prv_key->param->p);

  /* Linearize (this _could_ feature some sort of hashing but we assume
     it could be left for higher level). */
  ssh_mp_to_buf(secret, len, &v);
  ssh_mp_to_buf(secret + len, len, &w);
  
  *return_length = len * 2;

  mpz_clear(&v);
  mpz_clear(&w);
  
  return TRUE;
}

#if 0

/* XXX This is old stuff, although useful, probably won't ever be
   finished. The idea was mine and further formalized by K. Nyberg, but
   sadly it's far from easy to do. It is integrated and nice, but
   to get some protocol use it is another thing. */

/* Basic authenticated key exchange with diffie-hellman */

/* Idea:

   This is a four part protocol. If only one side authentication is used
   this could be reduced to three part.
   
   1. A -> B (diffie-hellman phase 1)
   2. B -> A (diffie-hellman phase 1 + digital signature)
   3. A (verify digital signature) and A -> B (digital signature)
   4. B (verify digital signature)

   Problem.
     We should compute H(A,B,K), where K is the key, A,B are identifiers
     for parties A and B.

     Assuming identifiers are just public keys or name or internet address.

   Idea:

     Using my ElGamal variation:

       do first diffie-hellman
     
       K = g^(ab) mod p, is known,

       r = H(A,B,K), is known, then

       s = a^-1(1 - rd) mod p

       message is  A || s

       verify (known K and r trivially)

       g^a = y^r.K^s mod p
       
     
 */

/* Send diffie-hellman g^k from A to B (with identifier). */ 

Boolean ssh_dlp_kex_dh_elgamal_phase1(unsigned char *identifier,
				 unsigned int id_length
				 void *parameters,
				 unsigned char *packet_buffer,
				 unsigned int buffer_length,
				 unsigned int *return_length,
				 SshRandomState state)
{
  Boolean rv;
  unsigned int used_length;
  
  /* Use our Diffie-Hellman implementation, no need to duplicate code. */
  rv = ssh_dlp_diffie_hellman_generate(packet_buffer + id_length + 8,
				  buffer_length - id_length - 8,
				  &used_length,
				  parameters, state);
  
  if (rv != TRUE)
    return FALSE;

  /* Put length. */
  SSH_PUT_32BIT(packet_buffer + id_length + 4, used_length);
  
  /* Set the identifier. */
  SSH_PUT_32BIT(packet_buffer, id_length);
  memset(packet_buffer + 4, identifier, id_length);

  *return_length = used_length + 4 + id_length;
  
  return TRUE;
}

/* Send diffie-hellman g^k from B to A (with identifier) and sign it. */

Boolean ssh_dlp_kex_dh_elgamal_phase2(unsigned char *input_packet, 
				 unsigned int input_packet_length, 
				 unsigned char *identifier,
				 unsigned int id_length, 
				 void *private_key,
				 unsigned char *packet_buffer,
				 unsigned int buffer_length,
				 unsigned int *return_length,
				 SshRandomState state)
{
  DLPrivateKey *prv_key = private_key;
  DLParam *param = prv_key->param;
  MP_INT v, ;
  unsigned int len = gen_mp_byte_size(&param->p);
  unsigned int tmp_len;
  unsigned int other_length;
  unsigned char *other_identifier;

  /* First check lengths. */

  other_length = SSH_GET_32BIT(input_packet);
  if (other_length > input_packet_length)
    return FALSE;

  other_identifier = input_packet + 4;

  /* Diffie-Hellman part of this operation. */

  if (input_packet_length - other_length - 8 < len)
    return FALSE;
  if (buffer_length < len * 2 + id_length + 8)
    return FALSE;

  /* Do the first part first. */
  SSH_PUT_32BIT(packet_buffer, id_length);
  memcpy(packet_buffer + 4, identifier, id_length);

  /* Next compute this sides Diffie-Hellman. */
  mpz_init(&v);

  ssh_dlp_diffie_hellman_internal_generate(&v, param, state);

  /* Put to the buffer. */
  /* XXX (&v, packet_buffer + 4 + id_length, tmp_len); */

  /* Get the othersides g^k. */
  gen_str_to_mp(&v, &input_packet + other_length + 8,
		SSH_GET_32BIT(input_packet + other_length + 4));

  /* Combine. */

  if (ssh_dlp_diffie_hellman_internal_final(&v, param) != TRUE)
    {
      mpz_clear(&v);
      return FALSE;
    }
  
  /* Now we're ready to compute the ElGamal part, i.e. the signature. */

  /* Formulas go as:

     r = H(A,B,v), where A and B are identifiers of sides,

     s = k^{-1}(1 - rd) ...
     */

  /* Compute the hash with sha-1. */

  temp_buffer = ssh_xmalloc(ssh_sha_ctxsize() + len);
  context = temp_buffer + len;
  ssh_sha_reset_context(context);

  gen_mp_to_str(temp_buffer, &v, len);

  ssh_sha_update(context, other_identifier, other_length);
  ssh_sha_update(context, identifier, id_length);
  ssh_sha_update(context, temp_buffer, len);
  
  ssh_sha_final(context, digest);
  ssh_xfree(temp_buffer);

  /* Use the 160-bit digest. */
  
  gen_str_to_mp(&r, digest, 20);

  stack_k = (DLStackSecretK *)ssh_cstack_pop(&param->stack,
					     SSH_DLP_STACK_SECRET_K);

  if (!stack_k)
    ssh_fatal("internal error.");
  
  mpz_mod_invert(&kinv, &stack->k, &param->q);
  mpz_mul(&s, &prv_key->x, &r);
  mpz_mod(&s, &s, &param->q);
  mpz_add_ui(&s, &s, 1);
  mpz_mul(&s, &s, &kinv);
  
  /* */
  

  
  /* Linearize. */
  gen_mp_to_str(shared_secret, &v, len);

  *return_length = len;

  /* Clear memory. */
  mpz_clear(&v);
  ssh_cstack_free(stack);
  
  return TRUE; 
}

/* Send signature from A to B (verify B's signature). */

Boolean ssh_dlp_kex_dh_elgamal_phase3(unsigned char *input_packet, 
				 unsigned int input_packet_length,
				 unsigned char *identifier,
				 unsigned char id_length,
				 void *private_key,
				 void *public_key,
				 unsigned char *packet_buffer,
				 unsigned int buffer_length,
				 unsigned int *return_length,
				 SshRandomState state)
{
}

/* Verify A's signature. */

Boolean ssh_dlp_kex_dh_elgamal_phase4(unsigned char *input_packet, 
				 unsigned int input_packet_length,
				 unsigned char *identifier,
				 unsigned int id_length,
				 void *public_key)
{
}
			    
     
#endif
#endif /* SSHDIST_CRYPT_DH */
