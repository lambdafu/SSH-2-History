/*

  psystem.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Oct 23 22:51:25 1997 [mkojo]

  Parse System.

  TODO: Finish this...

  This will in time be able to parse language of form

  Name operator { % Starting a new environment
    Name2  operator { % Another environment }
    Name3  operator [ % List Of
      { % Environment }
      { % Environment }]
    Name4  operator Data
    Name5  operator "String"
    Name6  operator <LDAP Distinguished Name>
    Name7  operator #Base64Encoded
    Name8  operator 0xHexDigits
    Name9  operator 929439882341
    Name10 operator 1.2.3.4
    }

  operator could be e.g. "::=" or just "=" or be missing altogether.
  However, ""{}[]<> etc. cannot be at the moment customized. It should be
  possible in a way that they could be replaced with strings, but it's not
  very easy to do.

  */

/*
 * $Id: psystem.c,v 1.8 1998/07/31 19:30:17 mkojo Exp $
 * $Log: psystem.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "gmp.h"
#include "mpaux.h"
#include "psystem.h"
#include "sshbuffer.h"
#include "base64.h"
#include "cstack.h"

char *ssh_psystem_msg[] =
{
  "success",
  "syntax error",
  "unknown language",
  "misplace close operator",
  "object was not created",
  "object addition failed",
  "no bind exists for given name",
  "same name used for environment and variable",
  "name not supported",
  "not an operator",
  "token was not expected here",
  "unsupported type requested",
  "type did not match the expected type",
  "list mismatch",
  "unknown type",
  "token string was empty, expected something else",
  "environment has no handler",
  "object addition failed",
  "could not open a list",
  "could not close a list",
  "initialization of an object failed",
  "expected assignment",
  NULL
};

char *ssh_psystem_error_msg(SshPSystemStatus status)
{
  if (status >= SSH_PSYSTEM_OK && status <= SSH_PSYSTEM_INIT_FAILED)
    return ssh_psystem_msg[status];
  return NULL;
}

typedef struct SshPSystemPosRec
{
  /* The more function. */
  int (*more)(void *context, unsigned char **buf, size_t *buf_len);
  void *more_context;

  Boolean eof;
  
  /* Our current buffer. */
  unsigned char *buf;
  size_t buf_len;

  /* LRU */
#define SSH_PSYSTEM_BYTE_LRU 5
  unsigned char lru[SSH_PSYSTEM_BYTE_LRU];
  size_t lru_pos;

  /* Position in the buffer and the line on which we currently are and
     index from start of that line. */
  size_t i, line, pos;
  
} SshPSystemPos;

void ssh_psystem_pos_init(SshPSystemPos *pos,
			  int (*more)(void *context, unsigned char **buf,
				      size_t *buf_len),
			  void *more_context)
{
  pos->more = more;
  pos->more_context = more_context;

  pos->eof = FALSE;
  pos->buf = NULL;
  pos->buf_len = 0;
  pos->i = 0;
  pos->line = 0;
  pos->pos = 0;
  pos->lru_pos = 0;

  pos->more = more;
  pos->more_context = more_context;
}

void ssh_psystem_pos_free(SshPSystemPos *pos)
{
  if (pos->buf)
    ssh_xfree(pos->buf);
  ssh_xfree(pos);
}

Boolean ssh_psystem_pos_lru(SshPSystemPos *pos, unsigned char byte)
{
  if (pos->lru_pos < SSH_PSYSTEM_BYTE_LRU)
    {
      pos->lru[pos->lru_pos] = byte;
      pos->lru_pos++;
      return TRUE;
    }
  return FALSE;
}

unsigned char ssh_psystem_next_byte(SshPSystemPos *pos)
{
  unsigned char *buf;
  size_t buf_len;
  unsigned char byte;
  int status;

  /* This feature is used only occasionally, and thus need not be
     handled with utmost care. That is we don't bother with little
     inconsistency with line numbers etc. */
  if (pos->lru_pos)
    {
      pos->lru_pos--;
      byte = pos->lru[pos->lru_pos];
      return byte;
    }
  
  if (pos->i < pos->buf_len)
    {
      byte = pos->buf[pos->i];
      pos->i++;
      pos->pos++;

      /* Detect line changes. */
      if (byte == '\n')
	{
	  pos->line++;
	  pos->pos = 0;
	}
      return byte;
    }

  /* Use the more functionality. */
  status = (*pos->more)(pos->more_context, &buf, &buf_len);
  if (status != 0)
    {
      pos->eof = TRUE;
      return 0x0;
    }

  /* Free the old buffer. */
  if (pos->buf)
    ssh_xfree(pos->buf);
  
  pos->i = 0;
  pos->buf = buf;
  pos->buf_len = buf_len;

  /* Recursively call oneself and get the byte requested. */
  return ssh_psystem_next_byte(pos);
}

#define NBYTE(pos) ssh_psystem_next_byte(pos)
#define PBYTE(pos, byte) ssh_psystem_pos_lru(pos, byte)

/* Thing that simplies greatly. */
char *buffer_to_str(SshBuffer *buffer, size_t *len)
{
  char *str;
  
  *len = ssh_buffer_len(buffer);
  str = ssh_xmalloc((*len) + 1);
  memcpy(str, ssh_buffer_ptr(buffer), *len);
  str[*len] = '\0';
  return str;
}

/* This seems to be easy enough. */
Boolean ssh_psystem_integer_decoder(unsigned char *in, size_t in_len,
				    void **out, size_t *out_len)
{
  MP_INT *temp;

  temp = ssh_xmalloc(sizeof(*temp));
  mpz_init(temp);

  /* Put a string. */
  if (mpz_set_str(temp, (char *) in, 10) == 0)
    {
      mpz_clear(temp);
      ssh_xfree(temp);
      return FALSE;
    }

  *out = temp;
  *out_len = 0;
  return TRUE;
}

/* XXX If a another hex decoder is written somewhere use that. */

/* My own hex table. */
static const unsigned char ssh_hextable[128] =
{
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
};

/* Our convention is to assume bit accuracy at the msb, not in the lsb. This
   makes decoding simpler. */
Boolean ssh_psystem_decode_hex(unsigned char *in, size_t in_len,
			       unsigned char **out, size_t *out_len)
{
  SshBuffer buffer;
  size_t i, len, s;
  unsigned char t, octet;

  for (len = 0; len < in_len; len++)
    {
      if (in[len] > 127)
	break;
      if (ssh_hextable[in[len]] == 0xff)
	break;
    }

  if (len < in_len)
    return FALSE;

  /* Check for zero length, which is correct but needs no work. */
  if (len == 0)
    {
      *out = NULL;
      *out_len = 0;
      return TRUE;
    }
  
  /* Make modification according the length of the hex string. */
  s = 1;
  if (len & 0x1)
    s ^= 1;

  /* Allocate a buffer. */
  ssh_buffer_init(&buffer);

  /* Loop through all hex information. */
  for (i = 0, octet = 0, t = 0; i < len; i++)
    {
      t = ssh_hextable[in[i]];
      if ((i & 0x1) == s)
	{
	  octet |= t;
	  ssh_buffer_append(&buffer, &octet, 1);
	}
      else
	octet = t << 4;
    }

  *out_len = ssh_buffer_len(&buffer);
  *out = ssh_xmalloc(*out_len);
  memcpy(*out, ssh_buffer_ptr(&buffer), *out_len);
  
  ssh_buffer_uninit(&buffer);
  return TRUE;
}

/* This should also work reasonably. */
Boolean ssh_psystem_hex_decoder(unsigned char *in, size_t in_len,
				void **out, size_t *out_len)
{
  if (in_len < 2)
    return FALSE;
  if (in[0] != '0' || in[1] != 'x')
    return FALSE;

  return ssh_psystem_decode_hex(in + 2, in_len - 2,
				(unsigned char **)out, out_len);
}

Boolean ssh_psystem_hex_decoder_int(unsigned char *in, size_t in_len,
				    void **out, size_t *out_len)
{
  void *my_out;
  size_t my_len;
  MP_INT *temp;
  
  if (ssh_psystem_hex_decoder(in, in_len,
			      &my_out, &my_len) == FALSE)
    return FALSE;

  temp = ssh_xmalloc(sizeof(*temp));
  mpz_init(temp);

  ssh_buf_to_mp(temp, my_out, my_len);
  ssh_xfree(my_out);

  *out = temp;
  *out_len = 0;
  return TRUE;
}

Boolean ssh_psystem_hex_decoder_str(unsigned char *in, size_t in_len,
				    void **out, size_t *out_len)
{
  void *my_out;
  size_t my_out_len;
  
  if (ssh_psystem_hex_decoder(in, in_len,
			      &my_out, &my_out_len) == FALSE)
    return FALSE;

  /* Force terminating zero, just in case. */
  *out = ssh_xmalloc(my_out_len + 1);
  memcpy(*out, my_out, my_out_len);
  ((unsigned char *)(*out))[my_out_len] = '\0';
  *out_len = my_out_len;
  ssh_xfree(my_out);
  return TRUE;
}
     
Boolean ssh_psystem_hex_decoder_ip(unsigned char *in, size_t in_len,
				   void **out, size_t *out_len)
{
  if (ssh_psystem_hex_decoder(in, in_len,
			      out, out_len) == FALSE)
    return FALSE;

  if (*out_len != 4)
    {
      ssh_xfree(out);
      return FALSE;
    }
  return TRUE;
}
     
Boolean ssh_psystem_base64_decoder(unsigned char *in, size_t in_len,
				   void **out, size_t *out_len)
{
  size_t len;
  unsigned char *str;

  if (in_len < 0)
    return FALSE;

  if (in[0] != '#')
    return FALSE;
  
  len = ssh_is_base64_buf(in + 1, in_len - 1);

  if (len < in_len - 1)
    return FALSE;
  
  if (len == 0)
    {
      *out = NULL;
      *out_len = 0;
      return TRUE;
    }
  
  /* This is rather ugly but have do it. */
  str = ssh_xmalloc(len + 1);
  memcpy(str, in + 1, len);
  str[len] = '\0';
  
  *out = ssh_base64_to_buf(str, out_len);
  ssh_xfree(str);
  return TRUE;
}
     
Boolean ssh_psystem_base64_decoder_int(unsigned char *in, size_t in_len,
				       void **out, size_t *out_len)
{
  void *my_out;
  size_t my_len;
  MP_INT *temp;
  
  if (ssh_psystem_base64_decoder(in, in_len,
				 &my_out, &my_len) == FALSE)
    return FALSE;

  temp = ssh_xmalloc(sizeof(*temp));
  mpz_init(temp);

  ssh_buf_to_mp(temp, my_out, my_len);
  ssh_xfree(my_out);

  *out = temp;
  *out_len = 0;
  return TRUE;
}

Boolean ssh_psystem_base64_decoder_str(unsigned char *in, size_t in_len,
				       void **out, size_t *out_len)
{
  void *my_out;
  size_t my_out_len;
  
  if (ssh_psystem_base64_decoder(in, in_len,
				 &my_out, &my_out_len) == FALSE)
    return FALSE;

  /* Force terminating zero, just in case. */
  *out = ssh_xmalloc(my_out_len + 1);
  memcpy(*out, my_out, my_out_len);
  ((unsigned char *)(*out))[my_out_len] = '\0';
  *out_len = my_out_len;
  ssh_xfree(my_out);
  return TRUE;
}
     
Boolean ssh_psystem_base64_decoder_ip(unsigned char *in, size_t in_len,
				      void **out, size_t *out_len)
{
  if (ssh_psystem_base64_decoder(in, in_len,
				 out, out_len) == FALSE)
    return FALSE;

  if (*out_len != 4)
    {
      ssh_xfree(out);
      return FALSE;
    }
  return TRUE;
}

Boolean ssh_psystem_ip_decoder(unsigned char *in, size_t in_len,
			       void **out, size_t *out_len)
{
  unsigned int a, b, c, d;
  if (sscanf((char *) in, "%3u.%3u.%3u.%3u",
	     &a, &b, &c, &d) != 4)
    return FALSE;

  if (a > 255 || b > 255 || c > 255 || d > 255)
    return FALSE;

  /* This seems too easy. */
  *out = ssh_xmalloc(4);
  *out_len = 4;

  ((unsigned char *)(*out))[0] = (unsigned char)a;
  ((unsigned char *)(*out))[1] = (unsigned char)b;
  ((unsigned char *)(*out))[2] = (unsigned char)c;
  ((unsigned char *)(*out))[3] = (unsigned char)d;
  return TRUE;
}

Boolean ssh_psystem_name_decoder(unsigned char *in, size_t in_len,
				 void **out, size_t *out_len)
{
  if (in_len == 0)
    return FALSE;
  *out = ssh_xmalloc(in_len + 1);
  *out_len = in_len;
  memcpy(*out, in, in_len);
  ((unsigned char*)(*out))[*out_len] = '\0';
  return TRUE;
}

typedef struct SshPSystemDecodersRec
{
  Boolean (*decoder)(unsigned char *in_buf, size_t in_len,
		     void **out_buf, size_t *out_len);
  unsigned int flag;
#define SSH_PSYSTEM_FLAG_NONE    0
#define SSH_PSYSTEM_FLAG_INTEGER 1
#define SSH_PSYSTEM_FLAG_STRING  2
#define SSH_PSYSTEM_FLAG_HEX     4
#define SSH_PSYSTEM_FLAG_BASE64  8
#define SSH_PSYSTEM_FLAG_IP      16
#define SSH_PSYSTEM_FLAG_LDAP_DN 32
#define SSH_PSYSTEM_FLAG_NAME    64
} SshPSystemDecoders;

SshPSystemDecoders ssh_psystem_decoders[] =
{
  { ssh_psystem_integer_decoder,
    SSH_PSYSTEM_FLAG_INTEGER },
  { ssh_psystem_hex_decoder_int,
    SSH_PSYSTEM_FLAG_HEX | SSH_PSYSTEM_FLAG_INTEGER },
  { ssh_psystem_hex_decoder_ip,
    SSH_PSYSTEM_FLAG_HEX | SSH_PSYSTEM_FLAG_IP },
  { ssh_psystem_hex_decoder_str,
    SSH_PSYSTEM_FLAG_HEX | SSH_PSYSTEM_FLAG_STRING },
  { ssh_psystem_base64_decoder_int,
    SSH_PSYSTEM_FLAG_BASE64 | SSH_PSYSTEM_FLAG_INTEGER },
  { ssh_psystem_base64_decoder_str,
    SSH_PSYSTEM_FLAG_BASE64 | SSH_PSYSTEM_FLAG_STRING },
  { ssh_psystem_base64_decoder_ip,
    SSH_PSYSTEM_FLAG_BASE64 | SSH_PSYSTEM_FLAG_IP },
  { ssh_psystem_ip_decoder,
    SSH_PSYSTEM_FLAG_IP },
  { ssh_psystem_name_decoder,
    SSH_PSYSTEM_FLAG_NAME },
  { NULL, 0 }
};

typedef struct SshPSystemMappingRec
{
  SshPSystemType type;
  unsigned int flag;
} SshPSystemMapping;

SshPSystemMapping ssh_psystem_mapping[] =
{
  { SSH_PSYSTEM_INTEGER, SSH_PSYSTEM_FLAG_INTEGER },
  { SSH_PSYSTEM_STRING,  SSH_PSYSTEM_FLAG_STRING },
  { SSH_PSYSTEM_IP,      SSH_PSYSTEM_FLAG_IP },
  { SSH_PSYSTEM_LDAP_DN, SSH_PSYSTEM_FLAG_LDAP_DN },
  { SSH_PSYSTEM_NAME,    SSH_PSYSTEM_FLAG_NAME },
  { 0, SSH_PSYSTEM_FLAG_NONE }
};

unsigned int ssh_psystem_map(SshPSystemType type)
{
  int i;
  for (i = 0; ssh_psystem_mapping[i].flag != SSH_PSYSTEM_FLAG_NONE; i++)
    {
      if (ssh_psystem_mapping[i].type == type)
	return ssh_psystem_mapping[i].flag;
    }
  return SSH_PSYSTEM_FLAG_NONE;
}

SshPSystemStatus ssh_psystem_read_string(SshPSystemPos *pos,
					 void **token_str,
					 size_t *token_str_len)
{
  SshBuffer buffer;
  Boolean escaped = FALSE, escape_whitespace = FALSE;
  unsigned char byte;
  
  ssh_buffer_init(&buffer);

  for (; pos->eof == FALSE;)
    {
      byte = NBYTE(pos);
      if (escaped)
	{
	  switch (byte)
	    {
	    case 'n':
	      ssh_buffer_append(&buffer, (unsigned char *) "\n", 1);
	      break;
	    case 't':
	      ssh_buffer_append(&buffer, (unsigned char *) "\t", 1);
	      break;
	    case 'r':
	      ssh_buffer_append(&buffer, (unsigned char *) "\r", 1);
	      break;
	    case '"':
	      ssh_buffer_append(&buffer, (unsigned char *) "\"", 1);
	      break;
	    case '\\':
	      ssh_buffer_append(&buffer, (unsigned char *) "\\", 1);
	      break;
	    case '\n':
	      escape_whitespace = TRUE;
	      break;
	    case ' ':
	      break;
	    case '\t':
	      break;
	    default:
	      ssh_buffer_append(&buffer, &byte, 1);
	      break;
	    }
	  escaped = FALSE;
	}
      else
	{
	  switch (byte)
	    {
	    case '"':
	      *token_str = (void *)buffer_to_str(&buffer, token_str_len);
	      ssh_buffer_uninit(&buffer);
	      return SSH_PSYSTEM_OK;
	      break;
	      
	    case '\\':
	      escaped = TRUE;
	      break;
	      
	    case ' ':
	    case '\n':
	    case '\t':
	      if (escape_whitespace == TRUE)
		continue;
	    default:
	      ssh_buffer_append(&buffer, &byte, 1);
	      break;
	    }
	  escape_whitespace = FALSE;
	}
    }
  ssh_buffer_uninit(&buffer);
  return SSH_PSYSTEM_FAILURE;
}

SshPSystemStatus ssh_psystem_read_ldap_dn(SshPSystemPos *pos,
					  void **token_str,
					  size_t *token_str_len)
{
  SshBuffer buffer;
  Boolean escaped, quoted, prev_was_whitespace;
  unsigned char byte;
  
  escaped = FALSE;
  quoted = FALSE;
  prev_was_whitespace = FALSE;

  ssh_buffer_init(&buffer);
  
  for (; pos->eof == FALSE; )
    {
      byte = NBYTE(pos);
      if (quoted)
	{
	  if (escaped)
	    {
	      switch (byte)
		{
		case ' ':
		case '\t':
		case '\n':
		  break;
		default:
		  ssh_buffer_append(&buffer, &byte, 1);
		  break;
		}
	      escaped = FALSE;
	    }
	  else
	    {
	      switch (byte)
		{
		case '\\':
		  escaped = TRUE;
		  break;
		case '"':
		  /* Finish quoting. */
		  ssh_buffer_append(&buffer, &byte, 1);
		  quoted = FALSE;
		  break;
		default:
		  ssh_buffer_append(&buffer, &byte, 1);
		  break;
		}
	    }
	}
      else
	{
	  /* We don't here concert ourselves with escaping. It is much
	     too difficult, and leave it to some other function. :) */
	  
	  switch (byte)
	    {
	    case '>':
	      /* Finished. */
	      *token_str = buffer_to_str(&buffer, token_str_len);
	      ssh_buffer_uninit(&buffer);
	      return SSH_PSYSTEM_OK;
	      break;
	      
	    case ' ':
	    case '\t':
	    case '\n':
	      if (!prev_was_whitespace)
		ssh_buffer_append(&buffer, &byte, 1);
	      prev_was_whitespace = TRUE;
	      continue;
	    case '"':
	      quoted = TRUE;
	      ssh_buffer_append(&buffer, &byte, 1);
	      break;
	    default:
	      ssh_buffer_append(&buffer, &byte, 1);
	      break;
	    }
	}
      prev_was_whitespace = FALSE;
    }
  ssh_buffer_uninit(&buffer);
  return SSH_PSYSTEM_FAILURE;
}

/* Internal data types which are recognized at some point, and a flag that
   one should try recognization by the decoders listed. */
typedef enum
{
  SSH_PSYSTEM_READ_ENV_OPEN,
  SSH_PSYSTEM_READ_ENV_CLOSE,
  SSH_PSYSTEM_READ_LIST_OPEN,
  SSH_PSYSTEM_READ_LIST_CLOSE,
  SSH_PSYSTEM_READ_LDAP_DN,
  SSH_PSYSTEM_READ_STRING,
  SSH_PSYSTEM_READ_USE_RECOGNIZE
} SshPSystemToken;

/* Read the next token. */
SshPSystemStatus ssh_psystem_read_next(SshPSystemDef *def,
				       SshPSystemPos *pos,
				       SshPSystemToken *token,
				       void **token_str,
				       size_t *token_str_len)
{
  Boolean name_read = FALSE, name_set = FALSE;
  Boolean escaped = FALSE, escape_whitespace = FALSE;
  SshBuffer buffer;
  unsigned char byte;

  /* Set to defaults. */
  *token = SSH_PSYSTEM_READ_USE_RECOGNIZE;
  *token_str = NULL;
  *token_str_len = 0;
  
  ssh_buffer_init(&buffer);
  
  for (; pos->eof == FALSE && name_read == FALSE;)
    {
      byte = NBYTE(pos);

      /* We allow a lot to be escaped. This might be indeed nice on many
	 occasions. */
      if (escaped)
	{
	  switch (byte)
	    {
	      /* Most useful operation, escaping the linefeed. */
	    case '\n':
	      escape_whitespace = TRUE;
	      /* name_set = FALSE; */
	      break;
	      /* The rest, what might be, is not yet implemented. */ 
	    default:
	      ssh_buffer_append(&buffer, &byte, 1);
	      name_set = TRUE;
	      break;
	    }
	  escaped = FALSE;
	}
      else
	{
	  switch (byte)
	    {
	    case '\n':
	    case ' ':
	    case '\t':
	      if (escape_whitespace)
		continue;
	      if (name_set == TRUE)
		name_read = TRUE;
	      break;
	      /* Special characters, which need to be checked before
		 continuing. They are errorneous if not in the beginning
		 of appropriate sequence. */
	    case '{':
	      if (name_set == FALSE)
		{
		  *token = SSH_PSYSTEM_READ_ENV_OPEN;
		  ssh_buffer_uninit(&buffer);
		  return SSH_PSYSTEM_OK;
		}
	      PBYTE(pos, byte);
	      name_read = TRUE;
	      break;
	    
	    case '}':
	      if (name_set == FALSE)
		{
		  *token = SSH_PSYSTEM_READ_ENV_CLOSE;
		  ssh_buffer_uninit(&buffer);
		  return SSH_PSYSTEM_OK;
		}
	      PBYTE(pos, byte);
	      name_read = TRUE;
	      break;
	    
	    case '[':
	      if (name_set == FALSE)
		{
		  *token = SSH_PSYSTEM_READ_LIST_OPEN;
		  ssh_buffer_uninit(&buffer);
		  return SSH_PSYSTEM_OK;
		}
	      PBYTE(pos, byte);
	      name_read = TRUE;
	      break;
	    
	    case ']':
	      if (name_set == FALSE)
		{
		  *token = SSH_PSYSTEM_READ_LIST_CLOSE;
		  ssh_buffer_uninit(&buffer);
		  return SSH_PSYSTEM_OK;
		}
	      PBYTE(pos, byte);
	      name_read = TRUE;
	      break;

	    case '<':
	      ssh_buffer_uninit(&buffer);
	      if (name_set == TRUE)
		return SSH_PSYSTEM_FAILURE;

	      /* Read the LDAP Distinguished Name. */
	      *token = SSH_PSYSTEM_READ_LDAP_DN;
	      return ssh_psystem_read_ldap_dn(pos, token_str, token_str_len);
	      break;
	    case '"':
	      ssh_buffer_uninit(&buffer);
	      if (name_set == TRUE)
		return SSH_PSYSTEM_FAILURE;

	      /* Read the standard string. */
	      *token = SSH_PSYSTEM_READ_STRING;
	      return ssh_psystem_read_string(pos, token_str, token_str_len);
	      break;
	    case '%':
	      for (; pos->eof == FALSE;)
		{
		  byte = NBYTE(pos);
		  if (byte == '\n')
		    break;
		}
	      /* This is important, thus comments also separate things. */
	      if (name_set == TRUE)
		name_read = TRUE;
	      break;
	    case '\\':
	      escaped = TRUE;
	      break;
	    default:
	      *token = SSH_PSYSTEM_READ_USE_RECOGNIZE;
	      ssh_buffer_append(&buffer, &byte, 1);
	      name_set = TRUE;
	      break;
	    }
	  escape_whitespace = FALSE;
	}
    }
  *token_str = buffer_to_str(&buffer, token_str_len);
  ssh_buffer_uninit(&buffer);
  return SSH_PSYSTEM_OK;
}

typedef struct SshPSystemStackEntryRec
{
  SshPSystemEnv *env;
  void *tmp_context;
  int list_level;
} SshPSystemStackEntry;

typedef enum
{
  SSH_PSYSTEM_NEXT_ENV,
  SSH_PSYSTEM_NEXT_VAR,
  SSH_PSYSTEM_NEXT_VAGUE, 
  SSH_PSYSTEM_NEXT_NAME,
  SSH_PSYSTEM_NEXT_DATA
} SshPSystemNextToken;

/* The main function which does it all. */

void *ssh_psystem_parse(SshPSystemDef *def,
			SshPSystemError *ret_error)
{
  SshPSystemPos pos;
  SshPSystemEnv *env, *new_env, *prev_env;
  SshPSystemVar *var;
  SshPSystemStatus error;
  SshPSystemStackEntry *entry;
  SshPSystemNextToken token_type;
  SshPSystemToken token, token_to_expect, prev_type;
  SshDStack *stack;
  void *token_str, *buf, *ret, *env_tmp_context,
    *object_context, *feed_context;
  size_t token_str_len, i, buf_len;
  int level;
  int list_level;
  unsigned int flag;
  
  /* Mainly just call the right function at the right time. */

  /* Information of the position and the current token. */
  ssh_psystem_pos_init(&pos, def->more, def->more_context);

  /* Main loop. */

  level = 0;
  stack = NULL;
  env = def->root;
  token_type = SSH_PSYSTEM_NEXT_ENV;
  list_level = 0;

  /* Initialize the root. */
  if (env->handler)
    {
      if ((*env->handler)(SSH_PSYSTEM_INIT,
			  0,
			  NULL, 0,
			  0,
			  /* in = feeding, out = context */
			  def->feeding, &env_tmp_context) == FALSE)
	{
	  error = SSH_PSYSTEM_FAILURE;
	  goto failed;
	}
    }
  else
    {
      error = SSH_PSYSTEM_FAILURE;
      goto failed;
    }
  
  for (token_to_expect = SSH_PSYSTEM_NEXT_NAME; ;) 
    {
      if (token_to_expect == SSH_PSYSTEM_NEXT_NAME)
	{
	  /* Read first the name. */
	  error = ssh_psystem_read_next(def, &pos, &token, &token_str,
					&token_str_len);
	  if (error != SSH_PSYSTEM_OK)
	    goto failed;
	  if (pos.eof == TRUE)
	    break;

	  switch (token)
	    {
	    case SSH_PSYSTEM_READ_ENV_CLOSE:
	      level--;
	      if (level < 0 || list_level != 0)
		{
		  error = SSH_PSYSTEM_MISPLACED_CLOSE;
		  goto failed;
		}
	      /* Finish the thing. */
	      if ((*env->handler)(SSH_PSYSTEM_FINAL,
				  0,
				  NULL, 0, 0,
				  /* in = temp, out = finalized, temp will
				     be freed in the process. */
				  env_tmp_context, &object_context) == FALSE)
		{
		  error = SSH_PSYSTEM_OBJECT_NOT_CREATED;
		  goto failed;
		}

	      /* Get the object type. */
	      prev_env  = env;
	      prev_type = env->aptype;

	      /* Get the old environment. */
	      entry = ssh_dstack_pop(&stack);
	      token_type = SSH_PSYSTEM_NEXT_ENV;

	      /* Get information. */
	      env = entry->env;
	      list_level = entry->list_level;
	      env_tmp_context = entry->tmp_context;
	      ssh_xfree(entry);
	      
	      /* Add the object. */
	      if ((*env->handler)(SSH_PSYSTEM_OBJECT,
				  prev_type,
				  object_context, 0,
				  list_level,
				  /* in = temp, out = NULL */
				  env_tmp_context, NULL) == FALSE)
		{
		  error = SSH_PSYSTEM_ADD_FAILED;
		  goto failed;
		}

	      /* What if we are still in middle of a list? */
	      if (list_level)
		{
		  token_to_expect = SSH_PSYSTEM_NEXT_DATA;
		  new_env = prev_env;
		}
	      continue;
	    default:
	      break;
	    }
	  
	  /* Could try to find a match here, and thus report error message
	     immediately. This would keep the line correct for error messages,
	     if one searches for set operator then the line number might be
	     totally different. */

	  /* Check first for variable. */
	  token_type = SSH_PSYSTEM_NEXT_VAGUE;
	  
	  if (env->var_bind == NULL &&
	      env->env_bind == NULL)
	    {
	      error = SSH_PSYSTEM_NO_BIND;
	      goto failed;
	    }

	  if (token_str == NULL)
	    {
	      error = SSH_PSYSTEM_TOKEN_STR_EMPTY;
	      goto failed;
	    }
	  
	  if (env->var_bind)
	    {
	      for (i = 0; env->var_bind[i].name; i++)
		{
		  if (strcmp(env->var_bind[i].name, token_str) == 0)
		    {
		      var = &env->var_bind[i];
		      token_type = SSH_PSYSTEM_NEXT_VAR;
		      goto match_success;
		    }
		}
	    }
	  
	  if (env->env_bind)
	    {
	      for (i = 0; env->env_bind[i].name; i++)
		{
		  if (strcmp(env->env_bind[i].name, token_str) == 0)
		    {
		      if (token_type == SSH_PSYSTEM_NEXT_VAR)
			{
			  error = SSH_PSYSTEM_SAME_NAME_USED;
			  goto failed;
			}
		      else
			token_type = SSH_PSYSTEM_NEXT_ENV;
		      new_env = &env->env_bind[i];
		      if (new_env->handler == NULL)
			{
			  error = SSH_PSYSTEM_HANDLER_MISSING;
			  goto failed;
			}
			
		      goto match_success;
		    }
		}
	    }

	  ssh_xfree(token_str);
	  
	  error = SSH_PSYSTEM_NOT_SUPPORTED_NAME;
	  goto failed;
	  
	  /* We were successful. */
	match_success:

	  ssh_xfree(token_str);

	  /* Now check for very simple cases (without operators even). */
	  if (token_type == SSH_PSYSTEM_NEXT_VAR)
	    {
	      switch (var->type)
		{
		case SSH_PSYSTEM_VOID:
		  /* Handle the void type, which is pretty easy. */
		  if ((*env->handler)(SSH_PSYSTEM_OBJECT,
				      var->aptype,
				      NULL, 0,
				      0,
				      /* in = temp, out = NULL */
				      env_tmp_context, NULL) == FALSE)
		    {
		      error = SSH_PSYSTEM_COULD_NOT_ADD;
		      goto failed;
		    }
		  continue;
		default:
		  break;
		}
	    }
	  
	  /* Read then the set sign, if one used. */
	  if (def->assign_operator)
	    {
	      error = ssh_psystem_read_next(def, &pos, &token,
					    &token_str, &token_str_len);
	      if (error != SSH_PSYSTEM_OK)
		goto failed;
	      if (pos.eof == TRUE)
		break;
	      if (token_str == NULL)
		{
		  error = SSH_PSYSTEM_EXPECTED_ASSIGNMENT;
		  goto failed;
		}
	      if (strcmp(token_str, def->assign_operator) != 0)
		{
		  error = SSH_PSYSTEM_NOT_OPERATOR;
		  goto failed;
		}
	    }
	  token_to_expect = SSH_PSYSTEM_NEXT_DATA;
	}
      else
	{
	  error = ssh_psystem_read_next(def, &pos,
					&token, &token_str, &token_str_len);
	  if (error != SSH_PSYSTEM_OK)
	    goto failed;
	  if (pos.eof == TRUE)
	    break;
	  
	  if (token_type == SSH_PSYSTEM_NEXT_ENV)
	    {
	      switch (token)
		{
		case SSH_PSYSTEM_READ_ENV_OPEN:
		  /* Read whether the parent environment wants to
		     feed off the children. */
		  /* Make sure that the feed_context is properly set. */
		  feed_context = NULL;
		  if ((*env->handler)(SSH_PSYSTEM_FEED,
				      new_env->aptype,
				      NULL, 0,
				      0,
				      env_tmp_context,
				      &feed_context) == FALSE)
		    {
		      /* Didn't want to and gave an error! However, this
			 is not that bad. Things happen. Lets continue. */
		    }
		  
		  /* Push the current environment. */
		  entry = ssh_xmalloc(sizeof(*entry));
		  entry->env = env;
		  entry->tmp_context = env_tmp_context;
		  entry->list_level = list_level;
		  ssh_dstack_push(&stack, entry);
		  
		  /* Start a new environment. */
		  level++;
		  env = new_env;
		  list_level = 0;
		  if ((*env->handler)(SSH_PSYSTEM_INIT,
				      0,
				      NULL, 0,
				      0,
				      /* in = feeding?, out = temp. */
				      feed_context,
				      &env_tmp_context) == FALSE)
		    {
		      error = SSH_PSYSTEM_INIT_FAILED;
		      goto failed;
		    }
		  
		  token_to_expect = SSH_PSYSTEM_NEXT_NAME;
		  break;
		case SSH_PSYSTEM_READ_LIST_OPEN:
		  list_level++;
		  if ((*env->handler)(SSH_PSYSTEM_LIST_OPEN,
				      0,
				      NULL, 0,
				      list_level,
				      /* in = temp, out = NULL */
				      env_tmp_context, NULL) == FALSE)
		    {
		      error = SSH_PSYSTEM_COULD_NOT_OPEN_LIST;
		      goto failed;
		    }
		  break;
		case SSH_PSYSTEM_READ_LIST_CLOSE:
		  list_level--;
		  if (list_level < 0)
		    {
		      error = SSH_PSYSTEM_LIST_MISMATCH;
		      goto failed;
		    }
		  if ((*env->handler)(SSH_PSYSTEM_LIST_CLOSE,
				      0, NULL, 0,
				      list_level,
				      /* in = temp, out = NULL */
				      env_tmp_context, NULL) == FALSE)
		    {
		      error = SSH_PSYSTEM_COULD_NOT_CLOSE_LIST;
		      goto failed;
		    }
		  /* Handle here the case when list is over, however,
		     maybe one could do this nicer... */
		  if (list_level == 0)
		    token_to_expect = SSH_PSYSTEM_NEXT_NAME;
		  break;
		default:
		  ssh_xfree(token_str);
		  error = SSH_PSYSTEM_TOKEN_NOT_EXPECTED;
		  goto failed;
		  break;
		}
	      continue;
	    }
	  
	  switch (token)
	    {
	    case SSH_PSYSTEM_READ_USE_RECOGNIZE:
	      /* Recognize with all known methods. */
	      flag = ssh_psystem_map(var->type);
	      
	      for (i = 0;
		   ssh_psystem_decoders[i].decoder != NULL; i++)
		{
		  if ((ssh_psystem_decoders[i].flag & flag) != 0)
		    {
		      if ((*ssh_psystem_decoders[i].decoder)
			  (token_str, token_str_len,
			   &buf, &buf_len) == TRUE)
			break;
		    }
		}
	      if (ssh_psystem_decoders[i].decoder == NULL)
		{
		  error = SSH_PSYSTEM_UNSUPPORTED_TYPE;
		  goto failed;
		}

	      /* Free the token string. */
	      ssh_xfree(token_str);
	      if ((*env->handler)(SSH_PSYSTEM_OBJECT,
				  var->aptype,
				  buf, buf_len,
				  list_level,
				  /* in = temp, out = NULL */
				  env_tmp_context, NULL) == FALSE)
		{
		  error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
		  goto failed;
		}
	      break;
	    case SSH_PSYSTEM_READ_LDAP_DN:
	      if (var->type != SSH_PSYSTEM_LDAP_DN)
		{
		  error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
		  goto failed;
		}
	      if ((*env->handler)(SSH_PSYSTEM_OBJECT,
				  var->aptype,
				  token_str, token_str_len,
				  list_level,
				  /* in = temp, out = NULL */
				  env_tmp_context, NULL) == FALSE)
		{
		  error = SSH_PSYSTEM_COULD_NOT_ADD;
		  goto failed;
		}
	      break;
	    case SSH_PSYSTEM_READ_STRING:
	      if (var->type != SSH_PSYSTEM_STRING)
		{
		  error = SSH_PSYSTEM_TYPE_DID_NOT_MATCH;
		  goto failed;
		}
	      if ((*env->handler)(SSH_PSYSTEM_OBJECT,
				  var->aptype,
				  token_str, token_str_len,
				  list_level,
				  /* in = temp, out = NULL */
				  env_tmp_context, NULL) == FALSE)
		{
		  error = SSH_PSYSTEM_COULD_NOT_ADD;
		  goto failed;
		}
	      break;
	    case SSH_PSYSTEM_READ_LIST_OPEN:
	      list_level++;
	      if ((*env->handler)(SSH_PSYSTEM_LIST_OPEN,
				  0, NULL, 0,
				  list_level,
				  /* in = temp, out = NULL */
				  env_tmp_context, NULL) == FALSE)
		{
		  error = SSH_PSYSTEM_COULD_NOT_OPEN_LIST;
		  goto failed;
		}
	      break;
	    case SSH_PSYSTEM_READ_LIST_CLOSE:
	      list_level--;
	      if (list_level < 0)
		{
		  error = SSH_PSYSTEM_LIST_MISMATCH;
		  goto failed;
		}
	      if ((*env->handler)(SSH_PSYSTEM_LIST_CLOSE,
				  0, NULL, 0,
				  list_level,
				  /* in = temp, out = NULL */
				  env_tmp_context, NULL) == FALSE)
		{
		  error = SSH_PSYSTEM_COULD_NOT_CLOSE_LIST;
		  goto failed;
		}
	      break;
	    default:
	      ssh_xfree(token_str);
	      error = SSH_PSYSTEM_UNKNOWN_TYPE;
	      goto failed;
	      break;
	    }

	  /* Only if the list level allows, use this. */
	  if (list_level == 0)
	    token_to_expect = SSH_PSYSTEM_NEXT_NAME;
	}
    }
  error = SSH_PSYSTEM_OK;
failed:

  /* Free current context. */
  if (env && ssh_dstack_exists(&stack))
    {
      if ((*env->handler)(SSH_PSYSTEM_ERROR,
			  0,
			  NULL,
			  0, 0,
			  /* in = temp, out = NULL */
			  env_tmp_context, NULL) == FALSE)
	{
	  /* Ignore the error for now. At this point some earlier error
	     must have also occurred. */
	}
      ret = NULL;
    }
  else
    {
      /* Have a environment at return. */
      ret = env;
    }
  
  while (ssh_dstack_exists(&stack))
    {
      entry = ssh_dstack_pop(&stack);
      env = entry->env;
      env_tmp_context = entry->tmp_context;
      if (env)
	{
	  /* Free the environment context. */
	  if ((*env->handler)(SSH_PSYSTEM_ERROR,
			      0, NULL, 0, 0,
			      /* in = temp, out = NULL */
			      env_tmp_context, NULL) == FALSE)
	    {
	      /* Ignore the error for now. At this point some earlier error
		 must have also occurred. */
	    }
	}
    }

  /* Build the suitable error message. */
  ret_error->status = error;
  /* Make the line no and pos no emacs compatible. */
  ret_error->line   = pos.line + 1;
  ret_error->pos    = pos.pos + 1;
  
  return ret;
}
