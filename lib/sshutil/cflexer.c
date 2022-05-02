/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Tue Jun  4 03:32:58 1996 [huima]



  */

/*
 * $Id: cflexer.c,v 1.15 1998/05/23 21:03:54 kivinen Exp $
 * $Log: cflexer.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "cflexer.h"

#define CNORM   0x00
#define CWHITE  0x01  /* Tab, CR, LF, space */
#define CQUOTE  0x02  /* double quote */
#define CSLASH  0x04  /* backslash */
#define CEQUAL  0x08  /* equal sign */
#define COCOMM  0x10  /* sharp sign */

#define STABLE(x) ssh_cflex_syntactic_table[x]

/* This is the syntactic table of the 256 characters. */

const unsigned char SSH_CODE_SEGMENT ssh_cflex_syntactic_table[] = {

/* Non-printable characters */

CWHITE,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 0 - 7 */
/* Tab, CR and LF are white space */
CNORM,	CWHITE, CWHITE,	CNORM,	CNORM,  CWHITE,	CNORM,	CNORM, /* 8 - 15 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 16 - 23 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 24 - 31 */

/* Printable characters */

/* Space is white space. Sharp sign (#) begins comment.
   Double quote is the quotation mark. */
CWHITE,	CNORM,	CQUOTE,	COCOMM,	CNORM,	CNORM,	CNORM,	CNORM, /* 32 - 39 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 40 - 47 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 48 - 55 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 56 - 63 */
CNORM, 	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 64 - 71 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 72 - 79 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 80 - 87 */
/* Backslash is the slashification character. */
CNORM,	CNORM,	CNORM,	CNORM, 	CSLASH,	CNORM,	CNORM,	CNORM, /* 88 - 95 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 96 - 103 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 104 - 111 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 112 - 119 */
CNORM,	CNORM,	CNORM,	CNORM, 	CNORM,	CNORM,	CNORM,	CNORM, /* 120 - 127 */

/* Eight-bit characters */

CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 128 - 135 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 136 - 143 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 144 - 151 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 152 - 159 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 160 - 167 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 168 - 175 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 176 - 183 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 184 - 191 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 192 - 199 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 200 - 207 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 208 - 215 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 216 - 223 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 224 - 231 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 232 - 239 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 240 - 247 */
CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM,	CNORM, /* 248 - 255*/
};

/* The hash table contains the reserved keywords with the
   corresponding token numbers. The hashing function is described in
   the comments for ssh_cflex_parse_identifier. */

typedef struct ssh_cf_id_hash_entry {
    const char *id;
    int token;
} SshCFIdHashEntry;

#define CF_HASH_MOD 25

/* Can't put this in the code segment because it contains pointers to const strings. */
const SshCFIdHashEntry ssh_cf_hash_table[CF_HASH_MOD] = { 
     { "", 0 },
     { "", 0 },
     { "", 0 },
     { "", 0 },
     { "end", CFT_END },
     { "merge", CFT_MERGE },
     { "", 0 },
     { "", 0 },
     { "with", CFT_WITH },
     { "else", CFT_ELSE },
     { "if", CFT_IF },
     { "for", CFT_FOR },
     { "enable", CFT_ENABLE },
     { "switch", CFT_SWITCH },
     { "", 0 },
     { "", 0 },
     { "default", CFT_DEFAULT },
     { "", 0 },
     { "", 0 },
     { "", 0 },
     { "use", CFT_USE },
     { "", 0 },
     { "not", CFT_NOT },
     { "", 0 },
     { "enabled", CFT_ENABLED } };

/* The lexer context. `data_ptr' points always to the beginning of the
   configuration file data. `end_ptr' is a pointer to the first char
   which does not belong to the configuration file, so that (end_ptr -
   data_ptr) is the length of the file. `current_ptr' points to the
   first unread character in the file (between calls to
   ssh_cflex_get_token). `error_message'[] is used to store the error
   message. `temp_buf' is used in constructing error messages, and is
   inside the structure just for speed (otherwise it would be
   allocated from the stack every time ssh_cflex_get_token is
   called). `line_feeds' keeps count of the line feeds ('\n')
   encountered; line_feeds + 1 is the current line number. */
struct SshCFlexContext {
  unsigned char *data_ptr;
  unsigned char *end_ptr;
  unsigned char *current_ptr;

  char error_message[200];
  char temp_buf[200];
  unsigned int line_feeds;
};


/* Constructor of the lexer context. */
SshCFlexContext ssh_cflex_create_context()
{
  SshCFlexContext created = ssh_xmalloc(sizeof(*created));
  created->data_ptr = NULL;
  created->line_feeds = 0;
  return created;
}

/* Destructor of the lexer context. */
void ssh_cflex_destroy_context(SshCFlexContext context)
{
  if (context->data_ptr)
    ssh_xfree(context->data_ptr);
  ssh_xfree(context);
}

/* This parses an identifier starting from `token_start' and of length
   (bound - token_start). It returns the corresponding token number,
   either one of the keywords or CFT_IDENTIFIER if the identifier was
   none of the keywords.

   The hashing function is: initialize HASH to zero, and then for
   every other char in the identifier, add the unsigned character
   value of the character to HASH and multiply HASH with 2 modulo
   65536. After the loop, compute HASH mod CF_HASH_MOD (the size of
   the hash table). */
static int ssh_cflex_parse_identifier(SshCFlexContext context,
				      unsigned char *token_start,
				      unsigned char *bound)
{
  int i;
  int len = bound - token_start;
  unsigned long hash = 0;
  char buf[100];
  assert(len > 0);

  strncpy(buf, (char *) token_start, bound - token_start);
  buf[bound - token_start] = 0;

  if (bound - token_start == 1)
    {
      if (token_start[0] == '=')
	return CFT_EQUAL;
      if (token_start[0] == '?')
	return CFT_CASE;
      return CFT_IDENTIFIER;
    }
  
  for (i = 0; i < (len & 7); i += 2)
    {
      hash += token_start[i];
      hash <<= 1;
      hash &= 65535;
    }

  hash %= CF_HASH_MOD;

  if (!ssh_cf_hash_table[hash].token)
    return CFT_IDENTIFIER;

  if (strncmp(ssh_cf_hash_table[hash].id, (char *) token_start, len))
    return CFT_IDENTIFIER;

  return ssh_cf_hash_table[hash].token;
}

/* This reads a configuration file into an internal buffer. */
int ssh_cflex_read_file(SshCFlexContext context,
			const char *filename)
{
  int fd;
  unsigned long file_size;

#ifdef WINDOWS
  fd = open(filename, O_RDONLY | O_BINARY);
#else
  fd = open(filename, O_RDONLY);
#endif

  if (fd < 0)
    return SSH_CFLEX_FILE_ERROR;

  file_size = (unsigned long) lseek(fd, 0L, SEEK_END);
  lseek(fd, 0L, SEEK_SET);

#ifdef WINDOWS
  if (file_size > 64000)
    {
      close(fd);
      return SSH_CFLEX_FILE_ERROR;
    }
#endif
  context->data_ptr = ssh_xmalloc(file_size);
  context->end_ptr = context->data_ptr + file_size;
  context->current_ptr = context->data_ptr;

  file_size -= read(fd, context->data_ptr, (size_t) file_size);

  close(fd);

  if (file_size != 0)
    {
      ssh_xfree(context->data_ptr);
      context->data_ptr = NULL;
      return SSH_CFLEX_FILE_ERROR;
    }

  return SSH_CFLEX_OK;
}

/* This sets the lexer's string to given mallocated string. */
void ssh_cflex_give_config(SshCFlexContext context, char *config_string)
{
  context->data_ptr = (unsigned char *) config_string;
  context->end_ptr = context->data_ptr + strlen(config_string);
  context->current_ptr = context->data_ptr;
}

static void ssh_cflex_unslashify(char *string, unsigned int *len)
{
  char *ptr;
  int shift, tmp;

  shift = 0;
  for (ptr = string; ptr - string < *len; ptr++)
    {
      if (*ptr != '\\')
	{
	  *(ptr - shift) = *ptr;
	  continue;
	}
      ptr++;
      shift++;
      switch(*ptr)
	{
	case 'a':
	  *(ptr - shift) = '\a';
	  break;
	case 'b':
	  *(ptr - shift) = '\b';
	  break;
	case 'f':
	  *(ptr - shift) = '\f';
	  break;
	case 'n':
	  *(ptr - shift) = '\n';
	  break;
	case 'r':
	  *(ptr - shift) = '\r';
	  break;
	case 't':
	  *(ptr - shift) = '\t';
	  break;
	case 'v':
	  *(ptr - shift) = '\v';
	  break;
	case '\\':
	  *(ptr - shift) = '\\';
	  break;
	case 'x':
	  tmp = 0;
	  while (isxdigit(ptr[1]))
	    {
	      shift++;
	      ptr++;
	      tmp *= 16;
	      if (isdigit(*ptr))
		{
		  tmp += *ptr - '0';
		}
	      else
		{
		  if (islower(*ptr)) 
		    tmp += *ptr - 'a' + 10;
		  else 
		    tmp += *ptr - 'A' + 10;
		}
	    }
	  *(ptr - shift) = tmp;
	  break;
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
	  tmp = 0;
	  while (isdigit(*ptr) && *ptr < '8')
	    {
	      tmp *= 8;
	      tmp += *ptr - '0';
	      shift++;
	      ptr++;
	    }
	  shift--;
	  ptr--;
	  *(ptr - shift) = tmp;
	  break;
	default:
	  *(ptr - shift) = *ptr;
	  break;
	}
    }
  *(ptr - shift) = '\0';
  *len -= shift;
  return;
}

/* Return the next token from the file. */
int ssh_cflex_get_token(SshCFlexContext context,
			int *token_type,
			unsigned char **token,
			unsigned int *token_len)
{
  unsigned char *dptr = context->current_ptr;
  unsigned char *eptr = context->end_ptr;
  unsigned char *token_start = NULL;
  unsigned char *temp_ptr;
  int return_token_value = 0;
  int t_len = 0;
  char buf[11];

  strncpy(buf, (char *) dptr, 10);
  buf[10] = '\n';

  /* skip whitespace */
skip_over_whitespace:
  while (!(dptr == eptr) && (STABLE(*dptr) == CWHITE))
    {
      if ((*dptr) == '\n')
	context->line_feeds++;
      dptr++;
    }

  if (dptr == eptr) /* end of file reached */
    {
      *token_type = CFT_EOF;
      return SSH_CFLEX_OK;
    }
  /* comment? */

  if (STABLE(*dptr) == COCOMM)
    {
      /* skip the comment sign */
      dptr++; 

      while (!(dptr == eptr) && *dptr != '\n')
	dptr++;

      context->line_feeds++;

      dptr++; /* skip the return */
      if (dptr >= eptr) /* we might have skipped over the end above */
	{
	  *token_type = CFT_EOF;
	  return SSH_CFLEX_OK;
	}

      /* There may be still more whitespace */
      goto skip_over_whitespace;
    }

  /* We are now looking at non-white-space */

  switch (STABLE(*dptr))
    {
    case CQUOTE: /* quotation */
      dptr++;
      if (dptr == eptr)
	{
	  snprintf(context->temp_buf, sizeof(context->temp_buf),
		   "unterminated string");
	  goto lexically_bad;      
	}
      token_start = dptr;
      while (STABLE(*dptr) != CQUOTE)
	{
	  if (STABLE(*dptr) == CSLASH)
	    {
	      dptr++;
	      if (dptr == eptr)
		{
		  snprintf(context->temp_buf, sizeof(context->temp_buf),
			  "unterminated backslashification (in string)");
		  goto lexically_bad;
		}
	      /* Skip over octal and hex numbers */
	      if (*dptr == 'x' || *dptr == '0' || *dptr == '1' ||
		  *dptr == '2')
		{
		  dptr += 2;
		  if (dptr >= eptr)
		    {
		      snprintf(context->temp_buf, sizeof(context->temp_buf),
			      "illegal backslashification "
			      "(in string) `\\%c..'",
			      *(dptr - 2));
		      goto lexically_bad;
		    }
		}
	    }
	  dptr++;
	  if (dptr >= eptr)
	    {
	      snprintf(context->temp_buf, sizeof(context->temp_buf),
		       "unterminated string");
	      goto lexically_bad;
	    }
	}
      t_len = dptr - token_start;
      dptr++;
      return_token_value = CFT_STRING;
      break;
    case CSLASH:
    case CNORM:
      token_start = dptr;
      while (dptr < eptr && ((STABLE(*dptr) & (CWHITE | COCOMM))
			     == 0))
	{
	  dptr++;
	}
      return_token_value = ssh_cflex_parse_identifier(context,
						      token_start, dptr);
      t_len = dptr - token_start;
      goto lexically_ok;
    default:
      ssh_fatal("Fatal bug in flexer -- syntactic table inconsistent.\n");
      /* NOTREACHED */
      break;
    }
lexically_ok:
  if (token_start != NULL)
    {
      *token = token_start;
      *token_len = t_len;
      temp_ptr = token_start + t_len;

      if (*temp_ptr == '\n')
	context->line_feeds++;
      *temp_ptr = 0;
      
      if (return_token_value == CFT_STRING ||
	  return_token_value == CFT_IDENTIFIER)
	{
	  ssh_cflex_unslashify((char *) token_start, token_len);
	}
    }

  *token_type = return_token_value;
  context->current_ptr = dptr;
  return SSH_CFLEX_OK;

lexically_bad:
  snprintf(context->error_message, sizeof(context->error_message),
	   "Lexical error on line %d:\n%s",
	  ssh_cflex_get_line_number(context),
	  context->temp_buf);
  
  return SSH_CFLEX_LEXICAL_ERROR;
}

/* Return the error message. */
const char *ssh_cflex_get_error_message(SshCFlexContext context)
{
  return context->error_message;
}

/* Return the current line number. */
int ssh_cflex_get_line_number(SshCFlexContext context)
{
  return context->line_feeds + 1;
}
