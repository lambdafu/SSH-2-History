/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Tue Jun  4 03:39:26 1996 [huima]

  The lexical analyzer for the configuration files parser. 

  */

/*
 * $Id: cflexer.h,v 1.4 1998/01/28 10:13:55 ylo Exp $
 * $Log: cflexer.h,v $
 * $EndLog$
 */

#ifndef CFLEXER_H
#define CFLEXER_H

#include "sshincludes.h"

/* This are the different return values from some functions in this
   module. */
#define SSH_CFLEX_OK                         0
#define SSH_CFLEX_FILE_ERROR                 1
#define SSH_CFLEX_STAT_ERROR                 2
#define SSH_CFLEX_NO_TOKEN                   3
#define SSH_CFLEX_LEXICAL_ERROR              4
#define SSH_CFLEX_ILLEGAL_TOKEN              5

/* These are terminal tokens returned by the lexer; note that CFT_EOF
   is a token. It will be returned infinitely many times if the parser
   asks for it infinitely many times (after a CFT_EOF, an infinite
   stream of CFT_EOFs follow by subsequent calls to
   ssh_cflex_get_token). */
#define CFT_IDENTIFIER           1
#define CFT_STRING               2
#define CFT_DEFAULT              3
#define CFT_ELSE                 4
#define CFT_ENABLE               5
#define CFT_ENABLED              6
#define CFT_END                  7
#define CFT_FOR                  8
#define CFT_IF                   9
#define CFT_MERGE               10
#define CFT_NOT                 11
#define CFT_SWITCH              12
#define CFT_USE                 13 
#define CFT_WITH                14
#define CFT_EQUAL               15
#define CFT_CASE                16
#define CFT_EOF                 17

typedef struct SshCFlexContext *SshCFlexContext;

/* Create a lexer context. */
SshCFlexContext ssh_cflex_create_context(void);


/* Destroy it. Note that this releases the file from memory, and the
   structures created by the parser refer to this memory area. So
   destroying the lexer context before the parser context is *extremely
   bad idea*. */
void ssh_cflex_destroy_context(SshCFlexContext context);

/* This reads a file into the lexer; it returns an error if the file
   couldn't be opened. */
int ssh_cflex_read_file(SshCFlexContext context,
			const char *filename);

/* This gives the file as string to lexer. */
void ssh_cflex_give_config(SshCFlexContext context,
			   char *config_string);

/* Get the next token from the file. *token_type will contain the
   token type (CFT_<something>), and *token will point to a
   null-terminated string containing the token. If the token is a
   string, this will point to the string (backslashs unquoted). If
   the token is an identifier, this will point to the identifier
   string. If the token is something else (a reserved word), this and
   *token_len may contain garbage. If *token is set, then token_len is
   the length of the string. */
int ssh_cflex_get_token(SshCFlexContext context,
			int *token_type,
			unsigned char **token,
			unsigned int *token_len);

/* This returns the error message from the lexer, if an error has
   occurred. Otherwise it returns garbage. */
const char *ssh_cflex_get_error_message(SshCFlexContext context);

/* This returns the line number that the last token ended on. */
int ssh_cflex_get_line_number(SshCFlexContext context);

#endif /* CFLEXER_H */

