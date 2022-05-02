/*

  psystem.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Oct 23 22:22:30 1997 [mkojo]

  The Parse System for Configuration files.

  */

/*
 * $Id: psystem.h,v 1.6 1998/07/31 19:30:18 mkojo Exp $
 * $Log: psystem.h,v $
 * $EndLog$
 */

#ifndef PSYSTEM_H
#define PSYSTEM_H

/* Types which are of interest to the developer of configure file
   parser. */

/* Following data types are supported. Note that Hex and Base64 could
   be anything. Thus when data of hex or base64 type is found then it
   is automagically converted into a suitable format. However, the
   callback should take some care in checking input (as always
   naturally).  */
typedef enum
{
  /* Some environment. */
  SSH_PSYSTEM_OBJECT,

  /* These are not always necessary to handle. */
  SSH_PSYSTEM_LIST_OPEN,
  SSH_PSYSTEM_LIST_CLOSE,

  /* Basic operations which must be handled. */
  SSH_PSYSTEM_INIT,
  SSH_PSYSTEM_ERROR,
  SSH_PSYSTEM_FINAL,
  SSH_PSYSTEM_FEED
} SshPSystemEvent;

typedef enum
{
  SSH_PSYSTEM_INTEGER,
  SSH_PSYSTEM_STRING,
  SSH_PSYSTEM_LDAP_DN,
  SSH_PSYSTEM_IP,
  SSH_PSYSTEM_NAME,
  SSH_PSYSTEM_VOID
} SshPSystemType;

/* Definition of a variable. */
typedef struct SshPSystemVarRec
{
  const char *name;
  unsigned int aptype;
  /* The data type of the name. */
  SshPSystemType type;
} SshPSystemVar;

/* The structure to define a environment. */
typedef struct SshPSystemEnvRec
{
  /* The name of the given environment. */
  const char *name;
  /* Type by which this is known in the handler. */
  unsigned int aptype;

  /* Generic handler for all cases. */
  Boolean (*handler)(SshPSystemEvent event,
		     unsigned int aptype,
		     void *data, size_t data_len,
		     unsigned int list_level,
		     void *context_in, void **context_out);
  
  /* Define suitable namespaces. It might be easiest at start to just
     use one global list of both. However, later one could build
     hierachial systems with namespaces. */
  struct SshPSystemEnvRec *env_bind;
  SshPSystemVar *var_bind;
} SshPSystemEnv;

typedef struct SshPSystemDefRec
{
  /* The root. */
  SshPSystemEnv *root;
  /* Must be NULL if nothing to feed. */
  void *feeding;
  
  /* The operators. */

  /* The assignment operator (e.g. "=" or "::=" etc.). */
  char *assign_operator; 
  
  /* The more function. This reads additional information for the
     parser. */
  int (*more)(void *context, unsigned char **buf, size_t *buf_len);
  void *more_context;
} SshPSystemDef;

/* Just to help us out in writing many handlers. */
#define SSH_PSYSTEM_HANDLER(name) \
Boolean name##_handler(SshPSystemEvent event, \
		       unsigned int aptype,  \
		       void *data, size_t data_len, \
		       unsigned int list_level,  \
		       void *context_in, void **context_out)

/* Following routines can be used from the callbacks. */

/* Error status table (global). */
typedef enum
{
  SSH_PSYSTEM_OK,
  SSH_PSYSTEM_FAILURE,
  SSH_PSYSTEM_UNKNOWN_LANGUAGE,
  SSH_PSYSTEM_MISPLACED_CLOSE,
  SSH_PSYSTEM_OBJECT_NOT_CREATED,
  SSH_PSYSTEM_ADD_FAILED,
  SSH_PSYSTEM_NO_BIND,
  SSH_PSYSTEM_SAME_NAME_USED,
  SSH_PSYSTEM_NOT_SUPPORTED_NAME,
  SSH_PSYSTEM_NOT_OPERATOR,
  SSH_PSYSTEM_TOKEN_NOT_EXPECTED,
  SSH_PSYSTEM_UNSUPPORTED_TYPE,
  SSH_PSYSTEM_TYPE_DID_NOT_MATCH,
  SSH_PSYSTEM_LIST_MISMATCH,
  SSH_PSYSTEM_UNKNOWN_TYPE,
  SSH_PSYSTEM_TOKEN_STR_EMPTY,
  SSH_PSYSTEM_HANDLER_MISSING,
  SSH_PSYSTEM_COULD_NOT_ADD,
  SSH_PSYSTEM_COULD_NOT_OPEN_LIST,
  SSH_PSYSTEM_COULD_NOT_CLOSE_LIST,
  SSH_PSYSTEM_INIT_FAILED,
  SSH_PSYSTEM_EXPECTED_ASSIGNMENT
  /* etc. */
} SshPSystemStatus;

typedef struct
{
  SshPSystemStatus status;
  unsigned int line, pos;
} SshPSystemError;

/* Return a standard error message. */
char *ssh_psystem_error_msg(SshPSystemStatus status);

/* The function which runs the parse system for the selected input. */
void *ssh_psystem_parse(SshPSystemDef *def,
			SshPSystemError *error);

#if 0
/* An example of a handler, use this if you don't want to figure out
   more suitable format to your application. (And still want to
   use PSystem). */

SSH_PSYSTEM_HANDLER(name)
{
  NameCtx *c;
#if 0
  if (list_level)
    return FALSE;
#endif
  switch (event)
    {
    case SSH_PSYSTEM_INIT:
    case SSH_PSYSTEM_ERROR:
    case SSH_PSYSTEM_FINAL:
    case SSH_PSYSTEM_OBJECT:
      switch (aptype)
	{
	default:
	  break;
	}
      break;
    default:
      break;
    }
  return FALSE;
}     
#endif

#endif /* PSYSTEM_H */
