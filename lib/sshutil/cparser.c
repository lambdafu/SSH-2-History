/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sun Jun  9 22:28:54 1996 [huima]

  Configuration file parser (C-code).  The syntax is described in
  SSH-Devel-2 (and hopely in some user's manual!)

  The parser is a table-based bottom-up parser.

  It uses cflexer as a lexical front-end (see cflexer.h).

  */

/*
 * $Id: cparser.c,v 1.29 1998/05/23 21:08:51 kivinen Exp $
 * $Log: cparser.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "cflexer.h"
#include "cparser.h"
#include "nspace.h"
#ifndef WINDOWS
#include "sshtcp.h"
#endif

/* First available id number for user types. */
#define CF_USER			200

/* The maximum number of tokens involved in a reduction. This
   corresponds to the size of the token[] array in structure
   CFReduction. */
#define CF_MAX_REDUCTION_LEN 6

/* The number of reductions in cf_parser_reduction_table. */
#define CF_NUMBER_REDUCTIONS 38

/* The maximum number of stack items in the parser stack. */
#define CF_STACK_SIZE 1000

/* Non-terminals (terminals are defined in cflexer.h) */
#define CFN_ACTUAL_DEF          30
#define CFN_ANONYMOUS_BEGIN     31
#define CFN_CONDITIONAL         32
#define CFN_COPIED_NAME_SPACE   33
#define CFN_DEFAULT_DEF         34
#define CFN_IDENTIFIER          35
#define CFN_NAME_SPACE          36
#define CFN_STRING              37
#define CFN_TYPE                38
#define CFN_SWITCH              39

/* Special values for tokens in reductions */
#define CFS_ANY                101
#define CFS_BOTTOM             100

/* The id number for the global structure type. */
#define CF_GLOBAL_TYPE         100

#ifdef DEBUG_HEAVY
const char *const cf_token_name[] =
{
  "What?",
  "ID", "STRING", "DEFAULT", "ELSE", "ENABLE", "ENABLED", "END", "FOR",
  "IF", "MERGE", "NOT", "SWITCH", "USE", "WITH", "EQUAL", "CASE", "EOF",
  "18", "19", "20",
  "21", "22", "23", "24", "25", "26", "27", "28", "29",
  "ActualDef", "AnonymousBegin", "Cond", "CopiedNameSpace", "DefaultDef",
  "Ident", "NameSpace", "String", "Type", "Switch",
};
#endif

/* Skip `backwards' topmost items of the stack, and then scan
   downwards to see if we are in a conditional which has evaluated to
   false. Then forget the top of the stack and return immediately from
   a reducor (see below). */
#define SKIP_IF_NECESSARY(backwards) \
{ if (cf_parser_should_skip(parser, stack_position - backwards)) \
  { return stack_position - backwards; } }

#define SKIP_IF_NECESSARY_WITH_LOOKAHEAD(backwards) \
{ if (cf_parser_should_skip(parser, stack_position - (backwards + 1))) \
  { COPY_STACK(backwards + 1, 1); \
    return stack_position - backwards; } }

#define COPY_STACK(to, from) memcpy(&parser->stack[stack_position - (to)],\
  &parser->stack[stack_position - (from)], sizeof(CFStack))

/* A macro to get the token string from the `x'nd stack position (1 ==
   the topmost item) */
#define STACKTOKEN(x)  (parser->stack[stack_position - (x)].\
	    	        value.token.token_start)

/* A macro to get the token len from the `x'nd stack position (1 ==
   the topmost item) */
#define STACKTOKENLEN(x)  (parser->stack[stack_position - (x)].\
	    	        value.token.token_len)

/* A macro to quickly define the header for a reducor function (see
   below) */
#define REDUCOR(x) int x (CFParser parser, int stack_position)

/* Reducors are functions which are called when a particular reduction
   should take place. They all receive the same standard set of
   arguments (the parser context and the current stack position -- the
   stack position is never saved in the context). */
typedef int(* CFReducor)(CFParser parser, int stack_position);

#define CF_CONDITIONAL_TRUE     0x01
#define CF_CONDITIONAL_REVERSED 0x02
#define CF_CONDITIONAL_SWITCH   0x04

/* A stack item in the parser stack. `token' is the type of the stack
   item; it is either CFT_<something>, corresponding to a terminal
   token. In such a case the `token' field of the union `value' should
   be used. CFN_<something> token types correspond to
   non-terminals. They use various fields of the union. */
typedef struct cf_stack {
  int token;
  union {
    struct {
      unsigned char *token_start;
      unsigned int token_len;
    } token;
    NameSpace *name_space;
    struct {
      unsigned char *string;
      unsigned int len;
    } str;
    int conditional;
    int type_id;
  } value;
  int line_number;
} CFStack;

/* An item in the reduction table. token[] contains n tokens and
   CF_MAX_REDUCTION_LEN - n zeros following. There must be at least one
   zero. If the n top items of the stack match the values in the token[]
   array, the reduction function `reducor' is called. */
typedef struct cf_reduction {
  int token[CF_MAX_REDUCTION_LEN];
  CFReducor reducor; 
  const char *debug_name;
} CFReduction;

/* NOTE! The reduction table is AT BOTTOM of the file (and cannot be
   moved, because it contains pointers to functions in this file) */
extern const CFReduction cf_parser_reduction_table[CF_NUMBER_REDUCTIONS];

/* The parser context. `nscontext' is a handle to the name space
   module which is used extensively. `lex' is a handle to the lexical
   scan module cflexer. `global_space' is (a pointer to) the global
   name space; it is the name space which is in use when the parsing
   goes on the top level of a configuration file. `current_space'
   denotes the current name space during the parsing (when the parser
   moves to a new, inner name space, the outer is saved onto the
   stack).

   `chosen_configuration' is the name space which the user has chosen
   to be the configuration in use with the final use clause.

   `config_id' is the type id of the top-level configuration structure
   type (e.g., the type id of structure "Configuration", provided that
   the application uses such a structure as the top-levle
   configuration structure.

   `enables' is a name space which contains the enabled (with enable-
   clause) names mapped to some uninteresting numbers (they aren't
   used, the only thing counting is whether a name is mapped or
   not). It is used in evaluating if-clauses.

   `error_message' points to an error message if an error is
    signaled. `stack'[] is the parser stack. */
struct CFParser {
  NSContext nscontext;
  SshCFlexContext lex;
  NameSpace *global_space, *current_space;
  NameSpace *chosen_configuration;
  int config_id;
  NameSpace enables;
  char *error_message;
  CFStack stack[CF_STACK_SIZE];
  CFApplicationVariableCallback callback;
  void *context;
  int false_conditionals;
};

/* Set the error message using vsnprintf.  The length of the error
   message must not exceed 150 characters in size. */
void cf_parser_error(CFParser parser, int stack_position,
		     const char *format, ...)
{
  
  char formatbuf[200];
  char buf[200];

  va_list args;
  va_start(args, format);
  vsnprintf(formatbuf, sizeof(formatbuf), format, args);
  va_end(args);

  if (stack_position > 0)
    {
      snprintf(buf, sizeof(buf),
	       "Error on (or near) line %d:\n%s",
	       parser->stack[stack_position].line_number, formatbuf);
    }
  else
    {
      snprintf(buf, sizeof(buf),
	       "General parser error:\n%s", formatbuf);
    }
      
  if (parser->error_message)
    ssh_xfree(parser->error_message);

  parser->error_message = ssh_xstrdup(buf);
}

/* Create a parser context. The type `Global' is registered for the
   top level name space type. Applications should use type id numbers
   CF_USER and above. */
CFParser cf_parser_create()
{
  CFParser created = ssh_xmalloc(sizeof(*created));
  created->nscontext = name_space_create_context();
  created->lex = ssh_cflex_create_context();
 
  created->error_message = NULL;

  name_space_register_type(created->nscontext, "Global", 0,
			   NSPACE_STRUCTURE, CF_GLOBAL_TYPE);

  created->global_space =
    name_space_create_name_space(created->nscontext, CF_GLOBAL_TYPE);

  created->chosen_configuration = NULL;

  name_space_init_name_space(&created->enables, 0, NSPACE_STRUCTURE, 0);
			     
  return created;
}

/* Delete a parser context. The name space context is destroyed
   (causing all name space structures to get destroyed). The lexical
   context is destroyed, too. */
void cf_destroy_parser(CFParser parser)
{
  name_space_destroy_context(parser->nscontext);
  ssh_cflex_destroy_context(parser->lex);
  if (parser->error_message != NULL)
    ssh_xfree(parser->error_message);
  name_space_free_name_space(&parser->enables);
  ssh_xfree(parser);
}

/* Return the current error message (in the normal usage of the
   parser, the error message will get set only once. Note that
   *error_message could point to the error message of the lexer. */
const char *cf_parser_get_error_message(CFParser parser)
{
  return parser->error_message;
}

/* Delcare the grammar to parser. The grammar is declared in
   CFParserDeclareItemList array. */
int cf_declare_grammar(CFParser parser, const CFParserDeclareItemList grammar)
{
  int i;
  unsigned int type_id = CF_USER;
  unsigned int last_struct_id = 0;
  unsigned int type;
  unsigned int len;
  NameSpace *space, *def;
  char buffer[1024];
  const char *default_value;

  for(i = 0; grammar[i].item_type != CF_END; i++)
    {
      switch (grammar[i].item_type)
	{
	case CF_STRUCT:		/* Register new structure */
	  if (name_space_register_type(parser->nscontext, grammar[i].name, 0,
				       NSPACE_STRUCTURE, type_id))
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Type `%.50s' already registered while "
		       "declaring grammar", grammar[i].name);
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  last_struct_id = type_id;
	  type_id++;
	  break;
	case CF_FIELD:		/* Register field in structure */
	  if (last_struct_id == 0)
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Field `%.50s' is not in CF_STRUCT context while "
		       "declaring grammar", grammar[i].name);
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  type = name_space_get_type_id(parser->nscontext,
				    grammar[i].value_type_name);
	  if (type < CF_USER)
	    {			/* Value is basic type with defaults */
	      default_value = grammar[i].default_value;
	      len = grammar[i].length;
	      if (default_value == NULL)
		{
		  if (type == NSPACE_INTEGER || type == NSPACE_BOOLEAN ||
		      type == NSPACE_TPORT || type == NSPACE_UPORT ||
		      type == NSPACE_REAL)
		    default_value = "0";
		  else
		    default_value = "";
		  len = 0;
		}
	      if (len == 0)
		len = strlen(default_value);
	      space = name_space_get_default_ns(parser->nscontext,
						last_struct_id);
	      
	      if (space == NULL ||
		  name_space_add_mapping(space, grammar[i].name,
					 type, default_value, len))
		{
		  if (parser->error_message)
		    ssh_xfree(parser->error_message);
		  snprintf(buffer, sizeof(buffer),
			   "Field `%.50s' have invalid default `%.50s' for "
			   "type %.50s while declaring grammar",
			   grammar[i].name, default_value,
			   grammar[i].value_type_name);
		  parser->error_message = ssh_xstrdup(buffer);
		  return CF_PARSER_DECLARATION_ERROR;
		}
	    }
	  else
	    {			/* Value is complex type, no defaults */
	      space = name_space_get_default_ns(parser->nscontext,
						last_struct_id);
	      def = name_space_get_default_ns(parser->nscontext, type);
	      if (space == NULL || def == NULL ||
		  name_space_add_ns_mapping(space, grammar[i].name, def))
		{
		  if (parser->error_message)
		    ssh_xfree(parser->error_message);
		  snprintf(buffer, sizeof(buffer),
			   "Error occured while declaring compound field"
			   "`%.50s' (type = %.50s) while declaring grammar",
			   grammar[i].name, 
			   grammar[i].value_type_name);
		  parser->error_message = ssh_xstrdup(buffer);
		  return CF_PARSER_DECLARATION_ERROR;
		}
	    }
	  break;
	case CF_ENVIRONMENT_DEFAULT: /* Environment defaults */
	  type = name_space_get_type_id(parser->nscontext,
				    grammar[i].value_type_name);
	  if (type < CF_USER)
	    return CF_PARSER_DECLARATION_ERROR;
	  space = name_space_get_default_ns(parser->nscontext, type);
	  if (space->type.base_type != NSPACE_ENVIRONMENT ||
	      space->type.base_type != NSPACE_ENVIRONMENT_OVERWRITABLE)
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Enviroment default for type `%.50s' which is "
		       "not enviroment while declaring grammar", 
		       grammar[i].value_type_name);
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  
	  if (space == NULL ||
	      name_space_add_mapping(space,
				     grammar[i].name,
				     space->type.base_type,
				     grammar[i].default_value,
				     (grammar[i].length == 0 ?
				      strlen(grammar[i].
					     default_value) : 
				      grammar[i].length)))
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Enviroment `%.50s' have invalid default `%.50s' for "
		       "type %.50s while declaring grammar",
		       grammar[i].value_type_name,
		       grammar[i].default_value,
		       name_space_get_type_name(parser->nscontext,
						space->type.base_type));
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  break;
	case CF_LIST:		/* Register new list type */
	  if (name_space_register_type(parser->nscontext, grammar[i].name,
				       NSPACE_LIST,
				       name_space_get_type_id(parser->
							      nscontext,
							      grammar[i].
							      value_type_name),
				       type_id)) 
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Type `%.50s' already registered while "
		       "declaring grammar", grammar[i].name);
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  last_struct_id = 0;
	  type_id++;
	  break;
	case CF_ENVIRONMENT:	/* Register new environment type */
	  if (name_space_register_type(parser->nscontext, grammar[i].name,
				       NSPACE_ENVIRONMENT,
				       name_space_get_type_id(parser->
							      nscontext,
							      grammar[i].
							      value_type_name),
				       type_id)) 
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Type `%.50s' already registered while "
		       "declaring grammar", grammar[i].name);
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  last_struct_id = 0;
	  type_id++;
	  break;
	case CF_OVERWRITABLE_ENVIRONMENT: /* Register new overwritable
					     environment type */
	  if (name_space_register_type(parser->nscontext, grammar[i].name,
				       NSPACE_ENVIRONMENT_OVERWRITABLE,
				       name_space_get_type_id(parser->
							      nscontext,
							      grammar[i].
							      value_type_name),
				       type_id)) 
	    {
	      if (parser->error_message)
		ssh_xfree(parser->error_message);
	      snprintf(buffer, sizeof(buffer),
		       "Type `%.50s' already registered while "
		       "declaring grammar", grammar[i].name);
	      parser->error_message = ssh_xstrdup(buffer);
	      return CF_PARSER_DECLARATION_ERROR;
	    }
	  last_struct_id = 0;
	  type_id++;
	  break;
	case CF_TOPLEVEL_TYPE:	/* Declare top level configuration variable
				   type  */
	  parser->config_id = name_space_get_type_id(parser->nscontext,
						     grammar[i].name);
	  last_struct_id = 0;
	  break;
	case CF_END:
	  break;
	}
    }
  return CF_PARSER_OK;
}

/* Begin from the name space *space and traverse through contained
   structures as specified in `steps' and `args'.

   `steps' is a string which must contain only characters `n' and
   `i'. `args' is a set of arguments, the number of which must
   correspond to the length of `steps'.

   If length(steps) == 1, then the only va_list item is handled as
   number (if the corresponding character is `n') or a pointer to an
   identifier string (if the corresponding character is `i'). `space'
   is searched for a mapping identified by the argument. Then the
   value of the mapping is returned (NULL, if mapping was not
   found). If `identifier' is non-NULL, then a pointer to the
   identifier which mapped will get written to it. This is useful,
   when an environment mapping is identifier by its sequence number,
   and the application wants to know both the identifier WHICH mapped,
   and the string (or name space) it mapped TO.

   cf_traverse is used in cf_get_compound_handle,
   cf_get_string_option and cf_get_identifier. */
static NameSpaceValue
*cf_traverse(const char *steps, NameSpace *space, va_list args,
	     char **identifier)
{
  char *id;
  int num_id;
  NameSpaceValue *value = NULL;

  while (*steps != '\0')
    {
      if (space == NULL)
	return NULL;

      switch (*steps)
	{
	case 'i':
	  id = va_arg(args, char *);
	  value = name_space_map(space, id);
	  break;
	case 'n':
	  num_id = va_arg(args, int);
	  value = name_space_map_sequence(space, num_id);
	  if (identifier != NULL && space->type.complex_type != NSPACE_LIST)
	    *identifier = space->mapping[num_id].id.identifier;
	  break;
	default:
	  ssh_fatal("Unknown traverse type `%c' in cf_traverse.", *steps);
	  break;
	}

      if (value->type != NSPACE_NSPACE)
	space = NULL;
      else
	space = value->value.name_space;

      steps++;
    }

  return value;
}

/* Read the configuration file in. This does NOT imply parsing yet;
   the lexer simply reads the file. This will return CF_PARSER_OK,
   except if the lexer met an error during reading. Then
   CF_PARSER_FILE_ERROR shall be returned. */
int cf_read_file(CFParser parser, const char *filename)
{
  if (ssh_cflex_read_file(parser->lex, filename))
    {
      cf_parser_error(parser, 0, "Configuration file `%s' not found.",
		      filename);
      return CF_PARSER_FILE_ERROR;
    }
  return CF_PARSER_OK;
}

/* This gives a configuration file as a mallocated string to parser, but does
   not parse it. Check the return value! cf_parse will crash if this has
   returned an error. The parser will free when it doesn't need it anymore. */
void cf_give_config(CFParser parser, char *config_string)
{
  ssh_cflex_give_config(parser->lex, config_string);
}

/* Return non-zero, if `identifier' is unbound in `space'. Otherwise
   return zero and set the error message. */
static int cf_is_free_identifier(CFParser parser, int stack_position,
				 NameSpace *space,
				 const char *identifier)
{
  if (name_space_map(space, identifier))
    {
      cf_parser_error(parser, stack_position,
		      "Redeclaration of `%.50s'", identifier);
      return 0;
    }
  return 1;
}

/* Return TRUE, if the parser is in a state where it should skip all
   bindings (this is caused by conditional clauses that have evaluated
   to false). */
static Boolean cf_parser_should_skip(CFParser parser,
				     int stack_position)
{
  if (parser->false_conditionals > 0)
    return TRUE;
  return FALSE;
}

/* Try to bind `identifier' to name space `target' in the name space `space'. 
   Return non-zero if the operation succeeded, otherwise zero.

   This performs type checking in the following manner:

   If the space where the identifier is to be bound is a structure,
   then there must be a declared field `identifier' in the structure
   whose type must be equal to the type of `target'.

   If the space where the identifier is to be bound is a list or an
   environment, then the type of `target' must match the item type of
   the list/environment type name space.  */
static int cf_ns_bind(CFParser parser, int stack_position,
		      NameSpace *space,
		      const char *identifier, NameSpace *target)
{
  int type = 0;
  
  if (space->type.base_type == NSPACE_STRUCTURE)
    {
      type = name_space_get_field_type(parser->nscontext,
				       identifier,
				       space->type.id_number);
    }
  if (space->type.complex_type == NSPACE_ENVIRONMENT ||
      space->type.complex_type == NSPACE_ENVIRONMENT_OVERWRITABLE ||
      space->type.complex_type == NSPACE_LIST)
    {
      type = space->type.base_type;
    }

  if (space != parser->global_space)
    {
      if (type == 0)
	{
	  cf_parser_error(parser, stack_position,
			  "Structure contains no field named `%.50s'",
			  identifier);
	  return 0;
	}

      if (type != target->type.id_number)
	{
	  cf_parser_error(parser, stack_position,
			  "Type mismatch in binding `%.50s' "
			  "(was waiting for %s, got %s)",
			  identifier,
			  name_space_get_type_name(parser->nscontext,
						   type),
			  name_space_get_type_name(parser->nscontext,
						   target->type.id_number));
	  return 0;
	}
    }
  if (space->type.complex_type == NSPACE_LIST)
    {
      if (name_space_add_ns_mapping_list(space, target))
	{
	  cf_parser_error(parser, stack_position,
			  "Error adding list entry `%.50s' ",
			  identifier);
	  return 0;
	}
    }
  else
    {
      if (!cf_is_free_identifier(parser, stack_position, space, identifier))
	{
	  if (space->type.complex_type == NSPACE_ENVIRONMENT_OVERWRITABLE)
	    {
	      if (name_space_write_ns_mapping(space, identifier, target))
		{
		  cf_parser_error(parser, stack_position,
				  "Error when overwriting environment item `%.50s'",
				  identifier);
		  return 0;
		}
	      return 1;
	    }
	  else
	    {
	      cf_parser_error(parser, stack_position,
			      "Error overwriting identifier `%.50s' ",
			      identifier);
	      return 0;
	    }
	}

      name_space_add_ns_mapping(space, identifier, target);
    }

  return 1;
}

/* Try to bind identifier `identifier' to string `string' in the name
   space `space'. Other semantics are as for cf_ns_bind. */
int cf_bind(CFParser parser, int stack_position, NameSpace *space,
		const char *identifier, const char *string,
		unsigned int len)
{
  int type = 0, ret;
  
  if (space->type.base_type == NSPACE_STRUCTURE)
    {
      type = name_space_get_field_type(parser->nscontext,
				       identifier,
				       space->type.id_number);
    }
  if (space->type.complex_type == NSPACE_ENVIRONMENT ||
      space->type.complex_type == NSPACE_ENVIRONMENT_OVERWRITABLE ||
      space->type.complex_type == NSPACE_LIST)
    {
      type = space->type.base_type;
    }
  
  if (space != parser->global_space)
    {
      if (type == 0)
	{
	  cf_parser_error(parser, stack_position,
			  "Structure contains no field named `%.50s'",
			  identifier);
	  return 0;
	}

      if (type >= CF_USER)
	{
	  cf_parser_error(parser, stack_position,
			  "Type mismatch in binding `%.50s' "
			  "(was waiting for %s, got string)",
			  identifier,
			  name_space_get_type_name(parser->nscontext,
						   type));
	  return 0;
	}
    }

  /* If the current name space is list, add the value as a list
     item. Otherways try to bind it to the given identifier. */

  if (space->type.complex_type == NSPACE_LIST)
    {
      ret = name_space_add_mapping_list(space, type, string, len);
      if (ret)
	{
	  if (ret == NSPACE_VALUE_ERROR)
	    cf_parser_error(parser, stack_position,
			    "Invalid value for type %s in binding `%.50s' "
			    "(got string `%.50s')",
			    name_space_get_type_name(parser->nscontext,
						     type),
			    identifier,
			    string);
	  else 
	    cf_parser_error(parser, stack_position,
			    "name_space_add_mapping_list returned error %d "
			    "in binding `%.50s'",
			    ret, identifier);
	  return 0;
	}
    }
  else
    {
      if (!cf_is_free_identifier(parser, stack_position, space, identifier))
	{
	  if (space->type.complex_type == NSPACE_ENVIRONMENT_OVERWRITABLE)
	    {
	      ret = name_space_write_mapping(space, identifier,
					     type, string, len);
	    }
	  else
	    {
	      cf_parser_error(parser, stack_position,
			      "Error overwriting identifier `%.50s' ",
			      identifier);
	      return 0;
	    }
	}
      else
	{
	  ret = name_space_add_mapping(space, identifier, type, string, len);
	}
      if (ret)
	{
	  if (ret == NSPACE_VALUE_ERROR)
	    cf_parser_error(parser, stack_position,
			    "Invalid value for type %s in binding "
			    "`%.50s' (got string `%.50s')",
			    name_space_get_type_name(parser->nscontext,
						     type),
			    identifier,
			    string);
	  else 
	    cf_parser_error(parser, stack_position,
			    "name_space_add_mapping returned error %d "
			    "in binding `%.50s'",
			    ret, identifier);
	  return 0;
	}
    }
  return 1;
}

/***********************************************************************
 * REDUCORS. Reducors are functions which are used to reduce stack
 * items from the parser stack. Macro REDUCOR is declared at the
 * beginning of this file.  */

/* ERRORS */
REDUCOR(reduce_err_enable_not_at_bottom)
{
  cf_parser_error(parser,
		  stack_position - 2,
		  "Enable clause not the top level of the file");
  return 0;
}

REDUCOR(reduce_err_mangled_enable)
{
  cf_parser_error(parser, stack_position - 2,
		  "Mangled enable clause");
  return 0;
}

REDUCOR(reduce_err_mangled_if)
{
  cf_parser_error(parser, stack_position - 4,
		  "Mangled conditional");
  return 0;
}

REDUCOR(reduce_err_final_use_not_at_bottom)
{
  cf_parser_error(parser,
		  stack_position - 2,
		  "The final use clause does not appear at the "
		  "top level of the file");
  return 0;
}

REDUCOR(reduce_err_use_default_not_at_bottom)
{
  cf_parser_error(parser, stack_position - 4,
		  "The use default clause does not appear at the "
		  "top level of the file");
  return 0;
}

REDUCOR(reduce_err_mangled_use)
{
  cf_parser_error(parser, stack_position - 4,
		  "Mangled use clause");
  return 0;
}

REDUCOR(reduce_err_decl_end)
{
  int token = parser->stack[stack_position - 2].token;
  if (token == CFN_IDENTIFIER)
    {
      cf_parser_error(parser, stack_position - 3,
		      "Erroneus declaration block: could not understand `%s'",
		      STACKTOKEN(2));
    }
  else
    {
      cf_parser_error(parser, stack_position - 3,
		      "Erroneus declaration block");
    }

  return 0;
}

/* Enable clauses are totally reduced from the stack (they
   ``disappear'' after getting handled */
REDUCOR(reduce_enable)
{
  unsigned char *token = STACKTOKEN(1);
  if (name_space_map(&parser->enables, (char *) token))
    {
      cf_parser_error(parser, stack_position - 2,
		      "Enabling `%s' twice", token);
      return 0;
    }
      
  name_space_add_integer_mapping(&parser->enables,
				 (char *) token, 1);
  return stack_position - 2;
}

/* This is the final reducor which will be called if the file has
   ended and everything is all right */
REDUCOR(reduce_eof)
{
  return stack_position - 1;
}

/* This reduces the final use clause */
REDUCOR(reduce_final_use)
{
  parser->chosen_configuration =
    parser->stack[stack_position - 2].value.name_space;
  
  if (parser->chosen_configuration->type.id_number !=
      parser->config_id)
    {
      cf_parser_error(parser, stack_position - 3,
		      "Mismatching types in the final use "
		      "(configuration type is %s, got %s)",
		      name_space_get_type_name(parser->nscontext,
					       parser->config_id),
		      name_space_get_type_name(parser->nscontext,
					       parser->chosen_configuration->
					       type.id_number));
      return 0;
    }

  parser->stack[stack_position - 3].token = CFT_EOF;
  return stack_position - 2;
}

/* This reduces a default use clause */
REDUCOR(reduce_use_default)
{
  NameSpace *default_space, *target;
  int type_id;
  
  type_id = parser->stack[stack_position - 1].value.type_id;
  default_space = name_space_get_default_ns(parser->nscontext, type_id);

  /* If such a structure does not exist, then there is no such type --
     barf. */
  assert(default_space != NULL);
  target = parser->stack[stack_position - 3].value.name_space;

  /* If defaults for the given type have been already chosen, signal
     an error. */
  if (default_space->defaults != NULL)
    {
      cf_parser_error(parser, stack_position - 4,
		      "Defaults for type %s have been already chosen",
		      name_space_get_type_name(parser->nscontext, type_id));
      return 0;
    } 

  if (target->type.id_number != type_id ||
      (target->flags & NSPACE_IS_DEFAULT) == 0)
    {
      cf_parser_error(parser, stack_position - 4,
		      "The given structure is not declared "
		      "as a default value");
      return 0;
    }
  
  default_space->defaults = target;

  /* Remove the whole thing from the stack. */
  return stack_position - 4;
}

/* This begins a declaration of a default structure */
REDUCOR(reduce_default_begin)
{
  NameSpace *space;
  int type_id;

  if (!cf_is_free_identifier(parser, stack_position - 1,
			     parser->global_space, (char *) STACKTOKEN(1)))
    return 0;
  type_id = parser->stack[stack_position - 2].value.type_id;
  if (parser->current_space != parser->global_space)
    {
      cf_parser_error(parser, stack_position - 3,
		      "Default declarations may occur only on top level");
      return 0;
    }

  /* Save the current space onto the stack */
  parser->stack[stack_position - 3].value.name_space =
    parser->current_space;
  space = name_space_create_name_space(parser->nscontext, type_id);
  parser->stack[stack_position - 3].token = CFN_DEFAULT_DEF;
  parser->current_space = space;
  space->flags |= NSPACE_IS_DEFAULT;  

  /* Bind */
  if (!cf_ns_bind(parser, stack_position - 1,
		  parser->global_space, (char *) STACKTOKEN(1), space))
    return 0;

  return stack_position - 2;
}

REDUCOR(reduce_actual_begin)
{
  NameSpace *space;
  int type_id;

  if (!cf_is_free_identifier(parser, stack_position - 1,
			     parser->global_space, (char *) STACKTOKEN(1)))
    return 0;

  type_id = parser->stack[stack_position - 2].value.type_id;
  if (parser->current_space != parser->global_space)
    {
      cf_parser_error(parser, stack_position - 2,
		      "Named structure declarations may occur only on "
		      "top level.");
      return 0;
    }

  /* Save the current space onto the stack */
  parser->stack[stack_position - 2].value.name_space =
    parser->current_space;
  space = name_space_create_name_space(parser->nscontext, type_id);
  parser->stack[stack_position - 2].token = CFN_ACTUAL_DEF;
  parser->current_space = space;

  /* Bind */
  if (!cf_ns_bind(parser, stack_position - 1,
		  parser->global_space, (char *) STACKTOKEN(1), space))
    return 0;

  return stack_position - 1;
}

/* This finishes a top-level declaration, both default and actual
   ones. */
REDUCOR(reduce_declaration_end)
{
  parser->current_space = parser->global_space;
  return stack_position - 2;
}

/* BINDINGS */

/* This reduces a compound binding IDENTIFIER = NAME SPACE */
REDUCOR(reduce_compound_binding)
{
  NameSpace *space;

  SKIP_IF_NECESSARY_WITH_LOOKAHEAD(3);

  space = parser->stack[stack_position - 2].value.name_space;

  if (!cf_ns_bind(parser, stack_position - 4,
		  parser->current_space, (char *) STACKTOKEN(4), space))
    return 0;

  /* Move the look-ahead token to the current place. */
  COPY_STACK(4, 1);

  /* reduct stack */
  return stack_position - 3;
}

/* This reduces a string binding IDENTIFIER = STRING */
REDUCOR(reduce_string_binding)
{
  unsigned char *string;
  unsigned int len;

  SKIP_IF_NECESSARY(3);

  string = parser->stack[stack_position - 1].value.str.string;
  len = parser->stack[stack_position - 1].value.str.len;

  if (!cf_bind(parser, stack_position - 3,
	       parser->current_space, (char *) STACKTOKEN(3),
	       (char *) string, len))
    return 0;

  return stack_position - 3;
}

/* This reduces the unbound identifier in IDENTIFIER =
   UNBOUND_IDENTIFIER to a string, causing the binding to become
   IDENTIFIER = STRING */
REDUCOR(reduce_unbound_id_binding)
{
  unsigned char *string;
  unsigned int len;

  string = parser->stack[stack_position - 1].value.token.token_start;
  len = parser->stack[stack_position - 1].value.token.token_len;
  parser->stack[stack_position - 1].token = CFN_STRING;
  parser->stack[stack_position - 1].value.str.string = string;
  parser->stack[stack_position - 1].value.str.len = len;
  return stack_position;
}

/* This reduces NAME SPACE to a compound list item, if the current
   name space is a list; otherwise it returns negative number causing
   the parser to skip this reduction (this is contex-dependent
   parsing). */
REDUCOR(reduce_compound_list_item)
{
  NameSpace *space;

  if (parser->current_space->type.complex_type != NSPACE_LIST)
    return -1;

  SKIP_IF_NECESSARY_WITH_LOOKAHEAD(1);

  space = parser->stack[stack_position - 2].value.name_space;

  if (!cf_ns_bind(parser, stack_position - 2,
		  parser->current_space, NULL, space))
    return 0;

  /* Move the look-ahead token to the current place. */
  COPY_STACK(2, 1);

  /* reduct stack */
  return stack_position - 1;  
}

/* This reduces STRING to a string list item, if the current name
   space is a list; see reduce_compound_list_item. */
REDUCOR(reduce_string_list_item)
{
  unsigned char *string;
  unsigned int len;

  if (parser->current_space->type.complex_type != NSPACE_LIST)
    return -1;

  SKIP_IF_NECESSARY_WITH_LOOKAHEAD(1);

  string = parser->stack[stack_position - 2].value.str.string;
  len = parser->stack[stack_position - 2].value.str.len;

  if (!cf_bind(parser, stack_position - 1,
	       parser->current_space, NULL,
	       (char *) string, len))
    return 0;

  /* Move the look-ahead token to the current place. */
  COPY_STACK(2, 1);

  return stack_position - 1;
}

/* This reduces unbound identifier which occurs in a list to a string,
   causing it to be then further reduced by reduce_string_list_item. */
REDUCOR(reduce_unbound_in_list)
{
  unsigned char *string;
  unsigned int len;

  if (parser->current_space->type.complex_type != NSPACE_LIST)
    return -1;
  
  string = parser->stack[stack_position - 1].value.token.token_start;
  len = parser->stack[stack_position - 1].value.token.token_len;
  parser->stack[stack_position - 1].token = CFN_STRING;
  parser->stack[stack_position - 1].value.str.string = string;
  parser->stack[stack_position - 1].value.str.len = len;
  return stack_position;
}

/* MERGES */

/* This reduces a merge clause `merge' NAME SPACE, merging the NAME
   SPACE to the current name space. */
REDUCOR(reduce_merge)
{
  NameSpace *space;
  const char *clashing;

  if (parser->current_space == parser->global_space)
    {
      cf_parser_error(parser, stack_position - 2,
		      "Merge clauses are not applicable on top level");
      return 0;
    }

  space = parser->stack[stack_position - 1].value.name_space;

  if (space->type.id_number != parser->current_space->type.id_number)
    {
      cf_parser_error(parser, stack_position - 2,
		      "Merge type error (you are merging to type %s, "
		      "got %s)",
		      name_space_get_type_name(parser->nscontext,
					       parser->current_space->
					       type.id_number),
		      name_space_get_type_name(parser->nscontext,
					       space->type.id_number));
      return 0;
    }

  if ((clashing = name_space_merge_ns(parser->current_space, space)))
    {
      cf_parser_error(parser, stack_position - 2,
		      "Merge clash: identifier `%s' tries to overrun",
		      clashing);
      return 0;
    }
  return stack_position - 2;
}

/* CONDITIONALS */

/* This reduces an if clause. If the last evaluated conditional has
   evaluated to false, then this evaluates to true... this is strange.
   Don't care! */
REDUCOR(reduce_if_clause)
{
  parser->stack[stack_position - 3].token = CFN_CONDITIONAL;

  if (cf_parser_should_skip(parser, stack_position - 3))
    parser->stack[stack_position - 3].value.conditional = CF_CONDITIONAL_TRUE;
  else
    if (name_space_map(&parser->enables, (char *) STACKTOKEN(1)))
      parser->stack[stack_position - 3].value.conditional =
	CF_CONDITIONAL_TRUE;
    else
      {
	parser->stack[stack_position - 3].value.conditional = 0;
	parser->false_conditionals++;
      }

  return stack_position - 2;
}

/* See above. */
REDUCOR(reduce_if_not_clause)
{
  parser->stack[stack_position - 4].token = CFN_CONDITIONAL;
  if (cf_parser_should_skip(parser, stack_position - 4))
    parser->stack[stack_position - 4].value.conditional = CF_CONDITIONAL_TRUE;
  else
    if (name_space_map(&parser->enables, (char *) STACKTOKEN(1)))
      {
	parser->stack[stack_position - 4].value.conditional = 0;
	parser->false_conditionals++;
      }
    else
      parser->stack[stack_position - 4].value.conditional =
	CF_CONDITIONAL_TRUE;
  return stack_position - 3;
}

/* This reduces an else clause, causing the conditional (which is now
   second topmost on the stack) to change its value from TRUE to FALSE
   or from FALSE to TRUE. Then the `else' item is deleted. However, if
   the parser is currently inside a false conditional, the conditional
   continues to be unconditionally FALSE. See comments before
   reduce_if_clause and cf_parser_should_skip. */
REDUCOR(reduce_else_clause)
{
  /* If there are more than one false conditional the else clause
     does not matter. */
  if (parser->stack[stack_position - 2].value.conditional &
      CF_CONDITIONAL_REVERSED)
    {
      cf_parser_error(parser, stack_position - 1,
		      "Multiple else clauses");
      return 0;
    }

  if (parser->stack[stack_position - 2].value.conditional &
      CF_CONDITIONAL_SWITCH)
    {
      cf_parser_error(parser, stack_position - 1,
		      "Else clauses cannot appear in conjunction with "
		      "case clauses.");
      return 0;
    }

  /* Change the value of the conditional */
  parser->stack[stack_position - 2].value.conditional ^=
    CF_CONDITIONAL_REVERSED | CF_CONDITIONAL_TRUE;
  if (parser->stack[stack_position - 2].value.conditional &
      CF_CONDITIONAL_TRUE)
    parser->false_conditionals--;
  else
    parser->false_conditionals++;

  return stack_position - 1;
}

/* This reduces IF .. END. */
REDUCOR(reduce_end_if)
{
  /* If the conditional was false, decrement the number of
     false conditional clauses now. */
  if ((parser->stack[stack_position - 2].value.conditional &
       CF_CONDITIONAL_TRUE) == 0)
    parser->false_conditionals--;

  return stack_position - 2;
}

/* VALUES */

/* This reduces a lone identifier. If it corresponds to a type, it is
   reduced to CFN_TYPE. It it maps to some value in the global space,
   it will be reduced to CFN_NAME_SPACE or CFN_STRING, depending on
   the type of that value. Otherwise it will be reduced to
   CFN_IDENTIFIER (unbound identifier). */
REDUCOR(reduce_identifier)
{
  int type;
  NameSpaceValue *value;
  /* If a lonely identifier is a type name, it changes to CFN_TYPE.
     If it is not, its global binding is searched. It if is bound,
     change to the value (CFN_STRING or CFN_NAME_SPACE). Otherwise
     this identifier is unknown; signal an error */

  type = name_space_get_type_id(parser->nscontext,
				(char *) STACKTOKEN(1));

  if (type != 0)
    {
      /* Change the stack item and return */
      parser->stack[stack_position - 1].token = CFN_TYPE;
      parser->stack[stack_position - 1].value.type_id = type;
      return stack_position;
    }
  value = name_space_map(parser->global_space, (char *) STACKTOKEN(1));

  if (!value)
    {
      parser->stack[stack_position - 1].token = CFN_IDENTIFIER;
      return stack_position;
    }

  if (value->type == NSPACE_STRING)
    {
      parser->stack[stack_position - 1].token = CFN_STRING;
      parser->stack[stack_position - 1].value.str.string = (unsigned char *)
	value->value.str.string;
      parser->stack[stack_position - 1].value.str.len = value->value.str.len;
      return stack_position;
    }

  if (value->type == NSPACE_NSPACE)
    {
      parser->stack[stack_position - 1].token = CFN_NAME_SPACE;
      parser->stack[stack_position - 1].value.name_space =
	value->value.name_space;
      return stack_position;
    }

  /* This should never happen. */

  cf_parser_error(parser, stack_position - 1,
		  "Identifier is of unknown type: `%s' "
		  "[INTERNAL ERROR -- REPORT]", STACKTOKEN(1));
  return 0;
}

/* This reduces a string from the lexer to a non-terminal string item
   (CFT_STRING ==> CFN_STRING). This apparently void reduction exists
   because identifiers reduce in some circumstances to strings also,
   and reducing them to CFT_STRING would be unsatisfactory, because
   the resulting strings are non-terminals in essence. */
REDUCOR(reduce_string)
{
  unsigned char *string;
  unsigned int len;
  string = STACKTOKEN(1);
  len = STACKTOKENLEN(1);
  parser->stack[stack_position - 1].token = CFN_STRING;
  parser->stack[stack_position - 1].value.str.string = string;
  parser->stack[stack_position - 1].value.str.len = len;
  return stack_position;
}

/* ANONYMOUS STRUCTURES */

/* This begins an anonymous structure. Note that
   reduce_start_anonymous does not exist in the reductions table; it is
   called from reduce_type_in_list and reduce_anonymous_binding. */

REDUCOR(reduce_start_anonymous)
{
  int type_id;
  NameSpace *space;

  type_id = parser->stack[stack_position - 1].value.type_id;

  /* Save the current space onto the stack */
  parser->stack[stack_position - 1].value.name_space =
    parser->current_space;

  space = name_space_create_name_space(parser->nscontext, type_id);
  parser->stack[stack_position - 1].token = CFN_ANONYMOUS_BEGIN;
  parser->current_space = space;

  return stack_position;
}

/* A type name in a list will begin an anonymous structure declaration
   in the list. */
REDUCOR(reduce_type_in_list)
{
  if (parser->current_space->type.complex_type != NSPACE_LIST)
    return -1;

  return reduce_start_anonymous(parser, stack_position);
}

/* A binding of for IDENTIFIER = TYPE will cause TYPE to reduce to an
   anonymous structure declaration start, causing the result to be
   (hopefully) IDENTIFIER = NAME SPACE in future. */
REDUCOR(reduce_anonymous_binding)
{
  return reduce_start_anonymous(parser, stack_position);
}

/* This ends an anomyous structure declaration. Note that, as contrast
   to reduce_declaration_end, now parser->current_space is not set to
   parser->global_space but to whatever space was saved onto the stack
   when the structure declaration began. */
REDUCOR(reduce_anonymous_end)
{
  NameSpace *space;

  /* pop the old current_space */
  space = parser->stack[stack_position - 2].value.name_space;
  parser->stack[stack_position - 2].token = CFN_NAME_SPACE;
  parser->stack[stack_position - 2].value.name_space = parser->current_space;
  parser->current_space = space;
  return stack_position - 1;
}

/* WITH CLAUSES */

REDUCOR(reduce_with)
{
  NameSpace *new_space, *space;

  if (parser->current_space == parser->global_space)
    {
      cf_parser_error(parser, stack_position - 2,
		      "With clauses are not applicable on top level");
      return 0;
    }
  parser->stack[stack_position - 2].token = CFN_COPIED_NAME_SPACE;
  new_space = parser->stack[stack_position - 2].value.name_space =
    name_space_copy(parser->nscontext,
		    parser->stack[stack_position - 2].value.name_space);

  /* The with token gets replaced with an anonymous structure begin */

  /* Save the current space onto the stack */
  parser->stack[stack_position - 1].value.name_space =
    parser->current_space;

  space = name_space_create_name_space(parser->nscontext,
				       new_space->type.id_number);
  parser->stack[stack_position - 1].token = CFN_ANONYMOUS_BEGIN;
  parser->current_space = space;


  return stack_position;
}

REDUCOR(reduce_merge_with)
{
  const char *clashing;
  NameSpace *space, *target;
  target = parser->stack[stack_position - 2].value.name_space;
  space = parser->stack[stack_position - 1].value.name_space;
  
  if (space->type.id_number != target->type.id_number)
    {
      cf_parser_error(parser, stack_position - 2,
		      "Merge type error in a with clause "
		      "[INTERNAL ERROR -- REPORT]");
      return 0;
    }
  if ((clashing = name_space_merge_ns(target, space)))
    {
      cf_parser_error(parser, stack_position - 2,
		      "Merge clash in a with clause: identifier "
		      "`%s' already declared", clashing);
      return 0;
    }
  parser->stack[stack_position - 2].token = CFN_NAME_SPACE;
  return stack_position - 1;
}

/* SWITCH CLAUSES */

REDUCOR(reduce_switch)
{
  parser->stack[stack_position - 2].token = CFN_SWITCH;
  parser->stack[stack_position - 2].value.token.token_start =
    parser->stack[stack_position - 1].value.token.token_start;
  parser->stack[stack_position - 2].value.token.token_len =
    parser->stack[stack_position - 1].value.token.token_len;
  return stack_position - 1;
}

REDUCOR(reduce_switch_end)
{
  /* Kill the remaining tokens. */
  return stack_position - 2;
}

REDUCOR(reduce_case)
{
  int result;
  parser->stack[stack_position - 2].token = CFN_CONDITIONAL;
  if (parser->callback)
    {
      result = (*parser->callback)((char *) STACKTOKEN(3),
				   (char *) STACKTOKEN(2),
				   parser->context);
    }
  else
    {
      result = -1;
    }
  if (result < 0)
    {
      cf_parser_error(parser, stack_position - 2,
		      "Undefined application variable `%s'",
		      parser->stack[stack_position - 3].value.
		      token.token_start);
      return 0;
    }
  if (result > 0)
    {
      parser->stack[stack_position - 2].value.conditional =
	CF_CONDITIONAL_TRUE | CF_CONDITIONAL_SWITCH;
    }
  else
    {
      parser->stack[stack_position - 2].value.conditional =
	CF_CONDITIONAL_SWITCH;
      parser->false_conditionals++;
    }
  return stack_position - 1;
}

int cf_finalize_parsing(CFParser parser)
{
  int i; int count = 0;
  NameSpace *unique = NULL;

  /* Merge the defaults */
  name_space_merge_defaults(parser->nscontext);

  /* Check that the configuration structure has been chosen */
  if (!parser->chosen_configuration)
    {
      for (i = 0; i < parser->global_space->used_mappings; i++)
	{
	  if (parser->global_space->mapping[i].value.type == NSPACE_NSPACE)
	    if ((unique = parser->global_space->mapping[i].value.value.
		 name_space)->type.id_number == parser->config_id)
	      count++;
	}
      if (count == 1)
	{
	  parser->chosen_configuration = unique;
	}
      else
	{
	  if (count == 0)	    
	    cf_parser_error(parser, 0, "No configuration structure is found");
	  else
	    cf_parser_error(parser, 0, "Multiple configuration structures "
			    "but none selected.");
	  return CF_PARSER_SYNTAX_ERROR;
	}
    }
  return CF_PARSER_OK;
}

/* Cf_parse parses the file which has been previously read in with
   cf_read_file. It returns CF_PARSER_OK if the file was succesfully
   parsed. Otherways it returns CF_PARSER_SYNTAX_ERROR and sets the
   error message. The error message may be queried with
   cf_parser_get_error_message. */
int cf_parse(CFParser parser, CFApplicationVariableCallback callback,
	     void *context)
{
  int token_type, i, j;
  unsigned char *token;
  unsigned int token_len;
  int stack_position = 1;
  int result;
#ifdef DEBUG_HEAVY
  FILE *out;
#ifdef WINDOWS
  out = fopen("out", "a");
  if (out == NULL)
    ssh_fatal("Error opening debug output file 'out'");
#else
  out = stderr;
#endif
#endif

  parser->stack[0].token = CFS_BOTTOM;
  parser->current_space = parser->global_space;

  parser->callback = callback;
  parser->context  = context;

  parser->false_conditionals = 0;

  do {
    if (ssh_cflex_get_token(parser->lex, &token_type,
			    &token, &token_len) ==
	SSH_CFLEX_LEXICAL_ERROR)
      {
	parser->error_message =
	  (char *)ssh_cflex_get_error_message(parser->lex);
	return CF_PARSER_SYNTAX_ERROR;
      }

    parser->stack[stack_position].token = token_type;
    parser->stack[stack_position].line_number =
      ssh_cflex_get_line_number(parser->lex);
    parser->stack[stack_position].value.token.token_len = token_len;
    parser->stack[stack_position].value.token.token_start = token;
    stack_position++;

#ifdef DEBUG_HEAVY
    fprintf(out, "Pushed %d. Stack: ", token_type);
    for (i = 0; i < stack_position; i++)
      fprintf(out, "%s ",
	      (parser->stack[i].token < (sizeof(cf_token_name) /
					 sizeof(cf_token_name[0]))
	       ? cf_token_name[parser->stack[i].token] :
	       ">"));
    fprintf(out, "\n");
#endif

  check_reductions:
    for (i = 0; i < CF_NUMBER_REDUCTIONS; i++)
      {
	for (j = 0; j < CF_MAX_REDUCTION_LEN &&
	       j < stack_position &&
	       (cf_parser_reduction_table[i].token[j] ==
		parser->stack[stack_position - j - 1].token
		|| cf_parser_reduction_table[i].token[j] == CFS_ANY);
	     j++);
	if (cf_parser_reduction_table[i].token[j] == 0)
	  {
#ifdef DEBUG_HEAVY
	    fprintf(out, "Reduction: `%s'\n",
		    cf_parser_reduction_table[i].debug_name);
#endif
	    result =
	      (*(cf_parser_reduction_table[i].reducor))
	      (parser, stack_position);
	    if (result == 0)
	      return CF_PARSER_SYNTAX_ERROR;
	    if (result < 0)
	      continue; /* continue the outer for loop to the next
			   reduction */
	    /* reduction actually made */
	    stack_position = result;

#ifdef DEBUG_HEAVY
	    fprintf(out, "Reduced. Stack: ");
	    for (i = 0; i < stack_position; i++)
	      fprintf(out, "%s ",
		      (parser->stack[i].token < (sizeof(cf_token_name) /
						 sizeof(cf_token_name[0]))
		       ? cf_token_name[parser->stack[i].token] :
		       ">"));
	    fprintf(out, "\n");
#endif
	    goto check_reductions;
	  }
      }    
  } while (token_type != CFT_EOF);

  if (stack_position != 1)
    {
      cf_parser_error(parser, stack_position - 1, "Undefined syntax error");
      return CF_PARSER_SYNTAX_ERROR;
    }

  return cf_finalize_parsing(parser);
}

/* cf_dump is only for debugging and dumps all the name spaces defined. */

void cf_dump(FILE *out, CFParser parser)
{
  name_space_dump_context(out, parser->nscontext);
  fprintf(out, "\n\n");
  fprintf(out, "Chosen configuration:\n");
  name_space_dump_space(out, parser->global_space);
}

/*** REDUCTION TABLE ***/

/* There must be at least one zero at the tail of every token
   sequence! */

/* You've got to read this table in the wrong direction. */
const CFReduction cf_parser_reduction_table[CF_NUMBER_REDUCTIONS] =
{
  /* ENABLE CLAUSES */

  /* BOTTOM 'enable' identifier */
  { { CFT_IDENTIFIER, CFT_ENABLE, CFS_BOTTOM, 0, 0, 0 }, reduce_enable,
    "enable" } ,

  /* 'enable' identifier everywhere else is an error */
  { { CFT_IDENTIFIER, CFT_ENABLE, 0, 0, 0, 0 },
    reduce_err_enable_not_at_bottom,
    "err_enable_not_at_bottom" },
  { { CFS_ANY, CFT_ENABLE, 0, 0, 0, 0 },
    reduce_err_mangled_enable,
    "err_mangled_enable" },

  /* CONDITIONALS */

  /* 'if' 'enabled' identifer is an if clause */
  { { CFT_IDENTIFIER, CFT_ENABLED, CFT_IF, 0, 0, 0},
    reduce_if_clause,
    "if_clause" },

  /* 'if' 'not' 'enabled' is an if-not clause */
  { { CFT_IDENTIFIER, CFT_ENABLED, CFT_NOT, CFT_IF, 0, 0 },
    reduce_if_not_clause,
    "if_not_clause" },
  { { CFS_ANY, CFS_ANY, CFS_ANY, CFT_IF, 0, 0 },
    reduce_err_mangled_if,
    "err_mangled_if" },

  /* 'else' changes the current enable-status */
  { { CFT_ELSE, CFN_CONDITIONAL, 0, 0, 0}, reduce_else_clause,
    "else_clause" },

  /* conditional begin with an end following means that the
     conditional has been succesfully parsed */
  { { CFT_END, CFN_CONDITIONAL, 0, 0, 0}, reduce_end_if,
    "end_if" },

  /* SWITCH CLAUSES */

  /* An identifier after the "switch" keyword is an application
     variable */
  { { CFT_IDENTIFIER, CFT_SWITCH, 0, 0, 0, 0 }, reduce_switch,
    "switch" } ,

  /* End a switch clause */
  { { CFT_END, CFN_SWITCH, 0, 0, 0, 0 }, reduce_switch_end,
    "switch_end" } ,
  
  /* Now, when all rules which include CFT_IDENTIFIER have been
     checked out, it is safe to reduce identifiers to values.
     
     IDENTIFIERS */

  /* A string alone reduces to a string value */
  { { CFT_STRING, 0, 0, 0, 0, 0 }, reduce_string,
    "string"} ,

  /* An identifier alone might change to a value (a name space or a string) */
  { { CFT_IDENTIFIER, 0, 0, 0, 0, 0 }, reduce_identifier,
    "identifier" } ,

  /* CASE CLAUSES */

  /* An string preceded by the question mark and a switch is a case clause */
  { { CFT_CASE, CFN_STRING, CFN_SWITCH, 0, 0, 0 }, reduce_case,
    "case" } ,

  /* USE CLAUSES */

  /* 'use' NAMESPACE EOF is the final use clause */
  { { CFT_EOF, CFN_NAME_SPACE, CFT_USE, CFS_BOTTOM, 0, 0}, reduce_final_use,
    "final_use" } ,
  { { CFT_EOF, CFN_NAME_SPACE, CFT_USE, 0, 0, 0},
    reduce_err_final_use_not_at_bottom,
    "err_final_use_not_at_bottom" },

  /* 'use' NAMESPACE 'for' TYPE is a use-for-defaults clause */
  { { CFN_TYPE, CFT_FOR, CFN_NAME_SPACE, CFT_USE, CFS_BOTTOM, 0},
    reduce_use_default,
    "use_default" } ,
  { { CFN_TYPE, CFT_FOR, CFN_NAME_SPACE, CFT_USE, 0, 0},
    reduce_err_use_default_not_at_bottom,
    "err_use_default_not_at_bottom" },
  { { CFS_ANY, CFS_ANY, CFS_ANY, CFT_USE, 0, 0 },
    reduce_err_mangled_use,
    "err_mangled_use" },

  /* DEFAULTS STRUCTURE DEFINITIONS */

  /* 'default' identifier identifier is the beginning of a defaults
     structure declaration */
  { { CFN_IDENTIFIER, CFN_TYPE, CFT_DEFAULT, CFS_BOTTOM, 0, 0},
    reduce_default_begin,
    "default_begin" } ,

  /* Defaults structure definition beginning with an end following
     means that the structure has been succesfully parsed (everything
     between has been reduced) */
  { { CFT_END, CFN_DEFAULT_DEF , 0, 0, 0, 0 }, reduce_declaration_end,
    "declaration_end" } ,

  /* ACTUAL STRUCTURE DEFINITIONS */

  /* type identifier might be the beginning of an actual structure
     declaration */
  { { CFN_IDENTIFIER, CFN_TYPE, 0, 0, 0, 0}, reduce_actual_begin,
    "actual_begin" } ,

  /* Actual structure definition beginning with an end following means
     that the structure has been succesfully parsed (see
     reduce_default_end, "default_end") */
  { { CFT_END, CFN_ACTUAL_DEF, 0, 0, 0, 0}, reduce_declaration_end,
    "declaration_end" } ,

  /* MERGE CLAUSES */

  /* 'merge' identifer is a merge clause */
  { { CFN_NAME_SPACE, CFT_MERGE, 0, 0, 0, 0}, reduce_merge,
    "merge" } ,

  /* ANONYMOUS STRUCTURES */

  { { CFT_END, CFN_ANONYMOUS_BEGIN, 0, 0, 0, 0},
    reduce_anonymous_end,
    "anonymous_end" },

  /* identifier = TYPE might begin an anonymous compound structure
     binding */
  { { CFN_TYPE, CFT_EQUAL, CFN_IDENTIFIER, 0, 0, 0},
    reduce_anonymous_binding,
    "anonymous_binding" },    

  /* WITH CLAUSES */

  { { CFT_WITH, CFN_NAME_SPACE, 0, 0, 0, 0}, reduce_with,
    "with" },

  { { CFN_NAME_SPACE, CFN_COPIED_NAME_SPACE, 0, 0, 0, 0}, reduce_merge_with,
    "merge_with" },

  /* BINDINGS */

  /* identifier = NAMESPACE is a compound binding.  This needs
     look-ahead, because if a `white' keyword follows, it must be
     handled before the binding is made. */
  { { CFS_ANY, CFN_NAME_SPACE, CFT_EQUAL, CFN_IDENTIFIER, 0, 0},
    reduce_compound_binding,
    "compound_binding" },

  /* identifier = string is a string binding */
  { { CFN_STRING, CFT_EQUAL, CFN_IDENTIFIER, 0, 0, 0},
    reduce_string_binding,
    "string_binding" } ,

  /* unbound identifiers reduce to strings in a bindings */
  { { CFN_IDENTIFIER, CFT_EQUAL, CFN_IDENTIFIER, 0, 0, 0},
    reduce_unbound_id_binding,
    "unbound_id_binding" },
    
  /* A string alone might belong to a list. Lookahead needed because
     `string' ? is a case clause. */
  { { CFS_ANY, CFN_STRING, 0, 0, 0, 0 }, reduce_string_list_item,
    "string_list_item" },

  /* A name space alone might belong to a list. This needs look-ahead
     for the same reason as reduce_compound_binding, "compound_binding". */
  { { CFS_ANY, CFN_NAME_SPACE, 0, 0, 0, 0}, reduce_compound_list_item,
    "compound_list_item" },

  /* A type name along might belong to a list ... */
  { { CFN_TYPE, 0, 0, 0, 0, 0}, reduce_type_in_list,
    "type_in_list" },

  /* An unbound identifier might like to reduce to a string in a list ... */
  { { CFN_IDENTIFIER, 0, 0, 0, 0, 0}, reduce_unbound_in_list,
    "unbound_in_list" },

  /* FILE END */

  /* BOTTOM EOF means that the file has been succesfully parsed */
  { { CFT_EOF, CFS_BOTTOM, 0, 0, 0, 0}, reduce_eof,
    "eof" } ,

  /* MORE ERRORS. The order of the reductions is significant! */
  { { CFT_END, CFS_ANY, CFN_ACTUAL_DEF, 0, 0, 0}, reduce_err_decl_end,
    "err_decl_end" },
  { { CFT_END, CFS_ANY, CFN_DEFAULT_DEF, 0, 0, 0}, reduce_err_decl_end,
    "err_decl_end" },
  { { CFT_END, CFS_ANY, CFN_ANONYMOUS_BEGIN, 0, 0, 0}, reduce_err_decl_end,
    "err_decl_end" },

};

/***********************************************************************
 * INTERFACES TO THE READ CONFIGURATION. */

/* This returns a handle to the global data structure read (actually,
   a pointer to the name space). This may be NULL, if the user has
   chosen no configuration. */
CFHandle cf_get_toplevel_handle(CFParser parser)
{
  return (CFHandle)(parser->chosen_configuration);
}

/* This returns a handle to the global name space (actually,
   a pointer to the name space). */
CFHandle cf_get_global_space_handle(CFParser parser)
{
  return (CFHandle)(parser->global_space);
}

/* Get a string-valued field. See cparser.h for more information. */
const char *cf_get_string(CFHandle handle, unsigned int *len,
			  const char *traverse, ...)
{
  NameSpaceValue *value;
  va_list args;
  
  va_start(args, traverse);
  value = cf_traverse(traverse, (NameSpace *)handle, args, NULL);
  va_end(args);
  
  if (value->type != NSPACE_STRING && value->type != NSPACE_IP &&
      value->type != NSPACE_IP_NETMASK && value->type != NSPACE_UPORT &&
      value->type != NSPACE_TPORT)
    return NULL;

  if (len != NULL)
    *len = value->value.str.len;
  return value->value.str.string;
}

/* Get a integer-valued field. See cparser.h for more information. */
long cf_get_integer(CFHandle handle, const char *traverse, ...)
{
  NameSpaceValue *value;
  va_list args;
  
  va_start(args, traverse);
  value = cf_traverse(traverse, (NameSpace *)handle, args, NULL);
  va_end(args);
  
  if (value->type != NSPACE_INTEGER && value->type != NSPACE_BOOLEAN &&
      value->type != NSPACE_UPORT && value->type != NSPACE_TPORT)
    return 0;

  if (value->type == NSPACE_UPORT && value->type == NSPACE_TPORT)
    {
      return ssh_tcp_get_port_by_service(value->value.str.string,
					    value->type == NSPACE_UPORT ?
					    "udp" : "tcp");
    }
  return value->value.integer;
}

/* Get a real-valued field. See cparser.h for more information. */
double cf_get_real(CFHandle handle, const char *traverse, ...)
{
  NameSpaceValue *value;
  va_list args;
  
  va_start(args, traverse);
  value = cf_traverse(traverse, (NameSpace *)handle, args, NULL);
  va_end(args);
  
  if (value->type != NSPACE_REAL)
    return 0.0;
  
  return value->value.real;
}

/* Get the identifier-part of a mapping in the configuration
   space. See cparser.h for more information. */
const char *cf_get_identifier(CFHandle handle, const char *traverse, ...)
{
  char *string;

  va_list args;
  va_start(args, traverse);
  cf_traverse(traverse, (NameSpace *)handle, args, &string);
  va_end(args);

  return string;
}

/* Get a handle (similiar to the one returned by cf_get_global_handle)
   for a compound structure. See cparser.h for more information. */
CFHandle cf_get_compound_handle(CFHandle handle, const char *traverse, ...)
{
  NameSpaceValue *value;
  
  va_list args;
  va_start(args, traverse);
  value = cf_traverse(traverse, (NameSpace *)handle, args, NULL);
  va_end(args);

  if (value->type != NSPACE_NSPACE)
    return NULL;

  return value->value.name_space;
}

/* See cparser.h. */
int cf_get_number_of_items(CFHandle handle)
{
  NameSpace *space = (NameSpace *)handle;
  return space->used_mappings;
}

/* Get complex type. */
int cf_get_complex_type(CFHandle handle)
{
  NameSpace *space = (NameSpace *)handle;
  return (int) (space->type.complex_type);
}

/* Get base type. */
int cf_get_base_type(CFHandle handle)
{
  NameSpace *space = (NameSpace *)handle;
  return (int) (space->type.base_type);
}

/* Get type id. */
int cf_get_type_id(CFHandle handle)
{
  NameSpace *space = (NameSpace *)handle;
  return (int) (space->type.id_number);
}

int cf_name_to_type_id(CFParser parser, const char *name)
{
  return name_space_get_type_id(parser->nscontext, name);
}

const char *cf_type_id_to_name(CFParser parser, int type)
{
  return name_space_get_type_name(parser->nscontext, type);
}

#if 0
/* Data conversion */
int cf_data_enumerated(CFParser parser, const char *data,
		       const char **table, int num, int *i)
{
  int j;
  for (j = 0; j < num; j++)
    {
      if (!strcmp(table[j], data))
	{
	  *i = j;
	  return CF_PARSER_OK;
	}
    }
  cf_parser_error(parser, 0, "`%s' does not fit to the enumerated type.",
		  data);
  return CF_PARSER_CONVERSION_ERROR;
}

int cf_data_integer(CFParser parser, const char *data, int *i)
{
  char *endptr;
  long result = strtol(data, &endptr, 0);
  if (endptr != data && *endptr == '\0')
    {
      *i = (int)result;
      return CF_PARSER_OK;
    }
  return CF_PARSER_DECLARATION_ERROR;
}
#endif
