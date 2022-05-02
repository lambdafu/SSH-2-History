/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jun  6 21:58:29 1996 [huima]

  The configuration file parser.

  */

/*
 * $Id: cparser.h,v 1.14 1998/01/28 10:14:00 ylo Exp $
 * $Log: cparser.h,v $
 * $EndLog$
 */

#ifndef CPARSER_H
#define CPARSER_H

/* Return values of some functions.

   CF_PARSER_OK: operation succeeded

   CF_PARSER_FILE_ERROR: the denoted file refused to open, or similar error

   CF_PARSER_SYNTAX_ERROR: some error is encountered during
   parsing. Actually the errors are not restricted to by syntactic
   errors, instead, lexical and semantic and type errors are included.

   CF_PARSER_DECLARATION_ERROR: the application has declared some
   types or fields in an erroneus manner. */
#define CF_PARSER_OK                0
#define CF_PARSER_FILE_ERROR        1
#define CF_PARSER_SYNTAX_ERROR      2
#define CF_PARSER_DECLARATION_ERROR 3
#define CF_PARSER_CONVERSION_ERROR  4

/* Type for a defined parser (grammar).  The contents of the type are private,
   but the handle is passed to various functions. */
typedef struct CFParser *CFParser;

/* Pointer to a part of the parse result.  These pointers are used to traverse
   the tree that results from the parse. */
typedef void *CFHandle;

/* Callback to be given when there is a switch clause and the parser
   wants to know if `try' is the value of the application variable
   whose name is `variable_name'.

   Return values:
   -1: variable unknown
    0: variable known but the try does not match
    1: variable known and the try maches */
typedef int (*CFApplicationVariableCallback)(const char *variable_name,
					     const char *try,
					     void *context);

/* Creates a parser context.  This function begins definition of the
   grammar. */
CFParser cf_parser_create(void);

/* Destroys the parser context. */
void cf_destroy_parser(CFParser parser);

/* Get a pointer to the error message set by the parser. If no error
   has occurred, this function returns NULL.  The returned value will
   be valid until the parser is freed or used again.
   XXX Internationalization issues? */
const char *cf_parser_get_error_message(CFParser parser);

/* Built in types. They can be used in the value_type_name field in the
   CFParserDeclareItem struct. */
#define CF_BUILTIN_STRING	"builtin string"  /* This returns string */
#define CF_BUILTIN_IP		"builtin ip"	  /* This returns string */
#define CF_BUILTIN_IP_NETMASK	"builtin ip/mask" /* This returns string */
#define CF_BUILTIN_INTEGER	"builtin integer" /* This returns int */
#define CF_BUILTIN_BOOLEAN	"builtin boolean" /* This returns int */
#define CF_BUILTIN_TPORT	"builtin tport"	  /* This returns str or int */
#define CF_BUILTIN_UPORT	"builtin uport"	  /* This returns str or int */
#define CF_BUILTIN_REAL		"builtin real"    /* This returns double */

typedef enum {
  /* Start structure declaration, and declare its name, the only parameter is
     the name if the struct type to be declared */
  CF_STRUCT,			/* 1 param */
  /* Declare new field to previous structure. The structure declaration ends
     when the first non CF_FIELD item is reaced. The first parameter is the
     name of the field. The second parameter is the type of the field (any
     declared type name or built in types above). Optional third and fourth
     parameters declare the default value for field and its length. If the
     length is 0 then strlen of string is used.  */
  CF_FIELD,			/* 2, 3, or 4 params */
  /* Declare list/environment/overwritable environment type, the first
     parameter is the name of the type to be declared and the second parameter
     is the type of values in the list/environment. */
  CF_LIST,			/* 2 params */
  CF_ENVIRONMENT,		/* 2 params */
  CF_OVERWRITABLE_ENVIRONMENT,	/* 2 params */
  /* Declare defaults to last environment, the first parameter is name to
     insert, second parameter is the environment type name where the name is
     inserted and the third and fourth argument is the value of identifier. See
     CF_FIELD for the documentation of length field */
  CF_ENVIRONMENT_DEFAULT,	/* 3, or 4 params */
  /* Declare the top level type name. The first parameter is the type name of
     the top level config variable (told with use clause). */
  CF_TOPLEVEL_TYPE,		/* 1 param */
  /* Ends the CFParserDeclareItemList. */
  CF_END			/* 0 params */
} CFParserDeclareType;

typedef const struct CFParserDeclareItemRec {
  CFParserDeclareType item_type;
  const char *name; /* Type name or field name */
  const char *value_type_name;	/* Type name for value,
				   see builtin types above */
  const char *default_value;	/* Default value for struct
				   fields, can be NULL */
  unsigned int length;		/* Length of default, or if 0 use strlen. */
} CFParserDeclareItem;

typedef CFParserDeclareItem *CFParserDeclareItemList;

/* Delcare the grammar to parser. The grammar is declared in
   CFParserDeclareItemList array. */
int cf_declare_grammar(CFParser parser, const CFParserDeclareItemList grammar);

/* This reads a configuration file, but does not parse it. Check the
   return value! cf_parse will crash if this has returned an error. */
int cf_read_file(CFParser parser, const char *filename);

/* This gives a configuration file as a mallocated string to parser, but does
   not parse it. Check the return value! cf_parse will crash if this has
   returned an error. The parser will free when it doesn't need it anymore. */
void cf_give_config(CFParser parser, char *config_string);

/* This parser the configuration file, which has been read with
   cf_read_file. Check the return value! If there were errors in the
   config file, then the configuration structure is invalid. Inform
   the user about the error and exit (preferably cleanly).
   See CFApplicationVariableCallback for documentation of callback. If it is
   NULL, all switch statements generates an error. */
int cf_parse(CFParser parser,
	     CFApplicationVariableCallback callback,
	     void *context);

/* For debugging */
void cf_dump(FILE *out, CFParser parser);

/* Traversing through the given configuration */

/* CONCEPT: When the configuration file has been succesfully read,
   there is a name space/structure called the top-level configuration
   structure which you need to access. Use cf_get_toplevel_handle to get
   a handle to that structure. It the return value is NULL, an error
   has occurred somewhere and the configuration structures are not
   accessible.

   More generally, CFHandles point to some structures in the
   configuration "space". For every handle, you may call the functions
   cf_get_string, cf_get_integer, cf_get_real, cf_get_identifier,
   cf_get_compound_handle and cf_get_number_of_items. Their meaning is
   as follows:

   cf_get_string, cf_get_integer, cf_get_real is used to retrieve a
   value of a particular field of a particular structure in the
   configuration space. The "particular structure" might be a structure,
   an environment or a list. `handle' specifies the structure from where
   to start traversing downwards the structure tree. Exactly
   strlen(traverse) steps will be taken. For every char in `traverse',
   the function advances one level in the tree. If the char is `n', then
   the corresponding argument in the variable length arguments list ...
   will be interpreted as a number, and the function chooses the
   (zero-based) nth mapping in the current structure. If the char is
   `i', then the corresponding argument in the variable length argument
   list will be interpreted as an identifier, and the function chooses
   the mapping identified by the identifier. Other characters cause an
   error. When the iteration ends, the function should be looking at a
   string/integer/real value. If it is, it returns a pointer to the
   string or integer or real value; the string behind the pointer should
   not be modified (this is emphasized by the `const' keyword). If any
   error occurred, the functions returns NULL.

   cf_get_identifier works similarly to cf_get_string_option, but does
   not return the string value a field; instead it returns the
   identifier which maps to a value. See the example below.

   cf_get_compound_handle works similarly to the previous two
   functions, but returns a handle to the compound structure it is
   looking on when the iteration has ended. This returns NULL for the
   handle if an error occurred (most probably, the application
   traversed through structures which didn't exist).

   cf_get_number_of_items is used to get the number of mappings in the
   structure behind the given handle.

   EXAMPLE: Suppose that the application has declared the following
   types:

   TYPES: Configuration: structure { Services : services, max-forks : integer }
	  Service:       structure { exec : string, exec-env : Environment }
          Services:      list : Service
          Environment:   environment : string

   and the configuration file has chosen the structure 'config' (of
   type Configuration) to be used as the configuration structure. The
   values of the structures are:

   config.services = [ sshd fingerd ]
   config.max-forks = 3

   sshd.environment = ( SSH_HOST = "foo.com", SSH_SERVICE = "sshd" )
   sshd.exec = "/usr/bin/sshd"

   finger.environment = ( SSH_HOST = "foo.com",  SSH_SERVICE = "finger" )
   finger.exec = "/usr/bin/fingerd"

   Then the following pieces of code return the following values
   (suppose that `parser' is the current parser context):

   cf_get_toplevel_handle(parser)
     --> a handle to structure `config'

   cf_get_integer(cf_get_toplevel_handle(parser), "i", "max-forks")
     --> 3

   cf_get_string(cf_get_toplevel_handle(parser), NULL, "ni", 0, "exec")
     --> "/usr/bin/sshd"

   cf_get_string(cf_get_toplevel_handle(parser), NULL, "nii",
                        1, "exec-env", "SSH_SERVICE")
     --> "finger"

   cf_get_compound_handle(cf_get_toplevel_handle(parser), "n", 1)
     --> a handle to structure `finger'

   cf_get_string(cf_get_compound_handle(cf_get_toplevel_handle(parser),
                                               "n", 1), NULL, "i", "exec")
     --> "/usr/bin/fingerd"

   Note that in real applications, the handles should be saved to
   variables for efficiency (they remain valid until the parser
   context gets destroyed). */

/* Get string value (string, or ip). `len' can be NULL. */
const char *cf_get_string(CFHandle handle, unsigned int *len,
			  const char *traverse, ...);

/* Get integer value (integer, boolean, port). */
long cf_get_integer(CFHandle handle, const char *traverse, ...);

/* Get double value (double). */
double cf_get_real(CFHandle handle, const char *traverse, ...);

/* Return mapping identifier name */
const char *cf_get_identifier(CFHandle handle, const char *traverse, ...);

/* Return new handle to compund value (structure, list, environment etc) */
CFHandle    cf_get_compound_handle(CFHandle handle, const char *traverse, ...);

/* This returns a handle to the global data structure read (actually,
   a pointer to the name space). This may be NULL, if the user has
   chosen no configuration. */
CFHandle    cf_get_toplevel_handle(CFParser parser);

/* Return handle to global name space. This can be used to enumerate
   through all config variables in config file */
CFHandle    cf_get_global_space_handle(CFParser parser);

/* Return number of items in structure/environment/list pointed by handle */
int         cf_get_number_of_items(CFHandle handle);

/* Return complex type of handle (NSPACE_STRUCTURE, NSPACE_LIST,
   NSPACE_ENVIRONMENT_OVERWRITABLE, NSPACE_ENVIRONMENT). */
int	    cf_get_complex_type(CFHandle handle);

/* Return the type of values in handle (type of list/environment values etc).
   Returns 0 if handle points to structure. */
int	    cf_get_base_type(CFHandle handle);

/* Return type id number of handle */
int         cf_get_type_id(CFHandle handle);

/* Return type id from type name */
int cf_name_to_type_id(CFParser parser, const char *name);

/* Return type name from type id */
const char *cf_type_id_to_name(CFParser parser, int type);

#if 0
/* This should be replaced with generic functions */
/* Argument conversions */
int         cf_data_enumerated(CFParser parser, const char *data,
			       const char **table, int num, int *i);
int         cf_data_integer(CFParser parser, const char *data, int *i);
#endif
#endif /* CPARSER_H */


