/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jun  6 17:17:43 1996 [huima]



  */

/*
 * $Id: nspace.h,v 1.8 1998/01/28 10:14:25 ylo Exp $
 * $Log: nspace.h,v $
 * $EndLog$
 */


#ifndef NSPACE_H
#define NSPACE_H

#include "sshincludes.h"

/* These are the "complex ways". They are the ways to build new
   types. Structures are types on their own; lists, arrays and
   environments need another type as the atomic type. For example,
   list types must know what type their items are. */
typedef enum {
  NSPACE_STRUCTURE, 
  NSPACE_LIST,
  NSPACE_ARRAY,
  NSPACE_ENVIRONMENT,
  NSPACE_ENVIRONMENT_OVERWRITABLE
} NSpaceComplexType;

/* These are the types of mappings. Currently there are two:
   mapping to string and mapping to a structure (another name space) */
typedef enum {
  NSPACE_UNDEFINED = 0,
  NSPACE_NSPACE,		/* name_space */
  NSPACE_STRING,		/* str */
  NSPACE_IP,			/* str */
  NSPACE_IP_NETMASK,		/* str */
  NSPACE_INTEGER,		/* integer */
  NSPACE_BOOLEAN,		/* integer */
  NSPACE_TPORT,			/* str/integer */
  NSPACE_UPORT,			/* str/integer */
  NSPACE_REAL,			/* real */
  NSPACE_VOID			/* ptr */
} NSpaceType;

/* Return values for some functions */
#define NSPACE_OK              0		/* This must be 0 so all
						 * errors are true and this is
						 * false. */
#define NSPACE_TYPE_CLASH      1
#define NSPACE_MERGE_CLASH     2
#define NSPACE_NO_DEFAULTS     3
#define NSPACE_ALREADY_DEFINED 4
#define NSPACE_NOT_DEFINED     5
#define NSPACE_VALUE_ERROR     6

/* Flags for the name spaces */
#define NSPACE_IS_DEFAULT      0x01
#define NSPACE_DEFAULTS_MERGED 0x02

struct name_space;

typedef struct name_space_type {
  NSpaceComplexType complex_type;
  int base_type;
  int id_number;
} NameSpaceType;

typedef struct name_space_or_string {
  NSpaceType type;
  union {
    struct name_space *name_space;
    struct {
      char *string;
      unsigned int len;
    } str;
    void *ptr;
    long integer;
    double real;
  } value;
} NameSpaceValue;

typedef struct mapping {
  union {
    char *identifier;
    int sequence;
    int id_number;
  } id;
  NameSpaceValue value;
  Boolean was_copied;
} Mapping;

typedef struct name_space {
  NameSpaceType type;
  Mapping *mapping;
  int used_mappings;
  int alloc_mappings;  
  unsigned int flags;
  /* This is used by the default name spaces only */
  struct name_space *defaults; 
} NameSpace;

typedef struct NSContext *NSContext;

/* Low level functions. These are used to manipulate single name
   spaces. */

/* Initialize a name space. `complex_type' must be one of the complex
   types declared at the beginning of this file. `base_type' is the
   type of the items in the name space. If the complex type is a
   structure, then the base type is totally ignored and without
   meaning. */
void name_space_init_name_space(NameSpace *name_space,
				NSpaceComplexType complex_type,
				int base_type,
				int id_number);

/* Add mappings to a name space */
int name_space_add_mapping(NameSpace *name_space,
			   const char *identifier,
			   NSpaceType type,
			   const char *string,
			   unsigned int len);
int name_space_write_mapping(NameSpace *name_space,
			     const char *identifier,
			     NSpaceType type,
			     const char *string,
			     unsigned int len);
int name_space_add_ns_mapping(NameSpace *name_space,
			      const char *identifier,
			      NameSpace *target_space);
int name_space_write_ns_mapping(NameSpace *name_space,
				const char *identifier,
				NameSpace *target_space);
int name_space_add_mapping_list(NameSpace *name_space,
				NSpaceType type, 
				const char *string,
				unsigned int len);
int name_space_add_ns_mapping_list(NameSpace *name_space,
				   NameSpace *target_space);
int name_space_add_integer_mapping(NameSpace *name_space,
				   const char *identifier,
				   int integer);

/* Merge `target' name space to `source'. The values will not get
   duplicated, only pointers will be added. This is taken into account
   when the name spaces get destroyed. */
const char *name_space_merge_ns(NameSpace *target,
				NameSpace *source);

void name_space_free_name_space(NameSpace *name_space);

/* Do mappings; map an identifier, a sequence number or an id number
   (id numbers are for sparse integer arrays) to a value. See above
   for the definition of the NameSpaceValue structure. */
NameSpaceValue *name_space_map(NameSpace *name_space,
			       const char *identifier);
NameSpaceValue *name_space_map_sequence(NameSpace *name_space,
					int sequence);
NameSpaceValue *name_space_map_array(NameSpace *name_space,
				     int id_number);



/* High level functions, providing methods for manipulating a set of
   name spaces. The functions keep book on the created name spaces and
   destroy them all at once when the context gets destroyed. */

/* Create a NSContext. */
NSContext name_space_create_context(void);

/* Destroy it. This properly destroys all namespaces that are
   allocated with name_space_create_name_space. */
void name_space_destroy_context(NSContext context);

/* Register a structure/environment/list type. The type identifier for
   the type will be *identifier. *identifier string is copied. The
   original may be destroyed after the call. id_number should be
   an integer greater than 100.
   
   base_type is the base type for the type. If complex_type ==
   NSPACE_STRUCTURE, base_type is not meaningful but is ignored.
   
   complex_type must be one of the complex types declared in this file.
   
   Example of a call:
   
   name_space_register_type(context, "UserEnvironmentsList",
                            NSPACE_ENVIRONMENT,
                            NSPACE_STRING,
			    ID_USER_ENV_LIST);

   */

int name_space_register_type(NSContext context,
			     const char *identifier,
			     NSpaceComplexType complex_type,
			     int base_type,
			     int id_number);

/* Get the type of the field `identifier' in the type `compound_id'. */
int name_space_get_field_type(NSContext context,
			      const char *identifier,
			      int compound_id);

/* Return a pointer to a namespace which contains the default values
   for structure type id_number. */
NameSpace *name_space_get_default_ns(NSContext context,
				     int id_number);

/* Create a name space whose type is id_number. */
NameSpace *name_space_create_name_space(NSContext context,
					int id_number);

/* Get the type name of type id_number. */
const char *name_space_get_type_name(NSContext context,
				     int id_number);

/* Return a (shallow) copy of the name space original; the first-level
   mappings are duplicated; no values are duplicated, and the
   higher-level mappings are shared. */
NameSpace *name_space_copy(NSContext context,
			   NameSpace *original);

/* Get the id for the type whose name is `identifier'. */
int name_space_get_type_id(NSContext context, const char *identifier);

/* Get the default name space (as with name_space_get_default_ns) but
   with the symbolic identifier name rather than the numeric id. */
NameSpace *name_space_type_get_default_ns(NSContext context,
					  const char *identifier);

/* Merge to all name spaces in NSContext the appropriate
   defaults. This means: first merge the structure which is pointed by
   the *defaults pointer from the defaults structure of the type; then
   merge the defaults structure of the type. */
void name_space_merge_defaults(NSContext context);

/* For debugging */
void name_space_dump_context(FILE *out, NSContext context);
void name_space_dump_space(FILE *out, NameSpace *space);

/* Types */


#endif /* NSPACE_H */
