/*

  Author: Antti Huima <huima@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Thu Jun  6 17:26:13 1996 [huima]



  */

/*
 * $Id: nspace.c,v 1.15 1998/07/29 18:23:39 tmo Exp $
 * $Log: nspace.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "nspace.h"
#include "cparser.h"
#include "sshtcp.h"

#define NSPACE_INITIAL_MAPPINGS 10

struct NSContext {
  NameSpace types_to_ids;
  NameSpace ids_to_defaults;
  NameSpace list_of_spaces;
};
void name_space_free_mapping(Mapping *mapping);

/* Initialize a new name space to type complex_type/base_type with a
   mapping whose domain has zero cardinality */

void name_space_init_name_space(NameSpace *name_space,
				NSpaceComplexType complex_type,
				int base_type,
				int id_number)
{
  name_space->type.complex_type = complex_type;
  name_space->type.base_type = base_type;
  name_space->type.id_number = id_number;
  name_space->alloc_mappings = NSPACE_INITIAL_MAPPINGS;
  name_space->used_mappings = 0;
  name_space->mapping = ssh_xmalloc(sizeof(Mapping) *
				name_space->alloc_mappings);
  name_space->flags = 0;
  name_space->defaults = NULL;
}

/* Request a new mapping item for the name space, expanding the
   internal array if necessary */

int name_space_get_free_mapping(NameSpace *name_space)
{
  /* Expand the mappings table if necessary. */
  if (name_space->used_mappings == name_space->alloc_mappings)
    {
      name_space->alloc_mappings += NSPACE_INITIAL_MAPPINGS;
      name_space->mapping = ssh_xrealloc(name_space->mapping,
					 sizeof(Mapping) *
					 name_space->alloc_mappings);
    }
  return name_space->used_mappings++;  
}

/* Internal mapping creation functions */

/* Overwrite mapping whose value is STRING, In case of error return NULL,
   otherwise return first argument. */
Mapping *name_space_write_mapping_internal(Mapping *mapping,
					   NameSpace *name_space,
					   NSpaceType type,
					   const char *string,
					   unsigned int len)
{
  char *endp, *p;

  mapping->value.type = type;
  mapping->was_copied = FALSE;
  switch (type)
    {
    case NSPACE_STRING:
      mapping->value.value.str.string = ssh_xmemdup(string, len);
      mapping->value.value.str.len = len;
      break;
    case NSPACE_IP_NETMASK:
      p = ssh_xmemdup(string, len);
      endp = strchr(p, '/');
      if (endp == NULL || strchr(endp + 1, '/') != NULL)
	{
	  ssh_xfree(p);
	  return NULL;
	}
      *endp = '\0';
      if (!ssh_inet_is_valid_ip_address(p))
	{
	  ssh_xfree(p);
	  return NULL;
	}
      *endp = '/';
      mapping->value.value.str.string = p;
      mapping->value.value.str.len = len;
      p = endp + 1;
      strtol(p, &endp, 0);
      if (p == endp || *endp != '\0')
	{
	  ssh_xfree(mapping->value.value.str.string);
	  mapping->value.value.str.string = NULL;
	  return NULL;
	}
      break;
    case NSPACE_IP:
      if (!ssh_inet_is_valid_ip_address(string))
	return NULL;
      mapping->value.value.str.string = ssh_xmemdup(string, len);
      mapping->value.value.str.len = len;
      break;
    case NSPACE_TPORT:
    case NSPACE_UPORT:
      {
	int tmp;
	char buffer[128];
	if (len >= 127)
	  return NULL;
	strncpy(buffer, string, len);
	buffer[len] = '\0';
	if (type == NSPACE_UPORT)
	  tmp = ssh_tcp_get_port_by_service(buffer, "udp");
	else
	  tmp = ssh_tcp_get_port_by_service(buffer, "tcp");
	if (tmp < 0 || tmp >= 65536)
	  return NULL;
	mapping->value.value.str.string = ssh_xmemdup(string, len);
	mapping->value.value.str.len = len;
	break;
      }
    case NSPACE_INTEGER:
      mapping->value.value.integer = 0;
      mapping->value.value.integer = strtol(string, &endp, 0);
      if (string == endp || *endp != '\0')
	{
	  return NULL;
	}
      break;
    case NSPACE_BOOLEAN:
      mapping->value.value.integer = 0;
      if (strcasecmp(string, "true") == 0 ||
	  strcasecmp(string, "yes") == 0 ||
	  strcasecmp(string, "on") == 0)
	{
	  mapping->value.value.integer = TRUE;
	}
      else if (strcasecmp(string, "false") == 0 ||
	       strcasecmp(string, "no") == 0 ||
	       strcasecmp(string, "off") == 0)
	{
	  mapping->value.value.integer = FALSE;
	}
      else
	{
	  return NULL;
	}
      break;
    case NSPACE_REAL:
      mapping->value.value.real = 0.0;
      mapping->value.value.real = strtod(string, &endp);
      if (string == endp || *endp != '\0')
	{
	  return NULL;
	}
      break;
    case NSPACE_UNDEFINED:
    case NSPACE_NSPACE:
    case NSPACE_VOID:
      ssh_fatal("Invalid type in name_space_write_mapping_internal");
      break;
    }
  return mapping;
}

/* Create mapping whose value is STRING, return NULL if error */
Mapping *name_space_add_mapping_internal(NameSpace *name_space,
					 NSpaceType type,
					 const char *string,
					 unsigned int len)
{
  int i = name_space_get_free_mapping(name_space);
  Mapping *mapping = &name_space->mapping[i];
  
  return name_space_write_mapping_internal(mapping, name_space,
					   type, string, len);
}

/* Overwrite mapping whose value is NAME SPACE */
Mapping *name_space_write_ns_mapping_internal(Mapping *mapping,
					      NameSpace *name_space,
					      NameSpace *target_space)
{
  name_space_free_mapping(mapping);
  mapping->value.type = NSPACE_NSPACE;
  mapping->value.value.name_space = target_space;
  mapping->was_copied = FALSE;
  return mapping;
}

/* Create mapping whose value is NAME SPACE */
Mapping *name_space_add_ns_mapping_internal(NameSpace *name_space,
					    NameSpace *target_space)
{
  int i = name_space_get_free_mapping(name_space);
  Mapping *mapping = &name_space->mapping[i];
  
  mapping->value.type = NSPACE_NSPACE;
  mapping->value.value.name_space = target_space;
  mapping->was_copied = FALSE;
  return mapping;
}

/* Create mapping whose value is VOID POINTER */
Mapping *name_space_add_void_mapping_internal(NameSpace *name_space,
					      void *ptr)
{
  int i = name_space_get_free_mapping(name_space);
  Mapping *mapping = &name_space->mapping[i];

  mapping->value.type = NSPACE_VOID;
  mapping->value.value.ptr = ptr;
  mapping->was_copied = FALSE;
  return mapping;
}

/* Create mapping whose value is INTEGER */
Mapping *name_space_add_integer_mapping_internal(NameSpace *name_space,
						 int number)
{
  int i = name_space_get_free_mapping(name_space);
  Mapping *mapping = &name_space->mapping[i];
  
  mapping->value.type = NSPACE_INTEGER;
  mapping->value.value.integer = number;
  mapping->was_copied = FALSE;
  return mapping;
}

/* Add mapping to namespace */
int name_space_add_mapping(NameSpace *name_space,
			   const char *identifier,
			   NSpaceType type,
			   const char *string,
			   unsigned int len)
{
  Mapping *mapping = name_space_add_mapping_internal(name_space, type,
						     string, len);
  if (mapping == NULL)
    return NSPACE_VALUE_ERROR;
  mapping->id.identifier = ssh_xstrdup(identifier);
  return NSPACE_OK;
}

/* Overwrite mapping to namespace, return error if mapping not found */
int name_space_write_mapping(NameSpace *name_space,
			     const char *identifier,
			     NSpaceType type,
			     const char *string,
			     unsigned int len)
{
  int i;
  for (i = 0; i < name_space->used_mappings; i++)
    {      
      if (!strcmp(name_space->mapping[i].id.identifier, identifier))
	{
	  if (name_space_write_mapping_internal(&name_space->mapping[i],
						name_space, type, 
						string, len) == NULL)
	    return NSPACE_VALUE_ERROR;
	  return NSPACE_OK;
	}
    }
  return NSPACE_NOT_DEFINED;
}

int name_space_add_ns_mapping(NameSpace *name_space,
			      const char *identifier,
			      NameSpace *target_space)
{
  Mapping *mapping =
    name_space_add_ns_mapping_internal(name_space, target_space);
  if (mapping == NULL)
    return NSPACE_VALUE_ERROR;
  mapping->id.identifier = ssh_xstrdup(identifier);
  return NSPACE_OK;
}

int name_space_write_ns_mapping(NameSpace *name_space,
				const char *identifier,
				NameSpace *target_space)
{
  int i;
  for (i = 0; i < name_space->used_mappings; i++)
    {      
      if (!strcmp(name_space->mapping[i].id.identifier, identifier))
	{
	  if (name_space_write_ns_mapping_internal(&name_space->mapping[i],
						   name_space,
						   target_space) == NULL)
	    return NSPACE_VALUE_ERROR;
	  return NSPACE_OK;
	}
    }
  return NSPACE_NOT_DEFINED;
}

int name_space_add_mapping_list(NameSpace *name_space,
				NSpaceType type, 
				const char *string,
				unsigned int len)
{
  Mapping *mapping = name_space_add_mapping_internal(name_space,
						     type, string, len);
  if (mapping == NULL)
    return NSPACE_VALUE_ERROR;
  mapping->id.sequence = name_space->used_mappings - 1;
  return NSPACE_OK;
}

int name_space_add_ns_mapping_list(NameSpace *name_space,
				   NameSpace *target_space)
{
  Mapping *mapping =
    name_space_add_ns_mapping_internal(name_space, target_space);
  mapping->id.sequence = name_space->used_mappings - 1;
  return NSPACE_OK;
}

int name_space_add_integer_mapping(NameSpace *name_space,
				   const char *identifier,
				   int integer)
{
  Mapping *mapping =
    name_space_add_integer_mapping_internal(name_space, integer);
  mapping->id.identifier = ssh_xstrdup(identifier);
  return NSPACE_OK;
}

int name_space_add_ns_mapping_array(NameSpace *name_space,
				    int id_number,
				    NameSpace *target_space)
{
  Mapping *mapping = 
    name_space_add_ns_mapping_internal(name_space, target_space);
  if (mapping == NULL)
    return NSPACE_VALUE_ERROR;
  mapping->id.id_number = id_number;
  return NSPACE_OK;
}

/* Copying mappings -- copied mappings will be marked with was_copied
   flag as to distinguish them from mappings which have pointers to
   data allocated really for them. */

void name_space_copy_mapping_internal(Mapping *target,
				      Mapping *source)
{
  target->value.type = source->value.type;
  switch (source->value.type)
    {
    case NSPACE_STRING:
    case NSPACE_IP:
    case NSPACE_IP_NETMASK:
    case NSPACE_TPORT:
    case NSPACE_UPORT:
      target->value.value.str.string = source->value.value.str.string;
      target->value.value.str.len = source->value.value.str.len;
      break;
    case NSPACE_INTEGER:
    case NSPACE_BOOLEAN:
      target->value.value.integer = source->value.value.integer;
      break;
    case NSPACE_REAL:
      target->value.value.real = source->value.value.real;
      break;
    case NSPACE_NSPACE:
      target->value.value.name_space = source->value.value.name_space;
      break;
    case NSPACE_UNDEFINED:
    case NSPACE_VOID:
      ssh_fatal("Invalid type in name_space_copy_mapping_internal");
      break;
    }
  target->was_copied = TRUE;
}

void name_space_copy_mapping(NameSpace *name_space,
			     Mapping *source)
{
  int i = name_space_get_free_mapping(name_space);
  Mapping *new_mapping = &name_space->mapping[i];

  name_space_copy_mapping_internal(new_mapping, source);
  new_mapping->id.identifier = source->id.identifier;
}

void name_space_copy_mapping_overwrite(NameSpace *name_space,
				       Mapping *source)
{
  int i;
  for (i = 0; i < name_space->used_mappings; i++)
    {      
      if (!strcmp(name_space->mapping[i].id.identifier, source->id.identifier))
	{
	  name_space_free_mapping(&(name_space->mapping[i]));
	  name_space_copy_mapping_internal(&(name_space->mapping[i]),
					   source);
	  break;
	}
    }
}

void name_space_copy_mapping_list(NameSpace *name_space,
				 Mapping *source)
{
  int i = name_space_get_free_mapping(name_space);
  Mapping *new_mapping = &name_space->mapping[i];
  
  name_space_copy_mapping_internal(new_mapping, source);
  new_mapping->id.sequence = i;
}

/* Arrays are for internal purposes. Copying is not needed now */

/* Merging two name spaces with copy functions */

const char *name_space_merge_ns(NameSpace *target,
				NameSpace *source)
{
  int i;

  switch (target->type.complex_type)
    {
    case NSPACE_STRUCTURE:
    case NSPACE_ENVIRONMENT:
      for (i = 0; i < source->used_mappings; i++)
	{
	  if (name_space_map(target, source->mapping[i].id.identifier))
	    return source->mapping[i].id.identifier;
	  name_space_copy_mapping(target, &source->mapping[i]);
	}
      break;
    case NSPACE_ENVIRONMENT_OVERWRITABLE:
      for (i = 0; i < source->used_mappings; i++)
	{
	  if (name_space_map(target, source->mapping[i].id.identifier))
	    name_space_copy_mapping_overwrite(target, &source->mapping[i]);
	  else
	    name_space_copy_mapping(target, &source->mapping[i]);
	}
      break;
    case NSPACE_LIST:
      for (i = 0; i < source->used_mappings; i++)
	{
	  name_space_copy_mapping_list(target, &source->mapping[i]);
	}
      break;
    case NSPACE_ARRAY:
      break;
    }
  return NULL;
}

int name_space_merge_default_ns(NameSpace *target,
				NameSpace *source)
{
  int i;

  switch (target->type.complex_type)
    {
    case NSPACE_STRUCTURE:
    case NSPACE_ENVIRONMENT:
    case NSPACE_ENVIRONMENT_OVERWRITABLE:
      for (i = 0; i < source->used_mappings; i++)
	{
	  if (!name_space_map(target, source->mapping[i].id.identifier))
	    {
	      name_space_copy_mapping(target, &source->mapping[i]);
	    }
	}
      break;
    case NSPACE_LIST:
    case NSPACE_ARRAY:
      return NSPACE_NO_DEFAULTS;
      break;
    }
  return NSPACE_OK;
}

void name_space_free_mapping(Mapping *mapping)
{
  if (!mapping->was_copied)
    switch (mapping->value.type)
      {
      case NSPACE_STRING:
      case NSPACE_IP:
      case NSPACE_IP_NETMASK:
      case NSPACE_TPORT:
      case NSPACE_UPORT:
	ssh_xfree(mapping->value.value.str.string);
	break;
      case NSPACE_INTEGER:
      case NSPACE_BOOLEAN:
      case NSPACE_REAL:
      case NSPACE_NSPACE:
      case NSPACE_UNDEFINED:
      case NSPACE_VOID:
	break;
      }
}

void name_space_free_name_space(NameSpace *name_space)
{
  int i;
  for (i = 0; i < name_space->used_mappings; i++)
    {
      if ((name_space->type.complex_type == NSPACE_ENVIRONMENT ||
	   name_space->type.complex_type == NSPACE_ENVIRONMENT_OVERWRITABLE ||
	   name_space->type.complex_type == NSPACE_STRUCTURE) &&
	  name_space->mapping[i].was_copied == FALSE)
	{
	  ssh_xfree(name_space->mapping[i].id.identifier);
	}
      name_space_free_mapping(&name_space->mapping[i]);
    }
  ssh_xfree(name_space->mapping);
}

/* Map identifier, sequences or id_numbers to values. */

NameSpaceValue *name_space_map(NameSpace *name_space,
			       const char *identifier)
{
  int i;
  for (i = 0; i < name_space->used_mappings; i++)
    {      
      if (!strcmp(name_space->mapping[i].id.identifier, identifier))
	return &name_space->mapping[i].value;
    }
  return NULL;
}

NameSpaceValue *name_space_map_sequence(NameSpace *name_space,
					int sequence)
{
  if (sequence < name_space->used_mappings)
    return &name_space->mapping[sequence].value;
  return NULL;
}

NameSpaceValue *name_space_map_array(NameSpace *name_space,
				     int id_number)
{
  int i;
  for (i = 0; i < name_space->used_mappings; i++)
    {
      if (name_space->mapping[i].id.id_number == id_number)
	return &name_space->mapping[i].value;
    }
  return NULL;
}

/*
 *
 * HIGHER LEVEL FUNCTIONS
 *
 *
 */

/* Create a name space management context.
   We construct three internal name spaces:
   
   types_to_ids maps type strings to id numbers

   ids_to_defaults maps id numbers to name spaces which contain
   the default values for the corresponding name space types

   list_of_spaces is a list which is used to eventually destroy all
   allocated name spaces */

NSContext name_space_create_context()
{
  NSContext created = ssh_xmalloc(sizeof(*created));

  name_space_init_name_space(&created->types_to_ids,
			     0, NSPACE_INTEGER, 0);
  name_space_init_name_space(&created->ids_to_defaults,
			     NSPACE_ARRAY, NSPACE_NSPACE, 0);
  name_space_init_name_space(&created->list_of_spaces,
			     NSPACE_LIST, NSPACE_NSPACE, 0);
  return created;
}

void name_space_destroy_context(NSContext context)
{
  NameSpace *name_space;
  int i;

  name_space_free_name_space(&context->types_to_ids);
  name_space_free_name_space(&context->ids_to_defaults);
  for (i = 0; i < context->list_of_spaces.used_mappings; i++)
    {
      name_space_free_name_space
	(name_space = (name_space_map_sequence
	  (&context->list_of_spaces, i))->value.name_space);
      ssh_xfree(name_space);
    }
  name_space_free_name_space(&context->list_of_spaces);
  ssh_xfree(context);
}

int name_space_register_type(NSContext context,
			     const char *identifier,
			     NSpaceComplexType complex_type,
			     int base_type,
			     int id_number)
{
  NameSpace *created;

  /* ssh_debug("Registering type %d-%d-%d", complex_type, base_type,id_number); */

  if (name_space_map(&(context->types_to_ids), identifier))
    return NSPACE_ALREADY_DEFINED;

  name_space_add_integer_mapping(&(context->types_to_ids), 
				 identifier,
				 id_number);

  created = ssh_xmalloc(sizeof(NameSpace));

  /* The default values structure will contain the correct complex and
     base types for this type name space */
  name_space_init_name_space(created, complex_type, base_type, id_number);

  name_space_add_ns_mapping_array(&context->ids_to_defaults,
				  id_number, created);

  name_space_add_ns_mapping_list(&context->list_of_spaces,
				 created);

  return NSPACE_OK;
}

NameSpace *name_space_get_default_ns(NSContext context,
				     int id_number)
{
  NameSpaceValue *value;
  if (!id_number)
    return NULL;

  value = name_space_map_array(&context->ids_to_defaults,
			       id_number);
  if (!value)
    return NULL;

  return value->value.name_space;
}

const char *name_space_get_type_name(NSContext context,
				     int id_number)
{
  int i;
  if (id_number == NSPACE_STRING)
    return CF_BUILTIN_STRING;
  if (id_number == NSPACE_IP)
    return CF_BUILTIN_IP;
  if (id_number == NSPACE_IP_NETMASK)
    return CF_BUILTIN_IP_NETMASK;
  if (id_number == NSPACE_INTEGER)
    return CF_BUILTIN_INTEGER;
  if (id_number == NSPACE_BOOLEAN)
    return CF_BUILTIN_BOOLEAN;
  if (id_number == NSPACE_TPORT)
    return CF_BUILTIN_TPORT;
  if (id_number == NSPACE_UPORT)
    return CF_BUILTIN_UPORT;
  if (id_number == NSPACE_REAL)
    return CF_BUILTIN_REAL;
  for (i = 0; i < context->types_to_ids.used_mappings; i++)
    {
      if (context->types_to_ids.mapping[i].value.value.integer == id_number)
	return context->types_to_ids.mapping[i].id.identifier;
    }
  return NULL;
}

int name_space_get_type_id(NSContext context, const char *identifier)
{
  NameSpaceValue *value;

  if (strcmp(identifier, CF_BUILTIN_STRING) == 0)
    return NSPACE_STRING;
  if (strcmp(identifier, CF_BUILTIN_IP) == 0)
    return NSPACE_IP;
  if (strcmp(identifier, CF_BUILTIN_IP_NETMASK) == 0)
    return NSPACE_IP_NETMASK;
  if (strcmp(identifier, CF_BUILTIN_INTEGER) == 0)
    return NSPACE_INTEGER;
  if (strcmp(identifier, CF_BUILTIN_BOOLEAN) == 0)
    return NSPACE_BOOLEAN;
  if (strcmp(identifier, CF_BUILTIN_TPORT) == 0)
    return NSPACE_TPORT;
  if (strcmp(identifier, CF_BUILTIN_UPORT) == 0)
    return NSPACE_UPORT;
  if (strcmp(identifier, CF_BUILTIN_REAL) == 0)
    return NSPACE_REAL;
  
  value = name_space_map(&context->types_to_ids, identifier);
  if (!value)
    return 0;
  return value->value.integer;
}

NameSpace *name_space_type_get_default_ns(NSContext context,
				   const char *identifier)
{
  return name_space_get_default_ns
    (context, name_space_get_type_id(context, identifier));
}

NameSpace *name_space_create_name_space(NSContext context,
					int id_number)
{
  NSpaceComplexType complex_type;
  int base_type;
  NameSpace *refer;
  
  NameSpace *created = ssh_xmalloc(sizeof(NameSpace));

  refer = (name_space_map_array(&context->ids_to_defaults, id_number))->
    value.name_space;

  complex_type = refer->type.complex_type;
  base_type = refer->type.base_type;

  name_space_init_name_space(created, complex_type, base_type, id_number);
  
  name_space_add_ns_mapping_list(&context->list_of_spaces, created);
  return created;
}

NameSpace *name_space_copy(NSContext context,
			   NameSpace *original)
{
  int i;
  NameSpace *created = name_space_create_name_space(context,
						    original->type.id_number);
  switch (created->type.complex_type)
    {
    case NSPACE_STRUCTURE:
    case NSPACE_ENVIRONMENT:
    case NSPACE_ENVIRONMENT_OVERWRITABLE:
      for (i = 0; i < original->used_mappings; i++)
	name_space_copy_mapping(created, &original->mapping[i]);
      break;
    case NSPACE_LIST:
      for (i = 0; i < original->used_mappings; i++)
	name_space_copy_mapping_list(created, &original->mapping[i]);
      break;
    case NSPACE_ARRAY:
      break;
    }
  return created;
}

int name_space_get_field_type(NSContext context,
			      const char *identifier,
			      int compound_id)
{
  NameSpaceValue *value;
  NameSpace *space = name_space_get_default_ns(context, compound_id);

  if (!space)
    return 0;
  value = name_space_map(space, identifier);
  if (!value)
    return 0;
  if (value->type != NSPACE_NSPACE)
    return value->type;

  return value->value.name_space->type.id_number;  
}

void name_space_merge_defaults(NSContext context)
{
  int i, spaces;
  NameSpace *name_space, *default_space;
  spaces = context->list_of_spaces.used_mappings;

  for (i = 0; i < spaces; i++)
    {
      name_space = (name_space_map_sequence(&context->list_of_spaces,
					    i))->value.name_space;
      if (((name_space->flags) & NSPACE_IS_DEFAULT) == 0)
	{
	  default_space =
	    name_space_get_default_ns(context, name_space->type.id_number);
	  if (default_space->defaults)
	    name_space_merge_default_ns(name_space, default_space->defaults);
	  name_space_merge_default_ns(name_space, default_space);
	}
    }
}

/* dumping */

void name_space_dump_value(FILE *out, NameSpaceValue *value)
{
  switch (value->type)
    {
    case NSPACE_UNDEFINED:
      fprintf(out, "*undefined*");
      break;
      return;
    case NSPACE_STRING:
    case NSPACE_IP:
    case NSPACE_IP_NETMASK:
    case NSPACE_TPORT:
    case NSPACE_UPORT:
      fprintf(out, "\"%s\"", value->value.str.string);
      break;
    case NSPACE_NSPACE:
      name_space_dump_space(out, value->value.name_space);
      break;
    case NSPACE_VOID:
      fprintf(out, "(void *)%lx", (unsigned long)value->value.ptr);
      break;
    case NSPACE_INTEGER:
    case NSPACE_BOOLEAN:
      fprintf(out, "%ld", value->value.integer);
      break;
    case NSPACE_REAL:
      fprintf(out, "%g", value->value.real);
      break;
    }  
}

void name_space_dump_space(FILE *out, NameSpace *space)
{
  NSpaceComplexType type = space->type.complex_type;
  int i;
  int mappings = space->used_mappings;

  switch (type)
    {
    case NSPACE_STRUCTURE:
      fprintf(out, "{ ");
      for (i = 0; i < mappings; i++)
	{
	  fprintf(out, "%s = ",space->mapping[i].id.identifier);
	  name_space_dump_value(out, &space->mapping[i].value);
	  fprintf(out, " ");
	}
      fprintf(out, "}");
      break;
    case NSPACE_LIST:
      fprintf(out, "< ");
      for (i = 0; i < mappings; i++)
	{
	  name_space_dump_value(out, &space->mapping[i].value);
	  fprintf(out, " ");
	}
      fprintf(out, ">");
      break;
    case NSPACE_ARRAY:
      fprintf(out, "[ ");
      for (i = 0; i < mappings; i++)
	{
	  fprintf(out, "#%d = ", space->mapping[i].id.id_number);
	  name_space_dump_value(out, &space->mapping[i].value);
	  fprintf(out, " ");
	}
      fprintf(out, "]");
      break;
    case NSPACE_ENVIRONMENT:
    case NSPACE_ENVIRONMENT_OVERWRITABLE:
      fprintf(out, "( ");
      for (i = 0; i < mappings; i++)
	{
	  fprintf(out, "%s = ", space->mapping[i].id.identifier);
	  name_space_dump_value(out, &space->mapping[i].value);
	  fprintf(out, " ");
	}
      fprintf(out, ")");
      break;
    }
}

void name_space_dump_context(FILE *out, NSContext context)
{
  int i;
  int types = context->types_to_ids.used_mappings;
  int this_type;
  int spaces = context->list_of_spaces.used_mappings;
  NameSpace *name_space;
  
  fprintf(out, "Begin of the name space context dump.\n");
  fprintf(out, "There are %d types defined.\n", types);

  for (i = 0; i < types; i++)
    {
      this_type = context->types_to_ids.mapping[i].value.value.integer;
      fprintf(out, "Dump of type: %s (id number %d)\n",
	      context->types_to_ids.mapping[i].id.identifier,
	      this_type);
      name_space = (name_space_map_array(&context->ids_to_defaults,
					 this_type))->value.name_space;
      name_space_dump_space(out, name_space);
      fprintf(out, "\n");
    }

  fprintf(out, "Dumping all defined name spaces.\n");
  for (i = 0; i < spaces; i++)
    {
      name_space = (name_space_map_sequence(&context->list_of_spaces,
					    i))->value.name_space;
      name_space_dump_space(out, name_space);
      fprintf(out, "\n");
    }

  fprintf(out, "End of dump.\n");
}
