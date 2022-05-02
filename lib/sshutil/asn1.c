/*

  asn1_tree.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Mon Feb 10 16:09:37 1997 [mkojo]

  Implementation of a tree structure to handle BER/DER objects.

  Problem areas:

    - sorting because:

      tagging _smoothly_ hides knowledge of SET's and SET-OF's thus the
      sorting must be done manually (however not always?).

    - when error happens in reading code, it is possible that that library
      has already build some results. However, it should go around again
      and free the results. See the sshencode.c for way to do it. This
      is reasonably urgent addition. XXX
      
  Clean-ups if time is available:

    Minor things:
      add more types (all the string types and time types, enumeration etc.)
      add some extended types like node insertion etc.

  This implementation is quite slow because uses ascii format string which it
  parses very horribly.

  On the otherhand, these routines do have some power in parsing ASN.1 and
  you can see them in use at SSH X.509 Certificate library.
  
  */

/*
 * $Id: asn1.c,v 1.16 1998/08/24 11:10:47 mkojo Exp $
 * $Log: asn1.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "cmalloc.h"
#include "asn1.h"
#include "ber.h"
#include "sshenum.h"

/* Format of Asn.1 tree node. Notice that we have currently restricted
   ourselves to small tag numbers. There does not seem to be any reason to
   use larger than 32-bit tags. */

struct SshAsn1NodeRec
{
  /* Class of the node */
  SshAsn1Class class;

  /* Encoding of the node */
  SshAsn1Encoding encoding;

  /* Tag number of the node */
  SshAsn1Tag tag_number;
  
  /* Encoding of the length */
  SshAsn1LengthEncoding length_encoding;
  
  /* Tree is represented as doubly-linked list of nodes that might have
     children that could also have doubly-linked list of nodes and childred
     and so on recursively.

     Some restrictions are assumed. 'child' points to a child node that
     has no previous nodes. */

  struct SshAsn1NodeRec *next, *prev, *child, *parent;
  
  /* Data contained in the node (the tag and data are contiguous by
     definition). */

  /* BER/DER encoded tag. */
  size_t tag_length;
  unsigned char *tag;
  
  /* BER/DER encoded data. */
  size_t length;
  unsigned char *data;
};

/* Asn.1 internal allocation context. All allocation is redirected to
   cmalloc routines. */

struct SshAsn1ContextRec
{
  SshCMallocContext cmalloc_context;
};

/* Asn.1 moving context. */

struct SshAsn1TreeRec
{
  SshAsn1Node root;
  SshAsn1Node current;

  /* Data for the full tree. */
  unsigned char *data;
  size_t length;
};

/*************** Internal memory management *************/

/* Allocate and initialize Asn.1 context. */

SshAsn1Context ssh_asn1_init(void)
{
  SshAsn1Context created = ssh_xmalloc(sizeof(*created));
  created->cmalloc_context = ssh_cmalloc_init();  
  return created;
}

/* Free Asn.1 context and all data that might have been allocated
   under it. */

void ssh_asn1_free(SshAsn1Context context)
{
  ssh_cmalloc_free(context->cmalloc_context);
  ssh_xfree(context);
}

/* Allocate memory from context structure. */

unsigned char *ssh_asn1_malloc_b(SshAsn1Context context,
				 size_t size)
{
  return ssh_cmalloc_b(context->cmalloc_context, size);
}

void *ssh_asn1_malloc_s(SshAsn1Context context,
			size_t size)
{
  return ssh_cmalloc_s(context->cmalloc_context, size);
}

/************** Tree decoding and encoding from/to BER **************/

/* Decode given BER/DER buffer recursively to a Asn.1 tree. */

SshAsn1Status ssh_asn1_decode_recurse(SshAsn1Context context, 
				      unsigned char *buf, size_t len,
				      SshAsn1Node *first, SshAsn1Node parent)
{
  SshAsn1Node node, prev;
  SshAsn1Status status;
  SshBerStatus ber_status;
  size_t error_len;
  SshAsn1Class class;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  size_t length, tag_length;
  unsigned char *data, *tag;
  
  /* Get some defaults and error detection. */
  prev = NULL;
  error_len = len;
  
  while (len && len <= error_len)
    {
      /* Open the BER element to a opened form. Note that this means just
	 placing the pointer to the buffer correctly. */
      ber_status = ssh_ber_open_element(buf, len,
					&class, &encoding,
					&tag_number, &length_encoding,
					&tag_length,
					&tag,
					&length,
					&data);
      
      if (ber_status != SSH_BER_STATUS_OK)
	{
	  if (parent == NULL && *first)
	    return SSH_ASN1_STATUS_OK_GARBAGE_AT_END;
	  return SSH_ASN1_STATUS_BER_OPEN_FAILED;
	}

      /* Skip end-of-contents. This is not exactly correct, because we
	 really don't check whether this belongs to any structure
	 whatsoever. Although in general this should not affect anything. */
      if (class == SSH_ASN1_CLASS_UNIVERSAL && tag_number == 0)
	{
	  buf += tag_length + length;
	  len -= tag_length - length;

	  if (len > error_len)
	    {
	      if (parent == NULL && *first)
		return SSH_ASN1_STATUS_OK_GARBAGE_AT_END;
	      return SSH_ASN1_STATUS_BUFFER_OVERFLOW;
	    }
	  continue;
	}
      
      /* Allocate new node to place the data to be read. */
      node = ssh_asn1_malloc_s(context, sizeof(*node));
      node->next = node->prev = node->child = NULL;

      /* Set up the node. */
      node->class = class;
      node->encoding = encoding;
      node->tag_number = tag_number;
      node->length_encoding = length_encoding;
      node->tag_length = tag_length;
      node->tag = tag;
      node->length = length;
      node->data = data;
      node->parent = parent;
      
      /* Check if child actually do exist. */
      if (node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED)
	{
	  /* Recursively decode childs. */
	  if ((status = ssh_asn1_decode_recurse(context,
						node->data,
						node->length,
						&node->child,
						node)) != SSH_ASN1_STATUS_OK)
	      {
		/* If we have actually found out something, but
		   failed in some deep valley we still might want to
		   read about these things. */
		if (parent == NULL && *first)
		  return SSH_ASN1_STATUS_BAD_GARBAGE_AT_END;
		return status;
	      }
	}

      /* If previous node is available then link accordingly. */
      if (prev)
	{
	  node->prev = prev;
	  prev->next = node;
	}
      else
	{
	  /* Set as parent if no other has yet been set. */
	  if (*first == NULL)
	    *first = node;
	}
      prev = node;

      /* Step over element. */
      buf += tag_length + length;
      len -= tag_length + length;

      /* Simple check for errors. */
      if (len > error_len)
	return SSH_ASN1_STATUS_BUFFER_OVERFLOW;
    }
  
  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status ssh_asn1_decode(SshAsn1Context context,
			      const unsigned char *buf, size_t len,
			      SshAsn1Tree *tree)
{
  SshAsn1Status status;

  /* Allocate for a new tree. */
  (*tree) = ssh_asn1_malloc_s(context, sizeof(**tree));
  
  (*tree)->data = ssh_asn1_malloc_b(context, len);
  (*tree)->length = len;
  memcpy((*tree)->data, buf, (*tree)->length);

  /* Make NULL because ssh_asn1_decode_recurse assumes this. */
  (*tree)->root = NULL;
  
  status = ssh_asn1_decode_recurse(context, (*tree)->data, (*tree)->length,
				   &(*tree)->root, NULL);

  /* Set current also to point at the tree. */
  (*tree)->current = (*tree)->root;

  return status;
}

/* Count length of actual BER encoded tree or subtree. */

size_t ssh_asn1_count_length(SshAsn1Node node)
{
  size_t len = 0;

  while (node)
    {
      /* If constructed then count the childs too. */
      if (node->data == NULL &&
	  node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED)
	{
	  node->length = ssh_asn1_count_length(node->child);
	  
	  /* Add space for end-of-contents octets. */
	  if (node->length_encoding == SSH_ASN1_LENGTH_INDEFINITE)
	    node->length += 2;

	  /* Compute now the tag length. */
	  node->tag_length = ssh_ber_compute_tag_length(node->class,
							node->encoding,
							node->tag_number,
							node->length_encoding,
							node->length);

	}

      /* Increase the total length. */
      len += node->tag_length + node->length;
      node = node->next;
    }

  return len;
}

/* Recursively compose the buffer with BER encoded data from the Asn.1 tree.
   */

SshAsn1Status ssh_asn1_encode_recurse(SshAsn1Context context,
				      SshAsn1Node first,
				      unsigned char *buf, size_t len)
{
  SshAsn1Status status;
  SshBerStatus ber_status;
  SshAsn1Node node;
  
  node = first;
  
  while (node)
    {
      if (node->data != NULL || node->encoding == SSH_ASN1_ENCODING_PRIMITIVE)
	{
	  /* This element contains unchanged childs (or is primitive)
	     and thus can be simply copied to the buffer (i.e. closed). */

	  if (node->tag_length + node->length <= len)
	    {
	      memcpy(buf, node->tag, node->tag_length);
	      memcpy(buf + node->tag_length, node->data, node->length);

	      node->tag = buf;
	      node->data = buf + node->tag_length;
	    }
	  else
	    {
	      return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
	    }
	}
      else
	{
	  /* Compute tag length. */
	  
	  if (node->tag_length > len)
	    {
	      return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
	    }
	  
	  /* Recursively compose child lists. */
	  status = ssh_asn1_encode_recurse(context, node->child,
					   buf + node->tag_length,
					   len - node->tag_length);

	  if (status != SSH_ASN1_STATUS_OK)
	    return status;
	  
	  if (node->length_encoding == SSH_ASN1_LENGTH_INDEFINITE)
	    {
	      if (len < 2)
		{
		  return SSH_ASN1_STATUS_BUFFER_TOO_SMALL;
		}
	      
	      /* Add end-of-contents octets to the buffer. */
	      buf[node->tag_length + node->length - 2] = 0x0;
	      buf[node->tag_length + node->length - 1] = 0x0;
	    }

	  /* This node contains no encoded tag's because it contains no
	     contents :) Thus we are forced to build some. */

	  node->tag = buf;
	  node->data = buf + node->tag_length;
	  ber_status = ssh_ber_set_tag(node->tag, node->tag_length,
				       node->class, node->encoding,
				       node->tag_number, node->length_encoding,
				       node->length);

	  if (ber_status != SSH_BER_STATUS_OK)
	    return SSH_ASN1_STATUS_BER_CLOSE_FAILED;
	}

      /* Jump over the just encoded element. */
      buf += node->tag_length + node->length;
      len -= node->tag_length + node->length;
      
      node = node->next;
    }

  return SSH_ASN1_STATUS_OK;
}

int ssh_asn1_node_compare(SshAsn1Node n1, SshAsn1Node n2)
{
  size_t temp1_len, temp2_len, temp_len;
  int rv;

  /* Compute lengths. */
  temp1_len = n1->tag_length + n1->length;
  temp2_len = n2->tag_length + n2->length;

  /* Check if either is larger. */
  
  if (temp1_len >= temp2_len)
    temp_len = temp2_len;
  else
    temp_len = temp1_len;

  /* Compare. */
  rv = memcmp(n1->tag, n2->tag, temp_len); 

  /* Check for padding. */
  if (rv == 0)
    {
      if (temp1_len > temp2_len)
	rv = 1;
      if (temp2_len > temp1_len)
        rv = -1;
    }

  return rv;
}

/* Sort with delayed move. Methods such are qsort or radix sort are quicker,
   but take more coding and this should be fine. */

SshAsn1Node ssh_asn1_sort_list(SshAsn1Context context,
			       SshAsn1Node first)
{
  SshAsn1Node node, min, step;
  size_t size;
  unsigned char *buf;

  /* Sort the trivial case. */
  if (first == NULL)
    return NULL;
  
  /* Encode all data before sorting. */
  size = ssh_asn1_count_length(first);
  buf  = ssh_asn1_malloc_b(context, size);
  if (ssh_asn1_encode_recurse(context,
			      first, buf, size) != SSH_ASN1_STATUS_OK)
    return NULL;

  /* Defaults. */
  node = first;
  step = first;
  
  /* Sort nodes. */
  while (step)
    {
      /* Search the least... */
      node = step;
      min = step;
      while (node->next)
	{
	  if (ssh_asn1_node_compare(min, node->next) > 0)
	    min = node->next;
	  node = node->next;
	}

      if (min != step)
	{
	  /* Detach min. */
	  if (min->prev)
	    min->prev->next = min->next;
	  if (min->next)
	    min->next->prev = min->prev;

	  /* Append min. */
	  min->prev = step->prev;
	  min->next = step;

	  if (step->prev)
	    step->prev->next = min;
	  else
	    {
	      /* Now the step must be the first in row and thus
		 the parent must point to it. We however want that
		 the parent points to the first in row so set min there. */
	      if (step->parent)
		step->parent->child = min;
	      first = min;
	    }
	  step->prev = min;
	}
      else
	step = step->next;
    }

  /* Nodes are now in order. */
  
  return first;
}

/* Generic encoding of the Asn.1 tree to the BER byte code. */

SshAsn1Status ssh_asn1_encode(SshAsn1Context context,
			      SshAsn1Tree tree)
{
  SshAsn1Node root = tree->root;

  if (root == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;
  
  /* Compute the tree length when composed as BER byte code. */
  tree->length = ssh_asn1_count_length(root);
  tree->data = ssh_asn1_malloc_b(context, tree->length);

  /* Compose the actual BER byte code. */
  return ssh_asn1_encode_recurse(context, root, tree->data, tree->length);
}

/* Encode starting from some specific node. */

SshAsn1Status ssh_asn1_encode_node(SshAsn1Context context,
				   SshAsn1Node parent)
{
  SshBerStatus ber_status;
  SshAsn1Status status;
  
  if (parent->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
    return SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED;

  /* Compute the tree length when composed as BER byte code. */
  ssh_asn1_count_length(parent);

  /* Allocate new buffer for everything. */
  parent->tag = ssh_asn1_malloc_b(context,
				  parent->tag_length + parent->length);
  parent->data = parent->tag + parent->tag_length;
  
  /* Compose child's byte code. */
  status = ssh_asn1_encode_recurse(context, parent->child,
				   parent->data, parent->length);

  if (status != SSH_ASN1_STATUS_OK)
    return status;
  
  /* Do the actual tag encoding. */
  ber_status = ssh_ber_set_tag(parent->tag, parent->tag_length,
			       parent->class, parent->encoding,
			       parent->tag_number,
			       parent->length_encoding,
			       parent->length);
  if (ber_status != SSH_ASN1_STATUS_OK)
    return SSH_ASN1_STATUS_BER_CLOSE_FAILED;
  
  return SSH_ASN1_STATUS_OK;
}

/************** Creation and reading of ASN.1 Trees *******************/

/* Definitions for parsing. */

typedef unsigned int SshAsn1TaggingMode;
#define SSH_ASN1_TAGGING_IMPLICIT 0
#define SSH_ASN1_TAGGING_EXPLICIT 1

typedef unsigned int SshAsn1DefExt;
#define SSH_ASN1_DEFEXT_NONE       0
#define SSH_ASN1_DEFEXT_NODE       1
#define SSH_ASN1_DEFEXT_CHOICE     2
#define SSH_ASN1_DEFEXT_OPTIONAL   3

typedef struct
{
  /* Name of the function. */
  char *name;
  /* Tag number if any. */
  SshAsn1Tag tag_number;
  /* Extended type. */
  SshAsn1DefExt extended;
  /* BER (or any other) encoding function. */
  SshBerStatus (*encode)(SshCMallocContext,
			 SshAsn1Class, SshAsn1Encoding,
			 SshAsn1Tag, SshAsn1LengthEncoding,
			 unsigned char **, size_t *,
			 unsigned char **, size_t *,
			 va_list *);
  /* BER (or any other) decoding function. */
  SshBerStatus (*decode)(unsigned char *, size_t, va_list *);
  /* For skipping those vararg list arguments that are not used. */
  void (*step_over)(va_list *);
} SshAsn1Defs;

/* Definitions of all useful types. */

SshAsn1Defs ssh_asn1_definitions[] =
{
#if 0
  { "reserved",       SSH_ASN1_TAG_RESERVED_0,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL },
#endif
  { "boolean",              SSH_ASN1_TAG_BOOLEAN,
    SSH_ASN1_DEFEXT_NONE, ssh_ber_encode_boolean,
    ssh_ber_decode_boolean, ssh_ber_step_boolean },
  { "integer",              SSH_ASN1_TAG_INTEGER,
    SSH_ASN1_DEFEXT_NONE, ssh_ber_encode_integer,
    ssh_ber_decode_integer, ssh_ber_step_integer },
  { "bit-string",             SSH_ASN1_TAG_BIT_STRING,
    SSH_ASN1_DEFEXT_NONE, ssh_ber_encode_bit_string,
    ssh_ber_decode_bit_string, ssh_ber_step_bit_string },
  { "octet-string",           SSH_ASN1_TAG_OCTET_STRING, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "null",           SSH_ASN1_TAG_NULL, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_null, ssh_ber_decode_null, ssh_ber_step_null },
  { "object-identifier",            SSH_ASN1_TAG_OID_TYPE,
    SSH_ASN1_DEFEXT_NONE, ssh_ber_encode_oid_type,
    ssh_ber_decode_oid_type, ssh_ber_step_oid_type },
#if 0
  { "ode",            SSH_ASN1_TAG_ODE_TYPE,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "eti",            SSH_ASN1_TAG_ETI_TYPE,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "real",           SSH_ASN1_TAG_REAL,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
#endif
  { "enum",           SSH_ASN1_TAG_ENUM, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_integer, ssh_ber_decode_integer,
    ssh_ber_step_integer },
  { "enum-short",           SSH_ASN1_TAG_ENUM, SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_integer_short, ssh_ber_decode_integer_short,
    ssh_ber_step_integer_short },
#if 0
  { "embedded",       SSH_ASN1_TAG_EMBEDDED,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "reserved",       SSH_ASN1_TAG_RESERVED_1,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "reserved",       SSH_ASN1_TAG_RESERVED_2,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "reserved",       SSH_ASN1_TAG_RESERVED_3,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "reserved",       SSH_ASN1_TAG_RESERVED_4,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
#endif
  { "sequence",            SSH_ASN1_TAG_SEQUENCE,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "set",            SSH_ASN1_TAG_SET,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL, NULL },
  { "numeric-string",             SSH_ASN1_TAG_NUMERIC_STRING,
    SSH_ASN1_DEFEXT_NONE,
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "printable-string",             SSH_ASN1_TAG_PRINTABLE_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "teletex-string",             SSH_ASN1_TAG_TELETEX_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "visible-string",             SSH_ASN1_TAG_VIDEOTEX_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "ia5-string",             SSH_ASN1_TAG_IA5_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "graphic-string",             SSH_ASN1_TAG_GRAPHIC_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "visible-string",            SSH_ASN1_TAG_VISIBLE_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "general-string",           SSH_ASN1_TAG_GENERAL_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "universal-string",             SSH_ASN1_TAG_UNIVERSAL_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "unrestricted-string",            SSH_ASN1_TAG_UNRESTRICTED_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  { "bmp-string",           SSH_ASN1_TAG_BMP_STRING,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_octet_string,
    ssh_ber_decode_octet_string, ssh_ber_step_octet_string },
  
  { "utc-time",             SSH_ASN1_TAG_UNIVERSAL_TIME,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_universal_time,
    ssh_ber_decode_universal_time, ssh_ber_step_universal_time },
  { "generalized-time",             SSH_ASN1_TAG_GENERALIZED_TIME,
    SSH_ASN1_DEFEXT_NONE, 
    ssh_ber_encode_generalized_time,
      ssh_ber_decode_generalized_time, ssh_ber_step_generalized_time },
#if 0
  { "reserved",       SSH_ASN1_TAG_RESERVED_5,
    SSH_ASN1_DEFEXT_NONE, NULL, NULL },
#endif

  /* Special extensions. */
  { "any",                0,
    SSH_ASN1_DEFEXT_NODE, NULL, NULL, NULL },
  { "choice",             0,
    SSH_ASN1_DEFEXT_CHOICE, NULL, NULL, NULL },
  { "optional",           0,
    SSH_ASN1_DEFEXT_OPTIONAL, NULL, NULL, NULL },
  
  /* extensions that ease the use of some types*/
  { "integer-short",        SSH_ASN1_TAG_INTEGER,
    SSH_ASN1_DEFEXT_NONE, ssh_ber_encode_integer_short,
    ssh_ber_decode_integer_short, ssh_ber_step_integer_short },

  /* The end. */
  { NULL }
};

SshAsn1Status ssh_asn1_command(const char *str, size_t str_len,
			       SshAsn1Defs **defs)
{
  int i;

  *defs = NULL;
  
  for (i = 0; ssh_asn1_definitions[i].name != NULL; i++)
    {
      if (memcmp(str, ssh_asn1_definitions[i].name,
		 str_len) == 0)
	{
	  *defs = &ssh_asn1_definitions[i];
	  return SSH_ASN1_STATUS_OK;
	}
    }
  return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
}

SshAsn1Status ssh_asn1_format_find_subspace(const char open, const char close,
					    const char *str, size_t len,
					    size_t *end_pos)
{
  int i, j;
  
  for (i = 0, j = 0; i < len; i++)
    {
      if (str[i] == open)
	{
	  j++;
	}
      if (str[i] == close)
	{
	  j--;
	  if (j == 0)
	    break;
	}
    }

  if (i == len)
    return SSH_ASN1_STATUS_MISSING_CLOSING_MARKER;
  
  *end_pos = i - 1;
  
  return SSH_ASN1_STATUS_OK;
}

/* This is the Lisp-style format for the tree definition. */

SshAsn1Status
ssh_asn1_parse_command_lisp(const char *format, size_t len,
			    size_t *step,
			    const char **child_ptr,
			    size_t *child_len,
			    SshAsn1Defs **defs,
			    SshAsn1LengthEncoding *length_encoding,
			    Boolean *is_tagged,
			    SshAsn1Class *class,
			    SshAsn1Tag *tag_number,
			    SshAsn1TaggingMode *tagging_mode,
			    Boolean *match_defs)
{
  size_t i, keep, end_pos;
  SshAsn1Status status;
  
  /* Some helpful macros. */
#define ADVANCE(i,v,l)           \
  if (((i) += (v)) >= (l))       \
    return SSH_ASN1_STATUS_FORMAT_STRING_TOO_SHORT;

#define SKIP(i,l,rule)           \
  while ((rule) && ((i) < (l)))  \
    (i)++;                       \
  if (i >= l)                    \
    return SSH_ASN1_STATUS_FORMAT_STRING_TOO_SHORT;

  /* Set to default values. */

  *is_tagged = FALSE;
  *class = SSH_ASN1_CLASS_CONTEXT;
  *tag_number = 0;
  *tagging_mode = SSH_ASN1_TAGGING_IMPLICIT;
  *length_encoding = SSH_ASN1_LENGTH_DEFINITE;
  *child_ptr = NULL;
  *child_len = 0;
  *match_defs = FALSE;
  
  for (i = 0; i < len;)
    {
      switch (format[i])
	{
	  /* Check if valid command. */
	case '(':

	  /* Find the closing parenthesis. */
	  if ((status = ssh_asn1_format_find_subspace('(', ')',
						      &format[i],
						      len - i,
						      &end_pos))
	      != SSH_ASN1_STATUS_OK)
	    return status;

	  /* Add to the ending position... */
	  end_pos += i;
	  
	  /* Advance one. */
	  ADVANCE(i,1,len);

	  SKIP(i, len, isspace(format[i]));
	  
	  keep = i;

	  /* Rule for skipping the name. */
	  SKIP(i, len, islower(format[i]) || format[i] == '-' ||
	       isdigit(format[i]) );
	  
	  /* Check the command i.e. function. */
	  if (ssh_asn1_command(&format[keep],
			       i - keep, defs) != SSH_ASN1_STATUS_OK)
	    return SSH_ASN1_STATUS_UNKNOWN_COMMAND;

	  SKIP(i, len, isspace(format[i]));

	  if ((*defs)->extended == SSH_ASN1_DEFEXT_CHOICE ||
	      (*defs)->extended == SSH_ASN1_DEFEXT_OPTIONAL)	      
	    goto no_tags;
	  
	  /* Check if command contains options (i.e. tags). */
	  if (format[i] == '(')
	    {
	      ADVANCE(i,1,len);

	      /* Check for class. */
	      while (islower(format[i]) || format[i] == '*' ||
		     isspace(format[i]))
		{
		  if (isspace(format[i]))
		    {
		      ADVANCE(i,1,len);
		      continue;
		    }
		  
		  switch (format[i])
		    {
		    case 'u':
		      *class = SSH_ASN1_CLASS_UNIVERSAL;
		      *is_tagged = TRUE;
		      break;
		    case 'p':
		      *class = SSH_ASN1_CLASS_PRIVATE;
		      *is_tagged = TRUE;
		      break;
		    case 'c':
		      *class = SSH_ASN1_CLASS_CONTEXT;
		      *is_tagged = TRUE;
		      break;
		    case 'a':
		      *class = SSH_ASN1_CLASS_APPLICATION;
		      *is_tagged = TRUE;
		      break;
		    case 'i':
		      *length_encoding = SSH_ASN1_LENGTH_INDEFINITE;
		      break;
		    case 'e':
		      *tagging_mode = SSH_ASN1_TAGGING_EXPLICIT;
		      *is_tagged = TRUE;
		      break;
		    case '*':
		      *match_defs = TRUE;
		      break;
		    default:
		      return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
		      break;
		    }
		  ADVANCE(i,1,len);
		}

	      if (isdigit(format[i]))
		{
		  *is_tagged = TRUE;
		  *tag_number = atol(&format[i]);
		}
	      else
		{
		  /* Set the tag_number to type, making the definition
		     of indefinite types more easier. */
		  if (!is_tagged)
		    *tag_number = (*defs)->tag_number;
		}

	      SKIP(i,len, isdigit(format[i]));
	      SKIP(i,len, isspace(format[i]));

	      if (format[i] != ')')
		return SSH_ASN1_STATUS_UNKNOWN_COMMAND;

	      ADVANCE(i,1,len);
	    }
	  else
	    {
	      return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
	    }

	  SKIP(i,len,isspace(format[i]));

	no_tags:
	  
	  *child_ptr = &format[i];
	  if (end_pos > i)
	    *child_len = end_pos - i + 1;
	  else
	    *child_len = 0;
	  
	  *step = end_pos + 2;
	  return SSH_ASN1_STATUS_OK;
	  break;
	  
	default:
	  if (isspace(format[i]))
	    {
	      /* This is a little special case, because we can indeed quit
		 while running in whitespace. */
	      if (++i >= len)
		{
		  /* But don't lie about that one can move this far. */
		  *step = 0;
		  return SSH_ASN1_STATUS_OK;
		}
	      break;
	    }

	  return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
	  break;
	}
    }

  /* Is reasonable to undefine these local macros. */
#undef ADVANCE
#undef SKIP

  /* Cannot step so tell it to upper level. */
  *step = 0;
  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status
ssh_asn1_create_tree_recurse(SshAsn1Context context,
			     SshAsn1Node *first, SshAsn1Node parent,
			     const char *format, size_t len,
			     va_list *ap)
{
  SshAsn1Node node, prev, tag_node, temp;
  SshAsn1Status status;
  SshAsn1Defs *defs;
  unsigned int i;
  const char *child_ptr;
  size_t child_len;
  SshAsn1Tag tag_number;
  SshAsn1Class tag_class;
  SshAsn1LengthEncoding length_encoding;
  Boolean is_tagged, match_defs;
  size_t step;
  SshAsn1TaggingMode tagging_mode;

  defs = NULL;
  
  for (i = 0, prev = NULL; i < len;)
    {
      status = ssh_asn1_parse_command_lisp(&format[i], len - i,
					   &step,
					   &child_ptr,
					   &child_len,
					   &defs,
					   &length_encoding,
					   &is_tagged,
					   &tag_class,
					   &tag_number,
					   &tagging_mode,
					   &match_defs);
      
      if (status != SSH_ASN1_STATUS_OK)
	return status;

      /* Advance (or return to upper level). */
      if (step == 0)
	return SSH_ASN1_STATUS_OK;
      i += step;

      /* This implies internal error, but lets try to quit nicely. */
      if (defs == NULL)
	return SSH_ASN1_STATUS_UNKNOWN_COMMAND;

      switch (defs->extended)
	{
	case SSH_ASN1_DEFEXT_CHOICE:
	case SSH_ASN1_DEFEXT_OPTIONAL:
	  /* This makes no sense here. */
	  return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
	  
	  /* Case where you can insert pre-existing nodes to our
	     ASN.1 tree. */
	case SSH_ASN1_DEFEXT_NODE:
	  /* Get the node. */
	  node = va_arg(*ap, SshAsn1Node);

	  /* Ignore if NULL! This can be handy sometimes. */
	  if (node == NULL)
	    break;
	  
	  /* Clear the data section (for possibility that we have
	     constructed type at hand). */

	  /* Check whether explicit tagging is used. */
	  if (is_tagged && tagging_mode == SSH_ASN1_TAGGING_EXPLICIT)
	    {
	      tag_node = ssh_asn1_malloc_s(context,
					   sizeof(*tag_node));

	      /* Set the node correctly. */
	      tag_node->class = tag_class;
	      tag_node->tag_number = tag_number;
	      tag_node->encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
	      tag_node->length_encoding = SSH_ASN1_LENGTH_DEFINITE;
	      tag_node->data = tag_node->tag = NULL;
	      tag_node->length = tag_node->tag_length = 0;
	      tag_node->next = NULL;
	      
	      if (prev)
		prev->next = tag_node;
	      else
		*first = tag_node;

	      tag_node->prev = prev;
	      tag_node->parent = parent;
	      prev = tag_node;
	      
	      /* Add node to tree. */
	      node->prev = NULL;	      
	      node->parent = tag_node;
	      temp = node;
	      while (temp)
		{
		  temp->parent = tag_node;
		  temp = temp->next;
		}

	      tag_node->child = node;
	    }
	  else
	    {
	      if (prev)
		prev->next = node;
	      else
		*first = node;

	      node->prev = prev;
	      node->parent = parent;
	      temp = node;
	      while (temp)
		{
		  temp->parent = parent;
		  temp = temp->next;
		}

	      prev = node;
	    }
 
	  if (is_tagged && tagging_mode == SSH_ASN1_TAGGING_IMPLICIT)
	    {
	      node->class = tag_class;
	      node->tag_number = tag_number;
	    }

	  /* Do nothing else, we should now have "any" value set nicely. */
	  break;
	  /* Most useful case without any extensions. */
	case SSH_ASN1_DEFEXT_NONE:
	  /* Allocate new node. */
	  node = ssh_asn1_malloc_s(context, sizeof(*node));
	  
	  if (prev)
	    prev->next = node;
	  else
	    *first = node;
	  node->prev = prev;
	  node->next = node->child = NULL;
	  node->parent = parent;

	  /* Set the node to be the prev to the next node ;) huh... */
	  prev = node;

	  /* Clear the data section (for possibility that we have
	     constructed type at hand). */

	  node->data = node->tag = NULL;
	  node->length = node->tag_length = 0;
      
	  /* Check whether explicit tagging is used. */
	  if (is_tagged && tagging_mode == SSH_ASN1_TAGGING_EXPLICIT)
	    {
	      tag_node = node;
	      
	      /* Set the node correctly. */
	      tag_node->class = tag_class;
	      tag_node->tag_number = tag_number;
	      tag_node->encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
	      tag_node->length_encoding = SSH_ASN1_LENGTH_DEFINITE;
	      
	      /* Create new node and zero it. */
	      node = ssh_asn1_malloc_s(context, sizeof(*node));
	      node->prev = node->next = node->child = NULL;
	      node->parent = tag_node;
	      node->data = node->tag = NULL;
	      node->length = node->length = 0;
	      
	      tag_node->child = node;
	    }
	  
	  if (is_tagged && tagging_mode == SSH_ASN1_TAGGING_IMPLICIT)
	    {
	      node->class = tag_class;
	      node->tag_number = tag_number;
	    }
	  else
	    {
	      node->class = SSH_ASN1_CLASS_UNIVERSAL;
	      node->tag_number = defs->tag_number;
	    }

	  /* Assume constructed. */
	  node->encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
	  node->length_encoding = length_encoding;
	  
	  /* Now we are ready to check whether we are dealing with
	     constructed types.
	     */
	  
	  if (child_len != 0)
	    {
	      /* Recursively build childs. */
	      if ((status =
		   ssh_asn1_create_tree_recurse(context,
						&node->child, node,
						child_ptr,
						child_len,
						ap)) != SSH_ASN1_STATUS_OK)
		return status;
	    }
	  else
	    {
	      if (defs->encode == NULL)
		{
		  break;
		}

	      /* We're dealing with definite + primitive types. This
		 over rides the length_encoding, thus we don't currently
		 allow at all indefinite encoding. */
	      node->length_encoding = SSH_ASN1_LENGTH_DEFINITE;
	      node->encoding = SSH_ASN1_ENCODING_PRIMITIVE;

	      /* Encode primitive. */
	      (*defs->encode)(context->cmalloc_context,
			      node->class, node->encoding,
			      node->tag_number, node->length_encoding,
			      &node->data, &node->length,
			      &node->tag, &node->tag_length,
			      ap);

	    }

	  break;
	default:
	  ssh_fatal("ssh_asn1_create_tree_recurse: invalid extension.");
	  break;
	}
    }

  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status ssh_asn1_create_node(SshAsn1Context context,
				   SshAsn1Node *node,
				   const char *format, ...)
{
  SshAsn1Status status;
  va_list ap;

  va_start(ap, format);

  status = ssh_asn1_create_tree_recurse(context,
					node, NULL,
					format, strlen(format),
					&ap);

  va_end(ap);

  return status;
}

SshAsn1Status ssh_asn1_create_tree(SshAsn1Context context,
				   SshAsn1Tree *tree,
				   const char *format, ...)
{
  SshAsn1Status status;
  va_list ap;
  
  /* Allocate the tree. */
  *tree = ssh_asn1_malloc_s(context, sizeof(**tree));
  (*tree)->data = NULL;
  (*tree)->length = 0;
  
  va_start(ap, format);

  /* Create nodes. */
  status = ssh_asn1_create_tree_recurse(context,
					&(*tree)->root, NULL,
					format, strlen(format),
					&ap);

  va_end(ap);

  /* Set the current position. */
  (*tree)->current = (*tree)->root;
  
  return status;
}

/* Read data from the tree. 
  */
typedef unsigned int SshAsn1Rule;
#define SSH_ASN1_RULE_SCAN_ALL 1 /* Search tagged throughout. */
#define SSH_ASN1_RULE_NO_SCAN  2 /* Don't scan just match */
#define SSH_ASN1_RULE_SCAN_FWD 3 /* Scan only forwards (from the current). */
#define SSH_ASN1_RULE_NO_MATCH 4 /* No scan and no match. */

typedef unsigned int SshAsn1Fit;
#define SSH_ASN1_FIT       1
#define SSH_ASN1_CHILD_FIT 2
#define SSH_ASN1_NO_FIT    0

SshAsn1Fit ssh_asn1_compare_fit(SshAsn1Node temp,
				Boolean is_tagged,
				SshAsn1Defs *defs, 
				SshAsn1Class tag_class,
				SshAsn1LengthEncoding length_encoding,
				SshAsn1Tag tag_number,
				SshAsn1TaggingMode tagging_mode)
{
  if (is_tagged)
    {
      if (temp->class == tag_class &&
	  temp->tag_number == tag_number &&
	  temp->length_encoding == length_encoding)
	{
	  if (tagging_mode == SSH_ASN1_TAGGING_EXPLICIT)
	    {
	      if (defs->tag_number == 0)
		return SSH_ASN1_CHILD_FIT;

	      if (temp->child->class == SSH_ASN1_CLASS_UNIVERSAL &&
		  temp->child->tag_number == defs->tag_number &&
		  temp->child->length_encoding == length_encoding)
		return SSH_ASN1_CHILD_FIT;
	    }
	  else
	    return SSH_ASN1_FIT;
	}
    }
  else
    {
      if (temp->class == SSH_ASN1_CLASS_UNIVERSAL &&
	  temp->tag_number == defs->tag_number &&
	  temp->length_encoding == length_encoding)
	return SSH_ASN1_FIT;
    }
  return SSH_ASN1_NO_FIT;
}

SshAsn1Node ssh_asn1_search_node(SshAsn1Node first, SshAsn1Node *current,
				 SshAsn1Rule rule_tagged,
				 SshAsn1Rule rule_untagged,
				 SshAsn1Defs *defs,
				 Boolean is_tagged,
				 SshAsn1Class tag_class,
				 SshAsn1LengthEncoding length_encoding,
				 SshAsn1Tag tag_number,
				 SshAsn1TaggingMode tagging_mode)
{
  SshAsn1Node temp, node;
  SshAsn1Fit fitness;
  SshAsn1Rule rule;
  
  if (is_tagged)
    rule = rule_tagged;
  else
    rule = rule_untagged;

  fitness = SSH_ASN1_NO_FIT;
  node    = NULL;
  
  switch (rule)
    {
    case SSH_ASN1_RULE_SCAN_ALL:
      /* Search for the tag. */
      temp = first;
      while (temp)
	{
	  fitness = ssh_asn1_compare_fit(temp,
					 is_tagged,
					 defs,
					 tag_class,
					 length_encoding,
					 tag_number,
					 tagging_mode);
	  if (fitness != SSH_ASN1_NO_FIT)
	    break;
	  temp = temp->next;
	}
      break;
    case SSH_ASN1_RULE_NO_MATCH:
      temp = *current;
      fitness = SSH_ASN1_FIT;
      break;
    case SSH_ASN1_RULE_NO_SCAN:
      temp = *current;
      fitness = ssh_asn1_compare_fit(temp,
				     is_tagged,
				     defs,
				     tag_class,
				     length_encoding,
				     tag_number,
				     tagging_mode);
      break;
    case SSH_ASN1_RULE_SCAN_FWD:
      temp = *current;
      while (temp)
	{
	  fitness = ssh_asn1_compare_fit(temp,
					 is_tagged,
					 defs,
					 tag_class,
					 length_encoding,
					 tag_number,
					 tagging_mode);
	  if (fitness != SSH_ASN1_NO_FIT)
	    break;
	  temp = temp->next;
	}
      break;
    default:
      return NULL;
      break;
    }

  switch (fitness)
    {
    case SSH_ASN1_FIT:
      node = temp;
      break;
    case SSH_ASN1_CHILD_FIT:
      node = temp->child;
      break;
    case SSH_ASN1_NO_FIT:
      node = NULL;
      break;
    }

  if (is_tagged == FALSE)
    *current = temp;
  
  return node;
}

SshAsn1Status ssh_asn1_read_node_recurse(SshAsn1Node first,
					 const char *format, size_t len,
					 SshAsn1Rule rule_tagged,
					 SshAsn1Rule rule_untagged,
					 Boolean for_choice,
					 unsigned int *which,
					 Boolean optional,
					 va_list *ap)
{
  SshAsn1Node current, node, *node_ptr;
  SshAsn1Status status;
  SshAsn1Defs *defs;
  size_t i;
  const char *child_ptr;
  size_t child_len;
  SshAsn1Tag tag_number;
  SshAsn1Class tag_class;
  SshAsn1LengthEncoding length_encoding;
  Boolean is_tagged, *found, opt_flag, match_defs;
  size_t step;
  unsigned int pos, *new_which;
  SshAsn1TaggingMode tagging_mode;
  
  defs = NULL;
  opt_flag = FALSE;
  
  for (i = 0, current = first, pos = 0; i < len; pos ++)
    {
      status = ssh_asn1_parse_command_lisp(&format[i], len - i,
					   &step,
					   &child_ptr,
					   &child_len,
					   &defs,
					   &length_encoding,
					   &is_tagged,
					   &tag_class,
					   &tag_number,
					   &tagging_mode,
					   &match_defs);

      if (status != SSH_ASN1_STATUS_OK)
	return status;

      /* Advance (or return to upper level). */
      if (step == 0)
	return SSH_ASN1_STATUS_OK;
      i += step;

      if (defs == NULL)
	return SSH_ASN1_STATUS_UNKNOWN_COMMAND;
      
      switch (defs->extended)
	{
	  /* This allows us to skip some arguments although they do not
	     exists. */
	case SSH_ASN1_DEFEXT_OPTIONAL:

	  found = va_arg(*ap, Boolean *);
	  
	  status = ssh_asn1_read_node_recurse(current,
					      child_ptr, child_len,
					      rule_tagged, rule_untagged,
					      for_choice,
					      which, 
					      TRUE, ap);
	  if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND)
	    {
	      *found = FALSE;
	      break;
	    }
	  if (status != SSH_ASN1_STATUS_OK)
	    return status;
	  *found = TRUE;
	  if (current)
	    current = current->next;
	  break;
	  
	  /* This allows us to select one of many easier than one could
	     without this construction. */
	case SSH_ASN1_DEFEXT_CHOICE:

	  /* Find the position indicator. */
	  new_which = va_arg(*ap, unsigned int *);
	  *new_which = 0xffffffff;
	  
	  /* Recursively determine the current node value. */
	  if ((status = ssh_asn1_read_node_recurse(current,
						   child_ptr, child_len,
						   SSH_ASN1_RULE_NO_SCAN,
						   SSH_ASN1_RULE_NO_SCAN,
						   TRUE,
						   new_which,
						   optional,
						   ap)) != SSH_ASN1_STATUS_OK)
	    return status;

	  /* Next. */
	  if (current)
	    current = current->next;
	  
	  break;
	  
	  /* Check the any type. */
	case SSH_ASN1_DEFEXT_NODE:
	  /* Get argument. */

	  if (current == NULL && !optional)
	    return SSH_ASN1_STATUS_NODE_NULL;

	  node = ssh_asn1_search_node(first, &current,
				      rule_tagged, SSH_ASN1_RULE_NO_MATCH,
				      defs,
				      is_tagged, tag_class,
				      length_encoding,
				      tag_number, tagging_mode);

	  /* We skip the argument any way. */
	  node_ptr = va_arg(*ap, SshAsn1Node *);
	  if (node != NULL)
	    {
	      /* Found a match. */
	      *node_ptr = node;
	      if (!for_choice && current)
		current = current->next;
	      if (which)
		*which = pos;
	    }
	  else
	    {
	      if ((optional && i == len && opt_flag == FALSE) ||
		  (for_choice && i == len && *which == 0xffffffff) ||
		  (!for_choice && !optional))
		return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
	    }
	  break;
	  
	  /* Usual case. */
	case SSH_ASN1_DEFEXT_NONE:
	  /* Handle case when we're over NULL node. */
	  if (current == NULL && !optional)
	    return SSH_ASN1_STATUS_NODE_NULL;

	  /* Match defs apply only in this case. */
	  if (match_defs)
	    /* This means that no checking is done for types, but
	       sometimes its an ok. */
	    node = current;
	  else
	    {
	      /* Search for tagged or next suitable. */
	      node = ssh_asn1_search_node(first, &current,
					  rule_tagged, rule_untagged, defs,
					  is_tagged, tag_class,
					  length_encoding,
					  tag_number, tagging_mode);
	    }

	  if (node == NULL && !for_choice && !optional)
	    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
	  
	  /* Now we are ready to check whether we are dealing with
	     constructed types. */
	  
	  if (child_len != 0)
	    {
	      if (node == NULL)
		{
		  if (for_choice && i == len && *which == 0xffffffff)
		    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
		  if (optional && i == len && opt_flag == FALSE)
		    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
		}
	      	      
	      /* Skip if not of correct type. */
	      if (node && node->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
		node = NULL;

	      if (node != NULL)
		{
		  if (node->tag_number == SSH_ASN1_TAG_SET ||
		      (match_defs == TRUE &&
		       defs->tag_number == SSH_ASN1_TAG_SET))
		    {
		      status =
			ssh_asn1_read_node_recurse(node->child,
						   child_ptr,
						   child_len,
						   SSH_ASN1_RULE_SCAN_ALL,
						   SSH_ASN1_RULE_SCAN_ALL,
						   FALSE,
						   NULL,
						   optional,
						   ap);
		    }
		  if (node->tag_number == SSH_ASN1_TAG_SEQUENCE ||
		      (match_defs == TRUE &&
		       defs->tag_number == SSH_ASN1_TAG_SEQUENCE))
		    {
		      status =
			ssh_asn1_read_node_recurse(node->child,
						   child_ptr,
						   child_len,
						   SSH_ASN1_RULE_SCAN_ALL,
						   SSH_ASN1_RULE_SCAN_FWD,
						   FALSE,
						   NULL,
						   optional,
						   ap);
		    }

		  /* Handle return value, with optional and choice. */
		  
		  if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND &&
		      optional)
		    {
		      if (i == len && opt_flag == FALSE)
			return status;
		      else
			continue;
		    }
		  if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND &&
		      for_choice)
		    {
		      if (i == len && *which == 0xffffffff)
			return status;
		      else
			continue;
		    }
		  if (status != SSH_ASN1_STATUS_OK)
		    return status;

		  if (which)
		    *which = pos;
		}
	      else
		continue;
	    }
	  else
	    {
	      if (node == NULL)
		{
		  (*defs->step_over)(ap);
		  
		  if (for_choice && i == len && *which == 0xffffffff)
		    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
		  if (optional && i == len && opt_flag == FALSE)
		    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
		  continue;
		}
	      
	      /* We're dealing with primitive types. */
	      if (node->encoding != SSH_ASN1_ENCODING_PRIMITIVE ||
		  node->length_encoding != SSH_ASN1_LENGTH_DEFINITE)
		{
		  (*defs->step_over)(ap);
		  continue;
		}
	      
	      if (defs->decode == NULL)
		ssh_fatal("ssh_asn1_read_node_recurse: command definition"
			  "corrupted.");

	      if (which)
		if (*which != 0xffffffff)
		  return SSH_ASN1_STATUS_CHOICE_TOO_MANY_MATCHES;
	      
	      /* Do the actual decoding. */
	      (*defs->decode)(node->data, node->length,
			      ap);

	      if (optional)
		opt_flag = TRUE;
	      
	      if (which)
		*which = pos;
	    }

	  /* Step to next in list. */
	  if (is_tagged && tagging_mode == SSH_ASN1_TAGGING_EXPLICIT)
	    {
	      if (for_choice == FALSE && node)
		current = node->parent->next;
	    }
	  else
	    {
	      if (for_choice == FALSE && node)
		current = node->next;
	    }

	  break;
	default:
	  ssh_fatal("ssh_asn1_read_tree_recurse: invalid extension.");
	  break;
	}
    }

  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status ssh_asn1_read_tree(SshAsn1Tree tree,
				 const char *format, ...)
{
  SshAsn1Status status;
  va_list ap;

  va_start(ap, format);

  /* Call with default settings. */
  status = ssh_asn1_read_node_recurse(tree->current,
				      format, strlen(format),
				      SSH_ASN1_RULE_SCAN_ALL,
				      SSH_ASN1_RULE_SCAN_FWD,
				      FALSE,
				      NULL,
				      FALSE,
				      &ap);

  va_end(ap);

  return status;
}

SshAsn1Status ssh_asn1_read_node(SshAsn1Node node,
				 const char *format, ...)
{
  SshAsn1Status status;
  va_list ap;

  va_start(ap, format);

  /* Call with default settings. */
  status = ssh_asn1_read_node_recurse(node,
				      format, strlen(format),
				      SSH_ASN1_RULE_SCAN_ALL,
				      SSH_ASN1_RULE_SCAN_FWD,
				      FALSE,
				      NULL,
				      FALSE,
				      &ap);
  va_end(ap);

  return status;
}

/*
  Searching is divided in to two phases. First tries to find just the
  _first_ node. The second then verifies if the rest of the tree matches.
 */

SshAsn1Status ssh_asn1_match_node_recurse(SshAsn1Node first,
					  const char *format, size_t len,
					  SshAsn1Rule rule_tagged,
					  SshAsn1Rule rule_untagged,
					  Boolean for_choice)
{
  SshAsn1Node current, node;
  SshAsn1Status status;
  SshAsn1Defs *defs;
  size_t i;
  const char *child_ptr;
  size_t child_len;
  SshAsn1Tag tag_number;
  SshAsn1Class tag_class;
  SshAsn1LengthEncoding length_encoding;
  Boolean is_tagged, match_defs;
  size_t step;
  SshAsn1TaggingMode tagging_mode;

  defs = NULL;
  current = first;
  
  for (i = 0, current = first; i < len;)
    {
      if (current == NULL)
	return SSH_ASN1_STATUS_MATCH_NOT_FOUND;

      status = ssh_asn1_parse_command_lisp(&format[i], len - i,
					   &step,
					   &child_ptr,
					   &child_len,
					   &defs,
					   &length_encoding,
					   &is_tagged,
					   &tag_class,
					   &tag_number,
					   &tagging_mode,
					   &match_defs);

      if (status != SSH_ASN1_STATUS_OK)
	return status;

      /* Advance (or return to upper level). */
      if (step == 0)
	return SSH_ASN1_STATUS_OK;
      i += step;

      if (defs == NULL)
	return SSH_ASN1_STATUS_UNKNOWN_COMMAND;

      switch (defs->extended)
	{
	case SSH_ASN1_DEFEXT_OPTIONAL:
	  /* This is not implemented properly! */
	  status = ssh_asn1_match_node_recurse(current,
					       child_ptr,
					       child_len,
					       SSH_ASN1_RULE_NO_SCAN,
					       SSH_ASN1_RULE_NO_SCAN,
					       TRUE);
	  if (status == SSH_ASN1_STATUS_OK)
	    {
	      if (current)
		current = current->next;
	      break;
	    }
	  if (status != SSH_ASN1_STATUS_MATCH_NOT_FOUND)
	    return status;
	  break;
	case SSH_ASN1_DEFEXT_CHOICE:
	  /* This is not implemented properly. */
	  if ((status = ssh_asn1_match_node_recurse(current,
						    child_ptr,
						    child_len,
						    SSH_ASN1_RULE_NO_SCAN,
						    SSH_ASN1_RULE_NO_SCAN,
						    TRUE))
	      != SSH_ASN1_STATUS_OK)
	    return status;
	  break;
	case SSH_ASN1_DEFEXT_NODE:

	  /* Skip this one (any) */
	  if (current)
	    current = current->next;
	  break;
	  
	case SSH_ASN1_DEFEXT_NONE:
	  
	  /* Search for tagged or next suitable. */
	  
	  node = ssh_asn1_search_node(first, &current,
				      rule_tagged,
				      rule_untagged, defs,
				      is_tagged, tag_class,
				      length_encoding,
				      tag_number, tagging_mode);
	  
	  if (node == NULL)
	    {
	      if (!for_choice || (for_choice && i == len))
		return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
	      else
		break;
	    }
	  
	  /* Now we are ready to check whether we are dealing with
	     constructed types. */
	  
	  if (child_len != 0)
	    {
	      /* Skip if not of correct type. */
	      if (node->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
		{
		  if (for_choice == FALSE || (for_choice == TRUE && i == len))
		    return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
		  else
		    break;
		}

	      if (node->tag_number == SSH_ASN1_TAG_SET)
		{
		  status = ssh_asn1_match_node_recurse(node->child,
						       child_ptr,
						       child_len,
						       SSH_ASN1_RULE_SCAN_ALL,
						       SSH_ASN1_RULE_SCAN_ALL,
						       FALSE);
		}
	      else
		{
		  status = ssh_asn1_match_node_recurse(node->child,
						       child_ptr,
						       child_len,
						       SSH_ASN1_RULE_SCAN_ALL,
						       SSH_ASN1_RULE_SCAN_FWD,
						       FALSE);
		}

	      if (status == SSH_ASN1_STATUS_MATCH_NOT_FOUND &&
		  for_choice == TRUE)
		{
		  if (i == len)
		    return status;
		  continue;
		}
	      if (status != SSH_ASN1_STATUS_OK)
		return status;
	    }
	  
	  /* Set the next. */
	  if (is_tagged && tagging_mode == SSH_ASN1_TAGGING_EXPLICIT)
	    {
	      if (for_choice == FALSE)
		current = node->parent->next;
	    }
	  else
	    {
	      if (for_choice == FALSE)
		current = node->next;
	    }

	  break;
	default:
	  ssh_fatal("ssh_asn1_match_node_recurse: invalid extension.");
	  break;
	}
    }
  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status
ssh_asn1_search_node_recurse(SshAsn1Node first,
			     SshAsn1Node *ret,
			     const char *format,
			     size_t len,
			     SshAsn1Class class,
			     SshAsn1Tag tag_number,
			     SshAsn1Encoding encoding,
			     SshAsn1LengthEncoding length_encoding)
{
  SshAsn1Node node;
  SshAsn1Status status;

  node = first;

  while (node)
    {
      /* Check if correct. */
      if (node->class == class &&
	  node->tag_number == tag_number &&
	  node->encoding == encoding &&
	  node->length_encoding == length_encoding)
	{
	  /* Try it. */
	  status = ssh_asn1_match_node_recurse(node,
					       format, len,
					       SSH_ASN1_RULE_SCAN_ALL,
					       SSH_ASN1_RULE_SCAN_FWD,
					       FALSE);
	  if (status != SSH_ASN1_STATUS_MATCH_NOT_FOUND)
	    {
	      if (status == SSH_ASN1_STATUS_OK)
		*ret = node;
	      return status;
	    }
	}

      if (node->child)
	{
	  status = ssh_asn1_search_node_recurse(node->child,
						ret, 
						format, len,
						class,
						tag_number,
						encoding,
						length_encoding);
	  if (status != SSH_ASN1_STATUS_MATCH_NOT_FOUND)
	    return status;
	}
      /* Next in the list. */
      node = node->next;
    }
  /* Did not find a match. */
  return SSH_ASN1_STATUS_MATCH_NOT_FOUND;
}

SshAsn1Status ssh_asn1_search_tree(SshAsn1Tree tree,
				   const char *format)
{
  SshAsn1Status status;
  SshAsn1Class class;
  SshAsn1Defs *defs;
  SshAsn1Tag tag_number;
  SshAsn1Encoding encoding;
  SshAsn1LengthEncoding length_encoding;
  SshAsn1TaggingMode tagging_mode;
  size_t step;
  const char *child_ptr;
  size_t child_len;
  Boolean is_tagged, match_defs;
  
  /* Read the first in the format string. */
  status = ssh_asn1_parse_command_lisp(format, strlen(format),
				       &step,
				       &child_ptr,
				       &child_len,
				       &defs,
				       &length_encoding,
				       &is_tagged,
				       &class,
				       &tag_number,
				       &tagging_mode,
				       &match_defs);

  /* Verify that we can continue searching. */
  if (status != SSH_ASN1_STATUS_OK)
    return status;
  if (step == 0)
    return SSH_ASN1_STATUS_FORMAT_STRING_TOO_SHORT;

  if (child_len != 0 || defs->encode == NULL)
    encoding = SSH_ASN1_ENCODING_CONSTRUCTED;
  else
    encoding = SSH_ASN1_ENCODING_PRIMITIVE;
  
  if (is_tagged)
    {
      status = ssh_asn1_search_node_recurse(tree->current,
					    &tree->current,
					    format, strlen(format),
					    class, tag_number,
					    encoding, length_encoding);
    }
  else
    {
      status = ssh_asn1_search_node_recurse(tree->current,
					    &tree->current,
					    format, strlen(format),
					    SSH_ASN1_CLASS_UNIVERSAL,
					    defs->tag_number, encoding,
					    length_encoding);
    }

  return status;
}

/******************* Tree handling and moving 'round ********************/

SshAsn1Tree ssh_asn1_init_tree(SshAsn1Context context,
			       SshAsn1Node root, SshAsn1Node current)
{
  SshAsn1Tree tree = ssh_asn1_malloc_s(context, sizeof(*tree));

  tree->root = root;
  tree->current = current;

  return tree;
}

void ssh_asn1_copy_tree(SshAsn1Tree dest, SshAsn1Tree src)
{
  dest->root = src->root;
  dest->current = src->current;
}

void ssh_asn1_reset_tree(SshAsn1Tree tree)
{
  tree->current = tree->root;
}

unsigned int ssh_asn1_move_forward(SshAsn1Tree tree, unsigned int n)
{
  SshAsn1Node current = tree->current;
  unsigned int moved = 0;
  
  while (current->next && moved < n)
    {
      current = current->next;
      moved++;
    }

  tree->current = current;
  
  return moved;
}

unsigned int ssh_asn1_move_backward(SshAsn1Tree tree, unsigned int n)
{
  SshAsn1Node current = tree->current;
  unsigned int moved = 0;

  while (current->prev && moved < n)
    {
      current = current->prev;
      moved++;
    }

  tree->current = current;
  
  return moved;
}

SshAsn1Status ssh_asn1_move_down(SshAsn1Tree tree)
{
  if (tree->current->child)
    {
      tree->current = tree->current->child;
      return SSH_ASN1_STATUS_OK;
    }

  return SSH_ASN1_STATUS_NO_CHILD;
}

SshAsn1Status ssh_asn1_move_up(SshAsn1Tree tree)
{
  if (tree->current->parent)
    {
      tree->current = tree->current->parent;
      return SSH_ASN1_STATUS_OK;
    }

  return SSH_ASN1_STATUS_NO_PARENT;
}

SshAsn1Node ssh_asn1_get_current(SshAsn1Tree tree)
{
  return tree->current;
}

SshAsn1Node ssh_asn1_get_root(SshAsn1Tree tree)
{
  return tree->root;
}

/* Routine for getting data out from a tree. This data must be
   first encoded. */

void ssh_asn1_get_data(SshAsn1Tree tree, unsigned char **data, size_t *length)
{
  *data = ssh_xmalloc(tree->length);
  *length = tree->length;
  memcpy(*data, tree->data, tree->length);
}

#if 0 
void ssh_asn1_get_node(SshAsn1Node node, unsigned char **data, size_t *length)
{
  *data = ssh_xmalloc(node->length + node->tag_length);
  *length = node->length + node->tag_length;
  memcpy(*data, node->tag, node->length + node->tag_length);
}
#endif

/* Direct node moving routines. */

SshAsn1Node ssh_asn1_node_next(SshAsn1Node node)
{
  if (node)
    return node->next;
  return NULL;
}

SshAsn1Node ssh_asn1_node_prev(SshAsn1Node node)
{
  if (node)
    return node->prev;
  return NULL;
}

SshAsn1Node ssh_asn1_node_parent(SshAsn1Node node)
{
  if (node)
    return node->parent;
  return NULL;
}

SshAsn1Node ssh_asn1_node_child(SshAsn1Node node)
{
  if (node)
    return node->child;
  return NULL;
}

/*********************** Insertion and deletion *********************/

void ssh_asn1_flag_changes(SshAsn1Node node)
{
  /* Flag changes to parents. */
  
  while (node)
    {
      node->data = NULL;
      node->length = 0;

      node = node->parent;
    }
}

SshAsn1Node ssh_asn1_add_list(SshAsn1Node list, SshAsn1Node node)
{
  SshAsn1Node temp;
  
  if (list == NULL)
    return node;

  if (node == NULL)
    return list;

  /* Find last. */
  temp = list;
  while (temp->next)
    temp = temp->next;

  temp->next = node;
  node->prev = temp;

  temp = node;
  while (temp)
    {
      temp->parent = list->parent;
      temp = temp->next;
    }
  ssh_asn1_flag_changes(node->parent);
  return list;
}

SshAsn1Status ssh_asn1_insert_list(SshAsn1Node before,
				   SshAsn1Node after, SshAsn1Node node)
{
  SshAsn1Node temp;
  
  if (node == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;
  
  /* Find the last in the list. */
  temp = node;
  while (temp->next)
    {
      temp = temp->next;
    }
  
  if (before)
    {
      node->prev = before;
      temp->next = before->next;

      if (before->next)
	before->next->prev = temp;
      before->next = node;

      /* Set the parent pointers. */
      temp = node;
      while (temp)
	{
	  temp->parent = before->parent;
	  temp = temp->next;
	}

      /* Flag changes... */
      ssh_asn1_flag_changes(node->parent);
      
      return SSH_ASN1_STATUS_OK;
    }
  if (after)
    {
      node->prev = after->prev;
      node->next = after;

      if (after->prev)
	after->prev->next = node;
      after->prev = temp;

      /* Set the parent pointers. */
      temp = node;
      while (temp)
	{
	  temp->parent = after->parent;
	  temp = temp->next;
	}

      /* Flag changes. */
      ssh_asn1_flag_changes(node->parent);
      
      return SSH_ASN1_STATUS_OK;
    }
  return SSH_ASN1_STATUS_NODE_NULL;
}

SshAsn1Status ssh_asn1_remove_node(SshAsn1Node node)
{
  if (node == NULL)
    return SSH_ASN1_STATUS_OK;

  /* Detach node. */
  if (node->next)
    node->next->prev = node->prev;
  if (node->prev)
    node->prev->next = node->next;

  /* Flag changes... */
  ssh_asn1_flag_changes(node);

  node->parent = NULL;
  
  return SSH_ASN1_STATUS_OK;
}

SshAsn1Status ssh_asn1_insert_subnode(SshAsn1Node base, SshAsn1Node node)
{
  SshAsn1Node temp;
  
  if (base->encoding != SSH_ASN1_ENCODING_CONSTRUCTED)
    return SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED;
  
  if (base->child)
    {
      temp = base->child;

      /* Seek the last node in the list. */
      while (temp->next)
	temp = temp->next;

      /* Insert new nodes. */
      node->prev = temp;
      temp->next = node;

      while (node)
	{
	  node->parent = base;
	  node = node->next;
	}
    }
  else
    {
      base->child = node;
      node->prev = NULL;

      while (node)
	{
	  node->parent = base;
	  node = node->next;
	}
    }

  /* Flag changes. */
  ssh_asn1_flag_changes(base->child);

  return SSH_ASN1_STATUS_OK;
}

/************* Get directly the internals of one particular node ***********/

size_t ssh_asn1_bytes_used(SshAsn1Tree tree)
{
  return ssh_asn1_count_length(tree->root);
}

SshAsn1Status ssh_asn1_node_get_data(SshAsn1Node node,
				     unsigned char **data,
				     size_t *data_len)
{
  *data = ssh_xmalloc(node->length + node->tag_length);
  memcpy(*data, node->tag, node->length + node->tag_length );
  *data_len = node->length + node->tag_length;
  return SSH_ASN1_STATUS_OK;
}

SshAsn1Node ssh_asn1_node_init(SshAsn1Context context)
{
  SshAsn1Node node;

  node = ssh_asn1_malloc_s(context, sizeof(*node));
  
  node->class      = SSH_ASN1_CLASS_UNIVERSAL;
  node->encoding   = SSH_ASN1_ENCODING_PRIMITIVE;
  node->tag_number = SSH_ASN1_TAG_RESERVED_0;
  node->length_encoding = SSH_ASN1_LENGTH_DEFINITE;
  node->prev = node->next = node->child = node->parent = NULL;
  node->length = node->tag_length = 0;
  node->data = node->tag = NULL;

  return node;
}

SshAsn1Status ssh_asn1_node_get(SshAsn1Node node,
				SshAsn1Class *class,
				SshAsn1Encoding *encoding,
				SshAsn1Tag *tag_number,
				SshAsn1LengthEncoding *length_encoding,
				size_t *length,
				unsigned char **data)
{
  if (node == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;
  
  if (class)
    *class = node->class;

  if (encoding)
    *encoding = node->encoding;

  if (tag_number)
    *tag_number = node->tag_number;

  if (length_encoding)
    *length_encoding = node->length_encoding;

  if (length)
    {
      *length = node->length;
      if (data)
	{
	  /* Copy the data. */
	  *data = ssh_xmalloc(*length);
	  memcpy(*data, node->data, *length);
	}
    }

  return SSH_ASN1_STATUS_OK;
}

int ssh_asn1_node_size(SshAsn1Node node)
{
  if (node->encoding == SSH_ASN1_ENCODING_CONSTRUCTED)
    return node->tag_length;
  return node->tag_length + node->length;
}

SshAsn1Status ssh_asn1_node_put(SshAsn1Context context,
				SshAsn1Node node,
				SshAsn1Class class,
				SshAsn1Encoding encoding,
				SshAsn1Tag tag_number,
				SshAsn1LengthEncoding length_encoding,
				size_t length,
				unsigned char *data)
{
  SshBerStatus ber_status;
  
  if (node == NULL)
    return SSH_ASN1_STATUS_NODE_NULL;

  node->class = class;
  node->encoding = encoding;
  node->tag_number = tag_number;
  node->length_encoding = length_encoding;
  node->length = length;

  node->tag_length = ssh_ber_compute_tag_length(node->class,
						node->encoding,
						node->tag_number,
						node->length_encoding,
						node->length);
  
  node->tag = ssh_asn1_malloc_b(context, node->length + node->tag_length);
  node->data = node->tag + node->tag_length;
  memcpy(node->data, data, node->length);

  /* Set tag. */
  ber_status = ssh_ber_set_tag(node->tag, node->tag_length,
			       node->class, node->encoding,
			       node->tag_number, node->length_encoding,
			       node->length);

  if (ber_status != SSH_BER_STATUS_OK)
    return SSH_ASN1_STATUS_OPERATION_FAILED;
  
  /* Flag changes... */
  ssh_asn1_flag_changes(node);

  return SSH_ASN1_STATUS_OK;
}


SshAsn1Status ssh_asn1_copy_node(SshAsn1Context context, 
                                 SshAsn1Node *node_to, 
                                 SshAsn1Node node_from)
{
  if (!node_from)
    return SSH_ASN1_STATUS_OPERATION_FAILED;

  /* Allocate new node_to to place the data to be copied. */
  *node_to = ssh_asn1_malloc_s(context, sizeof(**node_to));

  (*node_to)->next = NULL;
  (*node_to)->prev = NULL;
  (*node_to)->child = node_from->child;

  /* Copy the values from node_from to node_to.  */
  (*node_to)->class = node_from->class;
  (*node_to)->encoding = node_from->encoding;
  (*node_to)->tag_number = node_from->tag_number;
  (*node_to)->length_encoding = node_from->length_encoding;
  (*node_to)->tag_length = node_from->tag_length;
  (*node_to)->tag = node_from->tag;
  (*node_to)->length = node_from->length;
  (*node_to)->data = node_from->data;
  (*node_to)->parent = NULL;
        
  return SSH_ASN1_STATUS_OK;
}

/* Mapping between identity type name and doi identity type number */
const SshKeyword ssh_asn1_error_codes[] = {
  { "Ok", SSH_ASN1_STATUS_OK },
  { "Ok garbage at end", SSH_ASN1_STATUS_OK_GARBAGE_AT_END },
  { "Bad garbage at end", SSH_ASN1_STATUS_BAD_GARBAGE_AT_END },
  { "Operation failed", SSH_ASN1_STATUS_OPERATION_FAILED },
  { "Constructed assumed", SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED },
  { "List empty", SSH_ASN1_STATUS_LIST_EMPTY },
  { "Missing closing marker", SSH_ASN1_STATUS_MISSING_CLOSING_MARKER },
  { "Format string too short", SSH_ASN1_STATUS_FORMAT_STRING_TOO_SHORT },
  { "Unknown command", SSH_ASN1_STATUS_UNKNOWN_COMMAND },
  { "Node null", SSH_ASN1_STATUS_NODE_NULL },
  { "All null", SSH_ASN1_STATUS_ALL_NULL },
  { "No child", SSH_ASN1_STATUS_NO_CHILD },
  { "No parent", SSH_ASN1_STATUS_NO_PARENT },
  { "Ber open failed", SSH_ASN1_STATUS_BER_OPEN_FAILED },
  { "Ber step failed", SSH_ASN1_STATUS_BER_STEP_FAILED },
  { "Ber close failed", SSH_ASN1_STATUS_BER_CLOSE_FAILED },
  { "Buffer overflow", SSH_ASN1_STATUS_BUFFER_OVERFLOW },
  { "Buffer too small", SSH_ASN1_STATUS_BUFFER_TOO_SMALL },
  { "Match not found", SSH_ASN1_STATUS_MATCH_NOT_FOUND },
  { "Choice too many matches", SSH_ASN1_STATUS_CHOICE_TOO_MANY_MATCHES },
  { "Not yet implemented", SSH_ASN1_STATUS_NOT_YET_IMPLEMENTED },
  { NULL, 0 }
};

/* Convert Asn1 status code to string */
const char *ssh_asn1_error_string(SshAsn1Status status) 
{
  const char *string;

  string = ssh_find_keyword_name(ssh_asn1_error_codes, status);
  if (string == NULL)
    return "UNKNOWN CODE, update ssh_asn1_error_codes table in asn1.c";
  return string;
}

/* asn1_tree.c */

