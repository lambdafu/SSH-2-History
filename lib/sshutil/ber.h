/*

  ber.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Feb 15 20:45:13 1997 [mkojo]

  BER encoding.

  */

/*
 * $Id: ber.h,v 1.7 1998/08/04 08:22:48 vsuontam Exp $
 * $Log: ber.h,v $
 * $EndLog$
 */

#ifndef BER_H
#define BER_H

#include "asn1.h"
#include "gmp.h"
#include "cmalloc.h"

/* Status reports from BER/DER routines. */

typedef enum
{
  /* BER/DER operation succeeded as planned. */
  SSH_BER_STATUS_OK,

  /* BER/DER operation failed. */
  SSH_BER_STATUS_ERROR,
  
  /* SshBuffer contains too little space. */
  SSH_BER_STATUS_BUFFER_TOO_SMALL,
  /* SshBuffer size was too small and contained data that implied otherwise. */
  SSH_BER_STATUS_BUFFER_OVERFLOW,
  
  /* Given table is too small. */
  SSH_BER_STATUS_TABLE_TOO_SMALL,

  /* This feature is not available. */
  SSH_BER_STATUS_NOT_AVAILABLE,

  /* This method is not implemented yet in this revision. */
  SSH_BER_STATUS_NOT_IMPLEMENTED
} SshBerStatus;

/* Compute the length of tag for certain ASN.1 type. Returns bytes needed
   to encode this tag (not the contents). */

size_t ssh_ber_compute_tag_length(SshAsn1Class a_class,
				  SshAsn1Encoding encoding,
				  SshAsn1Tag tag_number,
				  SshAsn1LengthEncoding lenght_encoding,
				  size_t length);

/* Set the tag octets to the given buffer (buf). Encoding is performed
   in DER. */

SshBerStatus ssh_ber_set_tag(unsigned char *buf, size_t len,
			  SshAsn1Class a_class, SshAsn1Encoding encoding,
			  SshAsn1Tag tag_number,
			  SshAsn1LengthEncoding length_encoding,
			  size_t length);

/* Opens given buffer, if it can be understood. data will point to the
   given buffer. */

SshBerStatus ssh_ber_open_element(unsigned char *buf, size_t len,
			       SshAsn1Class *a_class,
			       SshAsn1Encoding *encoding,
			       SshAsn1Tag *tag_number,
			       SshAsn1LengthEncoding *length_encoding,
			       size_t *tag_length,
			       unsigned char **tag,
			       size_t *length,
			       unsigned char **data);

/* Return size of the ber object in the buffer. Returns 0 if the length is
   indefinite, and -1 if error (buffer too short), otherwise returns number of
   bytes used by the asn1 object. */
size_t ssh_ber_get_size(unsigned char *buf, size_t len);

/* About encoding/decoding prototypes.

   These prototypes are used by asn1_tree.c and are not intended to be used
   in general.

   Encoding routines are called with
     cmalloc context
     type's class, encoding, tag-number, length-encoding
     also with va_list containing function specific input.

     returned is
      data, length 
      tag, tag_length

   Decoding routines are called with
     data, length

     returned is
       data in pointers in va_list. Function dependend.

   */

/* This prototype is very useful, nobody wants to write this large
   prototypes ;) */
#define SSH_BER_ENCODE_PROTOTYPE(name) \
SshBerStatus ssh_ber_encode_##name(SshCMallocContext context,   \
				   SshAsn1Class a_class,          \
				   SshAsn1Encoding encoding,    \
				   SshAsn1Tag tag_number,       \
				   SshAsn1LengthEncoding length_encoding,  \
				   unsigned char **data,        \
				   size_t *length,              \
				   unsigned char **tag,         \
				   size_t *tag_length,          \
				   va_list *ap)  

/* Encoding ASN.1 BER types. */

/* Encoding boolean type. va_list contains Boolean value that is encoded.
   ap is advanced over the boolean value. */

SSH_BER_ENCODE_PROTOTYPE(boolean);
     
/* Encoding a Multiple Precision integer. va_list contains one MP_INT type
   integer. ap is advanced over the integer. If you are certain you do 
   not need big integers you can use integer-short type. See the
   description of integer-short below.*/

SSH_BER_ENCODE_PROTOTYPE(integer);

/* Encoding a bit string. va_list contains pair
   (unsigned char *buffer, size_t length) which will be encoded. ap
   is advanced over both. */

SSH_BER_ENCODE_PROTOTYPE(bit_string);

/* Encoding an octet string. va_list contains pair
   (unsigned char *buffer, size_t length) which will be encoded. ap
   is advanced over both. */

SSH_BER_ENCODE_PROTOTYPE(octet_string);

/* Encoding a null value. This is rather simple, but included here
   for completeness. va_list is ignored and ap is not advanced. */

SSH_BER_ENCODE_PROTOTYPE(null);

/* Encoding an object identifier values. va_list contains the pair
   (unsigned long *oid_table, unsigned int table_length) and is encoded.
   ap is advanced over the pair. */

SSH_BER_ENCODE_PROTOTYPE(oid_type);

/* Encoding an universal time value. va_list contains a SshBerTime *
   value. */

SSH_BER_ENCODE_PROTOTYPE(universal_time);

/* Encoding an generalized time value. va_list contains a SshBerTime *
   value. */

SSH_BER_ENCODE_PROTOTYPE(generalized_time);


/* Encoding a SshWord. va_list contains one SshWord type word.
   ap is advanced over the integer. */

SSH_BER_ENCODE_PROTOTYPE(integer_short);


/* Decoding ASN.1 BER types. */

/* Decoding a boolean value. data is decoded to va_list containing
   a (Boolean *). ap is advanced over the pointer. */

SshBerStatus ssh_ber_decode_boolean(unsigned char *data, size_t length,
				 va_list *ap);

void ssh_ber_step_boolean(va_list *ap);

/* Decoding an integer (multiple precision) value. data is decoded to
   a (MP_INT *). ap is advaned over the pointer. */

SshBerStatus ssh_ber_decode_integer(unsigned char *data, size_t length,
				 va_list *ap);


void ssh_ber_step_integer(va_list *ap);

/* Decoding a bit string. data is decoded to the pair
   (unsigned char **, unsigned int *) from the va_list. ap is advanced over
   those pointers. */
     
SshBerStatus ssh_ber_decode_bit_string(unsigned char *data, size_t length,
				    va_list *ap);

void ssh_ber_step_bit_string(va_list *ap);

/* Decoding a octet string. data is decoded to pair (unsigned char **,
   size_t *) from the va_list. ap is advaned over those pointers. */

SshBerStatus ssh_ber_decode_octet_string(unsigned char *data, size_t length,
				      va_list *ap);

void ssh_ber_step_octet_string(va_list *ap);

/* Decoding a null value. This is a bit simple, but included here
   for completeness. va_list is ignored. */
     
SshBerStatus ssh_ber_decode_null(unsigned char *data, size_t length,
				 va_list *ap);

void ssh_ber_step_null(va_list *ap);

/* Decoding a object identifier values. data is decoded to the pair
   (unsigned long **, unsigned int *). ap is advanced over those pointers. */

SshBerStatus ssh_ber_decode_oid_type(unsigned char *data, size_t length,
				  va_list *ap);

void ssh_ber_step_oid_type(va_list *ap);

/* Decoding an universal time value. data is decoded into SshBerTime *. */

SshBerStatus ssh_ber_decode_universal_time(unsigned char *data, size_t length,
					   va_list *ap);

void ssh_ber_step_universal_time(va_list *ap);

/* Decoding a generalized time value. data is decoded into SshBerTime *. */

SshBerStatus ssh_ber_decode_generalized_time(unsigned char *data,
					     size_t length,
					     va_list *ap);

void ssh_ber_step_generalized_time(va_list *ap);


/* Decoding an integer_short (SshWord) value. data is decoded to
   a (SshWord *). ap is advaned over the pointer. */

SshBerStatus ssh_ber_decode_integer_short(unsigned char *data, size_t length,
				 va_list *ap);


void ssh_ber_step_integer_short(va_list *ap);


#endif /* BER_H */
