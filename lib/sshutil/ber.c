/*

  ber.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Feb 12 17:53:54 1997 [mkojo]

  Coding rules for BER/DER.

  */

/*
 * $Id: ber.c,v 1.16 1998/08/06 12:11:56 tmo Exp $
 * $Log: ber.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "ber.h"
#include "asn1.h"
#include "gmp.h"

/* Routines for BER time.

   This does not handle local and GMT times correctly if intertwined!
 */

int ssh_ber_time_cmp(SshBerTime *a, SshBerTime *b)
{
  /* Brute force attack to date comparison. Note that this is not exactly
     correct. */
  
  if (a->year > b->year)
    return 1;
  if (a->year < b->year)
    return -1;

  if (a->month > b->month)
    return 1;
  if (a->month < b->month)
    return -1;

  if (a->day > b->day)
    return 1;
  if (a->day < b->day)
    return -1;
  
  if (a->hour > b->hour)
    return 1;
  if (a->hour < b->hour)
    return -1;

  if (a->minute > b->minute)
    return 1;
  if (a->minute < b->minute)
    return -1;

  if (a->second > b->second)
    return 1;
  if (a->second < b->second)
    return -1;

  return 0;
}

void ssh_ber_time_set(SshBerTime *x, SshBerTime *v)
{
  /* Lets do it manually, its more fun this way. */
  x->year = v->year;
  x->month = v->month;
  x->day = v->day;
  x->hour = v->hour;
  x->minute = v->minute;
  x->second = v->second;
  x->local = v->local;
  x->absolute_hours = v->absolute_hours;
  x->absolute_minutes = v->absolute_minutes;
}

void ssh_ber_time_set_from_unix_time(SshBerTime *ber_time,
				     time_t unix_time)
{
  struct tm *t;

  t = gmtime(&unix_time);

  ber_time->year = t->tm_year + 1900;
  ber_time->month = t->tm_mon + 1;
  ber_time->day = t->tm_mday;
  ber_time->hour = t->tm_hour;
  ber_time->minute = t->tm_min;
  ber_time->second = t->tm_sec;
  ber_time->local = TRUE;
  ber_time->absolute_hours = 0;
  ber_time->absolute_minutes = 0;
}

void ssh_ber_time_intersect(SshBerTime *not_before,
			    SshBerTime *not_after,
			    SshBerTime *start, SshBerTime *end,
			    SshBerTime **min_start,
			    SshBerTime **min_end)
{
  if (ssh_ber_time_cmp(not_before, start) >= 0)
    *min_start = not_before;
  else
    *min_start = start;
  if (ssh_ber_time_cmp(not_after, end) >= 0)
    *min_end = end;
  else
    *min_end = not_after;
}

Boolean ssh_ber_time_set_from_string(SshBerTime *b, char *str)
{
  size_t i;
  char month[4], day_postfix[4];
  unsigned int year, day, hour, minute, second, rv;
  const char *months[13] =
  { "n/a", "jan", "feb", "mar", "apr",
    "may", "jun", "jul", "aug",
    "sep", "oct", "nov", "dec" };

  if (strlen(str) > 1024)
    return FALSE;
  
  rv = sscanf(str, "%04d %3s %2d%2s, %02d:%02d:%02d",
	      &year, month, &day, day_postfix,
	      &hour, &minute, &second);

  if (rv != 7)
    return FALSE;

  for (i = 0; i < strlen(month); i++)
    month[i] = tolower(month[i]);
  
  for (i = 1; i < 13; i++)
    {
      if (strcmp(month, months[i]) == 0)
	break;
    }
  if (i >= 13)
    return FALSE;

  /* This is just knit picking? */
  if ((day % 10) == 1 && strcmp(day_postfix, "st") != 0)
    return FALSE;
  if ((day % 10) == 2 && strcmp(day_postfix, "nd") != 0)
    return FALSE;
  if ((day % 10) == 3 && strcmp(day_postfix, "rd") != 0)
    return FALSE;
  if (((day % 10) > 3  || (day % 10) == 0) &&  strcmp(day_postfix, "th") != 0)
    return FALSE;

  if (day < 1 || day > 31)
    return FALSE;
  if (hour < 0 || hour > 23)
    return FALSE;
  if (minute < 0 || minute > 59)
    return FALSE;
  if (second < 0 || second > 59)
    return FALSE;
  
  /* Set up the Ber time. */
  b->year   = year;
  b->month  = i;
  b->day    = day;
  b->hour   = hour;
  b->minute = minute;
  b->second = second;
  b->local  = TRUE;
  b->absolute_hours = 0;
  b->absolute_minutes = 0;

  return 1;
}

void ssh_ber_time_to_string(SshBerTime *b, char **str)
{
  const char *months[13] =
  { "n/a", "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec" };
  char *day_postfix = "  ";
  char buffer[64];
  
  if ((b->day % 10) == 1)
    day_postfix = "st";
  if ((b->day % 10) == 2)
    day_postfix = "nd";
  if ((b->day % 10) == 3)
    day_postfix = "rd";
  if ((b->day % 10) > 3 || (b->day % 10) == 0)
    day_postfix = "th";

  if (b->month < 1 || b->month > 12)
    {
      *str = NULL;
      return;
    }
  
  /* Assume GMT. */
  snprintf(buffer, sizeof(buffer), "%04d %s %2d%s, %02d:%02d:%02d GMT",
	 b->year, months[b->month],
	 b->day, day_postfix,
	 b->hour, b->minute, (unsigned int)b->second);

  /* Do a copy. */
  *str = ssh_xstrdup(buffer);
}

void ssh_ber_time_zero(SshBerTime *ber_time)
{
  ber_time->year   = 0;
  ber_time->month  = 0;
  ber_time->day    = 0;
  ber_time->hour   = 0;
  ber_time->minute = 0;
  ber_time->second = 0.0;
  ber_time->local  = FALSE;
  ber_time->absolute_hours   = 0;
  ber_time->absolute_minutes = 0;
}

Boolean ssh_ber_time_available(SshBerTime *ber_time)
{
  if (ber_time->month != 0)
    return TRUE;
  return FALSE;
}

/* This could be written more clearly. */

size_t ssh_ber_compute_tag_length(SshAsn1Class a_class,
				  SshAsn1Encoding encoding,
				  SshAsn1Tag tag_number,
				  SshAsn1LengthEncoding length_encoding,
				  size_t length)
{
  size_t tag_len;

  /* The identifier octet */
  tag_len = 1;

  /* Compute the length needed by tag_number */
  if (tag_number >= 0x1f)
    {
      while (tag_number)
	{
	  tag_len++;
	  tag_number >>= 7;
	}
    }

  /* Compute the space taken by length from the tag area. */

  if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
    {
      if (length < 0x80)
	{
	  /* Short form */
	  tag_len ++;
	}
      else
	{
	  /* The long form. */
	  tag_len ++;
	  
	  while (length)
	    {
	      length >>= 8;
	      tag_len++;
	    }
	}
    }
  else
    {
      /* Indefinite length */
      tag_len++;
    }
  return tag_len;
}

SshBerStatus ssh_ber_set_tag(unsigned char *buf, size_t len,
			     SshAsn1Class a_class, SshAsn1Encoding encoding,
			     SshAsn1Tag tag_number,
			     SshAsn1LengthEncoding length_encoding,
			     size_t length)     
{
  size_t buf_pos;
  unsigned int i, mask, shift;
  
  if (ssh_ber_compute_tag_length(a_class, encoding, tag_number, length_encoding,
			     length) > len)
    {
      return SSH_BER_STATUS_BUFFER_TOO_SMALL;
    }

  buf_pos = 0;
  
  /* Set class and encoding bit fields */
  buf[buf_pos] = (a_class << 6) | (encoding << 5);

  /* Set tag */
  if (tag_number < 0x1f)
    {
      buf[buf_pos] |= tag_number;
      buf_pos++;
    }
  else
    {
      buf[buf_pos] |= 31;
      buf_pos++;
      
      /* Count length for the tag_number */
      for (i = 0, mask = tag_number; mask; mask >>= 7, i++)
	;
      
      for (i--, shift = i * 7; i; i--, shift -= 7, buf_pos++)
	{
	  buf[buf_pos] = 0x80 | ((tag_number >> shift) & 0x7f);
	}

      buf[buf_pos] = tag_number & 0x7f;
      buf_pos++;
    }
  
  /* Encode the length value. */

  if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
    {
      if (length < 0x80)
	{
	  /* Short form. */
	  buf[buf_pos] = length;
	  buf_pos++;
	}
      else
	{
	  for (i = 0, mask = length; mask; mask >>= 8, i++)
	    ;

	  buf[buf_pos] = 0x80 | i;
	  buf_pos++;

	  for (shift = (i - 1) * 8; i; i--, shift -= 8, buf_pos++)
	    {
	      buf[buf_pos] = (length >> shift) & 0xff;
	    }
	}
    }
  else
    {
      /* Indefinite length encoding. */
      buf[buf_pos] = 0x80;
      buf_pos++;
    }

  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_open_element(unsigned char *buf, size_t len,
				  SshAsn1Class *a_class,
				  SshAsn1Encoding *encoding,
				  SshAsn1Tag *tag_number,
				  SshAsn1LengthEncoding *length_encoding,
				  size_t *tag_length,
				  unsigned char **tag,
				  size_t *length,
				  unsigned char **data)
{
  size_t buf_pos;
  unsigned int i;
  
  /* Get class and encoding. */

  if (len == 0)
    return SSH_BER_STATUS_BUFFER_OVERFLOW;

  buf_pos = 0;
  
  *a_class = (buf[buf_pos] >> 6) & 0x3;
  *encoding = (buf[buf_pos] >> 5) & 0x1;

  /* Get tag number. */

  if ((buf[buf_pos] & 0x1f) != 0x1f)
    {
      *tag_number = buf[buf_pos] & 0x1f;
      buf_pos++;
    }
  else
    {
      buf_pos++;

      /* Read 7-bit 'windows' of the tag number. */
      *tag_number = 0;
      while ((buf[buf_pos] & 0x80) != 0 && buf_pos < len)
	{
	  *tag_number = (*tag_number << 7) | (buf[buf_pos] & 0x7f);
	  buf_pos++;
	}

      if (buf_pos >= len)
	return SSH_BER_STATUS_BUFFER_OVERFLOW;
      
      /* Read also the last length 7-bit part. */
      *tag_number = (*tag_number << 7) | (buf[buf_pos] & 0x7f);
      buf_pos++;      
    }

  if (buf_pos >= len)
    return SSH_BER_STATUS_BUFFER_OVERFLOW;

  /* Get length of the contents. */

  if (!(buf[buf_pos] & 0x80))
    {
      /* Short form definite. */
      *length = buf[buf_pos] & 0x7f;
      *length_encoding = SSH_ASN1_LENGTH_DEFINITE;
      buf_pos++;
    }
  else
    {
      if (buf[buf_pos] & 0x7f)
	{
	  /* Long form definite. */

	  i = buf[buf_pos] & 0x7f;
	  buf_pos++;

	  for (*length = 0; i && buf_pos < len; i--)
	    {
	      *length = ((*length) << 8) | buf[buf_pos];
	      buf_pos++;
	    }

	  if (i)
	    return SSH_BER_STATUS_BUFFER_OVERFLOW;

	  *length_encoding = SSH_ASN1_LENGTH_DEFINITE;
	}
      else
	{
	  /* Indefinite form. */
	  *length = 0;
	  *length_encoding = SSH_ASN1_LENGTH_INDEFINITE;
	  buf_pos++;
	}
    }
  if (*length + buf_pos > len)
    return SSH_BER_STATUS_BUFFER_OVERFLOW;

  *tag = buf;
  *tag_length = buf_pos;

  *data = buf + buf_pos;

  return SSH_BER_STATUS_OK;
}

/* Return size of the ber object in the buffer. Returns 0 if the length is
   indefinite, and -1 if error (buffer too short), otherwise returns number of
   bytes used by the asn1 object. */
size_t ssh_ber_get_size(unsigned char *buf, size_t len)
{
  size_t buf_pos;
  
  if (len == 0)
    return -1;

  buf_pos = 0;

  /* Skip tag number. */
  if ((buf[buf_pos] & 0x1f) != 0x1f)
    buf_pos++;
  else
    {
      buf_pos++;

      while ((buf[buf_pos] & 0x80) != 0 && buf_pos < len)
	buf_pos++;

      if (buf_pos >= len)
	return -1;
      buf_pos++;      
    }

  if (buf_pos >= len)
    return -1;

  /* Get length of the contents. */
  if (!(buf[buf_pos] & 0x80))
    {
      /* Short form definite. */
      return (buf[buf_pos] & 0x7f) + buf_pos + 1;
    }
  if (buf[buf_pos] & 0x7f)
    {
      size_t length;
      unsigned int i;
      
      /* Long form definite. */
      i = buf[buf_pos] & 0x7f;
      buf_pos++;
      
      for (length = 0; i && buf_pos < len; i--)
	{
	  length = ((length) << 8) | buf[buf_pos];
	  buf_pos++;
	}
      
      if (i)
	return -1;
      return length + buf_pos;
    }

  /* Indefinite form. */
  return 0;
}

#if 0

/* Following code is not used... */

SshBerStatus ssh_ber_close_element(unsigned char *buf, size_t len,
				   SshAsn1Class a_class,
				   SshAsn1Encoding encoding,
				   SshAsn1Tag tag_number,
				   SshAsn1LengthEncoding length_encoding,
				   size_t length,
				   unsigned char *data)
{
  size_t buf_pos;
  unsigned int i, shift, mask;
  
  if (ssh_ber_compute_tag_length(a_class, encoding, tag_number, length_encoding,
			     length) + length > len)
    return SSH_BER_STATUS_BUFFER_TOO_SMALL;

  buf_pos = 0;
  
  /* Set class and encoding bit fields */
  buf[buf_pos] = (a_class << 6) | (encoding << 5);

  /* Set tag */
  if (tag_number < 0x1f)
    {
      buf[buf_pos] |= tag_number;
      buf_pos++;
    }
  else
    {
      buf[buf_pos] |= 31;
      buf_pos++;
      
      /* Count length for the tag_number */
      for (i = 0, mask = tag_number; mask; mask >>= 7, i++)
	;
      
      for (i--, shift = i * 7; i; i--, shift -= 7, buf_pos++)
	{
	  buf[buf_pos] = 0x80 | ((tag_number >> shift) & 0x7f);
	}

      buf[buf_pos] = tag_number & 0x7f;
      buf_pos++;
    }
  
  /* Encode the length value. */

  if (length_encoding == SSH_ASN1_LENGTH_DEFINITE)
    {
      if (length < 0x80)
	{
	  /* Short form. */
	  buf[buf_pos] = length;
	  buf_pos++;
	}
      else
	{
	  for (i = 0, mask = length; mask; mask >>= 8, i++)
	    ;

	  buf[buf_pos] = 0x80 | i;
	  buf_pos++;

	  for (shift = (i - 1) * 8; i; i--, shift -= 8, buf_pos++)
	    {
	      buf[buf_pos] = (length >> shift) & 0xff;
	    }
	}
    }
  else
    {
      /* Indefinite length encoding. */
      buf[buf_pos] = 0x80;
      buf_pos++;
    }
  
  /* Set the BER encoded data. */
  if (length <= len - buf_pos)
    memcpy(buf + buf_pos, data, length);

  return SSH_BER_STATUS_OK;
}

/* These can be implemented with open and close functions easily. */

SshBerStatus ssh_ber_step_over_tag(unsigned char *buf, size_t len,
				   size_t *step_length)
{
  SshBerStatus status;
  SshAsn1Class a_class;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  size_t length;
  unsigned char *data;

  if ((status = ssh_ber_open_element(buf, len, &a_class, &encoding, &tag_number,
				     &length_encoding, &length, &data))
      != SSH_BER_STATUS_OK)
    return status;

  *step_length = (size_t)(data - buf);
  
  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_step_over_element(unsigned char *buf, size_t len,
				       size_t *step_length)
{
  SshBerStatus status;
  SshAsn1Class a_class;
  SshAsn1Encoding encoding;
  SshAsn1Tag tag_number;
  SshAsn1LengthEncoding length_encoding;
  size_t length;
  unsigned char *data;

  if ((status = ssh_ber_open_element(buf, len, &a_class, &encoding, &tag_number,
				     &length_encoding,
				     &length, &data)) != SSH_BER_STATUS_OK)
    return status;

  *step_length = (size_t)(data - buf) + length;
  
  return SSH_BER_STATUS_OK;
}

#endif

/* These pieces of code are used extensively in encoding, thus making them
   macros make the code a bit easier to write. If these are a problem,
   then perhaps some changes should be made... */

#define ALLOCATE_ENCODE                                             \
  /* Compute the length of the tag. */                              \
  *tag_length = ssh_ber_compute_tag_length(a_class, encoding,         \
				           tag_number, length_encoding, \
				           *length);                \
  /* Allocate space for the BER encoded data. */                    \
  *tag = ssh_cmalloc_b(context, (*length) + (*tag_length));         \
  *data = (*tag) + (*tag_length);

#define EXIT_ENCODE                                                 \
  /* Set the tag. */                                                \
  return ssh_ber_set_tag(*tag, *tag_length,                         \
		         a_class, encoding, tag_number, length_encoding,  \
		         *length);

/* Encode types. These functions handle only primitive encodings. For
   constructed you have to build upper-level logic. */

SSH_BER_ENCODE_PROTOTYPE(boolean)
{
  Boolean bool = va_arg(*ap, Boolean);
  
  /* The length of contents. */
  *length = 1;

  ALLOCATE_ENCODE;
  
  (*data)[0] = ((bool) == TRUE) ? 0xff : 0;

  EXIT_ENCODE;
}

void ssh_ber_step_boolean(va_list *ap)
{
  if (va_arg(*ap, Boolean))
    ;
}

SSH_BER_ENCODE_PROTOTYPE(integer)
{
  MP_INT temp, *integer = va_arg(*ap, MP_INT *);
  unsigned int i, byte;

  if (mpz_cmp_ui(integer, 0) < 0)
    {
      /* Negative integer */

      /* Init temporary variable. */
      mpz_init_set_ui(&temp, 0);

      /* Change sign. */
      mpz_sub(&temp, &temp, integer);

      /* Subtract by 1. Now we have the value in two's complementary form
	 but don't yet know where the highest bit will be. */
      mpz_sub_ui(&temp, &temp, 1);

      /* Compute the actual length of the BER encoded integer (it is also
	 DER encoded).

	 Problem here is that negative integer -128 is represented
	 as 0x80 and positive integer 128 is represented as 0x0080.
	 This code solves this dilemma with checking that whether the
	 highest bit will be one. */
      *length = mpz_sizeinbase(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
	{
	  *length = (*length + 7) / 8;
	  *length += 1;
	}
      else
	{
	  *length = (*length + 7) / 8;
	}

      ALLOCATE_ENCODE;
      
      /* Now build up the octet representation of the integer. Assuming
	 that we have the highest bit set. */

      /* Do it the slow way (octet at a time). We supposedly are in no
	 hurry. */
      for (i = 0; i < *length; i++)
	{
	  byte = mpz_get_ui(&temp);
	  (*data)[*length - 1 - i] = (~byte & 0xff);
	  mpz_div_2exp(&temp, &temp, 8);
	}

      /* We now have valid integer encoded in BER. */

      mpz_clear(&temp);
    }
  else
    {
      /* Positive integer case (which thank fully is somewhat easier). */

      mpz_init_set(&temp, integer);

      /* Get length. */
      *length = mpz_sizeinbase(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
	{
	  *length = (*length + 7) / 8;
	  *length += 1;
	}
      else
	{
	  *length = (*length + 7) / 8;
	}

      ALLOCATE_ENCODE;
      
      /* Encode it as negative (but don't compute one's complement). */
      for (i = 0; i < *length; i++)
	{
	  byte = mpz_get_ui(&temp);
	  (*data)[*length - 1 - i] = (byte & 0xff);
	  mpz_div_2exp(&temp, &temp, 8);
	}

      /* BER encoding ready. */
      mpz_clear(&temp);
    }

  EXIT_ENCODE;
}

void ssh_ber_step_integer(va_list *ap)
{
  if (va_arg(*ap, MP_INT *))
    ;
}

SSH_BER_ENCODE_PROTOTYPE(bit_string)
{
  unsigned char *bit_string;
  size_t bit_length;

  bit_string = va_arg(*ap, unsigned char *);
  bit_length = va_arg(*ap, size_t);
  
  /* Assuming the bit_length is in bits. */
  *length = (bit_length + 7) / 8;

  /* Add also the octet to represent the padding length. */
  (*length)++;

  ALLOCATE_ENCODE;

  /* Set the padding length. What this does is to compute how many unused
     bits are there in the last octet. */
  (*data)[0] = (8 - (bit_length & 7)) & 7;

  if (*length != 0)
    {
      /* Copy the rest of the bit string. */
      memcpy(*data + 1, bit_string, *length - 2);

      /* Set the last octet here, because we cannot be sure that the
	 original has all the bits zeroed. */
      (*data)[*length - 1] =
	bit_string[*length - 2] & ((0xff << (*data)[0]) & 0xff);
    }

  EXIT_ENCODE;
}

void ssh_ber_step_bit_string(va_list *ap)
{
  if (va_arg(*ap, unsigned char *))
    ;
  if (va_arg(*ap, size_t))
    ;
}

SSH_BER_ENCODE_PROTOTYPE(octet_string)
{
  unsigned char *octet_string;
  size_t octet_length;

  octet_string = va_arg(*ap, unsigned char *);
  octet_length = va_arg(*ap, size_t);
  
  /* Do a simple copy. */
  *length = octet_length;

  ALLOCATE_ENCODE;

  memcpy(*data, octet_string, octet_length);  

  EXIT_ENCODE;
}

void ssh_ber_step_octet_string(va_list *ap)
{
  if (va_arg(*ap, unsigned char *))
    ;
  if (va_arg(*ap, size_t))
    ;
}

SSH_BER_ENCODE_PROTOTYPE(null)
{
  *length = 0;

  ALLOCATE_ENCODE;
  EXIT_ENCODE;
}

void ssh_ber_step_null(va_list *ap)
{
  /* Do nothing. */
}

SSH_BER_ENCODE_PROTOTYPE(oid_type)
{
  unsigned long *oid_table;
  size_t oid_table_len;
  unsigned int i, j, buf_pos, shift;
  unsigned long value;

  /* Get oid table and length. */
  oid_table = va_arg(*ap, unsigned long *);
  oid_table_len = va_arg(*ap, size_t);
  
  if (oid_table_len < 2)
    return SSH_BER_STATUS_TABLE_TOO_SMALL;

  /* Minimum length for OID is 1 octet (atleast this implementation assumes
     this XXX). */
  *length = 1;
  
  /* Count the length needed for Object Identifier Value */
  for (i = 2; i < oid_table_len; i++)
    {
      if (oid_table[i] == 0)
	{
	  (*length)++;
	}
      else
	{
	  for (value = oid_table[i]; value; value >>= 7, (*length)++)
	    ;
	}
    }

  ALLOCATE_ENCODE;  

  /* Set the first octet. */
  (*data)[0] = oid_table[0] * 40 + oid_table[1];

  for (i = 2, buf_pos = 1; i < oid_table_len; i++)
    {
      if (oid_table[i] == 0)
	{
	  (*data)[buf_pos] = 0x0;
	  buf_pos++;
	}
      else
	{
      	  /* Count length for the tag_number, this is similar to the
	     insertion of tag numbers. */
	  for (j = 0, value = oid_table[i]; value; value >>= 7, j++)
	    ;
	  
	  for (j--, shift = j * 7; j; j--, shift -= 7, buf_pos++)
	    {
	      (*data)[buf_pos] = 0x80 | ((oid_table[i] >> shift) & 0x7f);
	    }

	  (*data)[buf_pos] = (oid_table[i] & 0x7f);
	  buf_pos++;
	}
    }

  EXIT_ENCODE;
}

void ssh_ber_step_oid_type(va_list *ap)
{
  if (va_arg(*ap, unsigned long *))
    ;
  if (va_arg(*ap, size_t))
    ;
}

/* Following are not implemented. */

SSH_BER_ENCODE_PROTOTYPE(ode_type)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(eti_type)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(real)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(embedded)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(universal_time)
{
  SshBerTime *time = va_arg(*ap, SshBerTime *);
  char buffer[128];
  size_t len;
  
  /* Encode into a octet string. This is not yet a final version, but allows
     me to use UTCTime encodings. XXX */
  snprintf(buffer, 128,
	   "%02d"  /* year */
	   "%02d"  /* month */
	   "%02d"  /* day */
	   "%02d"  /* hour */
	   "%02d"  /* minute */
	   "%02d", /* second */
	   time->year % 100,
	   time->month, time->day,
	   time->hour, time->minute, (unsigned int)time->second);

  len = strlen(buffer);
  
  if (time->absolute_hours)
    snprintf(buffer + len, 128 - len,
	     "%c"    /* local difference */
	     "%02d"  /* hours */
	     "%02d", /* minutes */
	     (time->local == TRUE ? '+' : '-'),
	     time->absolute_hours, time->absolute_minutes);
  else
    snprintf(buffer + len, 128 - len,
	     "Z");

  *length = strlen(buffer);
  ALLOCATE_ENCODE;

  memcpy(*data, buffer, *length);
  
  EXIT_ENCODE;
}

void ssh_ber_step_universal_time(va_list *ap)
{
  if (va_arg(*ap, SshBerTime *))
    ;
}

SSH_BER_ENCODE_PROTOTYPE(generalized_time)
{
  SshBerTime *time = va_arg(*ap, SshBerTime *);
  char buffer[128];
  
  /* Encode into a octet string. This is not yet a final version, but allows
     me to use GeneralizedTime encodings. XXX */
  snprintf((char *) buffer, 128,
	   "%04d"  /* year */
	   "%02d"  /* month */
	   "%02d"  /* day */
	   "%02d"  /* hour */
	   "%02d"  /* minute */
	   "%02d"  /* second */
	   "Z",
	   time->year,
	   time->month, time->day,
	   time->hour, time->minute, (unsigned int)time->second);  

  *length = strlen((char *) buffer);
  ALLOCATE_ENCODE;

  memcpy(*data, buffer, *length);

  EXIT_ENCODE;
}

void ssh_ber_step_generalized_time(va_list *ap)
{
  if (va_arg(*ap, SshBerTime *))
    ;
}


SSH_BER_ENCODE_PROTOTYPE(integer_short)
{
  MP_INT temp;

  SshWord word = va_arg(*ap, SshWord);
  unsigned int i, byte;

  /* Init temporary variable. */
  mpz_init(&temp);
  mpz_set_ui(&temp, word);

  if (mpz_cmp_ui(&temp, 0) < 0)
    {
      /* Negative integer */
      
      /* Change sign. */
      mpz_neg(&temp, &temp);
     
      /* Subtract by 1. Now we have the value in two's complementary form
	 but don't yet know where the highest bit will be. */
      mpz_sub_ui(&temp, &temp, 1);

      /* Compute the actual length of the BER encoded integer (it is also
	 DER encoded).

	 Problem here is that negative integer -128 is represented
	 as 0x80 and positive integer 128 is represented as 0x0080.
	 This code solves this dilemma with checking that whether the
	 highest bit will be one. */
      *length = mpz_sizeinbase(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
	{
	  *length = (*length + 7) / 8;
	  *length += 1;
	}
      else
	{
	  *length = (*length + 7) / 8;
	}

      ALLOCATE_ENCODE;
      
      /* Now build up the octet representation of the integer. Assuming
	 that we have the highest bit set. */

      /* Do it the slow way (octet at a time). We supposedly are in no
	 hurry. */
      for (i = 0; i < *length; i++)
	{
	  byte = mpz_get_ui(&temp);
	  (*data)[*length - 1 - i] = (~byte & 0xff);
	  mpz_div_2exp(&temp, &temp, 8);
	}

      /* We now have valid integer encoded in BER. */

      mpz_clear(&temp);
    }
  else
    {
      /* Positive integer case (which thank fully is somewhat easier). */

      /* Get length. */
      *length = mpz_sizeinbase(&temp, 2);

      /* If highest byte is set then add one new byte. */
      if ((*length & 7) == 0)
	{
	  *length = (*length + 7) / 8;
	  *length += 1;
	}
      else
	{
	  *length = (*length + 7) / 8;
	}

      ALLOCATE_ENCODE;
      
      /* Encode it as negative (but don't compute one's complement). */
      for (i = 0; i < *length; i++)
	{
	  byte = mpz_get_ui(&temp);
	  (*data)[*length - 1 - i] = (byte & 0xff);
	  mpz_div_2exp(&temp, &temp, 8);
	}

      /* BER encoding ready. */
      mpz_clear(&temp);
    }

  EXIT_ENCODE;
}

void ssh_ber_step_integer_short(va_list *ap)
{
  if (va_arg(*ap, SshWord *))
    ;
}


/* Prototype to ease writing redundant code, this need not be used... */
#define SSH_BER_DECODE_PROTOTYPE(name) \
SshBerStatus ssh_ber_decode_##name(unsigned char *data, size_t length, \
				   va_list *ap)

/* Decode BER encodings. Decoded values are probably used by some
   application and thus cannot be allocated with cmalloc, we use directly
   the ssh_xmalloc procedure. */

SshBerStatus ssh_ber_decode_boolean(unsigned char *data, size_t length,
				    va_list *ap)
{
  Boolean *boolean = va_arg(*ap, Boolean *);
  
  if (length != 1)
    return SSH_BER_STATUS_NOT_AVAILABLE;

  boolean[0] = (data[0] ? TRUE : FALSE);

  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_integer(unsigned char *data, size_t length,
				    va_list *ap)
{
  MP_INT temp, *integer = va_arg(*ap, MP_INT *);
  unsigned int i;
  
  if (data[0] & 0x80)
    {
      /* Negative integer. */
      mpz_set_ui(integer, 0);
      
      for (i = 0; i < length; i++)
	{
	  mpz_mul_2exp(integer, integer, 8);
	  mpz_add_ui(integer, integer, (~data[i] & 0xff));
	}

      /* Set the correct value (not the best way probably). */
      mpz_init_set_ui(&temp, 0);
      mpz_add_ui(integer, integer, 1);
      mpz_sub(integer, &temp, integer);
      mpz_clear(&temp);
    }
  else
    {
      /* Positive integer. */
      mpz_set_ui(integer, 0);

      /* This is rather simple (without one's complement compared to
	 negative case. */
      for (i = 0; i < length; i++)
	{
	  mpz_mul_2exp(integer, integer, 8);
	  mpz_add_ui(integer, integer, (data[i] & 0xff));
	}
    }
  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_bit_string(unsigned char *data, size_t length,
				       va_list *ap)
{
  unsigned char **bit_string;
  size_t *bit_length;

  /* Get bit string. */
  bit_string = va_arg(*ap, unsigned char **);
  bit_length = va_arg(*ap, size_t *);

  if (length == 0)
    return SSH_BER_STATUS_ERROR;

  /* Compute bit length of the bit string. */
  *bit_length = (length - 1) * 8 - data[0];

  /* Allocate the bit string. */
  *bit_string = ssh_xmemdup(data + 1, length - 1);
  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_octet_string(unsigned char *data, size_t length,
					 va_list *ap)
{
  unsigned char **octet_string;
  size_t *octet_length;

  /* Get the octet string pointers. */
  octet_string = va_arg(*ap, unsigned char **);
  octet_length = va_arg(*ap, size_t *);
  
  /* Do a simple copy. */
  if (length)
    {
      *octet_string = ssh_xmemdup(data, length);
      *octet_length = length;
    }
  else
    {
      *octet_string = NULL;
      *octet_length = 0;
    }
  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_null(unsigned char *buf, size_t length,
			  va_list *ap)
{
  if (length == 0)
    return SSH_BER_STATUS_OK;

  return SSH_BER_STATUS_NOT_AVAILABLE;
}

SshBerStatus ssh_ber_decode_oid_type(unsigned char *data, size_t length,
				     va_list *ap)
{
  unsigned long **oid_table;
  size_t *oid_table_len;
  unsigned int value, i, buf_pos;

  /* Get oid pointers. */
  oid_table = va_arg(*ap, unsigned long **);
  oid_table_len = va_arg(*ap, size_t *);
  
  /* The minimal length for the oid_table. */
  *oid_table_len = 2;

  /* Count OID values. Knowing that the highest bit of octet shall be
     zero if least octet of that OID value. */
  for (buf_pos = 1; buf_pos < length; buf_pos++)
    {
      if ((data[buf_pos] & 0x80) == 0)
	(*oid_table_len) ++;
    }

  /* Allocate some memory for the oid table. */
  *oid_table =
    (unsigned long *)ssh_xmalloc(*oid_table_len * sizeof(unsigned long));

  /* Set the first two. */
  (*oid_table)[0] = (data[0] & 0xff) / 40;
  (*oid_table)[1] = (data[0] & 0xff) % 40;

  for (i = 2, buf_pos = 1; i < *oid_table_len; i++)
    {
      for (value = 0; data[buf_pos] & 0x80; buf_pos++)
	{
	  value = (value << 7) | (data[buf_pos] & 0x7f);
	}
      value = (value << 7) | (data[buf_pos] & 0x7f);
      buf_pos++;

      (*oid_table)[i] = value;
    }

  return SSH_BER_STATUS_OK;
}

/* Following are not implemented. */

SshBerStatus ssh_ber_decode_ode_type(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_eti_type(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_real(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_embedded(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

/* Decoding of times. */

SshBerStatus ssh_ber_decode_universal_time(unsigned char *data, size_t length,
					   va_list *ap)
{
  SshBerTime *time = va_arg(*ap, SshBerTime *);
  unsigned int second;
  unsigned char byte;
	   
  if (sscanf((char *) data,
	     "%02d"  /* year % 100 */
	     "%02d"  /* month */
	     "%02d"  /* day */
	     "%02d"  /* hour */
	     "%02d"  /* minute */
	     "%02d"  /* second */
	     "%c",   /* local time? */
	     &time->year, &time->month, &time->day, &time->hour, 
	     &time->minute, &second, &byte) != 7)
    return SSH_BER_STATUS_ERROR;
  
  /* Seconds. */
  time->second = second;

  /* Set the year correctly. */
  if (time->year < 50)
    time->year += 2000;
  else
    time->year += 1900;
  
  if (byte == '+')
    time->local = TRUE;
  else
    time->local = FALSE;

  if (byte != 'Z')
    {
      if (sscanf((char *) data + 13,
		 "%02d"   /* hour */
		 "%02d",  /* minute */
		 &time->absolute_hours, &time->absolute_minutes) != 2)
	return SSH_BER_STATUS_ERROR;
    }
  else
    {
      time->absolute_hours = 0;
      time->absolute_minutes = 0;
    }

  return SSH_BER_STATUS_OK;
}

SshBerStatus ssh_ber_decode_generalized_time(unsigned char *data,
					     size_t length,
					     va_list *ap)
{
  SshBerTime *time = va_arg(*ap, SshBerTime *);
  unsigned char byte;
  
  if (sscanf((char *) data,
	     "%04d"  /* year */
	     "%02d"  /* month */
	     "%02d"  /* day */
	     "%02d"  /* hour */
	     "%02d"  /* minute */
	     "%lf"   /* second (a double value) */
	     "%c",   /* local time? */
	     &time->year, &time->month, &time->day, &time->hour, 
	     &time->minute, &time->second, &byte) != 7)
    return SSH_BER_STATUS_ERROR;

  if (byte != 'Z')
    return SSH_BER_STATUS_ERROR;
  
  time->local = FALSE;
  time->absolute_hours = 0;
  time->absolute_minutes = 0;

  return SSH_BER_STATUS_OK;
}

/* Following should not be implemented. These are just encoded as
   octet-strings. */

SshBerStatus ssh_ber_decode_numeric_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_printable_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_teletex_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_videotex_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_ia5_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_graphic_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_visible_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_general_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_universal_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_unrestricted_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_bmp_string(void)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(numeric_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(printable_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(teletex_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(videotex_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(ia5_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(graphic_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(visible_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(general_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(universal_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(unrestricted_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SSH_BER_ENCODE_PROTOTYPE(bmp_string)
{
  return SSH_BER_STATUS_NOT_IMPLEMENTED;
}

SshBerStatus ssh_ber_decode_integer_short(unsigned char *data, size_t length,
				    va_list *ap)
{
 
  MP_INT temp, new_int, *integer;
  SshWord word_max, *return_word = (SshWord*)va_arg(*ap, MP_INT *);
  SshBerStatus return_status = SSH_BER_STATUS_OK;

  unsigned int i;
  
  mpz_init(&new_int);
  word_max = -1;
  
  integer= &new_int;

  if (data[0] & 0x80)
    {
      /* Negative integer. */
      mpz_set_ui(integer, 0);
      
      for (i = 0; i < length; i++)
	{
	  mpz_mul_2exp(integer, integer, 8);
	  mpz_add_ui(integer, integer, (~data[i] & 0xff));
	}

      /* Set the correct value (not the best way probably). */
      mpz_init_set_ui(&temp, 0);
      mpz_add_ui(integer, integer, 1);
      mpz_sub(integer, &temp, integer);
      mpz_clear(&temp);
    }
  else
    {
      /* Positive integer. */
      mpz_set_ui(integer, 0);

      /* This is rather simple (without one's complement compared to
	 negative case. */
      for (i = 0; i < length; i++)
	{
	  mpz_mul_2exp(integer, integer, 8);
	  mpz_add_ui(integer, integer, (data[i] & 0xff));
	}
    }


  /* Check if the word fits into SshWord and is not negative. */
  if (mpz_cmp_ui(integer, word_max) == 1 && mpz_cmp_ui(integer, 0) == -1)
    return_status = SSH_BER_STATUS_ERROR;

  
  *return_word = mpz_get_ui(integer);
  
  /*Clean the memory*/
  mpz_clear(integer);

  return return_status;
}



/* ber.c */
