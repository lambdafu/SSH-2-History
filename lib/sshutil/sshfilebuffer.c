/*

sshfilebuffer.c

Author: Timo J. Rinne <tri@ssh.fi>

Copyright (c) 1998
              SSH Communications Security Oy, Espoo, Finland
              All rights reserved.

Created: Tue Sep  8 09:22:07 1998 tri

Code for reading files into SshBuffer.

*/

/*
 * $Id: sshfilebuffer.c,v 1.1 1998/09/22 11:49:47 tri Exp $
 * $Log: sshfilebuffer.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshbuffer.h"
#include "sshfilebuffer.h"

#define SSH_DEBUG_MODULE "SshFileBuffer"

/* Allocate a file buffer */
SshFileBuffer *ssh_file_buffer_allocate(void)
{
  SshFileBuffer *r;

  r = ssh_xmalloc(sizeof (SshFileBuffer));
  r->attached_as_fileptr = FALSE;
  r->f = NULL;
  ssh_buffer_init(&(r->buf));
  return r;
}

/* Free a file buffer */
void ssh_file_buffer_free(SshFileBuffer *buf)
{
  SSH_ASSERT(buf != NULL);
  if (ssh_file_buffer_attached(buf))
    {
      if (!(buf->attached_as_fileptr))
	fclose(buf->f);
      buf->attached_as_fileptr = FALSE;
      buf->f = NULL;
    }
  ssh_buffer_uninit(&(buf->buf));
  ssh_xfree(buf);
  return;
}

/* Initialize an already allocated file buffer */
void ssh_file_buffer_init(SshFileBuffer *buf)
{
  SSH_ASSERT(buf != NULL);
  buf->f = NULL;
  ssh_buffer_init(&(buf->buf));
  return;
}

/* Uninitialize a file buffer initialized by ssh_file_buffer_init */
void ssh_file_buffer_uninit(SshFileBuffer *buf)
{
  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  ssh_buffer_uninit(&(buf->buf));
  return;
}

/* Clear the allocated file buffer.
   Detach the possibly attached file and zero the buffer. */
void ssh_file_buffer_clear(SshFileBuffer *buf)
{
  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  ssh_buffer_clear(&(buf->buf));
  return;
}

/* Attech a file to a file buffer. */
Boolean ssh_file_buffer_attach(SshFileBuffer *buf, char *filename)
{
  FILE *f;

  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  f = fopen(filename, "rb");
  if (f == NULL)
    return FALSE;
  buf->f = f;
  buf->attached_as_fileptr = FALSE;
  return TRUE;
}

Boolean ssh_file_buffer_attach_fileptr(SshFileBuffer *buf, FILE *f)
{
  SSH_ASSERT(buf != NULL);
  ssh_file_buffer_detach(buf);
  buf->f = f;
  buf->attached_as_fileptr = TRUE;
  return TRUE;
}

/* Return TRUE if file is attached to a buffer. */
Boolean ssh_file_buffer_attached(SshFileBuffer *buf)
{
  SSH_ASSERT(buf != NULL);
  return ((buf->f != NULL) ? TRUE : FALSE);
}

/* Detach file.  Leave the buffer untouched. */
void ssh_file_buffer_detach(SshFileBuffer *buf)
{
  SSH_ASSERT(buf != NULL);
  if (ssh_file_buffer_attached(buf))
    {
      if (buf->attached_as_fileptr)
	buf->attached_as_fileptr = FALSE;
      else
	fclose(buf->f);
      buf->f = NULL;
    }
  return;
}

/* Read attached file so that buffer size exceeds argument bytes. */
Boolean ssh_file_buffer_expand(SshFileBuffer *buf, size_t bytes)
{
  size_t len;
  unsigned char *newdata;

  SSH_ASSERT(buf != NULL);
  len = ssh_buffer_len(&(buf->buf));
  if (len >= bytes)
    return TRUE;
  if (!ssh_file_buffer_attached(buf))
    return FALSE;
  bytes -= len;
  ssh_buffer_append_space(&(buf->buf), &newdata, bytes);
  SSH_ASSERT(newdata != NULL);
  len = fread(newdata, 1, bytes, buf->f);
  SSH_ASSERT(len <= bytes);
  if (len < bytes)
    {
      ssh_buffer_consume_end(&(buf->buf), bytes - len); 
      ssh_file_buffer_detach(buf);
      return FALSE;
    }
  return TRUE;
}

/* eof (sshfilebuffer.c) */
