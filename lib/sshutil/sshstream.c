/*

  Author: Antti Huima <huima@ssh.fi>
  	  Tatu Ylonen <ylo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Jul  3 23:32:09 1996 [huima]

  A generic bidirectional data stream with a callback-based interface.

*/

/*
 * $Id: sshstream.c,v 1.1 1998/01/28 10:14:56 ylo Exp $
 * $Log: sshstream.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshstream.h"
#include "sshtimeouts.h"

/* All stream types have a structure that starts with the method table
   pointer.  This structure should be considered private to the implementation
   and should not be accessed directly by applications. */

struct SshStreamRec {
  const SshStreamMethodsTable *methods;
  unsigned long read_bytes;
  unsigned long written_bytes;
  void *context;
  SshStreamCallback user_callback;
  void *user_context;
  Boolean closed;
  Boolean disconnected;
};

/* Callbacks from the stream implementation are passed to this function for
   sanity checks.  This will then call the application callback.  Note
   that the user callback is allowed to close the stream. */

void ssh_stream_internal_callback(SshStreamNotification notification,
				  void *context)
{
  SshStream stream = (SshStream)context;

  if (stream->closed)
    ssh_fatal("ssh_stream_internal_callback: stream implementation generated "
	      "a callback after close.");
  if (stream->disconnected)
    ssh_fatal("ssh_stream_internal_callback: stream implementation generated "
	      "a callback after disconnected notification");
  if (notification == SSH_STREAM_DISCONNECTED)
    stream->disconnected = TRUE;

  /* Call the user callback if set.  Note that it is legal for the user
     callback to be NULL, in which case it is just not called. */
  if (stream->user_callback)
    (*stream->user_callback)(notification, stream->user_context);
}

/* Creates a stream.  This is usually not called directly by applications;
   instead, applications call stream type specific creation functions that
   will eventually call this. */

SshStream ssh_stream_create(const SshStreamMethodsTable *methods,
			    void *context)
{
  SshStream stream;

  stream = ssh_xmalloc(sizeof(*stream));
  memset(stream, 0, sizeof(stream));
  stream->methods = methods;
  stream->context = context;
  stream->read_bytes = 0;
  stream->written_bytes = 0;
  stream->user_callback = NULL;
  stream->user_context = NULL;
  stream->closed = FALSE;
  stream->disconnected = FALSE;
  (*stream->methods->set_callback)(stream->context,
				   ssh_stream_internal_callback,
				   (void *)stream);
  return stream;
}

/* Reads at most `size' bytes to the buffer `buffer'.  Returns 0 if
  EOF is encountered, negative value if the read would block, and
  the number of bytes read if something was read. */

int ssh_stream_read(SshStream stream, unsigned char *buffer,
		    size_t size)
{
  int len;

  assert(!stream->closed);
  len = (*stream->methods->read)(stream->context, buffer, size);
  assert(!stream->disconnected || len == 0);
  if (len > 0)
    stream->read_bytes += len;
  return len;
}

/* Writes at most `size' bytes from the buffer `buffer'.  Returns 0 if the
   other end has indicated that it will no longer read (this condition is not
   guaranteed to be detected), a negative value if the write would block,
   and the number of bytes written if something was actually written. */

int ssh_stream_write(SshStream stream, const unsigned char *buffer,
		     size_t size)
{
  int len;

  assert(!stream->closed);
  len = (*stream->methods->write)(stream->context, buffer, size);
  assert(!stream->disconnected || len == 0);
  if (len > 0)
    stream->written_bytes += len;
  return len;
}

/* Signals that the application will not write anything more to the stream. */

void ssh_stream_output_eof(SshStream stream)
{
  assert(!stream->closed);
  (*stream->methods->output_eof)(stream->context);
}

/* Sets the callback that the stream uses to notify the application of
   events of interest.  This function may be called at any time, and
   may be called multiple times.  The callback may be NULL, in which
   case it just won't be called.  Setting the callback to non-NULL
   will result in a call to the callback, latest when something can be
   done.  Applications can rely on doing all I/O in the callback, if
   they wish. */

void ssh_stream_set_callback(SshStream stream,
			     SshStreamCallback callback,
			     void *context)
{
  assert(!stream->closed);
  stream->user_callback = callback;
  stream->user_context = context;
  (*stream->methods->set_callback)(stream->context,
				   ssh_stream_internal_callback,
				   (void *)stream);
}

/* Retrieves stream statistics. */

void ssh_stream_get_stats(SshStream stream, SshStreamStats *stats)
{
  assert(!stream->closed);
  stats->read_bytes = stream->read_bytes;
  stats->written_bytes = stream->written_bytes;
}

/* Frees the given stream immediately. */

void ssh_stream_real_destroy(void *context)
{
  SshStream stream = (SshStream)context;
  
  /* Fill the context with garbage as an extra sanity check. */
  memset(stream, 'F', sizeof(*stream));

  ssh_xfree(stream);
}

/* Schedules the stream to be closed and destroyed at the bottom of the
   event loop. */

void ssh_stream_destroy(SshStream stream)
{
  assert(!stream->closed);
  stream->closed = TRUE;
  (*stream->methods->destroy)(stream->context);
  
  /* Perform a delayed free of the stream context.  We would basically be
     allowed to free it immediately; however, as a sanity check, we keep
     the context around until all events have been processed, and
     call fatal if the stream is still accessed. */
  ssh_register_timeout(0L, 0L, ssh_stream_real_destroy, (void *)stream);
}

/* Returns the methods table for the stream.  This function is primarily
   used by various stream implementations to determine whether a particular
   stream is of the appropriate type. */

const SshStreamMethodsTable *ssh_stream_get_methods(SshStream stream)
{
  assert(!stream->closed);
  return stream->methods;
}

/* Returns the method context of the stream.  This function is intended
   for use by stream implementations only. */

void *ssh_stream_get_context(SshStream stream)
{
  assert(!stream->closed);
  return stream->context;
}
