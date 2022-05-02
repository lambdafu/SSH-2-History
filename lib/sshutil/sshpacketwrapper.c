/*

sshpacketwrapper.c

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

This module implements a wrapper around SshStream for sending/receiving
packets.  This has a simple interface based on a few function calls and
callbacks, making it easy to do packet-based communications over a SshStream.

*/

#include "sshincludes.h"
#include "sshbuffer.h"
#include "bufaux.h"
#include "sshgetput.h"
#include "sshstream.h"
#include "sshencode.h"
#include "sshpacketstream.h"
#include "sshpacketint.h"

#define SSH_DEBUG_MODULE "SshPacketWrapper"

#define ALLOW_AFTER_BUFFER_FULL         (10000 + 5)
#define BUFFER_MAX_SIZE                 50000


struct SshPacketWrapperRec
{
  /* The underlying stream going down.  This stream will be automatically
     closed when we are destroyed. */
  SshStream stream;

  /* SshBuffer for incoming data (downwards). */
  SshBuffer incoming;
  Boolean incoming_eof;

  /* SshBuffer for outgoing data (downwards). */
  SshBuffer outgoing;
  Boolean outgoing_eof;

  /* SshBuffer for constructing outgoing packets. */
  SshBuffer outgoing_packet;

  /* Flag indicating that ssh_packet_wrapper_can_send has returned FALSE, and
     thus we should call the can_send callback when sending is again
     possible. */
  Boolean send_blocked;

  /* Flag indicating whether we can receive.  This flag can be set by
     the application using ssh_packet_wrapper_can_receive. */
  Boolean can_receive;

  /* Flag indicating that we have been destroyed, but the destroy has been
     postponed until buffers have drained. */
  Boolean destroy_pending;

  /* If TRUE, we are in a callback in a situation where we cannot destroy
     immediately.  If this is true in a destroy, destroy_requested is set
     to TRUE, and destroy will be called when possible. */
  Boolean cannot_destroy;

  /* Set to TRUE to request immediate destroy after returning from a
     callback. */
  Boolean destroy_requested;

  /* Flag indicating that we have shortcircuited the stream.  If this is
     FALSE but shortcircuit_up_stream is non-NULL, we have a shortcircuit
     pending as soon as downward buffers have drained. */
  Boolean shortcircuited;

  /* The stream to which we have shortcircuited.  NULL if not shortcircuited
     and no shortcircuit pending. */
  SshStream shortcircuit_up_stream;

  /* Application callbacks. */
  SshPacketReceiveProc received_packet;
  SshPacketEofProc received_eof;
  SshPacketCanSendProc can_send;
  void *context;
};

/* Destroys the protocol context immediately.  Closes the downward stream
   and frees memory. */

void ssh_packet_wrapper_destroy_now(SshPacketWrapper down)
{
  /* Close the downward stream. */
  ssh_stream_destroy(down->stream);

  /* Uninitialize buffers. */
  ssh_buffer_uninit(&down->incoming);
  ssh_buffer_uninit(&down->outgoing);
  ssh_buffer_uninit(&down->outgoing_packet);

  /* Fill the context with 'F' to ease debugging, and free it. */
  memset(down, 'F', sizeof(*down));
  ssh_xfree(down);
}

/* This function outputs as much data from internal buffers to the downward
   stream.  This returns TRUE if something was successfully written. */

Boolean ssh_packet_wrapper_output(SshPacketWrapper down)
{
  int len;
  Boolean return_value = FALSE;

  /* Loop while we have data to output.  When all data has been sent,
     we check whether we need to send EOF. */
  while (ssh_buffer_len(&down->outgoing) > 0)
    {
      /* Write as much data as possible. */
      len = ssh_stream_write(down->stream, ssh_buffer_ptr(&down->outgoing),
                             ssh_buffer_len(&down->outgoing));
      if (len < 0)
        return return_value;  /* Cannot write more now. */
      if (len == 0)
        {
          /* EOF on output; will not be able to write any more. */
          down->outgoing_eof = TRUE;
          ssh_buffer_clear(&down->outgoing);
          return TRUE;
        }

      /* Consume written data. */
      ssh_buffer_consume(&down->outgoing, len);

      /* We've done something, so return TRUE. */
      return_value = TRUE;
    }

  /* All output has drained.  There is no more buffered data. */
  if (down->send_blocked)
    {
      down->cannot_destroy = TRUE;
      if (down->can_send)
        (*down->can_send)(down->context);
      down->cannot_destroy = FALSE;
      if (down->destroy_requested)
        {
          ssh_packet_wrapper_destroy(down);
          return FALSE;
        }
      down->send_blocked = FALSE;
    }

  /* If we should send EOF after output has drained, do it now. */
  if (down->outgoing_eof)
    ssh_stream_output_eof(down->stream);

  /* If we get here and the stream is shortcircuited, that means we had
     output data to drain before shortcircuiting. */
  if (down->shortcircuit_up_stream && !down->shortcircuited)
    {
      down->shortcircuited = TRUE;
      ssh_packet_impl_shortcircuit_now(down->shortcircuit_up_stream,
                                       down->stream);
    }

  /* If there's a destroy pending (that is, waiting for buffers to drain),
     do the destroy now. */
  if (down->destroy_pending)
    {
      /* Destroy the context now.  This also closes the stream. */
      ssh_packet_wrapper_destroy_now(down);

      /* Return FALSE to ensure that the loop in ssh_packet_wrapper_callback
         exits without looking at the context again. */
      return FALSE;
    }

  return return_value;
}

/* Reads as much data as possible from the downward stream, assuming we can
   receive packets.  Passes any received packets to the appropriate callbacks.
   Returns TRUE if packets were successfully received. */

Boolean ssh_packet_wrapper_input(SshPacketWrapper down)
{
  size_t data_to_read, data_read;
  int ret;
  unsigned char *ptr;
  SshPacketType type;
  Boolean return_value = FALSE;

  for (;;)
    {
      /* If we cannot receive, return immediately. */
      if (!down->can_receive || down->incoming_eof || down->destroy_pending ||
          down->shortcircuit_up_stream != NULL)
        return return_value;

      /* Get length of data read so far. */
      data_read = ssh_buffer_len(&down->incoming);

      /* Add enough space to buffer for reading either header or
         entire packet.  This also sets `ptr' to point to the place
         where data should be read, and `data_to_read' to the number
         of bytes that should be there after reading (should read
         data_to_read - data_read bytes). */
      if (data_read < 4)
        {
          /* Packet header not yet in buffer.  Read only header. */
          data_to_read = 4;
          ssh_buffer_append_space(&down->incoming, &ptr, 4 - data_read);
        }
      else
        {
          /* Packet header already in buffer. */
          ptr = ssh_buffer_ptr(&down->incoming);
          data_to_read = 4 + SSH_GET_32BIT(ptr);
          if (data_to_read > 100000000L)
            ssh_fatal("ssh_packet_wrapper_input: "
                      "invalid packet received: len %ld",
                      (long)data_to_read);
          SSH_ASSERT(data_to_read > data_read);
          ssh_buffer_append_space(&down->incoming, &ptr,
                                  data_to_read - data_read);
        }

      /* Keep reading until entire packet read, or no more data available. */
      while (data_read < data_to_read)
        {
          /* Try to read the remaining bytes. */
          ptr = (unsigned char *)ssh_buffer_ptr(&down->incoming) + data_read;
          ret = ssh_stream_read(down->stream, ptr, data_to_read - data_read);
          if (ret < 0)
            {
              /* No more data available at this time.  Remove
                 allocated but unread space from end of buffer. */
              ssh_buffer_consume_end(&down->incoming,
                                     data_to_read - data_read);
              return return_value;
            }

          if (ret == 0)
            {
              /* EOF received. */
              ssh_buffer_consume_end(&down->incoming,
                                     data_to_read - data_read);
              down->incoming_eof = TRUE;

              /* Pass the EOF to the application callback. */
              down->cannot_destroy = TRUE;
              if (down->received_eof)
                (*down->received_eof)(down->context);
              down->cannot_destroy = FALSE;
              if (down->destroy_requested)
                {
                  ssh_packet_wrapper_destroy(down);
                  return FALSE;
                }
              return TRUE;
            }

          if (data_read < 4 && data_read + ret >= 4)
            {
              /* Header has now been fully received.  Prepare to receive rest
                 of packet. */
              data_read += ret;
              ptr = ssh_buffer_ptr(&down->incoming);
              data_to_read = 4 + SSH_GET_32BIT(ptr);
              if (data_to_read > 100000000L)
                ssh_fatal("ssh_packet_wrapper_input: "
                          "invalid packet received: len %ld",
                          (long)data_to_read);
              if (data_to_read > data_read)
                ssh_buffer_append_space(&down->incoming, &ptr,
                                    data_to_read - data_read);
            }
          else
            data_read += ret;
        }

      /* An entire packet has been received. */
      SSH_ASSERT(ssh_buffer_len(&down->incoming) == data_to_read);

      /* Get packet type. */
      ptr = ssh_buffer_ptr(&down->incoming);
      type = (SshPacketType)ptr[4];

      /* Call the application callback if set. */
      down->cannot_destroy = TRUE;
      if (down->received_packet)
        (*down->received_packet)(type, ptr + 5, data_to_read - 5,
                                 down->context);
      down->cannot_destroy = FALSE;
      if (down->destroy_requested)
        {
          ssh_packet_wrapper_destroy(down);
          return FALSE;
        }
      ssh_buffer_clear(&down->incoming);

      return_value = TRUE;
    }
  /*NOTREACHED*/
}

/* Callback function for the lower-level stream.  This receives notifications
   when we can read/write data from the lower-level stream. */

void ssh_packet_wrapper_callback(SshStreamNotification op, void *context)
{
  SshPacketWrapper down = (SshPacketWrapper)context;
  Boolean ret;

  ret = FALSE;

  /* Process the notification.  We loop between input and output
     operations until one returns FALSE (they return TRUE if the other
     operation should be performed). */
  do
    {
      switch (op)
        {
        case SSH_STREAM_CAN_OUTPUT:
          ret = ssh_packet_wrapper_output(down);
          op = SSH_STREAM_INPUT_AVAILABLE;
          break;

        case SSH_STREAM_INPUT_AVAILABLE:
          ret = ssh_packet_wrapper_input(down);
          op = SSH_STREAM_CAN_OUTPUT;
          break;

        case SSH_STREAM_DISCONNECTED:
          ssh_debug("ssh_packet_wrapper_callback: disconnected");
          ret = FALSE;
          break;

        default:
          ssh_fatal("ssh_packet_wrapper_callback: unknown op %d", (int)op);
        }
      /* Note: `down' might have been destroyed by now.  In that case
         `ret' is FALSE. */
    }
  while (ret == TRUE);
}

/* Creates a packet stream wrapper around the given stream.
   This returns a wrapper handle.  The handle should be destroyed with
   ssh_packet_wrapper_destroy when no longer needed.  This takes over the
   stream, and the stream will be automatically closed when the wrapper
   is destroyed.  It is not legal to access the stream directly.
      `stream'               stream to lower-level protocol (or network)
      `received_packet'      called when a packet is received
      `received_eof'         called when EOF is received
      `can_send'             called when we can send after not being able to
      `context'              passed as argument to callbacks

   Any of the functions can be NULL if not needed.  It is guaranteed that
   the callbacks will not be called until from the bottom of the event
   loop.  This gives the caller a chance to store the returned pointer
   somewhere before one of the callbacks gets called.  Destroying the
   SshPacketWrapper object is legal in any callback.

   The stream will be ready to receive packets immediately.  If receiving
   packets immediately is not desirable, ssh_packet_wrapper_can_receive
   should be called immediately after creation to prevent receiving
   packets. */

SshPacketWrapper ssh_packet_wrap(SshStream down_stream,
                                 SshPacketReceiveProc received_packet,
                                 SshPacketEofProc received_eof,
                                 SshPacketCanSendProc can_send,
                                 void *context)
{
  SshPacketWrapper down;

  down = ssh_xcalloc(1, sizeof(*down));
  down->stream = down_stream;
  ssh_buffer_init(&down->incoming);
  ssh_buffer_init(&down->outgoing);
  ssh_buffer_init(&down->outgoing_packet);
  down->incoming_eof = FALSE;
  down->outgoing_eof = FALSE;
  down->send_blocked = TRUE;
  down->can_receive = FALSE;
  down->destroy_pending = FALSE;
  down->cannot_destroy = FALSE;
  down->destroy_requested = FALSE;
  down->shortcircuited = FALSE;

  /* Save the callback functions. */
  down->received_packet = received_packet;
  down->received_eof = received_eof;
  down->can_send = can_send;
  down->context = context;

  /* Set callback for the downward stream.  Note that this will also cause
     can_send to be called from the output callback. */
  ssh_stream_set_callback(down->stream, ssh_packet_wrapper_callback,
                          (void *)down);

  /* Enable receives. */
  ssh_packet_wrapper_can_receive(down, TRUE);

  return down;
}

/* Destroys the wrapper object, and closes the underlying stream.  None
   of the callbacks will be called after this has been called.  Any
   buffered data will be sent out before the stream is actually
   closed.  The wrapper pointer and the stream object will be invalid after
   this has been called. */

void ssh_packet_wrapper_destroy(SshPacketWrapper down)
{
  /* Clear the callbacks so that user functions are not called. */
  down->received_packet = NULL;
  down->received_eof = NULL;
  down->can_send = NULL;

  /* If we cannot destroy at this time, set the proper flag and return
     immediately without destroying.  This happens in some callbacks.
     The code after the callback will check for the flag and call destroy
     again if set. */
  if (down->cannot_destroy)
    {
      down->destroy_requested = TRUE;
      return;
    }

  down->destroy_pending = TRUE;

  if (ssh_buffer_len(&down->outgoing) == 0)
    ssh_packet_wrapper_destroy_now(down);
}

/* Informs the packet stream wrapper whether `received_packet' can be
   called.  This is used for flow control. */

void ssh_packet_wrapper_can_receive(SshPacketWrapper down, Boolean status)
{
  down->can_receive = status;
  if (status == TRUE)
    {
      /* Reset the callbacks to ensure that our callback gets called. */
      ssh_stream_set_callback(down->stream, ssh_packet_wrapper_callback,
                              (void *)down);
    }
}

/* Sends EOF to the packet stream (after sending out any buffered data).
   It is illegal to send any packets after calling this. */

void ssh_packet_wrapper_send_eof(SshPacketWrapper down)
{
  /* If EOF already sent, return immediately. */
  if (down->outgoing_eof)
    return;

  /* Otherwise, send EOF now. */
  down->outgoing_eof = TRUE;
  if (ssh_buffer_len(&down->outgoing) == 0)
    ssh_stream_output_eof(down->stream);
}

/* Returns TRUE if it is OK to send more data.  It is not an error to
   send small amounts of data (e.g. a disconnect) when this returns
   FALSE, but sending lots of data when this returns FALSE will
   eventually cause packets to be lost.  To give a specific value, it
   is OK to send 10000 bytes after this starts returning FALSE (this
   provision exists to avoid checks in every disconnect and debug
   message). */

Boolean ssh_packet_wrapper_can_send(SshPacketWrapper down)
{
  Boolean status;

  status = ssh_buffer_len(&down->outgoing) <
    BUFFER_MAX_SIZE - ALLOW_AFTER_BUFFER_FULL;

  /* If no more can be sent, mark that sending is blocked.  This will
     trigger a callback when data can again be sent. */
  if (!status)
    down->send_blocked = TRUE;

  return status;
}

/* Sends a packet to the underlying stream.  The payload will be encoded as
   specified for ssh_encode_buffer_va. */

void ssh_packet_wrapper_send_encode_va(SshPacketWrapper down,
                                       SshPacketType type,
                                       va_list va)
{
  /* Format the packet in a separate buffer. */
  ssh_buffer_clear(&down->outgoing_packet);
  ssh_packet_encode_va(&down->outgoing_packet, type, va);

  /* Check that we don't overflow maximum buffer size.  Drop the packet
     if we would. */
  if (ssh_buffer_len(&down->outgoing) +
      ssh_buffer_len(&down->outgoing_packet) >= BUFFER_MAX_SIZE)
    {
      ssh_debug("ssh_packet_wrapper_send_encode_va: flow control problems; "
                "outgoing packet dropped.");
      return;
    }

  /* Append the packet to the outgoing buffer. */
  ssh_buffer_append(&down->outgoing, ssh_buffer_ptr(&down->outgoing_packet),
                    ssh_buffer_len(&down->outgoing_packet));

  /* Reset the callback to ensure that our callback gets called. */
  ssh_stream_set_callback(down->stream, ssh_packet_wrapper_callback,
                          (void *)down);
}

/* Sends a packet to the underlying stream.  The payload will be encoded as
   specified for ssh_encode_buffer. */

void ssh_packet_wrapper_send_encode(SshPacketWrapper down,
                                    SshPacketType type,
                                    ...)
{
  va_list va;

  va_start(va, type);
  ssh_packet_wrapper_send_encode_va(down, type, va);
  va_end(va);
}

/* Sends a packet to the underlying stream.  The packet may actually
   get buffered and sent later.  Packets will always get sent in
   sequence.  The application should use ssh_packet_wrapper_can_send and
   the `can_send' callback to implement flow control. */

void ssh_packet_wrapper_send(SshPacketWrapper down, SshPacketType type,
                         const unsigned char *data, size_t len)
{
  ssh_packet_wrapper_send_encode(down, type,
                                 SSH_FORMAT_DATA, data, len,
                                 SSH_FORMAT_END);
}

/* Causes any I/O requests from `packet_stream' (which must be implemented
   using the ssh_impl_* functions in this module) to be shortcircuited to
   the stream inside `wrapper', and vice versa.  The `received_packet',
   `received_eof', and `can_send' callbacks will no longer be called for
   either object.  This will automatically allow sends/receives in each
   direction as appropriate.  This can only be called from a SshPacketWrapper
   `received_packet' callback.

   The `destroy' callback is not shortcircuited, and should destroy the
   wrapper and any other data that might have been allocated.

   The primary purpose is to allow a protocol module (e.g., an authentication
   module) to shortcircuit any traffic through it. */

void ssh_packet_shortcircuit(SshStream packet_stream,
                             SshPacketWrapper wrapper)
{
  /* Mark that the stream is shortcircuited. */
  wrapper->shortcircuited = FALSE;
  wrapper->shortcircuit_up_stream = packet_stream;

#if 0 /* the packet is still in wrapper->incoming when we call the callback */
  /* Sanity check: there must not be data in incoming buffer. */
  if (ssh_buffer_len(&wrapper->incoming) != 0)
    ssh_fatal("ssh_packet_shortcircuit: incoming data in buffer; not set in packet callback");
#endif /* 0 */

  /* If there is no data to drain, shortcircuit output now. */
  if (ssh_buffer_len(&wrapper->outgoing) == 0)
    {
      wrapper->shortcircuited = TRUE;
      ssh_packet_impl_shortcircuit_now(wrapper->shortcircuit_up_stream,
                                       wrapper->stream);
    }
}
