/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *	  Program: sshutil
 *	  $Source: /ssh/CVS/src/lib/sshutil/sshunixserial.c,v $
 *	  $Author: kivinen $
 *
 *	  Creation	    : 09:43 Aug 12 1998 kivinen
 *	  Last Modification : 02:16 Aug 20 1998 kivinen
 *	  Last check in	    : $Date: 1998/08/19 23:16:47 $
 *	  Revision number   : $Revision: 1.4 $
 *	  State		    : $State: Exp $
 *	  Version	    : 1.145
 *
 *	  Description	    : Generic interface for opening a data
 *			      stream to/from a serial line. This is
 * 			      a unix implementation.
 *
 *	  $Log: sshunixserial.c,v $
 *	  $EndLog$
 */

#include "sshincludes.h"
#include "sshserialstream.h"
#include "sshunixeloop.h"
#include "sshunixfdstream.h"
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif /* HAVE_TERMIOS_H */

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif /* HAVE_SYS_IOCTL_H */

typedef struct {
  SshStream stream;

  int fd;
  struct termios original_settings;
} *SshSerialStream;

extern const SshStreamMethodsTable ssh_serial_methods;

/* Opens a stream for the device specified by the given name.  Returns NULL
   on failure. */
SshStream ssh_serial_open(const char *name)
{
  SshSerialStream serial;

  serial = ssh_xcalloc(1, sizeof(*serial));

  /* Try to open the device. */
  serial->fd = open(name, O_RDWR | O_NONBLOCK, 0666);

  /* On error, return NULL. */
  if (serial->fd < 0)
    {
      ssh_xfree(serial);
      return NULL;
    }

  /* Read the orignal attributes. */
  if (tcgetattr(serial->fd, &serial->original_settings) < 0)
    {
      ssh_xfree(serial);
      return NULL;
    }

  /* Wrap the master fd into a stream. */
  serial->stream = ssh_stream_fd_wrap(serial->fd, TRUE);
  return ssh_stream_create(&ssh_serial_methods, (void *) serial);
}

/* Set serial stream parameters, returns TRUE if successfull */
Boolean ssh_serial_stream_params(SshStream stream,
				 SshSerialSpeed input_speed,
				 SshSerialSpeed output_speed,
				 SshSerialBits bits,
				 SshSerialParity parity,
				 SshSerialStopBits stop_bits,
				 SshSerialMode mode,
				 SshSerialFlowControl flow_control)
{
  SshSerialStream serial;
  struct termios t;

  if (ssh_stream_get_methods(stream) != (void *)&ssh_serial_methods)
    ssh_fatal("ssh_serial_stream_params: not a serial stream");
  serial = ssh_stream_get_context(stream);

  if (tcgetattr(serial->fd, &t) < 0)
    return FALSE;

  t.c_cc[VMIN] = 0;
  t.c_cc[VTIME] = 0;
  switch (mode)
    {
    case SSH_SERIAL_MODE_RAW:
      t.c_cflag = CREAD;
      t.c_lflag = 0;
      t.c_iflag = IGNBRK;
      break;
    case SSH_SERIAL_MODE_RAW_LOCAL:
      t.c_cflag = CREAD | CLOCAL;
      t.c_lflag = 0;
      t.c_iflag = IGNBRK;
     break;
    case SSH_SERIAL_MODE_CANON:
      t.c_cflag = CREAD;
      t.c_lflag = ICANON;
      t.c_iflag = IGNBRK;
      t.c_oflag = OPOST | OCRNL;
      break;
    case SSH_SERIAL_MODE_CANON_LOCAL:
      t.c_cflag = CREAD | CLOCAL;
      t.c_lflag = ICANON;
      t.c_iflag = IGNBRK;
      t.c_oflag = OPOST | OCRNL;
      break;
    case SSH_SERIAL_MODE_CANON_ECHO:
      t.c_cflag = CREAD;
      t.c_lflag = ICANON | ECHO;
      t.c_iflag = IGNBRK;
      t.c_oflag = OPOST | OCRNL;
      break;
    case SSH_SERIAL_MODE_CANON_ECHO_LOCAL:
      t.c_cflag = CREAD | CLOCAL;
      t.c_lflag = ICANON | ECHO;
      t.c_iflag = IGNBRK;
      t.c_oflag = OPOST | OCRNL;
      break;
    }

  switch (bits)
    {
    case SSH_SERIAL_BITS_5: t.c_cflag |= CS5; break;
    case SSH_SERIAL_BITS_6: t.c_cflag |= CS6; break;
    case SSH_SERIAL_BITS_7: t.c_cflag |= CS7; break;
    case SSH_SERIAL_BITS_8: t.c_cflag |= CS8; break;
    }

  switch (parity)
    {
    case SSH_SERIAL_PARITY_NONE: break;
    case SSH_SERIAL_PARITY_EVEN:
      t.c_cflag |= PARENB;
      t.c_iflag |= INPCK;
      break;
    case SSH_SERIAL_PARITY_ODD:
      t.c_cflag |= PARENB | PARODD;
      t.c_iflag |= INPCK;
      break;
    }

  switch (stop_bits)
    {
    case SSH_SERIAL_STOP_BITS_1: break;
    case SSH_SERIAL_STOP_BITS_2: t.c_cflag |= CSTOPB; break;
    }

  switch (flow_control)
    {
    case SSH_SERIAL_FLOW_NONE:
      break;
    case SSH_SERIAL_FLOW_XON_XOFF:
      t.c_iflag |= IXON | IXOFF | IXANY;
      break;
    case SSH_SERIAL_FLOW_RTS_CTS: 
#ifdef CRTSCTS
      t.c_cflag |= CRTSCTS;
#else
#if defined(CCTS_OFLOW) && defined(CRTS_IFLOW)
      t.c_cflag |= CCTS_OFLOW | CRTS_IFLOW;
#endif
#endif
      break;
    }

  if (cfsetispeed(&t, input_speed) < 0)
    return FALSE;
  
  if (cfsetospeed(&t, output_speed) < 0)
    return FALSE;

  if (tcsetattr(serial->fd, TCSANOW, &t) < 0)
    return FALSE;
  return TRUE;
}

int ssh_serial_stream_modem_flags(SshSerialModemControl modem)
{
  int flags;

#ifdef TIOCM_DTR
  if (modem & SSH_SERIAL_MODEM_DTR) flags |= TIOCM_DTR;
#endif /* TIOCM_DTR */
#ifdef TIOCM_RTS
  if (modem & SSH_SERIAL_MODEM_RTS) flags |= TIOCM_RTS;
#endif /* TIOCM_RTS */
#ifdef TIOCM_CTS
  if (modem & SSH_SERIAL_MODEM_CTS) flags |= TIOCM_CTS;
#endif /* TIOCM_CTS */
#ifdef TIOCM_CD
  if (modem & SSH_SERIAL_MODEM_CD) flags |= TIOCM_CD;
#else /* TIOCM_CD */
#ifdef TIOCM_CAR
  if (modem & SSH_SERIAL_MODEM_CD) flags |= TIOCM_CAR;
#endif /* TIOCM_CAR */
#endif /* TIOCM_CD */
#ifdef TIOCM_RI
  if (modem & SSH_SERIAL_MODEM_RI) flags |= TIOCM_RI;
#else /* TIOCM_RI */
#ifdef TIOCM_RNG
  if (modem & SSH_SERIAL_MODEM_CD) flags |= TIOCM_RNG;
#endif /* TIOCM_RNG */
#endif /* TIOCM_RI */
#ifdef TIOCM_DSR
  if (modem & SSH_SERIAL_MODEM_DSR) flags |= TIOCM_DSR;
#endif /* TIOCM_DSR */
  return flags;
}

/* Set modem control flags, return TRUE if successful */
Boolean ssh_serial_stream_modem_set(SshStream stream,
				    SshSerialModemControl modem)
{
  int flags;
  SshSerialStream serial;

  if (ssh_stream_get_methods(stream) != (void *)&ssh_serial_methods)
    ssh_fatal("ssh_serial_stream_params: not a serial stream");
  serial = ssh_stream_get_context(stream);

  flags = ssh_serial_stream_modem_flags(modem);

#ifdef TIOCMBIS
  if (ioctl(serial->fd, TIOCMBIS, &flags) < 0)
    return FALSE;
#endif /* TIOCMBIS */
  return TRUE;
}

/* Clear modem control flags, return TRUE if successful */
Boolean ssh_serial_stream_modem_clear(SshStream stream,
				      SshSerialModemControl modem)
{
  int flags;
  SshSerialStream serial;

  if (ssh_stream_get_methods(stream) != (void *)&ssh_serial_methods)
    ssh_fatal("ssh_serial_stream_params: not a serial stream");
  serial = ssh_stream_get_context(stream);

  flags = ssh_serial_stream_modem_flags(modem);

#ifdef TIOCMBIC
  if (ioctl(serial->fd, TIOCMBIC, &flags) < 0)
    return FALSE;
#endif /* TIOCMBIS */
  return TRUE;
}

/* Set modem control flags, return TRUE if successful */
Boolean ssh_serial_stream_modem_get(SshStream stream,
				    SshSerialModemControl *modem)
{
  int flags;
  SshSerialStream serial;

  if (ssh_stream_get_methods(stream) != (void *)&ssh_serial_methods)
    ssh_fatal("ssh_serial_stream_params: not a serial stream");
  serial = ssh_stream_get_context(stream);

  flags = 0;
  *modem = 0;
#ifdef TIOCMGET
  if (ioctl(serial->fd, TIOCMGET, &flags) < 0)
    return FALSE;
#endif /* TIOCMGET */

#ifdef TIOCM_DTR
  if (flags & TIOCM_DTR) *modem |= SSH_SERIAL_MODEM_DTR;
#endif /* TIOCM_DTR */
#ifdef TIOCM_RTS
  if (flags & TIOCM_RTS) *modem |= SSH_SERIAL_MODEM_RTS;
#endif /* TIOCM_RTS */
#ifdef TIOCM_CTS
  if (flags & TIOCM_CTS) *modem |= SSH_SERIAL_MODEM_CTS;
#endif /* TIOCM_CTS */
#ifdef TIOCM_CD
  if (flags & TIOCM_CD) *modem |= SSH_SERIAL_MODEM_CD;
#else /* TIOCM_CD */
#ifdef TIOCM_CAR
  if (flags & TIOCM_CAR) *modem |= SSH_SERIAL_MODEM_CD;
#endif /* TIOCM_CAR */
#endif /* TIOCM_CD */
#ifdef TIOCM_RI
  if (flags & TIOCM_RI) *modem |= SSH_SERIAL_MODEM_RI;
#else /* TIOCM_RI */
#ifdef TIOCM_RNG
  if (flags & TIOCM_RNG) *modem |= SSH_SERIAL_MODEM_CD;
#endif /* TIOCM_RNG */
#endif /* TIOCM_RI */
#ifdef TIOCM_DSR
  if (flags & TIOCM_DSR) *modem |= SSH_SERIAL_MODEM_DSR;
#endif /* TIOCM_DSR */
  return TRUE;
}

/* Implements a read from the serial stream. */
int ssh_serial_stream_read(void *context, unsigned char *buf, size_t size)
{
  SshSerialStream serial = (SshSerialStream)context;

  return ssh_stream_read(serial->stream, buf, size);
}

/* Implements write to the serial stream. */
int ssh_serial_stream_write(void *context, const unsigned char *buf,
			    size_t size)
{
  SshSerialStream serial = (SshSerialStream)context;

  return ssh_stream_write(serial->stream, buf, size);
}

/* This is supposed to indicate that we will not write any more. */
void ssh_serial_stream_output_eof(void *context)
{
  SshSerialStream serial = (SshSerialStream)context;

  ssh_stream_output_eof(serial->stream);
}

/* Sets the callback for the serial stream.  We pass the call directly to the
   underlying stdio stream. */
void ssh_serial_stream_set_callback(void *context, SshStreamCallback callback,
				    void *callback_context)
{
  SshSerialStream serial = (SshSerialStream)context;

  ssh_stream_set_callback(serial->stream, callback, callback_context);
}

/* Destroys the stream.  It is guaranteed that when this returns, no more
   callbacks will be delivered from the stream. */
void ssh_serial_stream_destroy(void *context)
{
  SshSerialStream serial = (SshSerialStream)context;

  /* Restore the orignal attributes. */
  if (tcsetattr(serial->fd, TCSANOW, &serial->original_settings) < 0)
    ssh_warning("Restoring original settings of serial line failed");

  /* Destroy the serial stream. */
  ssh_stream_destroy(serial->stream);

  ssh_xfree(serial);
}

const SshStreamMethodsTable ssh_serial_methods = {
  ssh_serial_stream_read,
  ssh_serial_stream_write,
  ssh_serial_stream_output_eof,
  ssh_serial_stream_set_callback,
  ssh_serial_stream_destroy
};
