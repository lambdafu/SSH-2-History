/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *	  Program: sshutil
 *	  $Source: /ssh/CVS/src/lib/sshutil/sshserialstream.h,v $
 *	  $Author: kivinen $
 *
 *	  Creation	    : 09:43 Aug 12 1998 kivinen
 *	  Last Modification : 00:01 Aug 19 1998 kivinen
 *	  Last check in	    : $Date: 1998/08/18 21:01:50 $
 *	  Revision number   : $Revision: 1.4 $
 *	  State		    : $State: Exp $
 *	  Version	    : 1.113
 *
 *	  Description	    : Generic interface for opening a data
 *			      stream to/from a serial line. 
 *
 *	  $Log: sshserialstream.h,v $
 *	  $EndLog$
 */

#ifndef SSHSERIALSTREAM_H
#define SSHSERIALSTREAM_H

#include "sshstream.h"

/* Opens a stream for the device specified by the given name.  Returns NULL
   on failure. */
SshStream ssh_serial_open(const char *name);

/* Serial input and output speed. */
typedef enum {
  SSH_SERIAL_SPEED_0 = 0,
  SSH_SERIAL_SPEED_50 = 50,
  SSH_SERIAL_SPEED_75 = 75,
  SSH_SERIAL_SPEED_110 = 110,
  SSH_SERIAL_SPEED_134 = 134,
  SSH_SERIAL_SPEED_150 = 150,
  SSH_SERIAL_SPEED_200 = 200,
  SSH_SERIAL_SPEED_300 = 300,
  SSH_SERIAL_SPEED_600 = 600,
  SSH_SERIAL_SPEED_1200 = 1200,
  SSH_SERIAL_SPEED_1800 = 1800,
  SSH_SERIAL_SPEED_2400 = 2400,
  SSH_SERIAL_SPEED_4800 = 4800,
  SSH_SERIAL_SPEED_7200 = 7200,
  SSH_SERIAL_SPEED_9600 = 9600,
  SSH_SERIAL_SPEED_14400 = 14400,
  SSH_SERIAL_SPEED_19200 = 19200,
  SSH_SERIAL_SPEED_28800 = 28800,
  SSH_SERIAL_SPEED_38400 = 38400,
  SSH_SERIAL_SPEED_57600 = 57600,
  SSH_SERIAL_SPEED_76800 = 76800,
  SSH_SERIAL_SPEED_115200 = 115200,
  SSH_SERIAL_SPEED_230400 = 230400
} SshSerialSpeed;

/* Serial character bit size */
typedef enum {
  SSH_SERIAL_BITS_5 = 5,
  SSH_SERIAL_BITS_6 = 6,
  SSH_SERIAL_BITS_7 = 7,
  SSH_SERIAL_BITS_8 = 8
} SshSerialBits;

/* Serial parity */
typedef enum {
  SSH_SERIAL_PARITY_NONE,
  SSH_SERIAL_PARITY_EVEN,
  SSH_SERIAL_PARITY_ODD
} SshSerialParity;

/* Number of stop bits in the line */
typedef enum {
  SSH_SERIAL_STOP_BITS_1,
  SSH_SERIAL_STOP_BITS_2
} SshSerialStopBits;

/* Input modes */
typedef enum {
  SSH_SERIAL_MODE_RAW,		/* Raw input and output, no input nor output
				   processing done. */
  SSH_SERIAL_MODE_RAW_LOCAL,	/* Raw input and output, no input nor output
				   processing done, no modem control, just
				   local line. */
  SSH_SERIAL_MODE_CANON,	/* Canonical mode, input and output processing.
				 */
  SSH_SERIAL_MODE_CANON_LOCAL,	/* Canonical mode, input and output processing.
				   No modem control, just local line. */
  SSH_SERIAL_MODE_CANON_ECHO,	/* Canonical mode, input and output processing.
				   Echo input characters. */
  SSH_SERIAL_MODE_CANON_ECHO_LOCAL /* Canonical mode, input and output
				      processing. No modem control, just local
				      line. Echo input characters. */
} SshSerialMode;

/* Flow control */
typedef enum {
  SSH_SERIAL_FLOW_NONE,		/* No flow control */
  SSH_SERIAL_FLOW_XON_XOFF,	/* XON/XOFF */
  SSH_SERIAL_FLOW_RTS_CTS	/* RTS/CTS */
} SshSerialFlowControl;
  
/* Set serial stream parameters, returns TRUE if successful */
Boolean ssh_serial_stream_params(SshStream stream,
				 SshSerialSpeed input_speed,
				 SshSerialSpeed output_speed,
				 SshSerialBits bits,
				 SshSerialParity parity,
				 SshSerialStopBits stop_bits,
				 SshSerialMode mode,
				 SshSerialFlowControl flow_control);

/* Modem control flags */
typedef enum {
  SSH_SERIAL_MODEM_DTR = 0x01,
  SSH_SERIAL_MODEM_RTS = 0x02,
  SSH_SERIAL_MODEM_CTS = 0x04,
  SSH_SERIAL_MODEM_CD = 0x08,
  SSH_SERIAL_MODEM_RI = 0x10,
  SSH_SERIAL_MODEM_DSR = 0x20
} SshSerialModemControl;

/* Set modem control flags, return TRUE if successful */
Boolean ssh_serial_stream_modem_set(SshStream stream,
				    SshSerialModemControl modem);

/* Clear modem control flags, return TRUE if successful */
Boolean ssh_serial_stream_modem_clear(SshStream stream,
				      SshSerialModemControl modem);
  
/* Set modem control flags, return TRUE if successful */
Boolean ssh_serial_stream_modem_get(SshStream stream,
				    SshSerialModemControl *modem);

#endif /* SSHSERIALSTREAM_H */
