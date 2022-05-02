/*

  Author: Tomi Salo <ttsalo@ssh.fi>
  	  Tatu Ylonen <ylo@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Portable interface for UDP communications.  (The implementation is
  machine-dependent, but provides this interface on all platforms.)

*/

#ifndef SSHUDP_H
#define SSHUDP_H

/* Data type for an UDP listener. */
typedef struct SshUdpListenerRec *SshUdpListener;

/* Callback function to be called when a packet or notification is
   available from the udp listener.  ssh_udp_read should be called
   from the callback. */
typedef void (*SshUdpCallback)(SshUdpListener listener, void *context);

/* Creates a listener for sending and receiving UDP packets.  The listener is
   connected if remote_address is non-NULL.  Connected listeners may receive
   notifications about the destination host/port being unreachable.
     local_address    local address for sending; NULL chooses automatically
     local_port       local port for receiving udp packets
     remote_address   specifies the remote address for this listener
     		      is non-NULL.  If specified, unreachable notifications
		      may be received for packets sent to the address.
     remote_port      remote port for packets sent using this listener, or NULL
     callback         function to call when packet or notification available
     context          argument to pass to the callback. */
SshUdpListener ssh_udp_make_listener(const char *local_address,   
				     const char *local_port,
				     const char *remote_address,
				     const char *remote_port,
				     SshUdpCallback callback,
				     void *context);

/* Destroys the udp listener. */
void ssh_udp_destroy_listener(SshUdpListener listener);

/* Return values for ssh_udp_read. */
typedef enum {
  /* A packet was successfully read from the listener. */
  SSH_UDP_OK,

  /* A host or network unreachable notification was received. */
  SSH_UDP_HOST_UNREACHABLE,

  /* A port unreachable notification was received. */
  SSH_UDP_PORT_UNREACHABLE,

  /* No packet or notification is available from the listener at this time. */
  SSH_UDP_NO_DATA
} SshUdpError;

/* Convert UDP error to string */
DLLEXPORT char * DLLCALLCONV
ssh_udp_error_string(SshUdpError error);

/* Ask for permission to send broadcast packets */
void ssh_udp_set_broadcasting(SshUdpListener listener, Boolean allow);

/* Reads the received packet or notification from the listener.  This
   function should be called from the listener callback.  This can be
   called multiple times from a callback; each call will read one more
   packet or notification from the listener until no more are
   available. */
SshUdpError ssh_udp_read(SshUdpListener listener,
			 char *remote_address, size_t remote_address_len,
			 char *remote_port, size_t remote_port_len,
			 unsigned char *datagram_buffer,
			 size_t datagram_buffer_len,
			 size_t *datagram_len_return);

/* This sends udp datagram to remote destination. This call always success, or
   the if not then datagram is silently dropped (udp is not reliable anyways */
void ssh_udp_send(SshUdpListener listener, 
		  const char *remote_address, const char *remote_port, 
		  const unsigned char *datagram_buffer, size_t datagram_len);


#endif /* SSHUDP_H */
