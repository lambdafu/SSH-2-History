/*

  Author: Tomi Salo <ttsalo@ssh.fi>
  	  Tatu Ylonen <ylo@ssh.fi>

  Copyright (c) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Unix implementation of the UDP communications interface.

  */

/*
 * $Id: sshunixudp.c,v 1.8 1998/08/06 19:03:11 kivinen Exp $
 * $Log: sshunixudp.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshdebug.h"
#include "sshudp.h"
#include "sshtcp.h"
#include "sshtimeouts.h"
#include "sshunixeloop.h"

#define SSH_DEBUG_MODULE "SshUdp"

#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else /* Some old linux systems at least have in_system.h instead. */
#include <netinet/in_system.h>
#endif /* HAVE_NETINET_IN_SYSTM_H */
#if !defined(__PARAGON__)
#include <netinet/ip.h>
#endif /* !__PARAGON__ */


/* Internal function; converts ip address from string format to in_addr. */
extern Boolean ssh_string_to_addr(const char *s, struct in_addr *addr);

/* Internal representation of Listener structure, not exported */
struct SshUdpListenerRec
{
  int sock;
  SshUdpCallback callback;
  void *context;
  struct sockaddr_in default_addr;
};

void ssh_socket_udp_io_cb(unsigned int events, void *context)
{
  SshUdpListener listener = (SshUdpListener)context;

  if (events & SSH_IO_READ)
    {
      /* Call the callback to inform about a received packet or
         notification. */
      if (listener->callback)
	(*listener->callback)(listener, listener->context);
    }
}

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
				     void *context)
{
  SshUdpListener listener;
  struct sockaddr_in sinaddr;
  int ret, port;

  SSH_TRACE(5, ("Making listener"));
  
  /* Allocate and initialize the listener context. */
  listener = ssh_xmalloc(sizeof(*listener));
  memset(listener, 0, sizeof(*listener));
  listener->context = context;
  listener->callback = callback;
  listener->default_addr.sin_family = AF_INET;

  /* Create the socket. */
  listener->sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (listener->sock < 0)
    {
      ssh_xfree(listener);
      return NULL;
    }

  if (local_address != NULL || local_port != NULL)
    {
      /* Initialize the address structure for the local address. */
      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;

      if (local_port != NULL)
	{
	  /* Look up the service name for the local port. */
	  port = ssh_tcp_get_port_by_service(local_port, "udp");
	  if (port == -1)
	    {
	      close(listener->sock);
	      ssh_xfree(listener);
	      return NULL;
	    }
	  sinaddr.sin_port = htons(port);
	}

      if (local_address != NULL)
	{
	  /* Decode the IP address.  Host names are not accepted. */
	  if (!ssh_string_to_addr(local_address, &sinaddr.sin_addr))
	    {
	      close(listener->sock);
	      ssh_xfree(listener);
	      return NULL;
	    }
	}
      ret = bind(listener->sock, (struct sockaddr *)&sinaddr,
		 sizeof(sinaddr));
      if (ret < 0)
	{
	  ssh_debug("ssh_udp_make_listener: bind failed: %s", strerror(errno));
	  close(listener->sock);
	  ssh_xfree(listener);
	  return NULL;
	}
    }

  if (remote_address != NULL || remote_port != NULL)
    {
      /* Initialize the address structure for the remote address. */
      memset(&sinaddr, 0, sizeof(sinaddr));
      sinaddr.sin_family = AF_INET;

      if (remote_port != NULL)
	{
	  /* Look up the service name for the remote port. */
	  port = ssh_tcp_get_port_by_service(remote_port, "udp");
	  if (port == -1)
	    {
	      close(listener->sock);
	      ssh_xfree(listener);
	      return NULL;
	    }
	  sinaddr.sin_port = htons(port);
	}

      if (remote_address != NULL)
	{
	  /* Decode the IP address.  Host names are not accepted. */
	  if (!ssh_string_to_addr(remote_address, &sinaddr.sin_addr))
	    {
	      close(listener->sock);
	      ssh_xfree(listener);
	      return NULL;
	    }
	}

      /* Save the remote address as the default address for sent packets. */
      listener->default_addr = sinaddr;

      /* Connect the socket, so that we will receive unreachable
	 notifications. */
      ret = connect(listener->sock, (struct sockaddr *)&sinaddr,
		    sizeof(sinaddr));
      if (ret < 0)
	{
	  ssh_debug("ssh_udp_make_listener: connect failed: %s",
		    strerror(errno));
	  close(listener->sock);
	  ssh_xfree(listener);
	  return NULL;
	}
    }

#ifdef SO_SNDBUF
  {
    int buf_len;
    
    buf_len = 65535;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_SNDBUF, &buf_len,
		   sizeof(int)) < 0)
      {
	ssh_debug("ssh_udp_make_listener: setsockopt SO_SNDBUF failed: %s",
		  strerror(errno));
      }
  }
#endif /* SO_SNDBUF */

#ifdef SO_RCVBUF
  {
    int buf_len;
    
    buf_len = 65535;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_RCVBUF, &buf_len,
		   sizeof(int)) < 0)
      {
	ssh_debug("ssh_udp_make_listener: setsockopt SO_RCVBUF failed: %s",
		  strerror(errno));
      }
  }
#endif /* SO_RCVBUF */

  /* Socket creation succeeded. Do the event loop stuff */
  ssh_io_register_fd(listener->sock, ssh_socket_udp_io_cb, (void *)listener);
  ssh_io_set_fd_request(listener->sock, SSH_IO_READ);
  
  return listener;
}

/* Destroys the udp listener. */

void ssh_udp_destroy_listener(SshUdpListener listener)
{
  ssh_io_unregister_fd(listener->sock, FALSE);
  close(listener->sock);
  ssh_xfree(listener);
}

/* Ask for permission to send broadcast packets */
void ssh_udp_set_broadcasting(SshUdpListener listener, Boolean allow)
{
  int option;
  if (allow)
    option = 1;
  else
    option = 0;
#ifdef SO_BROADCAST
  if (setsockopt(listener->sock, SOL_SOCKET, SO_BROADCAST, &option,
		 sizeof(int)) < 0)
    {
      ssh_debug("ssh_udp_set_broadcasting: setsockopt SO_BROADCAST failed: %s",
		strerror(errno));
    }
#endif /* SO_BROADCAST */
}

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
			 size_t *datagram_len_return)
{
  size_t ret;
  struct sockaddr_in from_addr;
  int port;
  int fromlen = sizeof(struct sockaddr_in);
  ret = recvfrom(listener->sock, datagram_buffer, datagram_buffer_len,
		 0, (struct sockaddr *)&from_addr, &fromlen);
  SSH_TRACE(6, ("Read result %ld", (long)ret));
  if (ret < 0)
    {
      switch (errno)
	{
	default:
	  return SSH_UDP_NO_DATA;

#ifdef EHOSTDOWN
	case EHOSTDOWN:
#endif /* EHOSTDOWN */
#ifdef EHOSTUNREACH
	case EHOSTUNREACH:
#endif /* EHOSTUNREACH */
	  return SSH_UDP_HOST_UNREACHABLE;
	  
#ifdef ECONNREFUSED
	case ECONNREFUSED:
#endif /* ECONNREFUSED */
#ifdef ENOPROTOOPT
	case ENOPROTOOPT:
#endif /* ENOPROTOOPT */
	  return SSH_UDP_PORT_UNREACHABLE;
	}
    }

  if (fromlen >= sizeof(struct sockaddr_in))
    {

      /* Format port number in user buffer. */
      if (remote_port != NULL)
	{
	  port = ntohs(from_addr.sin_port);
	  snprintf(remote_port, remote_port_len, "%d", port);
	}

      /* Format source address in user buffer. */
      if (remote_address != NULL)
	ssh_inet_v4tostr(remote_address, remote_address_len,
			 (SshUInt32) from_addr.sin_addr.s_addr); /* XXX */
    }
  
  /* Return the length of the received packet. */
  if (datagram_len_return)
    *datagram_len_return = ret;
  
  return SSH_UDP_OK;
}

/* This sends udp datagram to remote destination. This call always success, or
   the if not then datagram is silently dropped (udp is not reliable anyways */

void ssh_udp_send(SshUdpListener listener, 
		  const char *remote_address, const char *remote_port, 
		  const unsigned char *datagram_buffer, size_t datagram_len)
{
  struct sockaddr_in to_addr;
  int port;

  SSH_TRACE(6, ("Send %ld bytes", (long)datagram_len));
  
  /* Copy the default address for sending. */
  memcpy(&to_addr, &listener->default_addr, sizeof(to_addr));

  /* Decode the port number if given. */
  if (remote_port != NULL)
    {
      port = ssh_tcp_get_port_by_service(remote_port, "udp");
      if (port == -1)
	{
	  ssh_debug("ssh_udp_send: bad port %s", remote_port);
	  return;
	}
      to_addr.sin_port = htons(port);
    }

  /* Decode the destination address if given. */
  if (remote_address != NULL)
    {
      /* First check if it is already an ip address. */
      if (!ssh_string_to_addr(remote_address, &to_addr.sin_addr))
	{
	  ssh_debug("ssh_udp_send: bad address %s", remote_address);
	  return;
	}
    }

  /* Send the packet. */
  if (sendto(listener->sock, datagram_buffer, datagram_len, 0,
	     (struct sockaddr *)&to_addr, sizeof(to_addr)) < 0)
    ssh_debug("ssh_udp_send: sendto failed: %s", strerror(errno));
}
