/*

auths-passwd.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1997 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Password authentication, server-side.  This calls functions in machine-specific
files to perform the actual authentication.

*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshauth.h"
#include "sshmsgs.h"
#include "auths-passwd.h"
#include "sshuser.h"
#include "sshserver.h"
#include "sshconfig.h"

#define SSH_DEBUG_MODULE "Ssh2AuthPasswdServer"

/* Password authentication.  This handles all forms of password authentication,
   including local passwords, kerberos, and secure rpc passwords. */

SshAuthServerResult ssh_server_auth_passwd(SshAuthServerOperation op,
					   const char *user,
					   SshBuffer *packet,
					   const unsigned char *session_id,
					   size_t session_id_len,
					   void **state_placeholder,
					   void **longtime_placeholder,
					   void *method_context)
{
  SshUser uc = (SshUser)*longtime_placeholder;
  Boolean change_request;
  char *password, *prompt;
  int disable_method = 0;

  SSH_DEBUG(6, ("auth_passwd op = %d  user = %s", op, user));
  
  switch (op)
    {
    case SSH_AUTH_SERVER_OP_START:
      /* If user context not yet allocated, do it now. */
      if (uc == NULL)
	{
	  uc = ssh_user_initialize(user);
	  *longtime_placeholder = (void *)uc;
	}

      {
	SshConfig serverconf = ((SshServer)method_context)->config;

	serverconf->password_guesses--;
	if (serverconf->password_guesses <= 0)
	  {
	    /* If this attempt is not succesful, disable this method. */
	    disable_method = 1;
	  }


	/* If user context allocation failed, the user does not exist. */
	if (!uc)
	  goto password_bad;

	/* Reject the login if the user is not allowed to log in. */
	if (!ssh_user_login_is_allowed(uc))
	  {
	    ssh_debug("ssh_server_auth_passwd: login by '%s' not allowed.",
		      ssh_user_name(uc));
	    goto password_bad;
	  }
#ifndef SSHDIST_WINDOWS
        else if(ssh_user_uid(uc) == SSH_UID_ROOT &&
		serverconf->permit_root_login == FALSE)
	  {
	    /* XXX These should be logged, but where? */
	    ssh_debug("ssh_server_auth_passwd: root logins are not permitted.");
	    return SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED;
	  }
#endif /* SSHDIST_WINDOWS */
      }
      
      /* Parse the password authentication request. */
      if (ssh_decode_buffer(packet,
			    SSH_FORMAT_BOOLEAN, &change_request,
			    SSH_FORMAT_UINT32_STR, &password, NULL,
			    SSH_FORMAT_END) == 0)
	{
	  ssh_debug("ssh_server_auth_passwd: bad packet");
	  goto password_bad;
	}

      /* Password changing requests should only be received as continuation
	 messages. */
      if (change_request)
	{
	  ssh_debug("ssh_server_auth_passwd: changing password cannot start.");
	  goto password_bad;
	}
      
      /* Sanity check: do not pass excessively long passwords to system
	 functions to avoid buffer overflows in operating system code. */
      if (strlen(password) > 64)
	{
	  ssh_debug("ssh_server_auth_passwd: password too long.");
	  ssh_xfree(password);
	  goto password_bad;
	}

      /* Try SECURE RPC passwords.  We do this first, as this might be
	 needed to access disks. */
      if (ssh_user_validate_secure_rpc_password(uc, password))
	{
	  ssh_debug("ssh_server_auth_passwd: accepted by secure rpc");
	  goto password_ok;
	}

      /* Try KERBEROS passwords.  This might also be needed to access
	 disks. */
      if (ssh_user_validate_kerberos_password(uc, password))
	{
	  ssh_debug("ssh_server_auth_passwd: accepted by kerberos passwd");
	  goto password_ok;
	}

      /* Try a local password (either normal or shadow). */
      if (ssh_user_validate_local_password(uc, password))
	{
	  ssh_debug("ssh_server_auth_passwd: accepted by local passwd");
	  goto password_ok;
	}
      
      ssh_xfree(password);
      goto password_bad;

    password_bad:
      return (disable_method ?
	      SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED :
	      SSH_AUTH_SERVER_REJECTED);

    password_ok:
      /* Password authentication passed, but we still need to check whether
	 the password needs to be changed. */
      ssh_xfree(password);

      /* Check if the user's password needs to be changed. */
      if (ssh_user_password_must_be_changed(uc, &prompt))
	{
	  ssh_buffer_clear(packet);
	  ssh_encode_buffer(packet,
			    SSH_FORMAT_UINT32,
			    SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
			    SSH_FORMAT_UINT32_STR, prompt, strlen(prompt),
			    SSH_FORMAT_END);
	  ssh_xfree(prompt);
	  return SSH_AUTH_SERVER_CONTINUE_WITH_PACKET_BACK;
	}

      return SSH_AUTH_SERVER_ACCEPTED;

    case SSH_AUTH_SERVER_OP_ABORT:
      return SSH_AUTH_SERVER_REJECTED;
      
    case SSH_AUTH_SERVER_OP_CONTINUE:
      ssh_debug("ssh_server_auth_passwd: XXX CONTINUE not yet implemented");
      return SSH_AUTH_SERVER_REJECTED;
      
    case SSH_AUTH_SERVER_OP_UNDO_LONGTIME:
    case SSH_AUTH_SERVER_OP_CLEAR_LONGTIME:
      if (uc != NULL)
	{
	  if (!ssh_user_free(uc, op == SSH_AUTH_SERVER_OP_UNDO_LONGTIME))
	    {
	      /* XXX failed unto undo everything. Should disconnect, but we
		 don't yet have the interface for that. */
	      ssh_fatal("ssh_server_auth_passwd: undo failed XXX");
	    }
	}
      *longtime_placeholder = NULL;
      return SSH_AUTH_SERVER_REJECTED;
      
    default:
      ssh_fatal("ssh_server_auth_passwd: unknown op %d", (int)op);
    }
  /*NOTREACHED*/
  return SSH_AUTH_SERVER_REJECTED;
}
