/*

  auths-pubkey.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
		  
  Public key authentication, server-side.

*/

#include "ssh2includes.h"
#include "sshencode.h"
#include "sshauth.h"
#include "sshmsgs.h"
#include "auths-pubkey.h"
#include "sshuser.h"
#include "sshconfig.h"
#include "sshgetput.h"
#include "pubkeyencode.h"
#include "sshserver.h"
#include "sshdebug.h"
#include "userfile.h"
#include "sshuserfiles.h"
#ifdef SSHDIST_WINDOWS

#endif /* SSHDIST_WINDOWS */

#define SSH_DEBUG_MODULE "Ssh2AuthPubKeyServer"

/* Check whether the key is authorized for login as the specified
   user from specified host.  If check_signatures if FALSE, this is not 
   required to verify signatures on authorization certificates.  This may 
   use a local database or the certificates to determine authorization. */

Boolean ssh_server_auth_pubkey_verify(SshUser uc, char *remote_ip,
				      unsigned char *certs,
				      size_t certs_len, 
				      unsigned char *sig,
				      size_t sig_len,
				      const unsigned char *session_id,
				      size_t session_id_len,
				      SshServer server,
				      Boolean check_signatures,
                                      void * context)
{
  unsigned char *tblob;
  size_t tbloblen;
  SshPublicKey pubkey;
  Boolean sig_ok;
  SshBuffer *buf;
  char filen[1024];
  int i, n;
#ifndef SSHDIST_WINDOWS
  char *userdir, **vars = NULL, **vals = NULL;
  
  userfile_init(ssh_user_name(uc), ssh_user_uid(uc), ssh_user_gid(uc),
		NULL, NULL);

#else /* SSHDIST_WINDOWS */







#endif /* SSHDIST_WINDOWS */

  SSH_DEBUG(6, ("auth_pubkey_verify user = %s  check_sig = %s",
		ssh_user_name(uc), check_signatures ? "yes" : "no"));

  /* open and read the user's authorization file */

  if (certs_len < 16)  /* ever seen a 12-byte public key ? */
    goto exit_false;

#ifndef SSHDIST_WINDOWS
  if ((userdir = ssh_userdir(uc, FALSE)) == NULL)
    goto exit_false;


  snprintf(filen, sizeof(filen), "%s/%s", userdir,
	   server == NULL || server->common == NULL || 
	   server->common->config == NULL || 
	   server->common->config->authorization_file == NULL ?
	   SSH_AUTHORIZATION_FILE : 
	   server->common->config->authorization_file);

  n = ssh2_parse_config(uc, remote_ip ? remote_ip : "",
			filen, &vars, &vals, NULL);

  /* now see if we find matching "key" - definitions */

  for (i = 0; i < n; i++)
    { 
      if (strcmp(vars[i], "key") == 0)
	{
	  snprintf(filen, sizeof(filen), "%s/%s", userdir,
		   vals[i]);
	  SSH_DEBUG(6, ("auth_pubkey_verify: key %d, %s", i, filen));
	  tblob = NULL;
	  if (ssh_key_blob_read(uc, filen, NULL, &tblob, &tbloblen, NULL) 
	      != SSH_KEY_MAGIC_PUBLIC)
	    {
	      if (tblob != NULL)
 		ssh_xfree(tblob);
	      ssh_debug("unable to read the %s's public key %s",
			ssh_user_name(uc), filen); 
	    }
	  else 
	    {
	      if (tbloblen == certs_len)
		if (memcmp(certs, tblob, tbloblen) == 0)
		  {
		    if(check_signatures)
		      {
			if (i + 1 < n && strcmp(vars[i + 1], FORCED_COMMAND_ID) == 0)
			  {
			    server->common->config->forced_command = 
			      ssh_xstrdup(vals[i + 1]);
			  }
		      }
		    ssh_xfree(tblob);		    
		    goto match;
		  }
	      ssh_xfree(tblob);
	    }
	}    
    }
#else /* SSHDIST_WINDOWS */








































#endif /* SSHDIST_WINDOWS */

  SSH_DEBUG(6, ("auth_pubkey_verify: the key didn't match."));

#ifndef SSHDIST_WINDOWS
  ssh_xfree(userdir);

  ssh_free_varsvals(n, vars, vals);
#endif /* SSHDIST_WINDOWS */

  goto exit_false;

  /* ok, this public key can be used for authentication .. */
match:

  SSH_DEBUG(6, ("auth_pubkey_verify: the key matched."));
    
#ifndef SSHDIST_WINDOWS
  ssh_xfree(userdir);

  ssh_free_varsvals(n, vars, vals);
#else /* SSHDIST_WINDOWS */

#endif /* SSHDIST_WINDOWS */

  if (!check_signatures)
    goto exit_true;

  /* extract the signature and decode the public key blob */

  if ((pubkey = ssh_decode_pubkeyblob(certs, tbloblen)) == NULL)
    goto exit_false;
     
  /* construct a throw-away SSH_MSG_USERAUTH_REQUEST message */

  buf = ssh_buffer_allocate();
  ssh_buffer_append(buf, session_id, session_id_len);

  ssh_encode_buffer(buf,
                    SSH_FORMAT_CHAR, SSH_MSG_USERAUTH_REQUEST,
                    SSH_FORMAT_UINT32_STR, ssh_user_name(uc),
		    strlen(ssh_user_name(uc)),
                    SSH_FORMAT_UINT32_STR, SSH_USERAUTH_SERVICE,
		    strlen(SSH_USERAUTH_SERVICE),
                    SSH_FORMAT_BOOLEAN, TRUE,
                    SSH_FORMAT_UINT32_STR, certs, tbloblen,
		    SSH_FORMAT_END);

  SSH_DEBUG_HEXDUMP(7, ("auth_pubkey_verify: verifying following data"),
		    ssh_buffer_ptr(buf), ssh_buffer_len(buf));
  SSH_DEBUG_HEXDUMP(7, ("auth_pubkey_verify: signature"), sig, sig_len);

  /* verify the signature */

  sig_ok = ssh_public_key_verify_signature(pubkey,
					   sig, sig_len,
					   ssh_buffer_ptr(buf),
					   ssh_buffer_len(buf));   
  ssh_public_key_free(pubkey);
  ssh_buffer_free(buf);

  if (!sig_ok)
    {
      ssh_warning("Public key operation failed for %s.", ssh_user_name(uc));
      goto exit_false;
    }

exit_true:
#ifndef SSHDIST_WINDOWS
  userfile_uninit();
#endif /* SSHDIST_WINDOWS */

  return TRUE;

exit_false:
#ifndef SSHDIST_WINDOWS
  userfile_uninit();
#endif /* SSHDIST_WINDOWS */
  /* if login failed, free memory (possibly) allocated by forced command,
     so that we don't accidentally execute commands with wrong keys. */
  ssh_xfree(server->common->config->forced_command);
  server->common->config->forced_command = NULL;

  return FALSE;
}


/* Public key authentication.  The possession of a private key serves
   as authentication. */

SshAuthServerResult ssh_server_auth_pubkey(SshAuthServerOperation op,
					   const char *user,
					   SshBuffer *packet,
					   const unsigned char *session_id,
					   size_t session_id_len,
					   void **state_placeholder,
					   void **longtime_placeholder,
					   void *method_context)
{
  SshUser uc = (SshUser)*longtime_placeholder;
  unsigned char *certs, *data, *sig;
  size_t certs_len, sig_len, len, bytes;
  SshServer server;
  Boolean real_request;
 
  SSH_DEBUG(6, ("auth_pubkey op = %d  user = %s", op, user));

  server = (SshServer) method_context;

  switch (op)
    {
    case SSH_AUTH_SERVER_OP_START:
      /* If user context not yet allocated, do it now. */
      if (uc == NULL)
	{
	  uc = ssh_user_initialize(user, TRUE);
	  *longtime_placeholder = (void *)uc;
	}

      /* If user context allocation failed, the user probably does not 
	 exist. */

      if (!uc)
	return SSH_AUTH_SERVER_REJECTED;

      /* Reject the login if the user is not allowed to log in. */
      if (!ssh_user_login_is_allowed(uc))
	{
	  ssh_debug("ssh_server_auth_pubkey: login by '%s' not allowed.");
	  return SSH_AUTH_SERVER_REJECTED;
	}
      
      /* Parse the publickey authentication request. */

      data = ssh_buffer_ptr(packet);
      len = ssh_buffer_len(packet);
      sig = NULL;
      sig_len = 0;

      bytes = ssh_decode_array(data, len,
			       SSH_FORMAT_BOOLEAN, &real_request,
			       SSH_FORMAT_UINT32_STR_NOCOPY,
			       &certs, &certs_len,
			       SSH_FORMAT_END);
      if (bytes == 0 || (!real_request && bytes != len))
	{
	  ssh_debug("ssh_server_auth_pubkey: bad packet");
	  return SSH_AUTH_SERVER_REJECTED;
	}

      if (real_request)
	{
	  if (ssh_decode_array(data + bytes, len - bytes,
			       SSH_FORMAT_UINT32_STR, &sig, &sig_len,
			       SSH_FORMAT_END) != len - bytes)
	    {
	      ssh_debug("ssh_server_auth_pubkey: bad packet (real request)");
	      return SSH_AUTH_SERVER_REJECTED;
	    }
	}
      
      /* Check whether the key is authorized for login as the specified
	 user.  If real_request if FALSE, this does not need to verify
	 signatures on certificates as the result is only advisory. */
      if (ssh_server_auth_pubkey_verify(uc, server->common->remote_ip,
					certs, certs_len, 
					sig, sig_len,
					session_id, session_id_len,
					server,
					real_request, 
					server->config->callback_context) == FALSE)
	{
	  if (sig != NULL)
	    ssh_xfree(sig);
	  SSH_DEBUG(6, ("auth_pubkey_verify returned false"));
	  return SSH_AUTH_SERVER_REJECTED;
	}
      
      if (real_request)
	{	  
	  /* Free the signature blob. */
	  ssh_xfree(sig);

	  /* Check for root login and forced commands */
#ifndef SSHDIST_WINDOWS
          if(ssh_user_uid(uc) == SSH_UID_ROOT &&
	     server->config->permit_root_login == FALSE)
	    {
	      if(!server->config->forced_command)
		{ 
		  /* XXX These should be logged, but where? */
		  ssh_debug("ssh_server_auth_pubkey: root logins"
			    " are not permitted.");
		  return SSH_AUTH_SERVER_REJECTED_AND_METHOD_DISABLED;
		}
	      else
		{
		  ssh_debug("Root login accepted for forced command.");
		}
	    }
#endif /* SSHDIST_WINDOWS */

	  /* Because it is an real request, and it has been verified, the
	     authorization is granted. */
	  return SSH_AUTH_SERVER_ACCEPTED;
	}

      /* It was just a probe request, return status now. */
      
      ssh_buffer_clear(packet);
      ssh_encode_buffer(packet,			   
			SSH_FORMAT_CHAR, SSH_MSG_USERAUTH_PK_OK,
			SSH_FORMAT_UINT32_STR, certs, certs_len,
			SSH_FORMAT_END);
      return SSH_AUTH_SERVER_REJECTED_WITH_PACKET_BACK;

    case SSH_AUTH_SERVER_OP_ABORT:
      return SSH_AUTH_SERVER_REJECTED;
      
    case SSH_AUTH_SERVER_OP_CONTINUE:
      ssh_debug("ssh_server_auth_pubkey: unexpected CONTINUE");
      return SSH_AUTH_SERVER_REJECTED;
      
    case SSH_AUTH_SERVER_OP_UNDO_LONGTIME:
    case SSH_AUTH_SERVER_OP_CLEAR_LONGTIME:
      if (uc != NULL)
	{
	  if (!ssh_user_free(uc, op == SSH_AUTH_SERVER_OP_UNDO_LONGTIME))
	    ssh_fatal("ssh_server_auth_pubkey: undo failed XXX");
	}
      *longtime_placeholder = NULL;
      return SSH_AUTH_SERVER_REJECTED;
      
    default:
      ssh_fatal("ssh_server_auth_pubkey: unknown op %d", (int)op);
    }

  /* NOTREACHED */
  return SSH_AUTH_SERVER_REJECTED;
}
