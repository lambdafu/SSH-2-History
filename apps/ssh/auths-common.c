/*

  auths-common.c

  Author: Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.
                  
  Common functions for both pubkey- and password-authentication on the
  server side.

*/

#include "sshincludes.h"
#include "sshuser.h"
#include "auths-common.h"
#include "sshcommon.h"
#include "match.h"

#define SSH_DEBUG_MODULE "Ssh2AuthCommonServer"

/* returns FALSE on success. */
Boolean ssh_server_auth_check_user(SshUser *ucp, const char *user,
                                   SshConfig config)
{
  SshUser uc = *ucp;
  
  /* If user context not yet allocated, do it now. */
  if (uc == NULL)
    {
      uc = ssh_user_initialize(user, TRUE);
      if (!uc)
        {
          /* If user context allocation failed, the user probably does not 
             exist. */
          ssh_log_event(config->log_facility,
                        SSH_LOG_WARNING,
                        "User \"%s\" does not exist.", user);
          return TRUE;
        }       
      *ucp = uc;
    }

  /* Reject the login if the user is not allowed to log in. */
  if (!ssh_user_login_is_allowed(uc))
    {
      ssh_log_event(config->log_facility,
                    SSH_LOG_WARNING,
                    "login to account '%s' not allowed.",
                    ssh_user_name(uc));
      SSH_DEBUG(2, ("login to account '%s' not allowed.",\
                    ssh_user_name(uc)));
      return TRUE;
    }
  return FALSE;
}

/* Helper function to check whether given host name or ip-address
   matches a specified pattern. Returns FALSE if a match is found, and
   TRUE otherwise. */
Boolean match_host_id(char *host_name, char *host_ip, char *pattern)
{
  Boolean is_ip_pattern;
  const char *p;
  
  /* if the pattern does not contain any alpha characters then
     assume that it is a IP address (with possible wildcards),
     otherwise assume it is a hostname */
  if (host_ip)
    is_ip_pattern = TRUE;
  else
    is_ip_pattern = FALSE;

  for(p = pattern; *p; p++)
    if (!(isdigit(*p) || *p == '.' || *p == '?' || *p == '*'))
      {
        is_ip_pattern = FALSE;
        break;
      }
  if (is_ip_pattern)
    {
      return !ssh_match_pattern(host_ip, pattern);
    } 
  return !ssh_match_pattern(host_name, pattern);
}

/* This is the function for checking a host{name,ip} against
   {Allow,Deny}Hosts parameters. Also checks remote host against
   statements in the AllowDenyHostsFile. Returns FALSE if connection
   from host is allowed, TRUE otherwise. */
Boolean ssh_server_auth_check_host(SshCommon common)
{
  SshConfig config = common->config;
  int i = 0, length = 0;
  
  /* XXX AllowDenyHostsFile */
  /* XXX subnet masks "130.240.0.0/16" */
  /* XXX address ranges "130.240.20.15-130.240.21.76" */


  /* wildcards "130.240.*" or "*.foo.bar" */

  /* Check whether host is denied. Use ssh1-style policy, ie. if host
     is in DenyHosts, connection is denied even if the same host
     matches in AllowHosts.*/
  if (config->denied_hosts)
    {
      for (ssh_dllist_rewind(config->denied_hosts), i = 0,
             length = ssh_dllist_length(config->denied_hosts);
           i < length; ssh_dllist_fw(config->denied_hosts, 1), i++)
        if (!match_host_id(common->remote_host, common->remote_ip,
                          (char *)ssh_dllist_current(config->denied_hosts)))
          return TRUE;
    }

  if (config->allowed_hosts)
    {
      for (ssh_dllist_rewind(config->allowed_hosts), i = 0,
             length = ssh_dllist_length(config->allowed_hosts);
           i < length; ssh_dllist_fw(config->allowed_hosts, 1), i++)
        if (!match_host_id(common->remote_host, common->remote_ip,
                          (char *)ssh_dllist_current(config->allowed_hosts)))
          return FALSE;
      return TRUE;
    }
  
  
  /* RequireReverseMapping */
  if (config->require_reverse_mapping)
    {
      if (strcmp(common->remote_host, common->remote_ip) == 0)
        {
          /* If remote host's ip-address couldn't be mapped to a
             hostname and RequireReverseMapping = 'yes', deny
             connection.*/
          return TRUE;
        }
    }
  
  return FALSE;
}
