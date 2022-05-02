/*

sshconfig.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Processing configuration data in SSH (both client and server).

*/

#include "ssh2includes.h"
#include "sshconfig.h"
#include "sshuser.h"
#include "userfile.h"
#include "sshuserfiles.h"
#include "sshcipherlist.h"
#include "namelist.h"

#define SSH_DEBUG_MODULE "SshConfig"

/* separate (commandline)options from their parameters */
void ssh_split_arguments(int argc, char **argv, int *dest_ac, char ***dest_av)
{
  int temp_ac = 0, i;
  char **temp_av;
  
  int alloc = argc + 1;

  temp_av = ssh_xcalloc(alloc, sizeof(char*));
  
  /* count possible options and parameters */
  for (i = 0; i < argc ; i++)
    {
      if ( alloc < temp_ac + 3)
        {
          alloc = temp_ac + 3;
          temp_av = ssh_xrealloc(temp_av, alloc*sizeof(char*));
        }
      
      if (argv[i][0] == '-' || argv[i][0] == '+')
        {
          if(argv[i][1] && argv[i][2])
            {
              temp_av[temp_ac] = ssh_xstrdup(argv[i]);
              temp_av[temp_ac][2] = '\0';
              temp_av[++temp_ac] = ssh_xstrdup(argv[i] + 2);
            }
          else
            {
              temp_av[temp_ac] = ssh_xstrdup(argv[i]);
            }
        }
      else
        {
          temp_av[temp_ac] = ssh_xstrdup(argv[i]);        
        }
      temp_ac++;
    }
  temp_av[ temp_ac ] = NULL;
  (*dest_ac) = temp_ac;
  (*dest_av) = temp_av;
}

/* Free the "vars" and "vals" arrays */

void ssh_free_varsvals(int n, char **vars, char **vals)
{
  int i;

  for (i = 0; i < n; i++)
    {
      ssh_xfree(vars[i]);
      ssh_xfree(vals[i]);
    }
  ssh_xfree(vars);
  ssh_xfree(vals); 
}

/* Reads the host key that defined in the config data. 
   Returns TRUE if successful. */

/* Allocates and initializes a config structure */
/* XXX for Windows */
SshConfig ssh_config_init(Boolean client)
{
  SshConfig config;
  config = ssh_xcalloc(1, sizeof(*config));
  config->client = client;

  config->private_host_key = NULL;
  config->public_host_key_blob = NULL;
  config->public_host_key_blob_len = 0;

  config->callback_context = NULL;

  config->random_seed_file = ssh_xstrdup(SSH_RANDSEED_FILE);
  config->forward_agent = TRUE;
  config->forward_x11 = TRUE;
  config->password_authentication = TRUE;
  config->rhosts_authentication = TRUE;
  config->rhosts_pubkey_authentication = TRUE;
  config->pubkey_authentication = TRUE;
  config->force_ptty_allocation = FALSE;
  config->verbose_mode = FALSE;
  config->compression = FALSE;

  config->port = ssh_xstrdup("22");
  config->ciphers = NULL;
  config->user_conf_dir = ssh_xstrdup(SSH_USER_CONFIG_DIRECTORY);
  config->identity_file = ssh_xstrdup(SSH_IDENTIFICATION_FILE);
  config->authorization_file = ssh_xstrdup(SSH_AUTHORIZATION_FILE);

  config->password_prompt = ssh_xstrdup("%U's password: ");
  config->password_guesses = 3;

  config->host_to_connect = NULL;
  config->login_as_user = NULL;
  config->local_forwards = NULL;
  config->remote_forwards = NULL;
  
  config->fall_back_to_rsh = TRUE;
  config->use_rsh = TRUE;
  config->batch_mode = FALSE;
  config->strict_host_key_checking = FALSE;
  config->escape_char = ssh_xstrdup("~");
  config->go_background = FALSE;
  config->use_nonpriviledged_port = FALSE;
  config->dont_read_stdin = FALSE;

  config->permit_root_login = TRUE;
  config->permit_empty_passwords = FALSE;
  config->strict_modes = TRUE;
  config->quiet_mode = FALSE;
  config->fascist_logging = FALSE;
  config->print_motd = TRUE;
  config->keep_alive = TRUE;
  config->listen_address = ssh_xstrdup("0.0.0.0");
  config->login_grace_time = 600;
  config->host_key_file = ssh_xstrdup(SSH_HOSTKEY_FILE);
  config->public_host_key_file = ssh_xstrdup(SSH_PUBLIC_HOSTKEY);
  config->forced_command = NULL;

  config->no_subsystems = 0;
  config->subsystems_allocated = 0;
  config->subsystems = NULL;

#ifdef SSH1_COMPATIBILITY
  config->ssh1_path = ssh_xstrdup(client ? SSH1_PATH : SSHD1_PATH);
  config->ssh1compatibility = TRUE;
#else /* SSH1_COMPATIBILITY */
  config->ssh1_path = NULL;
  config->ssh1compatibility = FALSE;  
#endif /* SSH1_COMPATIBILITY */
  config->ssh_agent_compat = SSH_AGENT_COMPAT_NONE;
  
  return config;
}

/* Frees client configuration data. */

void ssh_config_free(SshConfig config)
{
  size_t i;
  
  /* free all allocated memory */
  ssh_xfree(config->random_seed_file);
  ssh_xfree(config->port);
  ssh_xfree(config->ciphers);
  ssh_xfree(config->identity_file);
  ssh_xfree(config->authorization_file);
  ssh_xfree(config->escape_char);
  ssh_xfree(config->listen_address);
  ssh_xfree(config->host_key_file);
  ssh_xfree(config->password_prompt);
  ssh_xfree(config->public_host_key_file);

  ssh_xfree(config->host_to_connect);
  ssh_xfree(config->login_as_user);
  ssh_xfree(config->local_forwards);
  ssh_xfree(config->remote_forwards);

  ssh_xfree(config->forced_command);

  /* Free subsystem-strings */  
  if (config->no_subsystems > 0 && config->subsystems != NULL)
    for (i = 0; i < config->no_subsystems; i++)
      ssh_xfree(config->subsystems[i]);
  ssh_xfree(config->subsystems);
      
  /* free the host key */
  if (config->client == FALSE)
    {
      if (config->private_host_key != NULL)
        ssh_private_key_free(config->private_host_key);
      ssh_xfree(config->public_host_key_blob);
    }

  memset(config, 0, sizeof(*config));
  ssh_xfree(config);
}


/* Returns default configuration information for the server. */

SshConfig ssh_server_create_config()
{
  return ssh_config_init(FALSE);
}

/* Returns default configuration information for the client. */

SshConfig ssh_client_create_config()
{
  return ssh_config_init(TRUE);
}


/* Set the variable corresponding to `var' to `val' in config */

Boolean ssh_config_set_parameter(SshConfig config, char *var, char *val)
{
  Boolean bool;
  unsigned int i;
  int num;
  SshSubsystem ss;
  
  switch (val[0])
    {
    case 'y':  /* for "yes" */
    case 'Y':
    case 't':  /* for "true" */
    case 'T':
    case 'k':  /* for kylla [finnish] :-) */
    case 'K':
      
      bool = TRUE;
      break;
      
    default:
      bool = FALSE;
    }

  num = atoi(val);

  /* These configuration parameters are common for both client and 
     server */

  if (strcmp(var, "forwardagent") == 0)
    {
      config->forward_agent = bool;
      return FALSE;
    }

  if (strcmp(var, "forwardx11") == 0)
    {
      config->forward_x11 = bool;
      return FALSE;
    }
  
  if (strcmp(var, "passwordauthentication") == 0)
    {
      config->password_authentication = bool;
      return FALSE;
    }
  
  if (strcmp(var, "rhostsauthentication") == 0)
    {
      config->rhosts_authentication = bool;
      return FALSE;
    }
  
  if (strcmp(var, "rhostspubkeyauthentication") == 0 ||
      strcmp(var, "rhostsrsaauthentication") == 0)
    {
      config->rhosts_pubkey_authentication = bool;
      return FALSE;
    }
  
  if (strcmp(var, "pubkeyauthentication") == 0 ||
      strcmp(var, "rsaauthentication") == 0)
    {
      config->pubkey_authentication = bool;
      return FALSE;
    }
  
  if (strcmp(var, "port") == 0)
    {
      if (num >= 1 && num < 65536)
        {
          ssh_xfree(config->port);
          config->port = ssh_xstrdup(val);
        }
      else
        {
          ssh_warning("Ignoring illegal port number %s", val);
          return TRUE;
        }
      return FALSE;
    }
  
  if (strcmp(var, "ciphers") == 0)
    {
      SSH_DEBUG(3, ("Got config cipherlist \"%s\"", val));
      ssh_xfree(config->ciphers);
      if (strcasecmp(val, "any") == 0)
        {
          int x;
          char *hlp1, *hlp2;
          
          hlp1 = ssh_cipher_get_supported_native();
          config->ciphers = ssh_name_list_intersection(SSH_STD_CIPHERS, hlp1);
          hlp2 = ssh_cipher_list_exclude(config->ciphers, "none");
          ssh_xfree(config->ciphers);
          x = strlen(hlp1) + strlen(hlp2) + 2;
          config->ciphers = ssh_xmalloc(x);
          snprintf(config->ciphers, x, "%s,%s", hlp2, hlp1);
          ssh_xfree(hlp1);
          ssh_xfree(hlp2);
          hlp1 = ssh_cipher_list_canonialize(config->ciphers);
          ssh_xfree(config->ciphers);
          config->ciphers = hlp1;
        }
      else if (strcasecmp(val, "anycipher") == 0)
        {
          int x;
          char *hlp1, *hlp2;
          
          hlp2 = ssh_cipher_get_supported_native();
          hlp1 = ssh_cipher_list_exclude(hlp2, "none");
          ssh_xfree(hlp2);
          config->ciphers = ssh_name_list_intersection(SSH_STD_CIPHERS, hlp1);
          hlp2 = ssh_cipher_list_exclude(config->ciphers, "none");
          ssh_xfree(config->ciphers);
          x = strlen(hlp1) + strlen(hlp2) + 2;
          config->ciphers = ssh_xmalloc(x);
          snprintf(config->ciphers, x, "%s,%s", hlp2, hlp1);
          ssh_xfree(hlp1);
          ssh_xfree(hlp2);
          hlp1 = ssh_cipher_list_canonialize(config->ciphers);
          ssh_xfree(config->ciphers);
          config->ciphers = hlp1;
        }
      else if (strcasecmp(val, "anystd") == 0)
        {
          char *hlp = ssh_cipher_get_supported_native();
          config->ciphers = ssh_name_list_intersection(hlp, SSH_STD_CIPHERS);
          ssh_xfree(hlp);
        }
      else if (strcasecmp(val, "anystdcipher") == 0)
        {
          char *hlp = ssh_cipher_get_supported_native();
          config->ciphers = ssh_name_list_intersection(hlp, SSH_STD_CIPHERS);
          ssh_xfree(hlp);
          hlp = config->ciphers;
          config->ciphers = ssh_cipher_list_exclude(hlp, "none");
          ssh_xfree(hlp);
        }
      else
        {
          config->ciphers = ssh_cipher_list_canonialize(val);
        }
      SSH_DEBUG(3, ("Final cipherlist \"%s\"", config->ciphers));
      return FALSE;
    }
  
  if (strcmp(var, "userconfigdirectory") == 0)
    {
      ssh_xfree(config->user_conf_dir);
      config->user_conf_dir = ssh_xstrdup(val);
      return FALSE;
    }

  if (strcmp(var, "identityfile") == 0)
    {
      ssh_xfree(config->identity_file);
      config->identity_file = ssh_xstrdup(val);
      return FALSE;
    }
  
  if (strcmp(var, "authorizationfile") == 0)
    {
      ssh_xfree(config->authorization_file);
      config->authorization_file = ssh_xstrdup(val);
      return FALSE;
    }
  
  if (strcmp(var, "randomseedfile") == 0)
    {
      ssh_xfree(config->random_seed_file);
      config->random_seed_file = ssh_xstrdup(val);
      return FALSE;
    }

  if (strcmp(var, "forcepttyallocation") == 0)
    {
      config->force_ptty_allocation = bool;
      return FALSE;
    }
  
  if (strcmp(var, "verbosemode") == 0)
    {
      config->verbose_mode = bool;
      if (bool)
        ssh_debug_set_level_string("2");
      return FALSE;
    }

  if (strcmp(var, "quietmode") == 0)
    {
      config->quiet_mode = bool;
      return FALSE;
    }

  if (strcmp(var, "fascistlogging") == 0)
    {
      config->fascist_logging = bool;
      return FALSE;
    }
  
  if (strcmp(var, "keepalive") == 0)
    {
      config->keep_alive = bool;
      return FALSE;
    }

  if (strcmp(var, "ssh1compatibility") == 0)
    {
      config->ssh1compatibility = bool;
      return FALSE;
    }
  
  /* for client only */

  if (config->client == TRUE)
    {
      if (strcmp(var, "host") == 0)
        {
          ssh_xfree(config->host_to_connect);
          config->host_to_connect = ssh_xstrdup(val);
          return FALSE;
        }
      if (strcmp(var, "user") == 0)
        {
          ssh_xfree(config->login_as_user);
          config->login_as_user = ssh_xstrdup(val);
          return FALSE;
        }
      if (strcmp(var, "compression") == 0)
        {
          config->compression = bool;
          return FALSE;
        }

      if (strcmp(var, "fallbacktorsh") == 0)
        {
          config->fall_back_to_rsh = bool;
          return FALSE;
        }
  
      if (strcmp(var, "usersh") == 0)
        {
          config->use_rsh = bool;
          return FALSE;
        }
      
      if (strcmp(var, "batchmode") == 0)
        {
          config->batch_mode = bool;
          return FALSE;
        }
      
      if (strcmp(var, "stricthostkeychecking") == 0)
        {
          config->strict_host_key_checking = bool;
          return FALSE;
        }
      
      if (strcmp(var, "escapechar") == 0)
        {
          ssh_xfree(config->escape_char);
          config->escape_char = ssh_xstrdup(val);
          return FALSE;
        }
      
      if (strcmp(var, "passwordprompt") == 0)
        {
          ssh_xfree(config->password_prompt);
          config->password_prompt = ssh_xstrdup(val);
          return FALSE;
        }

      if (strcmp(var, "gobackground") == 0)
        {
          config->go_background = bool;
          return FALSE;
        }
      
      if (strcmp(var, "usenonpriviledgedport") == 0)
        {
          config->use_nonpriviledged_port = bool;
          return FALSE;
        }
      
      if (strcmp(var, "dontreadstdin") == 0)
        {
          config->dont_read_stdin = bool;
          return FALSE;
        }

      if (strcmp(var, "ssh1path") == 0)
        {
          ssh_xfree(config->ssh1_path);
          config->ssh1_path = ssh_xstrdup(val);
          return FALSE;
        }

      if (strcmp(var, "ssh1agentcompatibility") == 0)
        {
          if (strcasecmp(val, "none") == 0)
            {
              config->ssh_agent_compat = SSH_AGENT_COMPAT_NONE;
              return FALSE;
            }
          else if (strcasecmp(val, "traditional") == 0)
            {
              config->ssh_agent_compat = SSH_AGENT_COMPAT_TRADITIONAL;
              return FALSE;
            }
          else if (strcasecmp(val, "ssh2") == 0)
            {
              config->ssh_agent_compat = SSH_AGENT_COMPAT_SSH2;
              return FALSE;
            }
          else
            {
              ssh_warning("Bad Ssh1AgentCompatibility definition \"%s\"", 
                          val);
              return TRUE;
            }
        }

#ifndef SSHDIST_WINDOWS
      if (strcmp(var, "localforward") == 0)
        {
          if(ssh_parse_forward(&(config->local_forwards), val))
            {
              ssh_warning("Bad LocalForward definition \"%s\"", val);
              return TRUE;
            }
          return FALSE;
        }

      if (strcmp(var, "remoteforward") == 0)
        {
          if(ssh_parse_forward(&(config->remote_forwards), val))
            {
              ssh_warning("Bad RemoteForward definition \"%s\"", val);
              return TRUE;
            }
          return FALSE;
        }  
#endif /* SSHDIST_WINDOWS */
    }
  else
    {
      /* These parameters are only for the server */
      
      if (strcmp(var, "ignorerhosts") == 0)
        {
          config->ignore_rhosts = bool;
          return FALSE;
        }
      
      if (strcmp(var, "permitrootlogin") == 0)
        {
          config->permit_root_login = bool;
          return FALSE;
        }
      
      if (strcmp(var, "permitemptypasswords") == 0)
        {
          config->permit_empty_passwords = bool;
          return FALSE;
        }
      
      if (strcmp(var, "strictmodes") == 0)
        {
          config->strict_modes = bool;
          return FALSE;
        }
      
      if (strcmp(var, "printmotd") == 0)
        {
          config->print_motd = bool;
          return FALSE;
        }
      
      if (strcmp(var, "listenaddress") == 0)
        {
          /* XXX some checks here */
          ssh_xfree(config->listen_address);
          config->listen_address = ssh_xstrdup(val);
          return FALSE;
        }
      
      if (strcmp(var, "hostkeyfile") == 0)
        {
          ssh_xfree(config->host_key_file);
          config->host_key_file = ssh_xstrdup(val);

          /* Note: if you specify PublicHostKeyFile first in the config file,
             and HostKey after that, and you give it the value of 
             SSH_PUBLIC_HOSTKEY (which, at the moment, is the same as 
             SSH_HOSTKEY_FILE with ".pub" appended) the value of 
             config->public_host_key_file will be config->host_key_file with 
             ".pub" appended. This is a minor problem. This kludge here is to 
             avoid changing the value of PublicHostKeyFile depending on the 
             order in which config parameters lie in the configfile. */

          if (strcmp(config->public_host_key_file, SSH_PUBLIC_HOSTKEY) == 0)
            {
              ssh_xfree(config->public_host_key_file);
              num = strlen(val) + strlen(".pub") + 1;
              config->public_host_key_file = ssh_xcalloc(1, num);
              snprintf(config->public_host_key_file, num, "%s.pub", val);
            }
          return FALSE;
        }
      
      if (strcmp(var, "publichostkeyfile") == 0)
        {
          ssh_xfree(config->public_host_key_file);
          config->public_host_key_file = ssh_xstrdup(val);
          return FALSE;
        }
          
      if (strcmp(var, "logingracetime") == 0)
        {
          if (num < 1)
            {
              ssh_warning("Ignoring illegal login grace time %d",
                          num);
              return TRUE;
            }
          config->login_grace_time = num;
          return FALSE;
        }
      
      if (strcmp(var, "passwordguesses") == 0)
        {
          config->password_guesses = num;
          return FALSE;
        }

      if (strcmp(var, "sshd1path") == 0)
        {
          ssh_xfree(config->ssh1_path);
          config->ssh1_path = ssh_xstrdup(val);
          return FALSE;
        }
      
      /* Parse subsystem definitions */
      
      if (strncmp(var, SUBSYSTEM_PREFIX, SUBSYSTEM_PREFIX_LEN) == 0)
        {
          if (strlen(val) < 1)
            {
              ssh_warning("Missing subsystem path");
              return TRUE;
            }
              
          if (config->no_subsystems > 0)
            {
              for (i = 0; i < config->no_subsystems; i++)
                if (strcmp(&var[SUBSYSTEM_PREFIX_LEN], 
                           config->subsystems[i]->name) == 0)
                  {
                    ssh_xfree(config->subsystems[i]->path);
                    config->subsystems[i]->path = ssh_xstrdup(val);
                    ssh_warning("Multiple definitions for subsystem %s",
                                config->subsystems[i]->name);
                    return FALSE; 
                  }
            }
          
          if (config->subsystems_allocated == 0 || 
              (config->no_subsystems + 1) >= config->subsystems_allocated)
            {
              if (config->subsystems_allocated < 4)
                config->subsystems_allocated = 4;
              else
                config->subsystems_allocated *= 2;
              
              config->subsystems = 
                ssh_xrealloc(config->subsystems,
                             config->subsystems_allocated * sizeof (*ss));
            }
          
          ss = ssh_xmalloc(sizeof (*ss));
          ss->name = ssh_xstrdup(&var[SUBSYSTEM_PREFIX_LEN]);
          ss->path = ssh_xstrdup(val);
          config->subsystems[config->no_subsystems++] = ss;
                          
          return FALSE;
        }
      
    }
  ssh_warning("Unrecognized configuration parameter %s", var);
  return TRUE;
}
