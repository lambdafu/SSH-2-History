/*

  sshconfig.h

  Authors:
        Tatu Ylönen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Processing configuration data in SSH (both client and server).

*/

#ifndef SSHCONFIG_H
#define SSHCONFIG_H

#include "sshuser.h"
#include "sshcrypt.h"

#define SUBSYSTEM_PREFIX "subsystem-"
#define SUBSYSTEM_PREFIX_LEN 10

typedef struct SshSubsystemRec
{
  char *name;                          /* name of the subsystem */
  char *path;                          /* command and arguments to execute */
} *SshSubsystem;

/* Definition for SshForward */

typedef struct SshForwardRec {
  struct SshForwardRec *next;
  char *local_addr;
  char *port;
  char *connect_to_host;
  char *connect_to_port;
} *SshForward;

typedef enum {
  /* No ssh1 agent compatibility */
  SSH_AGENT_COMPAT_NONE = 0, 
  /* Forward connections for old ssh1 agent.  Also ssh2 agent works with 
     this mode, but no agent forwarding path is added to the data. */
  SSH_AGENT_COMPAT_TRADITIONAL = 1,
  /* Forward connections for ssh2 agent emulating ssh1 agent.  Ssh1 agent
     do not work with this mode. */
  SSH_AGENT_COMPAT_SSH2 = 2
} SshAgentSsh1CompatMode;

/* Data type for SSH server configuration data. */

struct SshConfigRec
{
  /* TRUE if the config data is for a client. */
  Boolean client;

  /* The private host key */

  SshPrivateKey private_host_key;
  unsigned char *public_host_key_blob;
  size_t public_host_key_blob_len;

  /* A context structure to be used with various callbacks. 
     No use at *nix at this time, but Windows-code uses it
     to pass registry-arguments. */

  void * callback_context;

  /* common for both client and server */

  Boolean forward_agent;    
  Boolean forward_x11;
  Boolean password_authentication;
  Boolean rhosts_authentication;
  Boolean rhosts_pubkey_authentication;
  Boolean pubkey_authentication;
  Boolean force_ptty_allocation;
  Boolean verbose_mode;
  Boolean compression;

  char *port;      
  char *ciphers;   
  char *user_conf_dir;
  char *identity_file;
  char *authorization_file;
  char *random_seed_file;

  char *password_prompt;
  int password_guesses;

  char *host_to_connect;
  char *login_as_user;
  SshForward local_forwards;
  SshForward remote_forwards;
  
  Boolean fall_back_to_rsh;
  Boolean use_rsh;
  Boolean batch_mode;
  Boolean strict_host_key_checking;
  Boolean go_background;
  Boolean use_nonpriviledged_port;
  Boolean dont_read_stdin;
  char *escape_char;
  Boolean ignore_rhosts;
  Boolean permit_root_login;
  Boolean permit_empty_passwords;
  Boolean strict_modes;
  Boolean quiet_mode;
  Boolean fascist_logging;
  Boolean print_motd;
  Boolean keep_alive;
  Boolean inetd_mode;
  char *listen_address;
  int login_grace_time;
  char *host_key_file;
  char *public_host_key_file;
  
  char *forced_command;

  size_t no_subsystems;
  size_t subsystems_allocated;
  SshSubsystem *subsystems;

  
  /* Flag specifying whether to enable ssh1 compatibility. */
  Boolean ssh1compatibility;

  /* Ssh1 agent forwarding compatibility mode */
  SshAgentSsh1CompatMode ssh_agent_compat;

  /* Path to ssh1/sshd1.*/
  char *ssh1_path;
  
  /* Ssh1 arguments for compatibility. If this is NULL, there will be no
     ssh1 compatibility.  The first argument should be the program name. */
  char **ssh1_args;

  /* The file descriptor for the connection to the remote ssh1 server/client.
     This is used in ssh1 compatibility code. */
  int ssh1_fd;
};

typedef struct SshConfigRec *SshConfig;

/* Parse a configuration/authorization file into an array of 
   variable name <-> value pairs. Return the number of variables or -1 on 
   error. Pointers to tables of pointers to null-terminated strings are
   placed at *variables and *values */
int ssh2_parse_config(SshUser user, const char *instance, const char *path, 
                      char ***variables, char ***values, void *context);

/* Free the "vars" and "vals" arrays */
void ssh_free_varsvals(int n, char **vars, char **vals);

/* Returns default configuration information for the server. */
SshConfig ssh_server_create_config(void);

/* Returns default configuration information for the client. */
SshConfig ssh_client_create_config(void);

/* Frees client configuration data. */
void ssh_config_free(SshConfig config);

/* Reads config data from the given file.  Returns FALSE if an error
   occurs (displays error messages with ssh_warning) */
Boolean ssh_config_read_file(SshUser user, SshConfig config, char *instance, 
                             const char *filename, void *context);

/* Reads the host key that is defined in the config data. Returns
   TRUE if succesful. */

Boolean ssh_server_load_host_key(SshConfig config,
                                 SshPrivateKey *private_host_key,
                                 unsigned char **public_host_key_blob,
                                 size_t *public_host_key_blob_len, 
                                 void *context);

/* Set the variable corresponding to `var' to `val' in config. Return
   TRUE if an error occurs. */
Boolean ssh_config_set_parameter(SshConfig config, char *var, char *val);

/* Parse a line of input. Return TRUE if an error occurs. */
Boolean ssh_config_parse_line(SshConfig config, char *line);

/* separate (commandline)options from their parameters */
void ssh_split_arguments(int argc, char **argv, int *dest_ac, char ***dest_av);

/* Parse forwarding definitions. Format is port:remotehost:remoteport */
Boolean ssh_parse_forward(SshForward *forwards, char *spec);

#endif /* SSHCONFIG_H */
