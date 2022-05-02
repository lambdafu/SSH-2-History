/*

ssh-add.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

Adds an identity to the authentication server, or removes an identity.

*/

/*
 * $Id: ssh-add2.c,v 1.14 1998/11/15 13:33:43 tri Exp $
 * $Log: ssh-add2.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshcrypt.h"
#include "sshtimeouts.h"
#include "sshagent.h"
#include "sshuser.h"
#include "readpass.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshgetopt.h"

#define SSH_DEBUG_MODULE "SshAdd"

#define EXIT_STATUS_OK          0
#define EXIT_STATUS_NOAGENT     1
#define EXIT_STATUS_BADPASS     2
#define EXIT_STATUS_NOFILE      3
#define EXIT_STATUS_NOIDENTITY  4
#define EXIT_STATUS_ERROR       5

typedef enum 
{ 
  LIST, 
  ADD, 
  ADD_URL,
  DELETE,
  DELETE_URL,
  DELETE_ALL, 
  LOCK, 
  UNLOCK 
} SshAgentAction;

/* Files to add/delete from agent. */
char **files;
int num_files;
SshAgentAction action;

/* Possible attributes */
SshUInt32 path_limit = 0xffffffff;
char *path_constraint = NULL;
Boolean forbid_compat = FALSE;
time_t key_timeout = 0;
Boolean have_attrs = FALSE;
SshUInt32 use_limit = 0xffffffff;

/* Force to read passphrases from stdin. */
int use_stdin = FALSE;

/* Information about the current user. */
SshUser user;

void agent_completion(SshAgentError result, void *context);

void add_file(SshAgent agent, const char *filename)
{
  SshPrivateKey key;
  char *saved_comment, *comment, *pass;
  int query_cnt;
  unsigned char *certs;
  size_t certs_len;
  char privname[500], pubname[500];
  unsigned long magic;
  struct stat st;

  if (action == ADD_URL)
    {
      printf("Adding URL identity: %s\n", filename);
      snprintf(privname, sizeof(privname), "%s", filename);
      if (have_attrs)
        ssh_agent_add_with_attrs(agent, NULL, NULL, 0, privname,
                                 path_limit, path_constraint, use_limit,
                                 forbid_compat, key_timeout,
                                 agent_completion, (void *)agent);
      else
        ssh_agent_add(agent, NULL, NULL, 0, privname,
                      agent_completion, (void *)agent);
      return;
    }
  else if (action == DELETE_URL)
    {
      printf("Deleting URL identity: %s\n", filename);
      snprintf(privname, sizeof(privname), "%s", filename);
      ssh_agent_delete(agent, NULL, 0, privname,
                       agent_completion, (void *)agent);
      return;
    }
  /* Construct the names of the public and private key files. */
  if (strlen(filename) > 4 &&
      strcmp(filename + strlen(filename) - 4, ".pub") == 0)
    {
      snprintf(pubname, sizeof(pubname), "%s", filename);
      snprintf(privname, sizeof(privname), "%s", filename);
      privname[strlen(privname) - 4] = '\0';
    }
  else
    {
      snprintf(pubname, sizeof(pubname), "%s.pub", filename);
      snprintf(privname, sizeof(privname), "%s", filename);
    }

  if (action == ADD)
    printf("Adding identity: %s\n", pubname);
  else if (action == DELETE)
    printf("Deleting identity: %s\n", pubname);

  if (stat(pubname, &st) < 0)
    {
      printf("Public key file %s does not exist.\n", pubname);
      (*agent_completion)(SSH_AGENT_ERROR_OK, (void *)agent);
      return;
    }

  if (stat(privname, &st) < 0)
    {
      printf("Private key file %s does not exist.\n", privname);
      (*agent_completion)(SSH_AGENT_ERROR_OK, (void *)agent);
      return;
    }
  
  /* Read the public key blob. */
  magic = ssh_key_blob_read(user, pubname, &saved_comment, &certs, &certs_len,
                            NULL);
  if (magic != SSH_KEY_MAGIC_PUBLIC)
    {
      printf("Bad public key file %s\n", pubname);
      (*agent_completion)(SSH_AGENT_ERROR_OK, (void *)agent);
      return;
    }
  
  if (action == ADD)
    {
      /* Loop until we manage to load the file, or a maximum number of
         attempts have been made.  First try with an empty passphrase. */
      pass = ssh_xstrdup("");
      query_cnt = 0;
      while ((key = ssh_privkey_read(user, privname, pass, &comment, NULL)) == 
             NULL)
        {
          char buf[1024];
          FILE *f;
      
          /* Free the old passphrase. */
          memset(pass, 0, strlen(pass));
          ssh_xfree(pass);
          
          query_cnt++;
          if (query_cnt > 5)
            {
              fprintf(stderr,
                      "You don't seem to know the correct passphrase.\n");
              exit(EXIT_STATUS_BADPASS);
            }
          
          /* Ask for a passphrase. */
          if (!use_stdin && getenv("DISPLAY") && !isatty(fileno(stdin)))
            {
              snprintf(buf, sizeof(buf),
                       "ssh-askpass2 '%sEnter passphrase for %.100s'", 
                       ((query_cnt <= 1) ? 
                        "" : 
                        "You entered wrong passphrase.  "), 
                       saved_comment);
              f = popen(buf, "r");
              if (!fgets(buf, sizeof(buf), f))
                {
                  pclose(f);
                  ssh_xfree(saved_comment);
                  exit(EXIT_STATUS_BADPASS);
                }
              pclose(f);
              if (strchr(buf, '\n'))
                *strchr(buf, '\n') = 0;
              pass = ssh_xstrdup(buf);
            }
          else
            {
              if (query_cnt <= 1)
                printf("Need passphrase for %s (%s).\n", 
                       privname, saved_comment);
              else
                printf("Bad passphrase.\n");
              pass = ssh_read_passphrase("Enter passphrase: ", use_stdin);
              if (pass == NULL || strcmp(pass, "") == 0)
                {
                  ssh_xfree(saved_comment);
                  ssh_xfree(pass);
                  exit(EXIT_STATUS_BADPASS);
                }
            }
        }
      memset(pass, 0, strlen(pass));
      ssh_xfree(pass);
      ssh_xfree(saved_comment);
      /* Construct a comment for the key by combining file name and comment in
         the file. */
      snprintf(privname, sizeof(privname), "%s: %s", pubname, comment);
      ssh_xfree(comment);
    }
  else
    {
      /* Construct a comment for the key by combining file name and comment in
         the file. */
      snprintf(privname, sizeof(privname), "%s: %s", pubname, saved_comment);
      ssh_xfree(saved_comment);
    }

  if (action == ADD)
    {
      /* Send the key to the authentication agent. */
      if (have_attrs)
        ssh_agent_add_with_attrs(agent, key, certs, certs_len, privname,
                                 path_limit, path_constraint, use_limit,
                                 forbid_compat, key_timeout,
                                 agent_completion, (void *)agent);
      else
        ssh_agent_add(agent, key, certs, certs_len, privname,
                      agent_completion, (void *)agent);
      ssh_private_key_free(key);
    }
  else if (action == DELETE)
    {
      ssh_agent_delete(agent, certs, certs_len, privname,
                       agent_completion, (void *)agent);
    }
}

void agent_completion(SshAgentError result, void *context)
{
  SshAgent agent = (SshAgent)context;

  switch (result)
    {
    case SSH_AGENT_ERROR_OK:
      break;

    case SSH_AGENT_ERROR_TIMEOUT:
      fprintf(stderr, "Authentication agent timed out.\n");
      exit(EXIT_STATUS_NOAGENT);
      
    case SSH_AGENT_ERROR_KEY_NOT_FOUND:
      fprintf(stderr,
              "Requested key not in possession of authentication agent.\n");
      exit(EXIT_STATUS_NOIDENTITY);
      
    case SSH_AGENT_ERROR_DECRYPT_FAILED:
      fprintf(stderr, "Decryption failed.\n");
      exit(EXIT_STATUS_ERROR);
      
    case SSH_AGENT_ERROR_SIZE_ERROR:
      fprintf(stderr, "Argument size error.\n");
      exit(EXIT_STATUS_ERROR);
      
    case SSH_AGENT_ERROR_KEY_NOT_SUITABLE:
      fprintf(stderr, 
              "The specified key is not suitable for the operation.\n");
      exit(EXIT_STATUS_ERROR);
      
    case SSH_AGENT_ERROR_DENIED:
      fprintf(stderr, "The requested operation was denied.\n");
      exit(EXIT_STATUS_ERROR);
      
    case SSH_AGENT_ERROR_FAILURE:
      fprintf(stderr, "The requested operation failed.\n");
      exit(EXIT_STATUS_ERROR);
      
    case SSH_AGENT_ERROR_UNSUPPORTED_OP:
      fprintf(stderr, "The requested operation is not supported.\n");
      exit(EXIT_STATUS_ERROR);
      
    case SSH_AGENT_ERROR_BUSY:
      fprintf(stderr, "The authentication agent is busy.\n");
      exit(EXIT_STATUS_ERROR);
      
    default:
      fprintf(stderr, "Authentication agent failed with error %d\n",
              (int)result);
      exit(EXIT_STATUS_ERROR);
    }

  /* The last operation was successful.  Check if there is more work to do. */
  if (num_files <= 0)
    {
      /* All operations performed. */
      exit(EXIT_STATUS_OK);
    }

  /* Add any files listed. */
  num_files--;
  add_file(agent, *files++);
  /* A callback should already have been scheduled to occur at some point. */
}

void agent_list_callback(SshAgentError error, unsigned int num_keys,
                             SshAgentKeyInfo keys, void *context)
{
  SshAgent agent = (SshAgent)context;
  int i;

  if (error != SSH_AGENT_ERROR_OK)
    {
      agent_completion(error, (void *)agent);
      ssh_fatal("agent_list_callback: agent_completion returned after error");
    }

  if (num_keys == 0)
    printf("The authorization agent has no keys.\n");
  else
    {
      if (num_keys == 1)
        printf("The authorization agent has one key:\n");
      else
        printf("The authorization agent has %d keys:\n", num_keys);
      for (i = 0; i < num_keys; i++)
        printf("%s\n", keys[i].description);
    }
  agent_completion(SSH_AGENT_ERROR_OK, (void *)agent);
}

void agent_open_callback(SshAgent agent, void *context)
{
  char buf[1024];
  FILE *f;
  char *password;

  if (!agent)
    {
      fprintf(stderr,
        "Failed to connect to authentication agent - agent not running?\n");
      exit(EXIT_STATUS_NOAGENT);
    }

  switch (action)
    {
    case DELETE_ALL:
      fprintf(stderr, "Deleting all identities.\n");
      ssh_agent_delete_all(agent, agent_completion, (void *)agent);
      break;
      
    case LIST:
      fprintf(stderr, "Listing identities.\n");
      ssh_agent_list(agent, agent_list_callback, (void *)agent);
      break;
      
    case LOCK:
      if (!use_stdin && getenv("DISPLAY") && !isatty(fileno(stdin)))
        {
          snprintf(buf, sizeof (buf),
                   "ssh-askpass2 'Enter lock passphrase'");
          f = popen(buf, "r");
          if (! fgets(buf, sizeof (buf), f))
            {
              pclose(f);
              exit(EXIT_STATUS_BADPASS);
            }
          pclose(f);
          if (strchr(buf, '\n'))
            *strchr(buf, '\n') = 0;
          password = ssh_xstrdup(buf);
        }
      else
        {
          password = ssh_read_passphrase("Enter lock password: ", use_stdin);
          if (password == NULL)
            {
              exit(EXIT_STATUS_BADPASS);
            }
        }
      ssh_agent_lock(agent, password, agent_completion, (void *)agent);
      break;

    case UNLOCK:
      if (!use_stdin && getenv("DISPLAY") && !isatty(fileno(stdin)))
        {
          snprintf(buf, sizeof (buf),
                   "ssh-askpass2 'Enter unlock passphrase'");
          f = popen(buf, "r");
          if (! fgets(buf, sizeof (buf), f))
            {
              pclose(f);
              exit(EXIT_STATUS_BADPASS);
            }
          pclose(f);
          if (strchr(buf, '\n'))
            *strchr(buf, '\n') = 0;
          password = ssh_xstrdup(buf);
        }
      else
        {
          password = ssh_read_passphrase("Enter lock password: ", use_stdin);
          if (password == NULL)
            {
              exit(EXIT_STATUS_BADPASS);
            }
        }
      ssh_agent_unlock(agent, password, agent_completion, (void *)agent);
      break;

    case DELETE:
    case DELETE_URL:
    case ADD:
    case ADD_URL:
      /* Let the completion do all the work. */
      agent_completion(SSH_AGENT_ERROR_OK, (void *)agent);
      break;

    default:
      ssh_fatal("agent_open_callback: bad action %d\n", (int)action);
    }
}

void usage(void);
void usage()
{
  fprintf(stderr, "Usage: ssh-add [-l] [-d] [-p] [-t key_exp] [-f hop_limit] [-1] [files...]\n");
}

/* This is the main program for the agent. */

int main(int ac, char **av)
{
  int opt, i, len;
  DIR *ssh2dir;
  char *ssh2dirname;
  Boolean dynamic_array = FALSE;
  struct dirent * cand;

  user = ssh_user_initialize(NULL, FALSE);
  
  action = ADD;
  while ((opt = ssh_getopt(ac, av, "ldDput:f:F:1LU", NULL)) != EOF)
    {
      if (!ssh_optval)
        {
          fprintf(stderr, "Usage: ssh-add [-l] [-d] [-u] [-p] [files...]\n");
          exit(EXIT_STATUS_ERROR);
        }
      switch (opt)
        {
        case 'l':
          action = LIST;
          break;
        case 'p':
          use_stdin = TRUE;
          break;
        case 'd':
          if (action == ADD_URL)
            action = DELETE_URL;
          else
            action = DELETE;
          break;
        case 'D':
          action = DELETE_ALL;
          break;
        case 't':
          if (ssh_optargnum)
            {
              key_timeout = (time_t)(ssh_optargval * 60);
            }
          else
            {
              usage();
              exit(EXIT_STATUS_ERROR);
            }
          have_attrs = TRUE;
          break;
        case 'f':
          if (ssh_optargnum)
            {
              path_limit = (SshUInt32)ssh_optargval;
            }
          else
            {
              usage();
              exit(EXIT_STATUS_ERROR);
            }
          have_attrs = TRUE;
          break;
        case 'F':
          path_constraint = ssh_xstrdup(ssh_optarg);
          have_attrs = TRUE;
          break;
        case '1':
          forbid_compat = TRUE;
          have_attrs = TRUE;
          break;
        case 'u':
          if (action == DELETE)
            action = DELETE_URL;
          else
            action = ADD_URL;
          break;
        case 'L':
          action = LOCK;
          break;
        case 'U':
          action = UNLOCK;
          break;
        default:
          usage();
          exit(EXIT_STATUS_ERROR);
        }
    }

  files = &av[ssh_optind];
  num_files = ac - ssh_optind;

  /* Fetch default from ~/.ssh2/id_* (the first that we happen to get) */

#define ID_PREFIX "id_"
  
  if (ac == 1 && num_files == 0)
    {
      /* len includes '/' and '\0'*/
      len = strlen(ssh_user_dir(user)) + strlen(SSH_USER_DIR) + 2;
      ssh2dirname = ssh_xcalloc(len, sizeof(char));
      snprintf(ssh2dirname, len, "%s/%s", ssh_user_dir(user), SSH_USER_DIR);
      
      ssh2dir = opendir(ssh2dirname);
      while ((cand = readdir(ssh2dir)) != NULL)
        {
          if (strlen(cand->d_name) >= strlen(ID_PREFIX) &&
              strncmp(cand->d_name, ID_PREFIX, strlen(ID_PREFIX)) == 0)
            {
              files = ssh_xcalloc(2, sizeof(char *));

              /* len includes '/' and '\0'*/
              len = strlen(ssh2dirname) + strlen(cand->d_name) + 2; 
                                                                      
              files[0] = ssh_xcalloc(len, sizeof(char));
              snprintf(files[0],len, "%s/%s", ssh2dirname, cand->d_name);
              ssh_xfree(ssh2dirname);
              num_files++;
              dynamic_array = TRUE;
              break;
            }
        }
      (void)closedir(ssh2dir);
    }
  
  signal(SIGPIPE, SIG_IGN);
  
  ssh_event_loop_initialize();
  
  ssh_agent_open(agent_open_callback, NULL);

  ssh_event_loop_run();
  ssh_event_loop_uninitialize();

  if (dynamic_array)
    {
      for(i = 0; i < num_files ; i++)
        {
          ssh_xfree(files[i]);
        }
      ssh_xfree(files);
    }
  
  ssh_user_free(user, FALSE);
  exit(EXIT_STATUS_OK);
}
