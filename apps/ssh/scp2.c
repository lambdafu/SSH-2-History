/*

  scp2.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  A scp2 client 
 
 */

#include "ssh2includes.h"
#include "sshreadline.h"
#include "sshtimeouts.h"
#include "sshtcp.h"
#include "sshunixfdstream.h"
#include "sshbuffer.h"
#include "sshconfig.h"
#include "sshuserfiles.h"
#include "sshunixeloop.h"
#include "sshfilexfer.h"
#include "sshstreampair.h"
#include "sshunixpipestream.h"

#define SSH_DEBUG_MODULE "Scp2"

#define SCP_FILESERVER_TIMEOUT		30	/*XXX*/
#define SCP_BUF_SIZE			0x1000
#define SCP_ERROR_MULTIPLE		-1
#define SCP_ERROR_USAGE			1
#define SCP_ERROR_NOT_REGULAR_FILE	2
#define SCP_ERROR_CANNOT_STAT		3
#define SCP_ERROR_CANNOT_CREATE		4
#define SCP_ERROR_CANNOT_OPEN		5
#define SCP_ERROR_READ_ERROR		6
#define SCP_ERROR_WRITE_ERROR		7

void dummy_1(void *dummy)
{
  return;
}
/*#define ssh_xfree dummy_1*/
#define ssh_xfree_q dummy_1

typedef struct ScpFileLocationRec {
  char                      *user;
  char                      *host;
  char                      *file;
  int                        port;
  struct ScpFileLocationRec *next;
} ScpFileLocation;

typedef struct ScpCipherNameRec {
  char *name;
  struct ScpCipherNameRec *next;
} *ScpCipherName;

typedef struct ScpSessionRec {
  int verbose;
  char *debug_flag;
  int preserve_flag;
  int unlink_flag;
  int port_flag;
  int do_not_copy;
  int need_dst_dir;
  int dst_is_dir;
  int dst_is_file;
  int dst_is_local;
  int tty_fd;
  char *ssh_path;
  ScpCipherName cipher_list;
  ScpCipherName cipher_list_last;
  SshFileClient dst_client;
  SshFileClient dst_local_client;
  SshFileServer dst_local_server;
  SshFileClient dst_remote_client;
  SshFileClient src_local_client;
  SshFileServer src_local_server;
  SshFileClient src_remote_client;
  char *src_remote_host;
  int src_remote_port;
  char *src_remote_user;
  ScpFileLocation *src_list;
  ScpFileLocation *src_list_tail;
  ScpFileLocation *dst_location;
  char *current_dst_file;
  int current_src_is_local;
  ScpFileLocation *current_src_location;
  int timeout_is_fatal;
  int timeout_triggered;
  SshFileHandle tmp_handle;
  int tmp_status;
  struct SshFileAttributesRec tmp_attributes;
  int tmp_attributes_ok;
  char *tmp_data;
  int tmp_data_len;
  int callback_fired;
  int error;
} *ScpSession;

void usage(void);
void scp_set_error(ScpSession session, int error);
void scp_init_session(ScpSession session);
ScpFileLocation* scp_parse_location_string(ScpSession session, char *str);
SshFileClient scp_open_remote_connection(ScpSession session,
					 char *host,
					 char *user, 
					 int port);
void scp_set_src_remote_location(ScpSession session, 
				 char *host, 
				 int port, 
				 char *user);
char *scp_file_basename(char *pathname);
Boolean scp_set_src_is_remote_location_ok(ScpSession session, 
					  char *host, 
					  int port, 
					  char *user);
void scp_abort_if_remote_dead(ScpSession session, SshFileClient client);
void scp_get_win_dim(int *width, int *height);
void scp_kitt(off_t pos, off_t total, int width);
SshFileHandle scp_file_open(ScpSession session,
			    SshFileClient client,
			    char *file,
			    int flags,
			    SshFileAttributes attributes);
int scp_file_close(ScpSession session, SshFileHandle handle);
SshFileAttributes scp_file_fstat(ScpSession session, 
				 SshFileHandle handle);
int scp_file_read(ScpSession session, 
		  SshFileHandle handle,
		  off_t offset, 
		  char *buf,
		  size_t bufsize);
int scp_file_write(ScpSession session,
		   SshFileHandle handle, 
		   off_t offset, 
		   char *buf, 
		   size_t bufsize);
Boolean scp_move_file(ScpSession session,
		      char *src_host,
		      char *src_path,
		      SshFileClient src_client, 
		      char *dst_host,
		      char *dst_path,
		      SshFileClient dst_client);
void scp_remote_dead_timeout(void *context);
int scp_execute(ScpSession session);
ScpCipherName scp_new_cipher_item(char *name);

/* Debug stuff */
void scp_debug(const char *msg, void *context);
void scp_print_session_info(ScpSession session);
void scp_print_location_info(ScpFileLocation *location);

#if 1
static char *str_concat_3(char *s1, char *s2, char *s3)
{
  int l1 = strlen(s1), l2 = strlen(s2), l3 = strlen(s3);
  char *r = ssh_xmalloc(l1 + l2 + l3 + 1);

  strcpy(r, s1);
  strcpy(&(r[l1]), s2);
  strcpy(&(r[l1 + l2]), s3);

  return r;
}
#endif

int main(int argc, char **argv)
{
  struct ScpSessionRec session;
  int i;
  int ch;
  ScpFileLocation *location;
  extern char *optarg;
  extern int optind;

  ssh_event_loop_initialize();

  scp_init_session(&session);

  ssh_debug_register_callbacks(NULL, NULL, scp_debug, (void *)(&session));

  while ((ch = getopt(argc, argv, "dpvnuhS:P:c:D:tf")) != EOF)
    {
      switch(ch)
	{
	case 't':
	case 'f':
	  /* Scp 1 compatibility mode, this is remote server for ssh 1 scp,
	     exec old scp here. */
	  {
	    ssh_warning("Executing scp1 compatibility.");
	    execvp("scp1", argv);
	    ssh_fatal("Executing ssh1 in compatibility mode failed.");
	  }
	  break;
	case 'p':
	  session.preserve_flag = 1;
	  break;
	case 'P':
	  session.port_flag = atoi(optarg);
	  if ((session.port_flag <= 0) || (session.port_flag > 65535))
	    usage();
	  break;
	case 'c':
	  if (session.cipher_list == NULL)
	    {
	      session.cipher_list_last = scp_new_cipher_item(optarg);
	      session.cipher_list_last->next = NULL;
	      session.cipher_list = session.cipher_list_last;
	    }
	  else
	    {
	      session.cipher_list_last->next = scp_new_cipher_item(optarg);
	      session.cipher_list_last = session.cipher_list_last->next;
	      session.cipher_list_last->next = NULL;
	    }
	  break;
	case 'S':
	  ssh_xfree(session.ssh_path);
	  session.ssh_path = ssh_xstrdup(optarg);
	  break;
	case 'd':
	  session.need_dst_dir = 1;
	  break;
	case 'D':
	  session.debug_flag = ssh_xstrdup(optarg);
	  ssh_debug_set_level_string(session.debug_flag);
	  session.verbose = atoi(session.debug_flag);
	  if (session.verbose == 0)
	    session.verbose = 1;
	  break;
	case 'v':
	  session.debug_flag = ssh_xstrdup("2");
	  ssh_debug_set_level_string(session.debug_flag);
	  session.verbose = atoi(session.debug_flag);
	  break;
	case 'u':
	  session.unlink_flag = 1;
	  break;
	case 'n':
	  session.do_not_copy = 1;
	  break;
	case 'h':
	  usage();
	  break;
	default:
	  usage();
	}
    }

  argc -= optind;
  argv += optind;

  if (argc < 2)
    usage();

  for (i = 0; i < (argc - 1); i++)
    {
      location = scp_parse_location_string(&session, argv[i]);
      if (location == NULL)
	usage();
      if (strlen(location->file) < 1)
	{
	  usage();
	} else {
	  char *hlp = strrchr(location->file, '/');
	  if (hlp)
	    {
	      hlp++;
	      if (*hlp == '\000')
		usage();
	    }
	}
      if (session.src_list == NULL)
	{
	  session.src_list = session.src_list_tail = location;
	} else {
	  session.src_list_tail->next = location;
	  session.src_list_tail = location;
	}
    }

  location = scp_parse_location_string(&session, argv[i]);
  if (location == NULL)
    usage();
  if (strlen(location->file) < 1)
    {
      ssh_xfree(location->file);
      location->file = ssh_xstrdup(".");
    }
  session.dst_location = location;

  if (session.src_list != session.src_list_tail)
    session.need_dst_dir = 1;

  if (session.dst_location->host == NULL)
    session.dst_is_local = 1;
  else
    session.dst_is_local = 0;

  exit(scp_execute(&session));
}

void usage()
{
  fprintf(stderr, "usage: scp [-D debug_level_spec] [-d] [-p] [-n] [-u] [-v]\n");
  fprintf(stderr, "           [-c cipher] [-S ssh2-path] [-h] [-P ssh2-port]\n");
  fprintf(stderr, "           [[user@]host[#port]:]file ...\n");
  fprintf(stderr, "           [[user@]host[#port]:]file_or_dir\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -D debug_level_spec  Set debug level.\n");
  fprintf(stderr, "  -d                   Force target to be a directory.\n");
  fprintf(stderr, "  -p                   Preserve file attributes and timestamps.\n");
  fprintf(stderr, "  -n                   Show what would've been done without actually copying\n");
  fprintf(stderr, "                       any files.\n");
  fprintf(stderr, "  -u                   Remove source-files after copying.\n");
  fprintf(stderr, "  -v                   Verbose mode; equal to `-D 2'.\n");
  fprintf(stderr, "  -c cipher            Select encryption algorithm. Multiple -c options are \n");
  fprintf(stderr, "                       allowed and a single -c flag can have only one cipher.\n");
  fprintf(stderr, "  -S ssh2-path         Tell scp2 where to find ssh2.\n");
  fprintf(stderr, "  -P ssh2-port         Tell scp2 which port sshd2 listens on the remote machine.\n");
  fprintf(stderr, "  -h                   Display this help.\n");
  fprintf(stderr, "\n");
  exit(SCP_ERROR_USAGE);
}

void scp_init_session(ScpSession session)
{
  session->debug_flag = NULL;
  session->verbose = 0;
  session->preserve_flag = 0;
  session->port_flag = 0;
  session->need_dst_dir = 0;
  session->do_not_copy = 0;
  session->dst_is_dir = 0;
  session->dst_is_file = 0;
  session->tty_fd = 0;
  session->ssh_path = ssh_xstrdup("ssh2");
  session->cipher_list = NULL;
  session->cipher_list_last = NULL;
  session->dst_remote_client = NULL;
  session->dst_local_client = NULL;
  session->dst_local_server = NULL;
  session->src_remote_client = NULL;
  session->src_remote_host = NULL;
  session->src_remote_port = -1;
  session->src_remote_user = NULL;
  session->src_local_client = NULL;
  session->src_local_server = NULL;
  session->src_list = NULL;
  session->src_list_tail = NULL;
  session->dst_location = NULL;
  session->current_dst_file = NULL;
  session->current_src_is_local = 0;
  session->current_src_location = NULL;
  session->timeout_is_fatal = 0;
  session->timeout_triggered = 0;
  session->tmp_handle = NULL;
  session->tmp_attributes_ok = 0;
  session->tmp_data = NULL;
  session->callback_fired = 0;
  session->unlink_flag = 0;
  session->error = 0;

  return;
}

void scp_print_location_info(ScpFileLocation *location)
{
  fprintf(stderr, "    Location data: (%p)\n", location);
  if (location != NULL)
    {
      fprintf(stderr, "      user = ");
      if (location->user)
	fprintf(stderr, "\"%s\"\n", location->user);
      else
	fprintf(stderr, "NULL\n");
      fprintf(stderr, "      host = ");
      if (location->host)
	fprintf(stderr, "\"%s\"\n", location->host);
      else
	fprintf(stderr, "NULL\n");
      fprintf(stderr, "      file = ");
      if (location->file)
	fprintf(stderr, "\"%s\"\n", location->file);
      else
	fprintf(stderr, "NULL\n");
      fprintf(stderr, "      port = %d\n", location->port);
      fprintf(stderr, "      next = %p\n", location->next);
    }
  return;
}

void scp_print_session_info(ScpSession session)
{
  fprintf(stderr, "Session data: (%p)\n", session);
  fprintf(stderr, "  preserve_flag      = %d\n", session->preserve_flag);
  fprintf(stderr, "  debug_flag         = ");
  if (session->debug_flag)
    fprintf(stderr, "\"%s\"\n", session->debug_flag);
  else
    fprintf(stderr, "NULL\n");
	  
  fprintf(stderr, "  verbose            = %d\n", session->verbose);
  fprintf(stderr, "  preserve_flag      = %d\n", session->preserve_flag);
  fprintf(stderr, "  port_flag          = %d\n", session->port_flag);
  fprintf(stderr, "  need_dst_dir       = %d\n", session->need_dst_dir);
  fprintf(stderr, "  dst_is_dir         = %d\n", session->dst_is_dir);
  fprintf(stderr, "  dst_is_file        = %d\n", session->dst_is_file);
  fprintf(stderr, "  dst_is_local       = %d\n", session->dst_is_local);
  fprintf(stderr, "  tty_fd             = %d\n", session->tty_fd);
  fprintf(stderr, "  ssh_path           = \"%s\"\n", session->ssh_path);
  fprintf(stderr, "  dst_local_client   = %p\n", session->dst_local_client);
  fprintf(stderr, "  dst_local_server   = %p\n", session->dst_local_server);
  fprintf(stderr, "  dst_remote_client  = %p\n", session->dst_remote_client);
  fprintf(stderr, "  src_local_client   = %p\n", session->src_local_client);
  fprintf(stderr, "  src_local_server   = %p\n", session->src_local_server);
  fprintf(stderr, "  src_remote_client  = %p\n", session->src_remote_client);
  fprintf(stderr, "  src_list           = %p\n", session->src_list);
  if (session->src_list)
    {
      ScpFileLocation *loc = session->src_list;
      while (loc != NULL)
	{
	  scp_print_location_info(loc);
	  loc = loc->next;
	}
    }
  fprintf(stderr, "  src_list_tail      = %p\n", session->src_list_tail);
  fprintf(stderr, "  dst_location       = %p\n", session->dst_location);
  scp_print_location_info(session->dst_location);
  fprintf(stderr, "  current_dst_file   = ");
  if (session->current_dst_file != NULL)
    fprintf(stderr, "\"%s\"\n", session->current_dst_file);
  else
    fprintf(stderr, "NULL\n");
  fprintf(stderr, "  current_src_location = %p\n", 
	  session->current_src_location);
  scp_print_location_info(session->current_src_location);
  fprintf(stderr, "  current_src_is_local = %d\n", 
	  session->current_src_is_local);
  fprintf(stderr, "  timeout_is_fatal   = %d\n", session->timeout_is_fatal);
  fprintf(stderr, "  timeout_triggered  = %d\n", session->timeout_triggered);
  return;
}

void scp_debug(const char *msg, void *context)
{
  ScpSession session = (ScpSession)context;
  if (session->debug_flag)
    fprintf(stderr, "debug: %s\r\n", msg);
}

ScpCipherName scp_new_cipher_item(char *name)
{
  ScpCipherName r;

  r = (ScpCipherName)ssh_xcalloc(1, sizeof (struct ScpCipherNameRec));
  r->name = ssh_xstrdup(name);
  r->next = NULL;
  return r;
}

ScpFileLocation* scp_parse_location_string(ScpSession session, char *str)
{
  ScpFileLocation *loc;
  char *hlp;

  loc = ssh_xcalloc(1, sizeof (ScpFileLocation));

  if ((!str) || (!(*str)))
    goto error_ret;

  hlp = strchr(str, ':');
  if (!hlp)
    {
      /* It's local */
      loc->file = ssh_xstrdup(str);
      loc->user = NULL;
      loc->host = NULL;
      loc->next = NULL;
    } else {
      /* It's remote */
      *hlp = '\000';
      hlp++;
      loc->file = ssh_xstrdup(hlp);
      hlp = strchr(str, '@');
      if (hlp)
	{
	  *hlp = '\000';
	  hlp++;
	  if (!hlp)
	    goto error_ret;

	  loc->user = ssh_xstrdup(str);
	  str = hlp;
	} else {
	  loc->user = NULL;      
	}
      hlp = strchr(str, '#');
      if (hlp)
	{
	  *hlp = '\000';
	  hlp++;
	  loc->port = atoi(hlp);
	  if ((loc->port < 1) || (loc->port > 65535))
	    goto error_ret;
	} else {
	  loc->port = session->port_flag;
	}
      if (!(*str))
	goto error_ret;
      loc->host = ssh_xstrdup(str);
    }

  return loc;

 error_ret:
  if (loc->user)
    ssh_xfree(loc->user);
  if (loc->host)
    ssh_xfree(loc->host);
  if (loc->file)
    ssh_xfree(loc->file);
  ssh_xfree(loc);
  return NULL;
}

#define SSH_ARGV_SIZE 	64

SshFileClient scp_open_remote_connection(ScpSession session,
					 char *host,
					 char *user, 
					 int port)
{
  SshFileClient client;
  SshStream client_stream;
  char *ssh_argv[SSH_ARGV_SIZE];
  char port_buf[16];
  int i;
  ScpCipherName cipher;

  assert(host != NULL);
  assert(session != NULL);
  assert(session->ssh_path != NULL);

  i = 0;

  ssh_argv[i++] = session->ssh_path;
  if (user != NULL)
    {
      ssh_argv[i++] = "-l";
      ssh_argv[i++] = user;
    }
  if (port > 0)
    {
      snprintf(port_buf, sizeof (port_buf), "%d", port);
      ssh_argv[i++] = "-p";
      ssh_argv[i++] = port_buf;
    }
  if (session->verbose)
    ssh_argv[i++] = "-v";
  ssh_argv[i++] = "-o";
  ssh_argv[i++] = "passwordprompt %U@%H's password: ";

  for (cipher = session->cipher_list; cipher != NULL; cipher = cipher->next)
    {
      assert(i < SSH_ARGV_SIZE);

      ssh_argv[i++] = "-c";
      ssh_argv[i++] = cipher->name;
    }

  ssh_argv[i++] = host;

  ssh_argv[i++] = "-s";
  ssh_argv[i++] = "sftp";

  ssh_argv[i] = NULL;

  assert(i < SSH_ARGV_SIZE);
     
  if (session->verbose)
    {
      for (i = 0; ssh_argv[i]; i++)
	SSH_DEBUG(2, ("argv[%d] = %s", i, ssh_argv[i]));
    }
  
  switch (ssh_pipe_create_and_fork(&client_stream, NULL))
    {
    case SSH_PIPE_ERROR:
      ssh_fatal("ssh_pipe_create_and_fork() failed");
    
    case SSH_PIPE_PARENT_OK:      
      /* Try to wrap this as the server */
    
      client = ssh_file_client_wrap(client_stream);
      return client;
    
    case SSH_PIPE_CHILD_OK:
      execvp(ssh_argv[0], ssh_argv);
      exit(-2);
    }  
  return NULL;
}

void scp_set_src_remote_location(ScpSession session, 
				 char *host, 
				 int port, 
				 char *user)
{
  assert(host != NULL);

  if (session->src_remote_host != NULL)
    ssh_xfree(session->src_remote_host);
  if (session->src_remote_user != NULL)
    ssh_xfree(session->src_remote_user);
  session->src_remote_host = ssh_xstrdup(host);
  session->src_remote_user = user ? ssh_xstrdup(user) : NULL;
  session->src_remote_port = port;
}

Boolean scp_set_src_is_remote_location_ok(ScpSession session, 
					  char *host, 
					  int port, 
					  char *user)
{
  if ((session->src_remote_client == NULL) ||
      (session->src_remote_host == NULL) ||
      (strcmp(session->src_remote_host, host) != 0) ||
      (session->src_remote_port != port) ||
      ((session->src_remote_user == NULL) && (user != NULL)) ||
      ((session->src_remote_user != NULL) && (user == NULL)))
    return FALSE;
      
  if (((session->src_remote_user == NULL) && (user == NULL)) ||
      (strcmp(session->src_remote_user, user) == 0))
    return TRUE;

  return FALSE;
}

char *scp_file_basename(char *pathname)
{
  char *r;

  r = strrchr(pathname, '/');
  if (r == NULL)
    return ssh_xstrdup(pathname);
  r++;
  if (*r != '\000')
    return ssh_xstrdup(r);
  return NULL;
}

void scp_set_next_src_location(void *context)
{
  ScpSession session = (ScpSession)context;

  if (session->current_src_location)
    {
      if (session->current_src_location->user != NULL)
	ssh_xfree_q(session->current_src_location->user);
      if (session->current_src_location->host != NULL)
	ssh_xfree_q(session->current_src_location->host);
      if (session->current_src_location->file != NULL)
	ssh_xfree_q(session->current_src_location->file);
      ssh_xfree_q(session->current_src_location);
    }

  if (session->src_list == NULL)
    {
      session->src_list_tail = NULL;    
      if (session->src_remote_client != NULL)
	{
	  ssh_file_client_destroy(session->src_remote_client);
	  session->src_remote_client = NULL;
	}
      return;
    }

  session->current_src_location = session->src_list;
  session->src_list = session->src_list->next;
  if (session->src_list == NULL)
    session->src_list_tail = NULL;    

  if (session->current_dst_file != NULL)
    {
      ssh_xfree(session->current_dst_file);
      session->current_dst_file = NULL;
    }
  if (session->dst_is_dir)
    {
      char *hlp = strrchr(session->current_src_location->file, '/');

      if (hlp == NULL)
	{
	  session->current_dst_file = 
	    str_concat_3(session->dst_location->file,
			 "/",
			 session->current_src_location->file);
	} else {
	  hlp++;
	  session->current_dst_file = 
	    str_concat_3(session->dst_location->file,
			 "/",
			 hlp);
	}
    } else {
      session->current_dst_file = ssh_xstrdup(session->dst_location->file);
    }

  if (session->current_src_location->host == NULL)
    {
      session->current_src_is_local = 1;
      /* Next source file is local */
      return;
    } else {
      session->current_src_is_local = 0;
    }

  if (!(scp_set_src_is_remote_location_ok(session, 
					 session->current_src_location->host, 
					 session->current_src_location->port, 
					 session->current_src_location->user)))
    {
      if (session->src_remote_client != NULL)
	{
	  ssh_file_client_destroy(session->src_remote_client);
	  session->src_remote_client = NULL;
	}
      session->src_remote_client = scp_open_remote_connection(session,
				      session->current_src_location->host, 
				      session->current_src_location->user,
				      session->current_src_location->port);
      scp_set_src_remote_location(session, 
				  session->current_src_location->host,
				  session->current_src_location->port,
				  session->current_src_location->user);
      if (session->src_remote_client == NULL)
	ssh_fatal("Cannot reach the source location.");
      scp_abort_if_remote_dead(session, session->src_remote_client);
    }
  /* Next source file is remote and client is now up */
  return;
}

void scp_timeout_callback(void *context)
{
  ScpSession session = (ScpSession)context;

  if (session->timeout_is_fatal)
    ssh_fatal("Operation timed out.");
  session->timeout_triggered++;
  return;
}

void scp_remote_dead_timeout(void *context)
{
  ScpSession session = (ScpSession)context; 

  session->callback_fired = 1;

  ssh_fatal("Connection timed out.");
}

void scp_remote_alive_callback(SshFileClientError error,
			       const char *name,
			       const char *long_name,
			       SshFileAttributes attrs,
			       void *context)
{
  ScpSession session = (ScpSession)context; 

  session->callback_fired = 1;
  if (error != SSH_FX_OK)
    ssh_fatal("Connection lost.");
  ssh_event_loop_abort();
}

void scp_abort_if_remote_dead(ScpSession session, SshFileClient client)
{
  session->callback_fired = 0;
  ssh_file_client_realpath(client, ".", scp_remote_alive_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
}

void scp_is_dst_directory_callback(SshFileClientError error,
				   SshFileAttributes attributes,
				   void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  if (error != SSH_FX_OK)
    {
      session->dst_is_dir = 0;
      session->dst_is_file = 0;
    } else {
      if ((attributes->permissions & S_IFMT) == S_IFDIR)
	{
	  session->dst_is_dir = 1;
	  session->dst_is_file = 0;
	} else {
	  session->dst_is_dir = 0;
	  session->dst_is_file = 1;
	}
    }
  ssh_event_loop_abort();
}

void scp_get_win_dim(int *width, int *height)
{
#ifdef TIOCGWINSZ
  struct winsize ws;
    
  if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) >= 0)
    {
      if (width != NULL)
	*width = ws.ws_col;
      if (height != NULL)
	*height = ws.ws_row;
    }    
  else  
#endif 
    {
      if (width != NULL)
	*width = 80;
      if (height != NULL)
	*height = 25;    
    }
}

void scp_kitt(off_t pos, off_t total, int width)
{
  int i, p;

  p = width * pos / total;  

  printf("\r|");
  for (i = 1; i < width - 2; i++)
    {
      switch(i - p)
	{
	case 0:
	  putchar('O');
	  break;
	  
	case 1:
	case -1:
	  putchar('o');
	  break;
	  
	default:
	  putchar('.');
	}
    }  
  putchar('|');
  fflush(stdout);
}

void scp_file_handle_callback(SshFileClientError error, 
			      SshFileHandle handle, 
			      void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  ssh_event_loop_abort();
  session->tmp_handle = handle;
  return;
}

SshFileHandle scp_file_open(ScpSession session,
			    SshFileClient client,
			    char *file,
			    int flags,
			    SshFileAttributes attributes)
{
  session->callback_fired = 0;
  session->tmp_handle = NULL;
  ssh_file_client_open(client, file, flags, attributes, 
		       scp_file_handle_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return session->tmp_handle;
}

void scp_file_status_callback(SshFileClientError error, void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  ssh_event_loop_abort();  
  session->tmp_status = error;
  return;
}

int scp_file_close(ScpSession session, SshFileHandle handle)
{
  session->callback_fired = 0;
  ssh_file_client_close(handle, scp_file_status_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return session->tmp_status;
}

void scp_file_attribute_callback(SshFileClientError error, 
				 SshFileAttributes attributes,
				 void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;

  ssh_event_loop_abort();  
  if (error == SSH_FX_OK)
    {
      session->tmp_attributes = *attributes;
      session->tmp_attributes_ok = 1;
    } else {
      session->tmp_attributes_ok = 0;
    }
}

SshFileAttributes scp_file_fstat(ScpSession session, 
				 SshFileHandle handle)
{
  session->callback_fired = 0;
  ssh_file_client_fstat(handle, scp_file_attribute_callback, session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return (session->tmp_attributes_ok ? (&session->tmp_attributes) : NULL);
}

void scp_file_read_callback(SshFileClientError error,
			    const unsigned char *data,
			    size_t len,
			    void *context)
{
  ScpSession session = (ScpSession)context;

  session->callback_fired = 1;
  ssh_event_loop_abort();  
  if (error == SSH_FX_OK)
    {
      session->tmp_data_len = len;
      memcpy(session->tmp_data, data, len);
    } else if (error == SSH_FX_EOF)
      {
	session->tmp_data_len = 0;
	session->tmp_data = NULL;
      } else {
	session->tmp_data_len = -1;
	session->tmp_data = NULL;
      }
  return;
}

int scp_file_read(ScpSession session, 
		  SshFileHandle handle,
		  off_t offset, 
		  char *buf,
		  size_t bufsize)
{
  session->callback_fired = 0;
  session->tmp_data = buf;
  session->tmp_data_len = bufsize;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  ssh_file_client_read(handle, offset, bufsize, 
		       scp_file_read_callback, session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  return session->tmp_data_len;
}

int scp_file_write(ScpSession session,
		   SshFileHandle handle, 
		   off_t offset, 
		   char *buf, 
		   size_t bufsize)
{
  session->callback_fired = 0;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  ssh_file_client_write(handle, offset, buf, bufsize, 
			scp_file_status_callback, session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  if (session->tmp_status != SSH_FX_OK)
    return -1;
  else
    return bufsize;
}

int scp_file_fsetstat(ScpSession session,
		      SshFileHandle handle,
		      SshFileAttributes attributes)
{
  session->callback_fired = 0;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  ssh_file_client_fsetstat(handle,
			   attributes,
                           scp_file_status_callback,
			   session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);
  if (session->tmp_status != SSH_FX_OK)
    return 1;
  else
    return 0;
}

int scp_file_remove(ScpSession session,
		    SshFileClient client,
		    const char *name)
{
  session->callback_fired = 0;
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  ssh_file_client_remove(client, name, scp_file_status_callback, session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);

  return (session->tmp_status != SSH_FX_OK);
}

Boolean scp_move_file(ScpSession session,
		      char *src_host,
		      char *src_file,
		      SshFileClient src_client,
		      char *dst_host,
		      char *dst_file,
		      SshFileClient dst_client)
{
  SshFileAttributes src_attributes;
  off_t offset;
  size_t src_len, file_len;
  int width, r;
  char data[SCP_BUF_SIZE];
  SshFileHandle src_handle = NULL, dst_handle = NULL;

  src_handle = scp_file_open(session, 
			     src_client,
			     src_file,
			     O_RDONLY,
			     NULL);
  if (src_handle == NULL)
    {
      scp_set_error(session, SCP_ERROR_CANNOT_OPEN);
      ssh_warning("Cannot open source file %s%s%s",
		  (src_host != NULL) ? src_host : "",
		  (src_host != NULL) ? ":" : "",
		  src_file);
      goto close_error;
    }
  
  src_attributes = scp_file_fstat(session, src_handle);
  if (src_attributes == NULL) 
    {
      scp_set_error(session, SCP_ERROR_CANNOT_STAT);
      ssh_warning("Cannot stat source file %s%s%s",
		  (src_host != NULL) ? src_host : "",
		  (src_host != NULL) ? ":" : "",
		  src_file);
      goto close_error;
    }
  file_len = src_attributes->size;

  if ((src_attributes->permissions & S_IFMT) != S_IFREG) 
    {
      ssh_warning("Source file %s%s%s is not a regular file",
		  (src_host != NULL) ? src_host : "",
		  (src_host != NULL) ? ":" : "",
		  src_file);
      scp_set_error(session, SCP_ERROR_NOT_REGULAR_FILE);
      goto close_error;
    }

  if (! session->do_not_copy)
    if (session->unlink_flag)
      scp_file_remove(session, dst_client, dst_file);

  if (! session->do_not_copy)
    {
      dst_handle = scp_file_open(session,
				 dst_client,
				 dst_file,
				 O_CREAT | O_WRONLY,
				 NULL);
      if (dst_handle == NULL) 
	{
	  ssh_warning("Cannot open destination file %s%s%s",
		      (dst_host != NULL) ? dst_host : "",
		      (dst_host != NULL) ? ":" : "",
		      dst_file);
	  scp_set_error(session, SCP_ERROR_CANNOT_CREATE);
	  goto close_error;
	}
    }

  offset = 0;

  if (! session->do_not_copy)
    {
      if (session->verbose > 0) 
	{  
	  printf("Transferring %s%s%s -> %s%s%s  (%luk)\n",
		 (src_host != NULL) ? src_host : "",
		 (src_host != NULL) ? ":" : "",
		 src_file,
		 (dst_host != NULL) ? dst_host : "",
		 (dst_host != NULL) ? ":" : "",
		 dst_file,
		 (unsigned long) (file_len >> 10) + 1);
	  
	  scp_get_win_dim(&width, NULL);
	  scp_kitt(0, file_len, width);
	}
    }
  else
    {
      printf("Not transferring %s%s%s -> %s%s%s  (%luk)\n",
	     (src_host != NULL) ? src_host : "",
	     (src_host != NULL) ? ":" : "",
	     src_file,
	     (dst_host != NULL) ? dst_host : "",
	     (dst_host != NULL) ? ":" : "",
	     dst_file,
	     (unsigned long) (file_len >> 10) + 1);
    }
  
  /* move the file */
    
  if (! session->do_not_copy)
    {
      do {
	src_len = scp_file_read(session, 
				src_handle,
				offset, 
				data,
				SCP_BUF_SIZE);
	if (src_len < 0)
	  {
	    ssh_warning("Read error in file %s%s%s",
			(src_host != NULL) ? src_host : "",
			(src_host != NULL) ? ":" : "",
			src_file);
	    scp_set_error(session, SCP_ERROR_READ_ERROR);
	    goto close_error;
	  }
	
	if (src_len > 0)
	  {
	    r = scp_file_write(session,
			       dst_handle, 
			       offset, 
			       data, 
			       src_len);
	    if (r != src_len)
	      {
		ssh_warning("Write error in file %s%s%s",
			    (dst_host != NULL) ? dst_host : "",
			    (dst_host != NULL) ? ":" : "",
			    dst_file);
		scp_set_error(session, SCP_ERROR_WRITE_ERROR);
		goto close_error;
	      }
	    offset += src_len;
	  
	    if (session->verbose > 0)
	      scp_kitt(offset, file_len, width);
	  }
      } while (src_len == SCP_BUF_SIZE);

      if (session->verbose > 0)
	putchar('\n');  

    }
  
  scp_file_close(session, src_handle);

  if (! session->do_not_copy)
    {
      if (session->preserve_flag)
	scp_file_fsetstat(session, dst_handle, src_attributes);
      scp_file_close(session, dst_handle);
    }
  return TRUE;
      
 close_error:
  if (src_handle != NULL)
    scp_file_close(session, src_handle);
  if (dst_handle != NULL)
    scp_file_close(session, dst_handle);
  return FALSE;
}

void scp_set_error(ScpSession session, int error)
{
  if (error == 0)
    session->error = 0;    
  else if (session->error == 0)
    session->error = error;
  else if (session->error != error)
    session->error = SCP_ERROR_MULTIPLE;
}

Boolean scp_is_dst_directory(ScpSession session)
{
  session->callback_fired = 0;

  ssh_file_client_stat(session->dst_client, 
		       session->dst_location->file, 
		       scp_is_dst_directory_callback,
		       session);
  ssh_register_timeout(SCP_FILESERVER_TIMEOUT,
		       0,
		       scp_remote_dead_timeout, 
		       session);
  if (!session->callback_fired)
    ssh_event_loop_run();
  ssh_cancel_timeouts(scp_remote_dead_timeout, session);

  return (session->dst_is_dir != 0);
}

int scp_execute(ScpSession session)
{
  SshStream tmp1a, tmp1b, tmp2a, tmp2b;
  Boolean r;

  if ((session->tty_fd = open("/dev/tty", O_RDWR, 0)) == -1)
    session->tty_fd = 0;

  ssh_stream_pair_create(&tmp2a, &tmp2b);  
  session->src_local_server = ssh_file_server_wrap(tmp2a);
  session->src_local_client = ssh_file_client_wrap(tmp2b);

  if (session->dst_is_local)
    {
      ssh_stream_pair_create(&tmp1a, &tmp1b);  
      session->dst_local_server = ssh_file_server_wrap(tmp1a);
      session->dst_local_client = ssh_file_client_wrap(tmp1b);
      session->dst_client = session->dst_local_client;
    } else {
      session->dst_remote_client = scp_open_remote_connection(session,
					      session->dst_location->host,
					      session->dst_location->user,
					      session->dst_location->port);
      if (session->dst_remote_client == NULL)
	ssh_fatal("Cannot reach the destination.");

      session->dst_client = session->dst_remote_client;
    }

  scp_abort_if_remote_dead(session, session->dst_client);
  scp_is_dst_directory(session);
  if (session->dst_is_file && session->need_dst_dir)
    {
      ssh_warning("Destination file is not a directory.");
      ssh_warning("Exiting.");
      exit(SCP_ERROR_USAGE);
    }

  /*scp_print_session_info(session);*/

  while (session->src_list != NULL)
    {
      scp_set_next_src_location((void *)session);

      r = scp_move_file(session,
			session->current_src_location->host,
			session->current_src_location->file,
			(session->current_src_is_local ? 
			 session->src_local_client :
			 session->src_remote_client),
			session->dst_location->host,
			session->current_dst_file, 
			session->dst_client);
    }

  if (session->src_remote_client != NULL)
    ssh_file_client_destroy(session->src_remote_client);
  if (session->dst_client != NULL)
    ssh_file_client_destroy(session->dst_client);

  if (session->tty_fd > 0)
    (void)close(session->tty_fd);

  /*scp_print_session_info(session);*/

  return session->error;
}

/* eof (scp2.c) */
