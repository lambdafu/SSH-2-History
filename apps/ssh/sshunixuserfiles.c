 /*

  sshunixuserfiles.c

  Authors:
        Tatu Ylonen <ylo@ssh.fi>
        Markku-Juhani Saarinen <mjos@ssh.fi>
        Timo J. Rinne <tri@ssh.fi>
        Sami Lehtinen <sjl@ssh.fi>

  Copyright (C) 1997-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Simple functions that update user's files. These are unix-spesific.

*/

/* 
 * $Log: sshunixuserfiles.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshuserfiles.h"
#include "sshencode.h"
#include "pubkeyencode.h"
#include "sshuser.h"
#include "userfile.h"
#include "sshconfig.h"

/* Return a pointer to user's ssh2 directory.
   The directory is created if `create_if_needed' is TRUE. 
   Return NULL on failure. The caller is responsible for freeing the returned
   value with ssh_xfree when no longer needed. */

char *ssh_userdir(SshUser user, Boolean create_if_needed)
{
  char *sshdir;
  size_t sshdirlen;
  struct stat st;

  /* create the .ssh2 directory name */

  if (ssh_user_uid(user) == 0)
    {
      sshdir = ssh_xstrdup(SSH_SERVER_DIR);
    }
  else
    {
      sshdirlen = sizeof(SSH_USER_DIR) + strlen(ssh_user_dir(user)) + 4;
      sshdir = ssh_xmalloc(sshdirlen);
      snprintf(sshdir, sshdirlen, "%s/%s", ssh_user_dir(user), SSH_USER_DIR);
    } 

  if (stat(sshdir, &st) < 0)
    {
      if (create_if_needed)
	{
	  if (mkdir(sshdir, 0755) < 0)
	    ssh_warning("ssh_userdir: could not create user's ssh" 
			"directory %s", sshdir);
	  ssh_xfree(sshdir);
	  return NULL;
	}
      else
	{
	  ssh_xfree(sshdir);
	  return NULL;
	}
    }

  return sshdir;
}


/* Make sure that the random seed file exists and return a pointer to it. 
   return NULL on failure. The file name is found from `config'. 
   If `config' is NULL, use the standard SSH_RANDSEED_FILE.

   The caller is responsible for freeing the returned value with ssh_xfree 
   when no longer needed. */

char *ssh_randseed_file(SshUser user, SshConfig config)
{
  UserFile f;
  char *sshdir, *sshseed;
  size_t sshseedlen;
  struct stat st;
  
  /* XXX config is not used */

  /* See if the random seed directory exists */
  
  if ((sshdir = ssh_userdir(user, TRUE)) == NULL)
    return NULL;
  sshseedlen = sizeof(SSH_RANDSEED_FILE) + strlen(sshdir) + 4;
  sshseed = ssh_xmalloc(sshseedlen);
  snprintf(sshseed, sshseedlen, "%s/%s", sshdir, SSH_RANDSEED_FILE);

  /* If it doesn't exist, create it. */

  if (userfile_stat(ssh_user_uid(user), sshseed, &st) < 0)
    {
      if ((f = userfile_open(ssh_user_uid(user), sshseed, O_RDWR | O_CREAT, 
			    0600)) == NULL)
	{
	  ssh_warning("ssh_randseed_file: Could not create random"
		      "seed file %s.", sshseed);
	  ssh_xfree(sshdir);
	  ssh_xfree(sshseed);
	  return NULL;
	}
      userfile_close(f);
    }
  
  ssh_xfree(sshdir);

  return sshseed;
}

/* Get the random state from the file.  This loads and merges any data
   in the seed file into the generator. */

void ssh_randseed_load(SshUser user, SshRandomState random_state,
		       SshConfig config)
{
  int i;
  UserFile f;
  unsigned char randbuf[16];
  char *sshseed;
  size_t nbytes;

  /* Stir a bit.  This will add a couple of bits of new randomness to the 
     pool. */
  for (i = 0; i < 3; i++)
    ssh_random_stir(random_state);
  
  /* Stir the seed file in, if possible. */
  sshseed = ssh_randseed_file(user, config);
  if ((f = userfile_open(ssh_user_uid(user), sshseed, O_RDONLY, 0)) != NULL)
    {
      while ((nbytes = userfile_read(f, randbuf, sizeof(randbuf))) > 0)
	ssh_random_add_noise(random_state, randbuf, nbytes);
      userfile_close(f);
    }
  ssh_xfree(sshseed); 
  
  /* Stir a bit.  This will add a few bits of new randomness to the pool. */
  for (i = 0; i < 3; i++)
    ssh_random_stir(random_state);
}

/* Updates the random seed file with information from the random
   number generator.  Information from the old random seed file and
   the generator is mixed, so that the new random seed file will
   contain traces of both the generator state and the old seed
   file. */

void ssh_randseed_update(SshUser user, SshRandomState rs, SshConfig config)
{
  size_t i;
  UserFile f;
  char *sshseed;
  unsigned char seed[SSH_RANDSEED_LEN];

  /* Load the old random seed file and mix it into the generator. */
  ssh_randseed_load(user, rs, config);
  
  /* Write data from the generator into the random seed file. */
  sshseed = ssh_randseed_file(user, config);
  if ((f = userfile_open(ssh_user_uid(user), sshseed, O_CREAT | O_WRONLY, 
			 0600)) == NULL)
    {
      ssh_warning("ssh_randseed_close: unable to write the random seed file!");
      goto error;
    }
  for (i = 0; i < SSH_RANDSEED_LEN; i++)
    seed[i] = ssh_random_get_byte(rs);
  if (userfile_write(f, seed, SSH_RANDSEED_LEN) != SSH_RANDSEED_LEN)
    ssh_warning("unable to write to the random seed file %s.", sshseed);

  memset(seed, 0, SSH_RANDSEED_LEN);
  userfile_close(f);

error:
  ssh_xfree(sshseed);
}


/* Reads a blob into a buffer. Return TRUE on failure.  The caller must free
   `*blob' with ssh_xfree when no longer needed. */

Boolean ssh_blob_read(SshUser user, const char *fname, unsigned char **blob, 
		      size_t *bloblen, void *context)
{
  UserFile f;
  unsigned char *data;
  struct stat st;
  size_t datalen;

  *bloblen = 0;
  *blob = NULL;

  if (userfile_stat(ssh_user_uid(user), fname, &st) < 0)
    {
      ssh_warning("ssh_blob_read: file %s does not exist.", fname);
      return TRUE;
    }
  datalen = st.st_size;
  data = ssh_xmalloc(datalen);

  if ((f = userfile_open(ssh_user_uid(user), fname, O_RDONLY, 0)) == NULL) 
    {
      ssh_warning("ssh_blob_read: Could not open %s.", fname);
      ssh_xfree(data);
      return TRUE;
    }

  if (userfile_read(f, data, datalen) != datalen)
    {
      ssh_warning("ssh_blob_read: Error while reading %s.", fname);
      memset(data, 0, datalen);
      ssh_xfree(data);
      userfile_close(f); 
      return TRUE;
    }

  userfile_close(f);
  *blob = data;
  *bloblen = datalen;

  return FALSE;
}


/* Write a blob. Return TRUE on failure. */

Boolean ssh_blob_write(SshUser user, const char *fname, mode_t mode,
		       const unsigned char *blob, size_t bloblen, void *context)
{
  UserFile f;

  if ((f = userfile_open(ssh_user_uid(user), fname, O_WRONLY | O_CREAT, 
			 mode)) == NULL)
    {
      ssh_warning("ssh_blob_write: could not open %s.", fname);
      return TRUE;
    }

  if(userfile_write(f, blob, bloblen) != bloblen)
    {
      ssh_warning("ssh_blob_write: failed to write %s.", fname);
      return TRUE;
    }

  userfile_close(f);

  return FALSE;
}

/* build a list of private key files that should be tried when
   logging into `host'.  The list's last entry will be NULL.
   The caller should free the array and all strings in it when no longer
   needed. */

char **ssh_privkey_list(SshUser user, char *host, SshConfig config)
{
  int i, j, n;
  char *udir, **vars, **vals, **prklist, buf[1024];

  if ((udir = ssh_userdir(user, TRUE)) == NULL)
    {
      ssh_warning("ssh_privkey_list: no user directory.");
      return NULL;
    }

  /* read and sort the names */

  snprintf(buf, sizeof(buf)-1, "%s/%s", udir, 
	   config == NULL || config->identity_file == NULL ?
	   SSH_IDENTIFICATION_FILE : config->identity_file);
  n = ssh2_parse_config(user, host, buf, &vars, &vals, NULL);

  if (n < 0)
    {
      ssh_xfree(udir);
      return NULL;
    }

  /* construct a name list with complete file paths */

  prklist = ssh_xcalloc(n + 1, sizeof(char *));

  j = 0;
  for (i = 0; i < n; i++)
    {
      if (strcmp(vars[i], "idkey") == 0)
	{
	  snprintf(buf, sizeof(buf), "%s/%s",
		   udir, vals[i]);
	  prklist[j++] = ssh_xstrdup(buf);
	}
    }
  prklist[j++] = NULL;
  ssh_free_varsvals(n, vars, vals);
  ssh_xfree(udir);

  return prklist;
}
