/*

  ssh-keygen.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov 23 18:53:04 1996 [mkojo]

  Generation of public/private keys.
  
  */

/*
 * $Id: ssh-keygen.c,v 1.12 1998/06/05 06:14:40 tri Exp $
 * $Log: ssh-keygen.c,v $
 * $EndLog$
 */

#include "sshincludes.h"

#ifdef macintosh
#define GETOPT_MISSING
#define HOME_DIR_MISSING
#endif /* macintosh */

#ifdef WINDOWS
#define GETOPT_MISSING
#define HOME_DIR_MISSING
#endif /* WINDOWS */

#ifndef HOME_DIR_MISSING
#include <pwd.h>
#endif
#include "sshcrypt.h"
#include "sshbuffer.h"
#include "keyblob.h"

#ifndef WINDOWS
#include "namelist.h"
#endif

#ifdef GETOPT_MISSING

/* MSVC 2.0 doesn't support getopt() function, thus we have to kludge
   similar method ourselves. This is by no means ment to replace
   the actual getopt() in general. */

char *optarg;
int optind = 2;

int getopt(int argc, char *argv[], char *opts)
{
  int opt, i;

  /* Check if no arguments. */
  if (argc < 2)
    return EOF;

  /* Check if no more. */
  if (argv[optind - 1] != NULL)
    {
      /* Seek for valid option. */
      
      if (argv[optind - 1][0] != '-')
	{
	  printf("error: invalid argument %s.\n", argv[optind-1]);
	  return '?';
	}
      
      for (i = 0; opts[i] != '\0'; i++)
	{
	  if (isalpha(opts[i]) || isdigit(opts[i]))
	    {
	      if (opts[i] == argv[optind - 1][1])
		break;
	    }
	}
      if (opts[i] == '\0')
	{
	  printf("error: invalid argument %s.\n", argv[optind-1]);
	  return '?';
	}

      /* Valid option found. Check if it has argument. */
      
      opt = argv[optind - 1][1];
      
      optind++;
      
      if (opts[i + 1] == ':')
	{
	  optarg = argv[optind - 1];
	  optind++;
	}
      else
	{
	  optarg = NULL;
	}
      
      return opt;
    }
  
  return EOF;
}
  
#endif /* GETOPT_MISSING */

#ifdef WINDOWS

/* This is kludge do this better later... The can also be found in the
   namelist.c but Windows DLL's are nasty... */

int ssh_name_list_name_len(const char *namelist)
{
  int i;
  if (namelist == NULL)
    return 0;
  for (i = 0; namelist[i] != ',' && namelist[i] != '\0'; i++)
    ;
  return i;
}

char *ssh_name_list_get_name(const char *namelist)
{
  int len = ssh_name_list_name_len(namelist);
  char *name = NULL;
  
  if (len > 0)
    {
      name = ssh_xmalloc(len + 1);
      memcpy(name, namelist, len);
      name[len] = '\0';
    }
  return name;
}

const char *ssh_name_list_step_forward(const char *namelist)
{
  int len = ssh_name_list_name_len(namelist);

  if (len > 0)
    {
      if (namelist[len] != '\0')
	return namelist + len + 1;
    }

  return NULL;
}

#endif

char *print_list(int tab, char *list)
{
  char *name;
  const char *tmp_list = list;
  char *first = NULL;
  int len = 0, prev = 0;
  
  while ((name = ssh_name_list_get_name(tmp_list)) != NULL)
    {
      if (prev)
	{
	  len += 2;
	  printf(", ");
	}

      if (len > 70)
	{
	  len = 0;
	  printf("\n");
	}
      
      if (len < tab)
	for (len = 0; len < tab; len++)
	  printf(" ");
      
      len += strlen(name) + 2;
      printf("'%s'", name);
      
      tmp_list = ssh_name_list_step_forward(tmp_list);

      if (!prev)
	{
	  first = name;
	  prev = 1;
	}
      else
	{
	  ssh_xfree(name);
	}
    }

  if (prev == 0)
    {
      printf("error: not available.\n");
      exit(1);
    }
  printf(".");

  return first;
}
	   
/* Generation of private and public keys and writing them to a files. */

void main(int ac, char **av)
{
  /* Buffers. */
  char buf[1024];
  /* Some Usage helps.. */
  char *cipher_list, *pkcs_list, *first_cipher, *first_pkcs;
  char *passphrase1, *passphrase2;
  int i;
  /* Ssh private and public key data structures. */
  SshPublicKey public_key;
  SshPrivateKey private_key;
  /* Random state for the cryptographically strong random number generator. */
  SshRandomState state;
  /* Default settings. RSA key length 1024 bits. */
  char *pkcs_name = "if-modn{encrypt{rsa-pkcs1-none},sign{rsa-pkcs1-md5}}";
  int bits = 1024;
  /* Default cipher for encrypting the private key. */
  char *cipher_name = "des-cbc";
  /* Few flags for the argument parsing. */
  int change_passphrase = 0,
    update_cipher = 0;
  char *identity_file = NULL,
    *identity_passphrase = NULL, 
    *identity_new_passphrase = NULL;
  unsigned char *blob;
  size_t blob_len;
  int opt;
  struct stat st;
  FILE *f;
#ifndef HOME_DIR_MISSING
  struct passwd *pw;
#endif /* HOME_DIR_MISSING */
#ifndef GETOPT_MISSING
  extern int optind;
  extern char *optarg;
#endif /* GETOPT_MISSING */

#ifndef HOME_DIR_MISSING
#ifdef HAVE_GETUID
  /* Get user's passwd structure. */
  pw = getpwuid(getuid());
  if (!pw)
    {
      printf("Password structure was not found, i.e. you do not exist.");
      exit(1);
    }

  snprintf(buf, sizeof(buf), "%s/%s", pw->pw_dir, "ssh");
  if (stat(buf, &st) < 0)
    if (mkdir(buf, 0755) < 0)
      {
	printf("Could not create directory '%s'.", buf);
	exit(1);
      }
#endif /* HAVE_GETUID */
#endif /* ! HOME_DIR_MISSING */

  /* Parse command line arguments. */
  while ((opt = getopt(ac, av, "pub:a:c:f:P:N:C:")) != EOF)
    {
      switch (opt)
	{
	case 'a':
	  pkcs_name = optarg;
	  break;

	case 'c':
	  cipher_name = optarg;
	  break;
	  
	case 'b':
	  bits = atoi(optarg);
	  break;
	  
	case 'p':
	  change_passphrase = 1;
	  break;

	case 'u':
	  update_cipher = 1;
	  break;

	case 'f':
	  identity_file = optarg;
	  break;

	case 'P':
	  identity_passphrase = optarg;
	  break;

	case 'N':
	  identity_new_passphrase = optarg;
	  break;

	case '?':
	default:
	  /* the Usage. */
	  
	  printf("ssh-keygen version 2.0 Test Only\n"
	         "Usage: \n"
		 "%s [-a method] [-b bits] [-c cipher] [-p] [-u] \n", av[0]);
	  i = strlen(av[0]);
	  for (; i; i--)
	    printf(" ");
	  printf(" [-f file] [-P pass] [-N new-pass]\n"
	         "\n"
	         "Options: \n"
	         "     -a x  Public key method. List of supported public \n"
		 "           key methods (*).\n"
	         "     -b x  Lenght of public key field modulus in \n"
		 "           bits (**).\n"
	         "     -c x  Cipher to encrypt the private key. List of\n"
		 "           supported ciphers (***).\n"
	         "     -p    Only to change the passphrase of the private\n"
		 "           key file.\n"
	         "     -u    Only to change the cipher of the private key\n"
		 "           file.\n"
	         "     -f x  Identity file, and public key file when x is\n"
		 "           appended with '.pub'.\n" 
	         "     -P x  Passphrase for private key file.\n"
	         "     -N x  New passphrase if changing old one.\n"
	         "\n");

	  pkcs_list = ssh_public_key_get_supported();
	  cipher_list = ssh_cipher_get_supported();

	  printf("(*)   Supported public key methods:\n");
	  first_pkcs = print_list(6, pkcs_list);
	  printf("\n"
		 "(**)  Suggested bit lengths for public key methods \n"
		 "      NOT AVAILABLE. Contact <staff@ssh.fi> for further\n"
		 "      information.\n");
	  printf("(***) Supported ciphers:\n");
	  first_cipher = print_list(6, cipher_list);

	  printf("\nExample:\n"
	         "%s -a %s -b 1024 -c %s -f mykey -P AbtO*0\n"
	         "\n"
	         "Copyright (c) 1996 SSH Communications Security, Finland\n"
	         "              All rights reserved.\n", av[0],
		 first_pkcs, first_cipher);

	  ssh_xfree(pkcs_list);
	  ssh_xfree(cipher_list);
	  ssh_xfree(first_pkcs);
	  ssh_xfree(first_cipher);
	  exit(1);
	}
    }

  /* Print some error messages if neccessary. */
  
  if (optind < ac)
    {
      printf("Too many arguments.\n");
      exit(1);
    }
  if (change_passphrase + update_cipher > 1)
    {
      printf("Can only have only either -p or -u.\n");
      exit(1);
    }

  if (change_passphrase == 1 && (identity_passphrase == NULL ||
      identity_new_passphrase == NULL))
    {
      printf("error: needs two passphrases.\n");
      exit(1);
    }

  if (identity_file == NULL)
    {
      printf("Identity file not given.\n");
      exit(1);
    }
      
  if (identity_file)
    {
      strncpy(buf, identity_file, sizeof(buf));
      buf[sizeof(buf) - 1] = '\0';
    }
  else
    {
      /* XXX Ask the file name from the user. */
      printf("Identity file not given.\n");
      exit(1);
    }

  if (stat(buf, &st) >= 0)
    {
      if (update_cipher + change_passphrase != 1)
	{
	  /* XXX Ask to overwrite. */
	  printf("File %s exists.\n", buf);
	  exit(1);
	}
    }
  else
    {
      if (update_cipher + change_passphrase == 1)
	{
	  printf("error: identity file missing or not existent.\n");
	  exit(1);
	}
    }
      
  if (identity_passphrase)
    passphrase1 = ssh_xstrdup(identity_passphrase);
  else
    if (identity_new_passphrase)
      passphrase1 = ssh_xstrdup(identity_new_passphrase);
  else
    {
      /* XXX Ask for passphrases (the passphrase and verification for it). */
      printf("error: no passhprase entered.\n");
      exit(1);
    }
  
  /* Start doing some useful things. */
  
  /* Initialize random number generator. */
  printf("Initializing random number generator...\n");
  /* XXX Do random seed setting. */
  state = ssh_random_allocate();

  if (update_cipher + change_passphrase == 1)
    {
      if (update_cipher)
	printf("Changing cipher...\n");
      else
	printf("Changing private key passphrase...\n");

      f = fopen(buf, "r");
      if (f == NULL)
	{
	  printf("error: could not open private key file.\n");
	  exit(1);
	}
	  
      blob = ssh_key_blob_read(f, &blob_len);
      if (blob == NULL)
	{
	  printf("error: could not parse private key file.\n");
	  exit(1);
	}
      
      fclose(f);

      if (ssh_private_key_import_with_passphrase(blob, blob_len,
						 passphrase1,
						 &private_key) !=
	  SSH_CRYPTO_OK)

	{
	  printf("error: private key import failed.\n");
	  exit(1);
	}

      if (change_passphrase)
	passphrase2 = ssh_xstrdup(identity_new_passphrase);
      else
	passphrase2 = ssh_xstrdup(passphrase1);

      if (ssh_private_key_export_with_passphrase(private_key,
						 cipher_name,
						 passphrase2,
						 state,
						 &blob,
						 &blob_len) != SSH_CRYPTO_OK)
	{
	  printf("error: private key export failed.\n");
	  exit(1);
	}

      f = fopen(buf, "w");
      if (f == NULL)
	{
	  printf("error: could not open"
		 " the just read private key file!\n"
		 "Makes me wonder where the world is going to...\n");
	  exit(1);
	}
      
      ssh_key_blob_write(f, blob, blob_len, FALSE);

      fclose(f);

      memset(passphrase2, 0, strlen(passphrase2));
      ssh_xfree(passphrase2);
      memset(passphrase1, 0, strlen(passphrase1));
      ssh_xfree(passphrase1);
      ssh_private_key_free(private_key);

      printf("Private key updated.\n");
      
      /* Leave before you start generating new keys... */
      exit(0);
    }
  
  printf("Generating private and public keys...\n");
  
  /* Generate the private/public key pair. RSA assumed. */
  if (ssh_private_key_generate(state, &private_key,
			       pkcs_name,
			       SSH_PKF_SIZE, bits,
			       SSH_PKF_END) != SSH_CRYPTO_OK)
    {
      printf("error: %s private key generation failed (%d bits).\n",
	     pkcs_name, bits);
      exit(1);
    }
  
  /* Derive public key from private key. */
  public_key = ssh_private_key_derive_public_key(private_key);
  if (public_key == NULL)
    {
      printf("error: %s public key generation failed (%d bits).\n",
	     pkcs_name, bits);
      exit(1);
    }
  
  /* Save private and public keys. */
  printf("Saving private and public keys.\n");

  f = fopen(buf, "w");
  if (f != NULL)
    {
      if (ssh_private_key_export_with_passphrase(private_key,
						 cipher_name,
						 passphrase1,
						 state,
						 &blob,
						 &blob_len) != SSH_CRYPTO_OK)
	{
	  printf("error: private key export failed.\n");
	  exit(1);
	}

      /* XXX Write the ssh private key (in same format as public key!) */
      ssh_key_blob_write(f, blob, blob_len, FALSE);
      
      ssh_xfree(blob);
      fclose(f);
    }
  else
    {
      printf("File %s could not be opened.\n", buf);
      exit(1);
    }

  memset(passphrase1, 0, strlen(passphrase1));
  ssh_xfree(passphrase1);

  printf("Your identification has been saved in %s.\n", buf);

  strcat(buf, ".pub");
  
  f = fopen(buf, "w");
  if (f != NULL)
    {
      if (ssh_public_key_export(public_key,
				&blob,
				&blob_len) != SSH_CRYPTO_OK)
	{
	  printf("error: public key export failed.\n");
	  exit(1);
	}

      ssh_key_blob_write(f, blob, blob_len, TRUE);

      ssh_xfree(blob);
      fclose(f);
    }
  else
    {
      printf("File %s could not be opened.\n", buf);
      exit(1);
    }

  printf("Your public key has been saved in %s.\n", buf);

  ssh_public_key_free(public_key);
  ssh_private_key_free(private_key);
  
  exit(0);
}
  
