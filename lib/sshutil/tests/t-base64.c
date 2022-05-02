/*

  t-base64.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
                   All rights reserved.

  Created: Wed Oct 22 17:23:38 1997 [mkojo]

  Test program which knows how to convert base64 into and onto.
  
*/

/*
 * $Id: t-base64.c,v 1.3 1998/05/24 01:46:51 kivinen Exp $
 * $Log: t-base64.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "base64.h"

unsigned int file_size(FILE *fp)
{
  unsigned int begin, end;

  fseek(fp, 0, SEEK_SET);
  begin = ftell(fp);
  fseek(fp, 0, SEEK_END);
  end = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  
  return end - begin;
}

/* Read base64 stuff (ignore all the rest). */
void read_base64(char *file,
		 unsigned char **buf, size_t *buf_len)
{
  FILE *fp;
  unsigned char *tmp, *cp;
  size_t len;
  
  fp = fopen(file, "r");
  if (fp == NULL)
    {
      printf("read_base64: cannot read non-existing file %s.\n",
	     file);
      exit(1);
    }
  
  len = file_size(fp);

  tmp = ssh_xmalloc(len + 1);
  if (fread(tmp, len, 1, fp) != 1)
    {
      fclose(fp);
      ssh_xfree(tmp);
      printf("read_base64: cannot load source file %s (%d bytes long).\n",
	     file, len);
      exit(1);
    }

  fclose(fp);

  cp = ssh_base64_remove_whitespace(tmp, len);
  *buf = ssh_base64_to_buf(cp, buf_len);
  ssh_xfree(cp);
  ssh_xfree(tmp);
}

void write_base64(char *filename,
		  unsigned char *buf, size_t buf_len)
{
  FILE *fp;
  unsigned char *tmp;
  size_t len, i, j;

  tmp = ssh_buf_to_base64(buf, buf_len);
  if (tmp == NULL)
    {
      printf("write_base64: cannot convert to base64!\n");
      exit(1);
    }

  fp = fopen(filename, "w");
  if (fp == NULL)
    {
      printf("write_base64: cannot write %s.\n", filename);
      exit(1);
    }

  len = strlen((char *) tmp);
  for (i = 0; i < len;)
    {
      for (j = 0; j < 75 && i < len; j++, i++)
	fprintf(fp, "%c", tmp[i]);
      fprintf(fp, "\n");
    }
  fclose(fp);
}

/* Read bin stuff (ignore all the rest). */
void read_bin(char *file,
	      unsigned char **buf, size_t *buf_len)
{
  FILE *fp;
  
  fp = fopen(file, "r");
  if (fp == NULL)
    {
      printf("read_bin: cannot read non-existing file %s.\n",
	     file);
      exit(1);
    }
  
  *buf_len = file_size(fp);

  *buf = ssh_xmalloc((*buf_len) + 1);
  if (fread(*buf, *buf_len, 1, fp) != 1)
    {
      fclose(fp);
      printf("read_bin: cannot load source file %s (%d bytes long).\n",
	     file, *buf_len);
      exit(1);
    }
  fclose(fp);
}

void write_bin(char *filename,
	       unsigned char *buf, size_t buf_len)
{
  FILE *fp;

  fp = fopen(filename, "w");
  if (fp == NULL)
    {
      printf("write_bin: cannot write %s.\n", filename);
      exit(1);
    }
  fwrite(buf, buf_len, 1, fp);
  fclose(fp);
}

void usage(void)
{
  printf("t-base64 [options] -from filename -to filename\n"
	 "options: \n"
	 " -base64     denotes that the input is in base 64.\n"
	 "             Default is from binary to base64.\n");
  exit(0);
}

int main(int ac, char *av[])
{
  int pos, base = 256;
  char *tofile = NULL, *fromfile = NULL;
  unsigned char *buf;
  size_t buf_len;
  
  for (pos = 1; pos < ac; pos++)
    {
      if (strcmp("-to", av[pos]) == 0)
	{
	  tofile = av[pos + 1];
	  pos++;
	  continue;
	}
      if (strcmp("-from", av[pos]) == 0)
	{
	  fromfile = av[pos + 1];
	  pos++;
	  continue;
	}
      if (strcmp("-base64", av[pos]) == 0)
	{
	  base = 64;
	  continue;
	}
      if (strcmp("-h", av[pos]) == 0 ||
	  strcmp("--help", av[pos]) == 0)
	{
	  usage();
	}
      printf("Unknown option '%s'.\n", av[pos]);
      exit(1);
    }

  if (tofile == NULL || fromfile == NULL)
    {
      usage();
    }

  if (base == 256)
    {
      read_bin(fromfile, &buf, &buf_len);
      write_base64(tofile, buf, buf_len);
      ssh_xfree(buf);
    }
  else
    {
      if (base == 64)
	{
	  read_base64(fromfile, &buf, &buf_len);
	  write_bin(tofile, buf, buf_len);
	  ssh_xfree(buf);
	}
      else
	{
	  usage();
	}
    }
  return 0;
}
