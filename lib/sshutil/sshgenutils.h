/*

sshgenutils.h

Author: Vesa Suontama <vsuontam@ssh.fi>
	
Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
	      All rights reserved.

General small utilities which are yet too long to be written again every 
time.
 

*/ 




#ifndef SSHGENUTILSH
#define  SSHGENUTILSH
#include <stdio.h>



/* Returns the size of the file. File must be opened with fopen before calling
   this. */

long ssh_fsize(FILE* file);


/* Reads the binary file and allocates the space for it. Returns the number of 
   bytes read. */

size_t ssh_read_binary_file(const char *filename, char **buf);


/* Writes the binary file.  Returns the number of bytes written to file. 
   If file exists it will be overwritten.*/

size_t ssh_write_binary_file(const char *filename, size_t file_size, char *buf);


#endif /* SSHGENUTILSH */

