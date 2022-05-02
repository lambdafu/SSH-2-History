/*
 *
 * Author: Tero Kivinen <kivinen@iki.fi>
 *
 * Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshutil
 *        $Source: /ssh/CVS/src/lib/sshutil/sshfileio.h,v $
 *        $Author: kivinen $
 *
 *        Creation          : 11:16 Oct  9 1998 kivinen
 *        Last Modification : 13:38 Oct  9 1998 kivinen
 *        Last check in     : $Date: 1998/10/09 13:10:34 $
 *        Revision number   : $Revision: 1.2 $
 *        State             : $State: Exp $
 *        Version           : 1.7
 *
 *        Description       : Read and write file from and to the disk
 *                            in various formats.
 *
 *        $Log: sshfileio.h,v $
 *        $EndLog$
 */

#ifndef SSHFILEIO_H
#define SSHFILEIO_H

/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
Boolean ssh_read_file(const char *file_name,
                      unsigned char **buf,
                      size_t *buf_len);

/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_base64(const char *file_name,
                             unsigned char **buf,
                             size_t *buf_len);

/* Read hexl encoded file from the disk. Return mallocated buffer and the size
   of the buffer. If the reading of file failes return FALSE. If the file name
   is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_hexl(const char *file_name,
                           unsigned char **buf,
                           size_t *buf_len);

/* Write binary file to the disk. If the write fails retuns FALSE. If the file
   name is NULL or "-" then write to the stdout */
Boolean ssh_write_file(const char *file_name,
                       const unsigned char *buf,
                       size_t buf_len);

/* Write base 64 encoded file to the disk. If the write fails retuns FALSE. If
   the file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_base64(const char *file_name,
                              const char *begin,
                              const char *end,
                              const unsigned char *buf,
                              size_t buf_len);

/* Write hexl encoded file to the disk. If the write fails retuns FALSE. If the
   file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_hexl(const char *file_name,
                            const unsigned char *buf,
                            size_t buf_len);

#endif /* SSHFILEIO_H */
