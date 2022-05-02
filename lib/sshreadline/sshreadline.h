/*
 * Author: Tero Kivinen <kivinen@iki.fi>
 * 
 * Copyright (c) 1996 SSH Communications Security Oy <info@ssh.fi>
 */
/*
 *        Program: sshreadline
 *        $Source: /ssh/CVS/src/lib/sshreadline/sshreadline.h,v $
 *        $Author: ylo $
 *
 *        Creation          : 19:52 Mar 12 1997 kivinen
 *        Last Modification : 01:01 Mar 17 1997 kivinen
 *        Last check in     : $Date: 1998/01/28 10:12:55 $
 *        Revision number   : $Revision: 1.3 $
 *        State             : $State: Exp $
 *        Version           : 1.12
 *
 *        Description       : Readline library
 *
 *
 *        $Log: sshreadline.h,v $
 *        $EndLog$
 */

#ifndef SSHREADLINE_H
#define SSHREADLINE_H

/*
 * Read line from user. The tty at file descriptor FD is put to raw
 * mode and data is read until CR is received. The PROMPT is used to prompt
 * the input. LINE is pointer to char pointer and it should either contain
 * NULL or the mallocated string for previous value (that string is freed).
 * If line can be successfully read the LINE argument contains the
 * new mallocated string.
 *
 * The ssh_readline will return the number of characters returned in line
 * buffer. If eof or other error is noticed the return value is -1. 
 */
int ssh_readline(const unsigned char *prompt,
		 unsigned char **line,
		 int fd);


#endif /* SSHREADLINE_H */
