/*

tty.h

Author: Tatu Ylonen <ylo@ssh.fi>

Copyright (c) 1997 SSH Communications Security, Finland
                   All rights reserved

*/

#ifndef TTY_H
#define TTY_H


/* Returns the user's terminal to normal mode if it had been put in raw 
   mode. */
void ssh_leave_raw_mode();

/* Puts the user\'s terminal in raw mode. */
void ssh_enter_raw_mode();

/* Puts stdin terminal in non-blocking mode. */
void ssh_leave_non_blocking();

/* Restores stdin to blocking mode. */
void ssh_enter_non_blocking();

#endif /* TTY_H */
