/*

sshincludes.h

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Mon Jan 15 10:36:06 1996 ylo

Common include files for various platforms.

*/

/*
 * $Id: sshincludes.h,v 1.22 1998/10/02 01:32:33 ylo Exp $
 * $Log: sshincludes.h,v $
 * $EndLog$
 */

#ifndef INCLUDES_H
#define INCLUDES_H

#if (defined(_WINDOWS) || defined(WIN32)) && !defined(WINDOWS)
#define WINDOWS
#ifndef __STDC__
#define __STDC__ 1
#endif
#endif

#ifndef macintosh
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <stat.h>
#endif

#ifdef WINDOWS
#include "sshwindefines.h" 
#include "sshwindist.h" 
#else /* WINDOWS */
#ifdef HAVE_CONFIG_H
/* Note: autoconf documentation tells to use the <...> syntax and have -I. */
#include "sshconf.h"
#endif /* HAVE_CONFIG_H */
#endif /* WINDOWS */

#ifdef WINDOWS
#ifdef WIN32
#ifdef DLL
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT 
#endif /* DLL */
#define DLLCALLCONV
#else
#define DLLCALLCONV __far __pascal __export
#define DLLEXPORT
#endif /* WIN32 */
#else /* WINDOWS */
#define DLLCALLCONV 
#define DLLEXPORT 
#endif /* WINDOWS */

typedef unsigned char SshUInt8;		/* At least 8 bits. */
typedef signed char SshInt8;		/* At least 8 bits. */

typedef unsigned short SshUInt16;	/* At least 16 bits. */
typedef short SshInt16;			/* At least 16 bits. */

#if SIZEOF_LONG == 4
typedef unsigned long SshUInt32;	/* At least 32 bits. */
typedef long SshInt32;			/* At least 32 bits. */
#else
#if SIZEOF_INT == 4
typedef unsigned int SshUInt32;		/* At least 32 bits. */
typedef int SshInt32;			/* At least 32 bits. */
#else
#if SIZEOF_SHORT >= 4
typedef unsigned short SshUInt32;	/* At least 32 bits. */
typedef short SshInt32;			/* At least 32 bits. */
#else
#error "Autoconfig error, your compiler doesn't seem to support any 32 bit type"
#endif
#endif
#endif

#if SIZEOF_LONG >= 8
typedef unsigned long SshUInt64;
typedef long SshInt64;
#else
#if SIZEOF_LONG_LONG >= 8
typedef unsigned long long SshUInt64;
typedef long long SshInt64;
#else
/* No 64 bit type; SshUInt64 and SshInt64 will be 32 bits. */
typedef unsigned long SshUInt64;
typedef long SshInt64;
#endif
#endif

#ifndef macintosh
#include <sys/types.h>
#else /* macintosh */
#ifdef __MWERKS__
#include <types.h>
#include <OpenTransport.h>
#else
#error "Don't know how to compile Mac code with other compilers but CodeWarrior"
#endif /* __MWERKS__ */
#endif /* macintosh */

#ifdef HAVE_MACHINE_ENDIAN_H
#include <sys/param.h>
#include <machine/endian.h>
#endif

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif



#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#else /* STDC_HEADERS */



#ifdef SSHIPSEC
#ifdef WINDOWS

#include <wisock.h>

#else

#include <sys/socket.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>

#include <net/if.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#endif
#endif

/* stdarg.h is present almost everywhere, and comes with gcc; I am too lazy
   to make things work with both it and varargs. */
#include <stdarg.h>
#ifndef HAVE_STRCHR
#define strchr index
#define strrchr rindex
#endif
char *strchr(), *strrchr();
#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy((s), (d), (n))
#define memmove(d, s, n) bcopy((s), (d), (n))
#define memcmp(a, b, n) bcmp((a), (b), (n))
#endif
#endif /* STDC_HEADERS */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif /* HAVE_PATHS_H */
#ifdef _PATH_VARRUN
#define PIDDIR _PATH_VARRUN
#else /* _PATH_VARRUN */
#ifdef HAVE_VAR_RUN
#define PIDDIR "/var/run"
#else /* HAVE_VAR_RUN */
#define PIDDIR "/etc"
#endif /* HAVE_VAR_RUN */
#endif /* _PATH_VARRUN */

#if defined(HAVE_SYS_TIME_H) && !defined(SCO)
#include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */
#include <time.h>

/* These are used for initializing the random number generator. */
#ifdef HAVE_GETRUSAGE
#include <sys/resource.h>
#ifdef HAVE_RUSAGE_H
#include <sys/rusage.h>
#endif /* HAVE_RUSAGE_H */
#endif /* HAVE_GETRUSAGE */


#ifdef HAVE_TIMES
#include <sys/times.h>
#endif /* HAVE_TIMES */

#ifdef HAVE_UTIME
#include <utime.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */

#ifdef HAVE_GRP_H
#include <grp.h>
#endif /* HAVE_GRP_H */

#ifdef HAVE_DIRENT_H
#include "dirent.h"
#endif /* HAVE_DIRENT_H */

/* These POSIX macros are not defined in every system. */

#ifndef S_IRWXU
#define S_IRWXU 00700		/* read, write, execute: owner */
#define S_IRUSR 00400		/* read permission: owner */
#define S_IWUSR 00200		/* write permission: owner */
#define S_IXUSR 00100		/* execute permission: owner */
#define S_IRWXG 00070		/* read, write, execute: group */
#define S_IRGRP 00040		/* read permission: group */
#define S_IWGRP 00020		/* write permission: group */
#define S_IXGRP 00010		/* execute permission: group */
#define S_IRWXO 00007		/* read, write, execute: other */
#define S_IROTH 00004		/* read permission: other */
#define S_IWOTH 00002		/* write permission: other */
#define S_IXOTH 00001		/* execute permission: other */
#endif /* S_IRWXU */

#ifndef S_ISUID
#define S_ISUID 0x800
#endif /* S_ISUID */
#ifndef S_ISGID
#define S_ISGID 0x400
#endif /* S_ISGID */

#ifndef S_ISDIR
/* NextStep apparently fails to define this. */
#define S_ISDIR(mode)   (((mode)&(_S_IFMT))==(_S_IFDIR))
#endif
#ifndef _S_IFMT
#define _S_IFMT 0170000
#endif
#ifndef _S_IFDIR
#define _S_IFDIR 0040000
#endif
#ifndef _S_IFLNK
#define _S_IFLNK 0120000
#endif
#ifndef S_ISLNK
#define S_ISLNK(mode) (((mode)&(_S_IFMT))==(_S_IFLNK))
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif

#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef STAT_MACROS_BROKEN
/* Some systems have broken S_ISDIR etc. macros in sys/stat.h.  Please ask
   your vendor to fix them.  You can then remove the line below, but only
   after you have sent a complaint to your vendor. */
#error "Warning macros in sys stat h are broken on your system read sshincludes.h"
#endif /* STAT_MACROS_BROKEN */

#if USE_STRLEN_FOR_AF_UNIX
#define AF_UNIX_SIZE(unaddr) \
  (sizeof((unaddr).sun_family) + strlen((unaddr).sun_path) + 1)
#else
#define AF_UNIX_SIZE(unaddr) sizeof(unaddr)
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef macintosh
typedef unsigned int Boolean;
#endif

#ifndef O_BINARY
/* Define O_BINARY for compatibility with Windows. */
#define O_BINARY 0
#endif


/* The sprintf and vsprintf functions are FORBIDDEN in all SSH code.  This is
   for security reasons - they are the source of way too many security bugs.
   Instead, we guarantee the existence of snprintf and vsnprintf.  These
   should be used instead. */
#ifdef sprintf
# undef sprintf
#endif
#ifdef vsprintf
# undef vsprintf
#endif

#define sprintf ssh_fatal(SPRINTF_IS_FORBIDDEN_USE_SNPRINTF_INSTEAD)
#define vsprintf ssh_fatal(VSPRINTF_IS_FORBIDDEN_USE_VSNPRINTF_INSTEAD)

#ifdef index
# undef index
#endif
#define index ssh_fatal(INDEX_IS_BSDISM_USE_STRCHR_INSTEAD)

#if 0
#ifdef interface
# undef interface
#endif
#define interface ssh_fatal(INTERFACE_IS_RESERVED_AT_MVC)
#endif

#ifdef rindex
# undef rindex
#endif
#define rindex ssh_fatal(RINDEX_IS_BSDISM_USE_STRRCHR_INSTEAD)

/* Force library to use ssh- memory allocators (they may be implemented
   using zone mallocs, debug-routines or something similar) */
#ifdef malloc 
# undef malloc
#endif
#ifdef calloc 
# undef calloc
#endif
#ifdef realloc 
# undef realloc
#endif
#ifdef free 
# undef free
#endif
#ifdef strdup
# undef strdup
#endif
#ifdef memdup
# undef memdup
#endif

# define malloc ssh_fatal(MALLOC_IS_FORBIDDEN_USE_SSH_XMALLOC_INSTEAD)
# define calloc ssh_fatal(CALLOC_IS_FORBIDDEN_USE_SSH_XCALLOC_INSTEAD)
# define realloc ssh_fatal(REALLOC_IS_FORBIDDEN_USE_SSH_XREALLOC_INSTEAD)
# define free ssh_fatal(FREE_IS_FORBIDDEN_USE_SSH_XFREE_INSTEAD)
# define strdup ssh_fatal(STRDUP_IS_FORBIDDEN_USE_SSH_XSTRDUP_INSTEAD)
# define memdup ssh_fatal(MEMDUP_IS_FORBIDDEN_USE_SSH_XMEMDUP_INSTEAD)

#ifndef HAVE_SNPRINTF
/* Define prototypes for those systems for which we use our own versions. */
#include "snprintf.h"
#endif /* HAVE_SNPRINTF */

/* Some internal headers used in almost every file. */
#include "sshdebug.h"
#include "sshmalloc.h"

#ifndef SSH_CODE_SEGMENT
#ifdef WINDOWS
#define SSH_CODE_SEGMENT __based(__segname("_CODE"))
#else /* WINDOWS */
#define SSH_CODE_SEGMENT
#endif /* WINDOWS */
#endif /* SSH_CODE_SEGMENT */

#ifndef SSH_UID_ROOT
#define SSH_UID_ROOT 0
#endif /* SSH_UID_ROOT */

#ifdef macintosh
int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t len);
#endif
#endif /* INCLUDES_H */
