/*

Authors: Antti Huima <huima@ssh.fi>
         Tatu Ylonen <ylo@ssh.fi>

Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
All rights reserved.

Displaying debugging, warning, and fatal error messages.
Sending messages to the system log.

*/

#ifndef SSHDEBUG_H
#define SSHDEBUG_H

/***********************************************************************
 * Internal definitions
 ***********************************************************************/

/* Internal prototypes. */
char *ssh_debug_format(const char *fmt, ...);
void ssh_debug_output(const char *file, unsigned int line,
		      const char *module, const char *function, char *message);
Boolean ssh_debug_enabled(const char *module, int level);
void ssh_debug_hexdump(size_t offset, const unsigned char *buf, size_t len);

/***********************************************************************
 * Debugging macros
 ***********************************************************************/

/* USAGE:

   At the beginning of your C file, define the name of the module
   that the file belongs to as follows:

   #define SSH_DEBUG_MODULE "ModuleName"

   The module numbers are assigned in sshdmod.h and the mapping
   from numbers to names is found in sshdmod.c.
   
   Use SSH_TRACE, SSH_DEBUG and SSH_HEAVY_DEBUG to write a debug message.
   SSH_TRACE is compiled always in. SSH_DEBUG is compiled if DEBUG_LIGHT is
   defined, and SSH_HEAVY_DEBUG is compiled if DEBUG_HEAVY is defined.

   The correct way to call the macros is (SSH_TRACE works as an example):

   SSH_TRACE(<level>, (<format>, <args>, ...));

   <level> is an integer between 0 and 9 and is the debug level this
   message belongs to (zero most commonly viewed). <format> and <args>
   are passed to snprintf.

   ssh_debug_initialize [see sshdmod.h] must be called in
   the beginning of the application.

   The debugging message will automatically include the file name and line
   number of the debugging macro.  With some compilers, also the
   function name will be included. */
     
#ifdef __GNUC__
#define SSH_DEBUG_FUNCTION __FUNCTION__
#else /* __GNUC__ */
#define SSH_DEBUG_FUNCTION NULL
#endif /* __GNUC__ */

/* Outputs a debug message.  This macro is always compiled into the binary. */
#define SSH_TRACE(level, varcall) \
do { \
  if (ssh_debug_enabled(SSH_DEBUG_MODULE, level)) { \
    ssh_debug_output(__FILE__, __LINE__, SSH_DEBUG_MODULE, \
		     SSH_DEBUG_FUNCTION, \
		     ssh_debug_format varcall); \
  } \
} while (0)

/* Outputs a debug message with hex dump.  This macro is always compiled
   into the binary. 
   char buf[10];

   SSH_TRACE_HEXDUMP(1, 
                     ("Buffer (%d bytes):", sizeof(buf)), 
		     buf, sizeof(buf)); */

#define SSH_TRACE_HEXDUMP(level, varcall, buf, len) \
do { \
  if (ssh_debug_enabled(SSH_DEBUG_MODULE, level)) { \
    ssh_debug_output(__FILE__, __LINE__, SSH_DEBUG_MODULE, \
		     SSH_DEBUG_FUNCTION, \
		     ssh_debug_format varcall); \
    ssh_debug_hexdump(0, buf, len); \
  } \
} while (0)

/* SSH_DEBUG is compiled in only if DEBUG_LIGHT is defined. */
#ifdef DEBUG_LIGHT
#define SSH_DEBUG(level, varcall) SSH_TRACE(level, varcall)
#define SSH_DEBUG_HEXDUMP(level, varcall, buf, len) \
     SSH_TRACE_HEXDUMP(level, varcall, buf, len)
#else
#define SSH_DEBUG(level, varcall) do {} while (0)
#define SSH_DEBUG_HEXDUMP(level, varcall, buf, len) do {} while (0)
#endif

/* DEBUG_HEAVY is compiled in only if DEBUG_HEAVY is defined. */
#ifdef DEBUG_HEAVY
#define SSH_HEAVY_DEBUG(level, varcall) SSH_TRACE(level, varcall)
#define SSH_HEAVY_DEBUG_HEXDUMP(level, varcall, buf, len) \
     SSH_TRACE_HEXDUMP(level, varcall, buf, len)
#else
#define SSH_HEAVY_DEBUG(level, varcall) do {} while (0)
#define SSH_HEAVY_DEBUG_HEXDUMP(level, varcall, buf, len) do {} while (0)
#endif

/* Sets the debugging level for the named module.  Module names are
   case-sensitive, and the name may contain '*' and '?' as wildcards.
   Later assignments will override earlier ones if there is overlap. */
void ssh_debug_set_module_level(const char *module, unsigned int level);

/* Sets the debugging levels for several modules based on a string.
   The string is a comma-separated list of level assignments of the form
   "pattern=level".  Later assignments will override earlier ones if there
   is overlap. */
void ssh_debug_set_level_string(const char *string);

/* Sets the debugging level for all modules. */
void ssh_debug_set_global_level(unsigned int level);

/***********************************************************************
 * Functions for debugging, warning, and fatal error messages
 ***********************************************************************/

/* Outputs a warning message. */
void ssh_warning(const char *fmt, ...);

/* Outputs a debugging message. */
void ssh_debug(const char *fmt, ...);

/* Outputs a fatal error message.  This function never returns. */
void ssh_fatal(const char *fmt, ...);

/* This type represents a function used to intercept debugging, warning,
   or fatal error messages. */
typedef void (*SshErrorCallback)(const char *message, void *context);

/* Defines callbacks that will receive the debug, warning, and fatal error
   messages.  Any of the callbacks can be NULL to specify default
   handling. */
void ssh_debug_register_callbacks(SshErrorCallback fatal_callback,
				  SshErrorCallback warning_callback,
				  SshErrorCallback debug_callback,
				  void *context);

/***********************************************************************
 * Functions for logging data to the system log
 ***********************************************************************/

/* Log facility definitions.  Log facility identifies the subsystem that
   the message relates to; the platform-specific logging subsystem may e.g.
   direct messages from different facilities to different logs. */
typedef enum {
  /* The message is related to user authentication. */
  SSH_LOGFACILITY_AUTH,

  /* The message is related to security (other than authentication). */
  SSH_LOGFACILITY_SECURITY,

  /* The message is from a system daemon or service process running in
     the background. */
  SSH_LOGFACILITY_DAEMON,

  /* The message is from a normal program interacting with the user. */
  SSH_LOGFACILITY_USER,

  /* The message is related to the e-mail subsystem. */
  SSH_LOGFACILITY_MAIL
} SshLogFacility;

/* Log message severity definitions.  These identify the severity of the
   message. */
typedef enum {
  /* The message is information, and no action needs to be taken. */
  SSH_LOG_INFORMATIONAL,

  /* The message may indicate a significant event, but no action needs
     to be taken.  These might be summarized in a daily report. */
  SSH_LOG_NOTICE,

  /* The message is a warning about a potential problem. */
  SSH_LOG_WARNING,

  /* The message reports an error condition that probably needs attention. */
  SSH_LOG_ERROR,

  /* The message reports a critical error condition that needs immediate
     attention. */
  SSH_LOG_CRITICAL
} SshLogSeverity;

/* Sends a message to the system log.  The message is actually sent to the
   log callback if one is defined; otherwise, an implementation-specific
   mechanism is used. */
void ssh_log_event(SshLogFacility facility, SshLogSeverity severity,
		   const char *fmt, ...);

/* This type defines the callback function that can be used to send
   messages to the system log. */
typedef void (*SshLogCallback)(SshLogFacility facility,
			       SshLogSeverity severity,
			       const char *message,
			       void *context);

/* Sets the callback for processing log messages.  All log messages will
   be passed to this function instead of the default function.  NULL specifies
   to use the default function. */
void ssh_log_register_callback(SshLogCallback log_callback,
			       void *context);

#endif /* SSHDEBUG_H */
