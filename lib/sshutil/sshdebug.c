/*

  Author: Antti Huima <huima@ssh.fi>
  	  Tatu Ylonen <ylo@ssh.fi>

  Copyright (C) 1996-1998 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Displaying debugging, warning, and fatal error messages.
  Sending messages to the system log.

  */

#include "sshincludes.h"
#include "sshdebug.h"
#include "match.h"

#ifdef WINDOWS
#include <tchar.h>
#endif

/* Define as macros, because ctype functions are not available in the
   kernel. */
#undef isdigit
#define isdigit(ch) ((ch) >= '0' && (ch) <= '9')
#undef isspace
#define isspace(ch) ((ch) == ' ' || (ch) == '\t' || (ch) == '\n')

/* Size of buffers used in formatting the messages in ssh_debug functions. */
#define SSH_DEBUG_BUFFER_SIZE 512

/* Bit masks specifying which elements are to be included in debugging
   messages. */
#define SSH_DEBUG_FLAG_PID		0x01 /* Include process id */
#define SSH_DEBUG_FLAG_FILE		0x02 /* Include file and line */
#define SSH_DEBUG_FLAG_PATH		0x04 /* Include path in file names */
#define SSH_DEBUG_FLAG_FUNCTION		0x08 /* Include function name */
#define SSH_DEBUG_FLAG_MODULE		0x10 /* Include module name */

/* Current debugging flag settings.  The initial value specifies the default
   output format. */
unsigned int ssh_debug_flags = SSH_DEBUG_FLAG_FILE|SSH_DEBUG_FLAG_FUNCTION;

/* Data structure for module-specific debugging level settings. */
typedef struct SshDebugModuleLevelRec {
  /* Pointer to the next module-specific level setting. */
  struct SshDebugModuleLevelRec *next;

  /* Pattern specifying the modules for which this level is used.  The
     pattern may contain '*' and '?' as special characters.  It is allocated
     using ssh_xfree. */
  char *module;

  /* Debugging level for the modules whose name matches the given pattern. */
  int level;
} *SshDebugModuleLevel;

/* The global debugging level.  This is used when no per-module level
   can be found for a particular module. */
int ssh_debug_global_level = 0;

/* Per-module debugging level settings.  These override the global
   level on a per-module basis.  The module name can be a pattern containing
   asterisk '*' characters as wildcards.  The settings are applied in the
   order in which they are in the list, first match overriding later
   matches. */
SshDebugModuleLevel ssh_debug_module_levels = NULL;

/* Callbacks to which the debugging/error/log messages are delivered. */
SshErrorCallback ssh_debug_fatal_callback = NULL;
SshErrorCallback ssh_debug_warning_callback = NULL;
SshErrorCallback ssh_debug_debug_callback = NULL;
void *ssh_debug_error_context = NULL;
SshLogCallback ssh_debug_log_callback = NULL;
void *ssh_debug_log_context = NULL;

/* Formats an output string according to the sprintf-style variable-
   length argument list, and returns a string allocated with ssh_xmalloc
   containing the value.  The caller should free the string with ssh_xfree
   when no longer needed. */

char *ssh_debug_format(const char *format, ...)
{
  char buf[SSH_DEBUG_BUFFER_SIZE];

  va_list args;
  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  return ssh_xstrdup(buf);
}

/* Outputs a debugging message according to the parameters.  
     file        name of the source file generating the message
     line        source line on which the message is generated
     msg         the message to display (freed!)
   The `msg' argument is automatically freed by this function using
   ssh_xfree. */

void ssh_debug_output(const char *file, unsigned int line,
		      const char *module,
		      const char *function, char *msg)
{
  char pid_buf[100], function_buf[100], file_buf[100], module_buf[100];
  
  /* Format file name and line number. */
  if (ssh_debug_flags & SSH_DEBUG_FLAG_FILE)
    {
      if (!(ssh_debug_flags & SSH_DEBUG_FLAG_PATH))
	{
	  /* Strip unix-style path components from file name. */
	  if (strrchr(file, '/'))
	    file = strrchr(file, '/') + 1;
	  
	  /* Strip msdos/windows style path components from file name. */
	  if (strrchr(file, '\\'))
	    file = strrchr(file, '\\') + 1;
	}

      /* Format the file name and line number into the buffer. */
      snprintf(file_buf, sizeof(file_buf), "%s:%d", file, line);
    }
  else
    {
      /* Set file name and line number to empty. */
      strcpy(file_buf, "");
    }

  /* Format process id. */
#ifdef HAVE_GETPID
  if (ssh_debug_flags & SSH_DEBUG_FLAG_PID)
    snprintf(pid_buf, sizeof(pid_buf), "pid %ld: ", (long)getpid());
  else
    strcpy(pid_buf, "");
#else /* HAVE_GETPID */
  strcpy(pid_buf, "");
#endif /* HAVE_GETPID */

  /* Format module name. */
  if (ssh_debug_flags & SSH_DEBUG_FLAG_MODULE)
    snprintf(module_buf, sizeof(module_buf), "module %s: ", module);
  else
    strcpy(module_buf, "");
  
  /* Format function name. */
  if (function != NULL && (ssh_debug_flags & SSH_DEBUG_FLAG_FUNCTION))
    snprintf(function_buf, sizeof(function_buf), " (%s): ", function);
  else
    strcpy(function_buf, ": ");
  
  /* Format and send the  output message. */
  ssh_debug("%s%s%s%s%s", file_buf, function_buf, pid_buf, module_buf, msg);

  /* Free the `msg' argument. */
  ssh_xfree(msg);
}

/* Returns TRUE if debugging has been enabled for the given module
   at the given level.  Otherwise returns FALSE. */

Boolean ssh_debug_enabled(const char *module, int level)
{
  SshDebugModuleLevel dl;
  int debug_level;

  /* Default to the global level. */
  debug_level = ssh_debug_global_level;

  /* Check for any per-module overrides. */
  for (dl = ssh_debug_module_levels; dl; dl = dl->next)
    {
      if (ssh_match_pattern(module, dl->module))
	{
	  debug_level = dl->level;
	  break;
	}
    }

  /* Message should be printed if it is at a level below or equal to the
     current level. */
  return (level <= debug_level);
}

/* Sets the global debugging level.  This overrides any previous per-module
   settings. */

void ssh_debug_set_global_level(unsigned int level)
{
  SshDebugModuleLevel dl;

  /* Set the global level. */
  ssh_debug_global_level = level;

  /* Clear (free) any per-module settings. */
  while (ssh_debug_module_levels)
    {
      dl = ssh_debug_module_levels;
      ssh_debug_module_levels = dl->next;
      ssh_xfree(dl->module);
      ssh_xfree(dl);
    }
}

/* Sets the per-module debugging level for the given module.  The
   module name may contain wildcards ('*' and '?').  Any later
   setting overrides any previous settings for the matching modules. */

void ssh_debug_set_module_level(const char *module, unsigned int level)
{
  SshDebugModuleLevel dl;

  dl = ssh_xmalloc(sizeof(*dl));
  dl->module = ssh_xstrdup(module);
  dl->level = level;
  dl->next = ssh_debug_module_levels;
  ssh_debug_module_levels = dl;
}

/* Sets debugging levels as specified by the string.  The string
   is a comma-separated list of level assignments of the following format:
       pattern=level
   or  global=level
*/

void ssh_debug_set_level_string(const char *string)
{
  const char *name_start, *name_end, *level_start;
  char *level_end, *name;
  int name_len;
  long level_value;
  Boolean error;

#ifndef DEBUG_LIGHT
  ssh_warning("Development-time debugging not compiled in.");
  ssh_warning("To enable, configure with --enable-debug and recompile.");
#endif /* !DEBUG_LIGHT */

  while (*string)
    {
      error = FALSE;
      
      /* Skip whitespace */
      while(*string && isspace(*string))
	string++;

      /* Parse name */
      name_start = string;
      while(*string && !isspace(*string) && *string != '=' && *string != ',')
	string++;
      name_end = string;
      name_len = name_end - name_start;
      
      /* Skip whitespace */
      while (*string && isspace(*string))
	string++;

      level_value = -1;
      if (*string == '=')
	{
	  string++;
	  /* Skip whitespace */
	  while (*string && isspace(*string))
	    string++;
	  
	  level_start = string;
	  level_value = strtol(string, &level_end, 0);
	  if (level_value == 0 && level_end == level_start)
	    {
	      ssh_warning("ssh_debug_set_level_string: Invalid numeric argument for %s", name_start);
	      error = TRUE;
	    }
	  else
	    {
	      string = level_end;
	    }
	  
	  /* Skip whitespace */
	  while (*string && isspace(*string))
	    string++;
	}
      if (*string)
	if (*string != ',')
	  {
	    if (!error)
	      ssh_warning("ssh_debug_set_level_string: Ignored junk after command : %s", string);
	    while (*string && *string != ',')
	      string++;
	  }
	else
	  string++;
      
      if (name_len == 6 &&
	  strncasecmp(name_start, "global", name_len) == 0)
	{
	  if (level_value == -1)
	    level_value = 0;
	  ssh_debug_set_global_level(level_value);
	}
      else if (name_len == 3 &&
	  strncasecmp(name_start, "pid", name_len) == 0)
	{
	  if (level_value != 0)
	    ssh_debug_flags |= SSH_DEBUG_FLAG_PID;
	  else
	    ssh_debug_flags &= ~SSH_DEBUG_FLAG_PID;
	}
      else if (name_len == 4 &&
	  strncasecmp(name_start, "file", name_len) == 0)
	{
	  if (level_value != 0)
	    ssh_debug_flags |= SSH_DEBUG_FLAG_FILE;
	  else
	    ssh_debug_flags &= ~SSH_DEBUG_FLAG_FILE;
	}
      else if (name_len == 6 &&
	  strncasecmp(name_start, "module", name_len) == 0)
	{
	  if (level_value != 0)
	    ssh_debug_flags |= SSH_DEBUG_FLAG_MODULE;
	  else
	    ssh_debug_flags &= ~SSH_DEBUG_FLAG_MODULE;
	}
      else if (name_len == 8 &&
	  strncasecmp(name_start, "function", name_len) == 0)
	{
	  if (level_value != 0)
	    ssh_debug_flags |= SSH_DEBUG_FLAG_FUNCTION;
	  else
	    ssh_debug_flags &= ~SSH_DEBUG_FLAG_FUNCTION;
	}
      else
	{
	  if (level_value == -1)
	    level_value = 0;
	  if (name_len > 0 && isdigit(*name_start))
	    {
	      level_value = atoi(name_start);
	      ssh_debug_set_global_level(level_value);
	    }
	  else
	    {
	      name = ssh_xmalloc(name_len + 1);
	      memcpy(name, name_start, name_len);
	      name[name_len] = '\0';
	      ssh_debug_set_module_level(name, level_value);
	      ssh_xfree(name);
	    }
	}
    }
}

/* Dumps the given memory block in hex to stderr, 16 bytes per line,
   prefixed with an offset and followed by an ascii representation 
   (x for 32 < x < 127, '.' otherwise)

 offset__  00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f  0123456789abcdef
*/

void ssh_debug_hexdump(size_t offset, const unsigned char *data,
		       size_t buf_siz)
{
  size_t i, j, jmax;
  int c;
  char buf[100];

  for (i = 0; i < buf_siz; i += 0x10)
    {
      snprintf(buf, sizeof(buf),
	       "%08x  ", (unsigned int)(i + offset));

      jmax = buf_siz - i;
      jmax = jmax > 16 ? 16 : jmax;

      for (j = 0; j < jmax; j++) 
	{
	  if (j == 3 || j == 7 || j == 11)
	    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		     "%02x  ", (unsigned int)data[i+j]);
	  else
	    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		     "%02x ", (unsigned int)data[i+j]);
	}
      for (; j < 16; j++)
	{
	  if (j == 3 || j == 7 || j == 11)
	    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		     "    ");
	  else
	    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		     "   ");
	}			  

      snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " ");
      for (j = 0; j < jmax; j++)
	{
	  c = data[i+j];
	  c = c < 32 || c >= 127 ? '.' : c;
	  snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%c", c);
	}
      ssh_debug("%s", buf);
    }
}

/* Outputs a warning message. */

void ssh_warning(const char *fmt, ...)
{
  va_list va;
  char buf[SSH_DEBUG_BUFFER_SIZE];

  /* Format the message. */
  va_start(va, fmt);
  vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  /* Send the message to the callback registered for warning messages,
     or use default handling. */
  if (ssh_debug_warning_callback)
    (*ssh_debug_warning_callback)(buf, ssh_debug_error_context);
  else
    {
#ifndef _KERNEL
#ifdef WINDOWS
      _tprintf(TEXT("%s\n"), TEXT(buf));
#else /* WINDOWS */     
      fprintf(stderr, "%s\n", buf);
      fflush(stderr);
#endif /* WINDOWS */
#endif /* _KERNEL */
    }
}

/* Outputs a debugging message. */

void ssh_debug(const char *fmt, ...)
{
  va_list va;
  char buf[SSH_DEBUG_BUFFER_SIZE];

  /* Format the message. */
  va_start(va, fmt);
  vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  /* Send the message to the registered callback for debug messages,
     or use default handling. */
  if (ssh_debug_debug_callback)
    (*ssh_debug_debug_callback)(buf, ssh_debug_error_context);
  else
    {
#ifndef _KERNEL
#ifdef WINDOWS
      _tprintf(TEXT("%s\n"), TEXT(buf));
#else /* WINDOWS */     
      fprintf(stderr, "%s\n", buf);
      fflush(stderr);
#endif /* WINDOWS */
#endif /* _KERNEL */
    }
}

/* Outputs a fatal error message.  This function never returns. */

void ssh_fatal(const char *fmt, ...)
{
  va_list va;
  char buf[SSH_DEBUG_BUFFER_SIZE];

  /* Format the message. */
  va_start(va, fmt);
  vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  /* Send it to the callback, or do default handling if no callback has
     been specified. */
  if (ssh_debug_fatal_callback)
    (*ssh_debug_fatal_callback)(buf, ssh_debug_error_context);
  else
    {
#ifndef _KERNEL
#ifdef WINDOWS
      _tprintf(TEXT("%s\n"), TEXT(buf));
#else /* WINDOWS */     
      fprintf(stderr, "%s\n", buf);
      fflush(stderr);
#endif /* UNIX */
#endif /* _KERNEL */
    }

  /* Exit the current program; this is the fatal error handler, and should
     never return. */
  exit(1);
}

/* Defines callbacks that will receive the debug, warning, and fatal error
   messages.  Any of the callbacks can be NULL to specify default
   handling. */

void ssh_debug_register_callbacks(SshErrorCallback fatal_callback,
				  SshErrorCallback warning_callback,
				  SshErrorCallback debug_callback,
				  void *context)
{
  ssh_debug_fatal_callback = fatal_callback;
  ssh_debug_warning_callback = warning_callback;
  ssh_debug_debug_callback = debug_callback;
  ssh_debug_error_context = context;
}

/* Sends a message to the system log.  The message is actually sent to the
   log callback if one is defined; otherwise, an implementation-specific
   mechanism is used. */

void ssh_log_event(SshLogFacility facility, SshLogSeverity severity,
		   const char *fmt, ...)
{
  va_list va;
  char buf[SSH_DEBUG_BUFFER_SIZE];

  /* Format the message. */
  va_start(va, fmt);
  vsnprintf(buf, sizeof(buf), fmt, va);
  va_end(va);

  /* If a callback has been set, use it to send the message. */
  if (ssh_debug_log_callback)
    (*ssh_debug_log_callback)(facility, severity, buf, ssh_debug_log_context);

  /* There is no default handling for log messages; if the log callback
     has not been set, they are ignored. */
}

/* Sets the callback for processing log messages.  All log messages will
   be passed to this function instead of the default function.  NULL specifies
   to use the default function. */

void ssh_log_register_callback(SshLogCallback log_callback,
			       void *context)
{
  ssh_debug_log_callback = log_callback;
  ssh_debug_log_context = context;
}
