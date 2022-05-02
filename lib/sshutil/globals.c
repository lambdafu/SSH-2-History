
#ifdef WINDOWS
#include <windows.h>
#endif

#include "sshincludes.h"
#include "globals.h"


typedef struct globals_app_level_struct {
  char *app_name;
  struct globals_app_level_struct *next_app;
  struct globals_module_level_struct *first_mod;
#ifdef WINDOWS
  HTASK handle;
#endif
} GlobalsApplLevelStruct;

typedef struct globals_module_level_struct {
  char *mod_name;
  struct globals_module_level_struct *next_mod;
  void *value;
} GlobalsModuleLevelStruct;

GlobalsApplLevelStruct *globals_root_node = NULL;

/* Register value for the given module of the given application.
   Return GLOBALS_SUCCESS or GLOBALS_FAILURE. */

int globals_register(const char *application, const char *module,
		     void *value)
{
  GlobalsApplLevelStruct *ptr = globals_root_node, **indir;
  GlobalsModuleLevelStruct *m_ptr;
  indir = &globals_root_node;
#ifdef WINDOWS
  HTASK handle = GetCurrentTask();
#endif

  /* Search for an application level structure where the application
     name matches. */
  while (ptr != NULL)
    {
#ifdef WINDOWS
      if (ptr->handle != handle)
	break;
#endif
      if (!strcmp(application, ptr->app_name))
	break;
      indir = &ptr->next_app;
      ptr = ptr->next_app;
    }

  /* If none was found, create such now. */
  if (!ptr)
    {
      *indir = ptr = ssh_xmalloc(sizeof(*ptr));
      ptr->app_name = ssh_xstrdup(application);
      ptr->next_app = NULL;
      ptr->first_mod = NULL;
#ifdef WINDOWS
      ptr->handle = handle;
#endif
    }

  /* Search for a module level structure where the module name
     matches. */
  m_ptr = ptr->first_mod;
  while (m_ptr != NULL)
    {
      if (!strcmp(module, m_ptr->mod_name))
	break;
      m_ptr = m_ptr->next_mod;
    }

  /* If none was found, create such now. */
  if (!m_ptr)
    {
      m_ptr = ssh_xmalloc(sizeof(*m_ptr));
      m_ptr->next_mod = ptr->first_mod;
      m_ptr->mod_name = ssh_xstrdup(module);
      ptr->first_mod = m_ptr;
    }

  /* Set the value. */
  m_ptr->value = value;
  return GLOBALS_SUCCESS;
}

static int globals_remove_module(GlobalsApplLevelStruct *ptr,
				 const char *module)
{
  GlobalsModuleLevelStruct *m_ptr, **indir;
  indir = &ptr->first_mod;
  m_ptr = *indir;

  /* Serach for a module level structure where the module name
     matches. */
  while (m_ptr != NULL)
    {
      if (!strcmp(module, m_ptr->mod_name))
	{
	  /* Match found. Remove the structure from the list and free
	     data. */
	  *indir = m_ptr->next_mod;
	  ssh_xfree(m_ptr->mod_name);
	  ssh_xfree(m_ptr);
	  return GLOBALS_SUCCESS;
	}
      indir = &m_ptr->next_mod;
      m_ptr = m_ptr->next_mod;
    }
  return GLOBALS_FAILURE;
}

int globals_unregister(const char *application,
		       const char *module)
{
  GlobalsApplLevelStruct *ptr = globals_root_node, **indir;
  indir = &globals_root_node;
#ifdef WINDOWS
  HTASK handle = GetCurrentTask();
#endif

  /* Search for an application level structure where the application
     name matches. */
  while (ptr != NULL)
    {
#ifdef WINDOWS
      if ((handle == ptr->handle) &&
	  !strcmp(application, ptr->app_name))
#else
      if (!strcmp(application, ptr->app_name))
#endif
	{
	  /* Match found. Call globals_remove_module to remove the
	     module level structure. Return failure if the call
	     fails. */
	  if (globals_remove_module(ptr, module))
	    return GLOBALS_FAILURE;

	  /* Otherways check, whether we have any more modules
	     left. If not, remove the application too. */
	  if (ptr->first_mod == NULL)
	    {
#ifdef GLOBALS_TEST
	      printf("Removed application %s.\n", application);
#endif
	      *indir = ptr->next_app;
	      ssh_xfree(ptr->app_name);
	      ssh_xfree(ptr);
	    }
	  break;
	}
      indir = &ptr->next_app;
      ptr = ptr->next_app; 
    }
  return ptr == NULL ? GLOBALS_FAILURE : GLOBALS_SUCCESS;
}

void *globals_fetch(const char *application,
		    const char *module)
{
  GlobalsApplLevelStruct *ptr = globals_root_node;
  GlobalsModuleLevelStruct *m_ptr;
#ifdef WINDOWS
  HTASK handle = GetCurrentTask();
#endif

  /* Search for an application level structure where the application
     name matches. */
  while (ptr != NULL)
    {
#ifdef WINDOWS
      if ((handle == ptr->handle) &&
	  (!strcmp(application, ptr->app_name)))
#else
      if (!strcmp(application, ptr->app_name))
#endif
	{
	  /* Found. Search for a module level structure where the
	     module name matches. */
	  m_ptr = ptr->first_mod;
	  while (m_ptr != NULL)
	    {
	      if (!strcmp(module, m_ptr->mod_name))
		{
		  /* Found. Return value. */
		  return(m_ptr->value);
		}
	      m_ptr = m_ptr->next_mod;
	    }
	  return NULL;
	}
      ptr = ptr->next_app;
    }
  return NULL;
}

#ifdef GLOBALS_TEST
int main()
{
  char buf[3][100];
  int i = 0, j;
  printf("Globals test\n");
  while (1)
    {
      printf("> "); fflush(stdout);
      scanf("%s %s %s", buf[0], buf[1], buf[2]);
      if (!strcmp(buf[0], "c"))
	{
	  i++;
	  printf ("Registering %d for %s/%s... ", i, buf[1], buf[2]);
	  printf("%s.\n",
		 globals_register(buf[1], buf[2], (void *)i)
		 ? "failed" : "succeeded");
	}
      if (!strcmp(buf[0], "f"))
	{
	  printf ("Fetching for %s/%s... ", buf[1], buf[2]);
	  j = (int)(globals_fetch(buf[1], buf[2]));
	  printf ("%d\n", j);
	}
      if (!strcmp(buf[0], "r"))
	{
	  printf("Removing data from %s/%s... ", buf[1], buf[2]);
	  printf("%s.\n",
		 globals_unregister(buf[1], buf[2])
		 ? "failed" : "succeeded");
	}
    }
}
#endif
