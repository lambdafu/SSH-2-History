#ifndef GLOBALS_H
#define GLOBALS_H

#define GLOBALS_SUCCESS 0
#define GLOBALS_FAILURE -1

/* Register value for application/module. */
extern int globals_register(const char *application,
			    const char *module,
			    void *value);

/* Unregister application/module. */
extern int globals_unregister(const char *application,
			      const char *module);

/* Fetch the registered value for application/module. */
extern void *globals_fetch(const char *application,
			   const char *module);


#endif /* GLOBALS_H */
