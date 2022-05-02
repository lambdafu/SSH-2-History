/*
 
   Author: Timo J. Rinne <tri@iki.fi>
  
   Created:  Wed Sep 30 14:19:17 1998 tri

   Copyright (c) 1998 SSH Communications Security Oy <info@ssh.fi>

   Header for ssh_getopt.

   Implemets also IEEE Std1003.2-1992 compatible getopt as a macro.
   The exception is that no variables like `optarg' can be explicitely
   defined externs in the source.

*/

#ifndef SSHGETOPT_H
#define SSHGETOPT_H

struct SshGetOptDataRec {
  int err;        /* error message is printed if nonzero */
  int ind;        /* index into next argv element to be handled */
  int val;        /* 1 for '-' and 0 for '+' options */
  int opt;        /* option checked for validity */
  int reset;      /* reset ssh_getopt for next call */
  char *arg;      /* argument associated with option */
  int miss_arg;   /* 0 for missing argument and 1 for unknown opt */
  int arg_num;    /* nonzero if arg is legal number */
  int arg_val;    /* numerical value of arg if legal number */
  int allow_plus; /* nonzero if also '+' arguments are allowed */
  char *current;  /* internal current pointer for option parsing */
};

typedef struct SshGetOptDataRec *SshGetOptData;

#ifndef SSHGETOPT_C

extern struct SshGetOptDataRec ssh_getopt_default_data;

#define ssh_opterr               (ssh_getopt_default_data.err)
#define ssh_optind               (ssh_getopt_default_data.ind)
#define ssh_optval               (ssh_getopt_default_data.val)
#define ssh_optopt               (ssh_getopt_default_data.opt)
#define ssh_optreset             (ssh_getopt_default_data.reset)
#define ssh_optarg               (ssh_getopt_default_data.arg)
#define ssh_optmissarg           (ssh_getopt_default_data.miss_arg)
#define ssh_optargnum            (ssh_getopt_default_data.arg_num)
#define ssh_optargval            (ssh_getopt_default_data.arg_val)
#define ssh_optallowplus         (ssh_getopt_default_data.allow_plus)

#define opterr                   ssh_opterr
#define optind                   ssh_optind
#define optopt                   ssh_optopt
#define optreset                 ssh_optreset
#define optarg                   ssh_optarg

#define getopt(argc, argv, ostr) ssh_getopt((argc), (argv), (ostr), (void *)0)

#endif /* ! SSHGETOPT_C */

/*
 * Works like getopt(3).  If data pointer is NULL, the internal data
 * is stored into the global `ssh_getopt_default_data' structure,
 * that can be accessed through ssh_opt* macros.  If data is not
 * NULL, the structure should be initialized with ssh_getopt_init_data()
 * before the first call of ssh_getopt().
 */
int ssh_getopt(int argc, char **argv, char *ostr, SshGetOptData data);

/*
 * Initialize pre-allocated SshGetOptData data structure.
 */
void ssh_getopt_init_data(SshGetOptData data);

#endif /* ! SSHGETOPT_H */

/* eof (sshgetopt.c) */
