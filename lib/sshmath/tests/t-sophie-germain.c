/*

  testfile.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Jul 23 22:36:43 1997 [mkojo]

  Testing some things with GMP etc. 

  */

/*
 * $Id: t-sophie-germain.c,v 1.3 1998/11/06 13:47:24 tmo Exp $
 * $Log: t-sophie-germain.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "gmp.h"
#include "sieve.h"

/* Idea here is to find:

   p = c*2 + 1

   Thus we can see that

   p (mod k) = c*2 (mod k) + 1 (mod k)

             = c (mod k) * 2 (mod k) + 1 (mod k)

   However, we want

     p = n + s

   thus we have to select

     p = n + sk = c*2 + 1 + sk

   if at start s = 0 then 
             
     c = (n - 1)/2

   if s > 0 then

     n + sk = 2c + 1
     (n + sk - 1)/2 = c
     (n - 1)/2 + sk/2 = c
     (n - 1)/2 = c - sk/2

     c*2 + 1 + sk = n + sk

     (c + sk/2)*2 + 1

   */
void find_safe_prime(unsigned int sieve_size, MP_INT *input, MP_INT *add,
                     MP_INT *prime)
{
  unsigned long *table, *add_table, *primes;
  unsigned int len, t, p, i, j;
  MP_INT v, s, ret, aux;
  SshSieve sieve;
  Boolean rv;

  if ((mpz_get_ui(input) & 0x1) == 0x0)
    mpz_add_ui(input, input, 1);

  ssh_sieve_allocate_ui(&sieve, sieve_size, 1000000);
  for (len = 0, p = 2; p; p = ssh_sieve_next_prime(p, &sieve), len++)
    ;
  len--;
  
  if (len > 500000)
    {
      printf("Too many primes.\n");
      exit(1);
    }
  
  mpz_init(&v);
  mpz_init(&s);
  mpz_init(&ret);
  mpz_init(&aux);
  /* Compute v = (input - 1)/2 */
  mpz_sub_ui(&v, input, 1);
  mpz_div_ui(&v, &v, 2);

  /* Compute add */
  mpz_set(&s, add);
  mpz_div_ui(&s, &s, 2);

  printf("Initializing tables.\n");
  
  table = ssh_xmalloc(len*sizeof(*table));
  add_table = ssh_xmalloc(len*sizeof(*add_table));
  primes = ssh_xmalloc(len * sizeof(*primes));
  for (i = 0, p = 2; i < len ; i++,
         p = ssh_sieve_next_prime(p, &sieve))
    {
      mpz_mod_ui(&aux, &v, p);
      table[i] = mpz_get_ui(&aux);
      mpz_mod_ui(&aux, &s, p);
      add_table[i] = mpz_get_ui(&aux);
      primes[i] = p;
    }

  ssh_sieve_free(&sieve);

  printf("Starting to search.\n");
  
  /* We assume that only 16 million choices are needed. */
  for (i = 0; i < (1 << 24); i++)
    {
      if (i > 0 && (i & 0x0f) == 0)
        {
          /* Doing something. */
          printf(".");
          fflush(stdout);
        }
      rv = TRUE;
      for (j = 0; j < len; j++)
        {
          p = primes[j];

          if (table[j] == 0)
            rv = FALSE;
          else
            {
              /* If k < p then (k*2 + 1) < 2p */
              t = table[j] * 2 + 1;
              if (t > p)
                t -= p;
              if (t == 0)
                rv = FALSE;
            }
          
          table[j] += add_table[j];
          if (table[j] >= p)
            table[j] -= p;
        }
      if (rv == FALSE)
        continue; 

      printf("x");
      fflush(stdout);

      /* v = n + s*k*2 <=> c*2 + 1 = v = n + 2sk

         c = (n + 2sk - 1)/2 = (n - 1)/2 + sk
         
         */
      mpz_mul_ui(&s, add, i);
      mpz_add(&v, input, &s);
      mpz_set(&ret, &v);
      
      ssh_mp_powm_ui(&aux, 2, &ret, &ret);
      if (mpz_cmp_ui(&aux, 2) == 0)
        {
          printf("1");
          fflush(stdout);
          mpz_sub_ui(&v, &v, 1);
          mpz_div_ui(&v, &v, 2);

          if (mpz_get_ui(&v) & 1)
            {
              ssh_mp_powm_ui(&aux, 2, &v, &v);
              if (mpz_cmp_ui(&aux, 2) == 0)
                {
                  printf("2");
                  fflush(stdout);
                  if (mpz_probab_prime_p(&ret, 20))
                    {
                      printf("3");
                      fflush(stdout);
                      if (mpz_probab_prime_p(&v, 20))
                        break;
                    }
                }
            }
        }
    }

  ssh_xfree(table);
  ssh_xfree(add_table);
  ssh_xfree(primes);

  printf("\nThe i is: %d\n", i);
  printf("Safe prime: \n");
  mpz_out_str(NULL, 10, &ret);
  mpz_set(prime, &ret);
  printf("\nIt's orders large prime divisor:\n");
  mpz_out_str(NULL, 10, &v);
  printf("\n");

  mpz_clear(&v);
  mpz_clear(&s);
  mpz_clear(&ret);
  mpz_clear(&aux);
}

int main(int ac, char *av[])
{
  MP_INT input, add, prime;
  unsigned int sieve_size;

  mpz_init(&input);
  mpz_init(&add);
  mpz_init(&prime);

  if (ac == 1)
    {
      sieve_size = 20000;
      mpz_set_str(&input, "1", 0);
      mpz_set_str(&add, "2", 0);
    }
  else if (ac < 4)
    {
      printf("Program for finding Sophie Germain primes.\n");
      printf("usage: gmpt sieve-size start add\n");
      exit(1);
    }
  else
    {
      sieve_size = atoi(av[1]);
      mpz_set_str(&input, av[2], 0);
      mpz_set_str(&add, av[3], 0);
    }
  
  find_safe_prime(sieve_size, &input, &add, &prime);

  if (ac == 1)
    {
      if (mpz_cmp_ui(&prime, 39983) == 0)
        printf("OK\n");
      else
        printf("Find_safe_prime returned wrong number, it should have returned 39983\n");
    }
  mpz_clear(&prime);
  mpz_clear(&input);
  mpz_clear(&add);
  exit(0);
}
