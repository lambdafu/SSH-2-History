/*

  t-mathtest.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Apr 29 02:10:22 1998 [mkojo]

  Testing utility for math libraries. This program tries as many cases
  as possible to ensure that the math libraries are working correctly.

  Nevertheless, every application that uses these libraries should
  be tested thoroughly after changes to math libraries. This is because,
  although test here are reasonably good, they are not perfect. Also
  there might be changes to things that are "undocumented" but which
  previously worked.

  TODO:

    Integer arithmetic testing (reasonably wide coverage!)

    Modular arithmetic testing (using Montgomery representation)

    GF(2^n) testing.

    Binary polynomials (these work probably easier than GF(2^n))

    Polynomials over GF(2^n).

    Elliptic curves! 
    
  This is work in progress.

  */

/*
 * $Id: t-mathtest.c,v 1.9 1998/08/13 00:16:08 mkojo Exp $
 * $Log: t-mathtest.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmath-types.h"
#include "sshmp.h"
#include "gf2n.h"
#include "ecpmath.h"
#include "ec2nmath.h"
#include "timeit.h"
#include "sieve.h"

/* Printing of different types to the screen, these are helpful when
   trying to figure out what was wrong. And also, sometimes to compare
   results with other systems. */

void print_int(char *str, SshInt *op)
{
  char *mstr;

  mstr = ssh_mp_get_str(NULL, 10, op);
  printf("%s %s\n", str, mstr);
  ssh_xfree(mstr);
}

void print_mont(char *str, SshIntModQ *op)
{
  char *mstr;
  SshInt a;

  ssh_mp_init(&a);
  ssh_mp_set_mpm(&a, op);

  mstr = ssh_mp_get_str(NULL, 10, &a);
  printf("%s %s\n", str, mstr);
  ssh_xfree(mstr);

  ssh_mp_clear(&a);
}

int check_mod(SshIntModQ *b, SshInt *a)
{
  SshInt t;
  int rv;
  
  ssh_mp_init(&t);
  ssh_mp_set_mpm(&t, b);
  rv = ssh_mp_cmp(a, &t);
  ssh_mp_clear(&t);
  return rv;
}

void my_rand_mod(SshIntModQ *a, SshInt *b, int bits)
{
  int n = random() % bits;
  ssh_mp_rand(b, n);
  ssh_mpm_set_mp(a, b);
}

void true_rand(SshInt *op, int bits)
{
  ssh_mp_rand(op, random() % bits);

  /* Occasionally make also negative. */
  if (random() & 0x1)
    ssh_mp_neg(op, op);
}

void test_int(int flag, int bits)
{
  SshInt a, b, c, d, e, f;
  int j, k, i, l;

  ssh_mp_init(&a);
  ssh_mp_init(&b);
  ssh_mp_init(&c);
  ssh_mp_init(&d);
  ssh_mp_init(&e);
  ssh_mp_init(&f);

  printf(" * addition/subtraction test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);

      ssh_mp_sub(&c, &a, &b);
      ssh_mp_add(&d, &c, &b);
      if (ssh_mp_cmp(&d, &a) != 0)
	{
	  printf("error: subtraction/addition failed.\n");
	  print_int("a = ", &a);
	  print_int("a' = ", &d);
	  exit(1);
	}
    }

  printf(" * addition/multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mp_set_ui(&b, 0);
      k = random() % 1000;
      for (i = 0; i < k; i++)
	ssh_mp_add(&b, &b, &a);
      ssh_mp_mul_ui(&c, &a, k);
      if (ssh_mp_cmp(&c, &b) != 0)
	{
	  printf("error: addition/multiplication failed.\n");
	  print_int("a = ", &a);
	  print_int("b = ", &b);
	  print_int("c = ", &c);
	  printf("k = %u\n", k);
	  exit(1);
	}
    }

  printf(" * subtraction/multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      ssh_mp_set_ui(&b, 0);
      k = random() % 1000;
      for (i = 0; i < k; i++)
	ssh_mp_sub(&b, &b, &a);
      ssh_mp_neg(&c, &a);
      ssh_mp_mul_ui(&c, &c, k);
      if (ssh_mp_cmp(&c, &b) != 0)
	{
	  printf("error: subtraction/multiplication failed.\n");
	  print_int("a = ", &a);
	  print_int("b = ", &b);
	  print_int("c = ", &c);
	  printf("k = -%u\n", k);
	  exit(1);
	}
    }
  
  printf(" * division test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mp_cmp_ui(&b, 0) == 0 ||
	  ssh_mp_cmp_ui(&a, 0) == 0)
	continue;
      ssh_mp_mul(&c, &a, &b);
      ssh_mp_div(&d, &e, &c, &b);
      ssh_mp_div(&e, &f, &c, &a);

      if (ssh_mp_cmp(&d, &a) != 0 ||
	  ssh_mp_cmp(&e, &b) != 0)
	{
	  printf("error: division/multiplication failed.\n");
	  
	  print_int("c = ", &c);
	  print_int("a = ", &a);
	  print_int("a' = ", &d);
	  print_int("b = ", &b);
	  print_int("b' = ", &e);
	  exit(1);
	}
    }

  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mp_cmp_ui(&b, 0) == 0)
	continue;

      ssh_mp_div(&c, &d, &a, &b);
      ssh_mp_mul(&e, &c, &b);
      ssh_mp_add(&e, &e, &d);

      if (ssh_mp_cmp(&e, &a) != 0)
	{
	  printf("error: division/multiplication failed (in second test).\n");
	  print_int("a = ", &a);
	  print_int("a' = ", &e);
	  exit(1);
	}
    }

  printf(" * multiplication test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);

      ssh_mp_mul(&b, &a, &a);
      ssh_mp_square(&c, &a);

      if (ssh_mp_cmp(&c, &b) != 0)
	{
	  printf("error: multiplication/squaring failed.\n");
	  ssh_mp_dump(&a);
	  ssh_mp_dump(&b);
	  ssh_mp_dump(&c);
	  
	  print_int("a*a = ", &b);
	  ssh_mp_dump(&b);
	  print_int("a^2 = ", &c);
	  ssh_mp_dump(&c);
	  exit(1);
	}
    }

  printf(" * multiplication/gcd tests.\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);
      true_rand(&b, bits);
      if (ssh_mp_cmp_ui(&a, 0) == 0 ||
	  ssh_mp_cmp_ui(&b, 0) == 0)
	continue;
      
      /* Make positive. */
      ssh_mp_abs(&a, &a);
      ssh_mp_abs(&b, &b);
      
      ssh_mp_mul(&c, &a, &b);
      ssh_mp_gcd(&d, &c, &a);
      ssh_mp_gcd(&e, &c, &b);

      if (ssh_mp_cmp(&d, &a) != 0 ||
	  ssh_mp_cmp(&e, &b) != 0)
	{
	  printf("error: multiplication/gcd failed.\n");
	  print_int("d = ", &d);
	  print_int("a = ", &a);
	  print_int("e = ", &e);
	  print_int("b = ", &b);
	  exit(1);
	}
    }

  printf(" * squaring test\n");
  for (j = 0; j < 1000; j++)
    {
      true_rand(&a, bits);

      ssh_mp_square(&b, &a);
      ssh_mp_sqrt(&c, &b);

      ssh_mp_abs(&a, &a);
      
      if (ssh_mp_cmp(&a, &c) != 0)
	{
	  printf("error: square root/squaring failed.\n");
	  print_int("a = ", &a);
	  print_int("a' = ", &c);
	  exit(1);
	}
    }

  printf(" * exponentiation test\n");
  for (j = 0; j < 10; j++)
    {
      true_rand(&a, bits);
      ssh_mp_abs(&a, &a);

      if (ssh_mp_cmp_ui(&a, 3) < 0)
	continue;

      if ((ssh_mp_get_ui(&a) & 0x1) == 0)
	ssh_mp_add_ui(&a, &a, 1);

      k = random();
      ssh_mp_set_ui(&b, k);
      ssh_mp_mod(&b, &b, &a);
      ssh_mp_set(&c, &b);
      
      for (i = 1; i < 100; i++)
	{
	  ssh_mp_set_ui(&e, i);
	  ssh_mp_powm_ui(&d, k, &e, &a);
	  if (ssh_mp_cmp(&d, &c) != 0)
	    {
	      printf("error: powm ui/multiplication failed.\n");
	      print_int("mod = ", &a);
	      printf("g   = %u\n", k);
	      printf("exp = %u\n", i);
	      print_int("1   = ", &d);
	      print_int("2   = ", &c);
	      exit(1);
	    }

	  ssh_mp_mul(&c, &c, &b);
	  ssh_mp_mod(&c, &c, &a);
	}
    }

  printf(" * full exponentiation test\n");
  for (j = 0; j < 10; j++)
    {
      true_rand(&a, bits);
      ssh_mp_abs(&a, &a);

      if (ssh_mp_cmp_ui(&a, 3) < 0)
	continue;

      if ((ssh_mp_get_ui(&a) & 0x1) == 0)
	ssh_mp_add_ui(&a, &a, 1);

      k = random();
      ssh_mp_set_ui(&b, k);
      ssh_mp_mod(&b, &b, &a);
      ssh_mp_set(&c, &b);
      
      for (i = 1; i < 100; i++)
	{
	  ssh_mp_set_ui(&e, i);
	  ssh_mp_powm(&d, &b, &e, &a);
	  if (ssh_mp_cmp(&d, &c) != 0)
	    {
	      printf("error: powm/multiplication failed.\n");
	      print_int("mod = ", &a);
	      print_int("g   = ", &b);
	      print_int("exp = ", &e);
	      print_int("1   = ", &d);
	      print_int("2   = ", &c);
	      exit(1);
	    }

	  ssh_mp_mul(&c, &c, &b);
	  ssh_mp_mod(&c, &c, &a);
	}
    }
  
  for (j = 0; j < 100; j++)
    {
      true_rand(&a, bits);
      ssh_mp_abs(&a, &a);

      if (ssh_mp_cmp_ui(&a, 3) < 0)
	continue;

      if ((ssh_mp_get_ui(&a) & 0x1) == 0)
	ssh_mp_add_ui(&a, &a, 1);

      k = random();
      ssh_mp_set_ui(&b, k);
      true_rand(&e, bits);
      
      ssh_mp_powm(&c, &b, &e, &a);
      ssh_mp_powm_ui(&d, k, &e, &a);

      if (ssh_mp_cmp(&c, &d) != 0)
	{
	  printf("error: powm/powm_ui failed!\n");
	  print_int("mod = ", &a);
	  print_int("exp = ", &e);
	  print_int("g   = ", &b);
	  print_int("1   = ", &c);
	  print_int("2   = ", &d);

	  exit(1);
	}
    }

  printf(" * kronecker-jacobi-legendre symbol tests\n");
  for (j = 0; j < 100; j++)
    {
      static int table[100] =
      {1,1,1,1,-1,1,1,1,1,1,-1,-1,1,1,-1,1,1,1,-1,1,1,1,1,-1,1,-1,-1,
       1,-1,1,1,-1,-1,1,1,1,-1,1,-1,-1,1,1,1,1,1,1,1,1,-1,-1,-1,1,1,-1,
       1,-1,1,1,-1,-1,-1,1,-1,1,1,-1,1,-1,-1,1,1,1,1,1,-1,-1,-1,1,1,-1,
       1,-1,-1,1,-1,1,1,1,1,1,-1,1,1,1,1,1,1,1,-1,-1};
      ssh_mp_set_ui(&a, j + 3);
      ssh_mp_set_ui(&b, 7919);

      if (ssh_mp_kronecker(&a, &b) != table[j])
	{
	  printf("error: kronecker-jacobi-legendre symbol failed.\n");
	  print_int(" a =", &a);
	  print_int(" b =", &b);
	  printf(" assumed %d got %d\n",
		 table[j], ssh_mp_kronecker(&a, &b));
	  exit(1);
	}
    }
  
  if (flag)
    {
      printf(" * prime tests\n");
      for (j = 0; j < 10; j++)
	{
	  printf("    - searching... [%u bit prime]\n", bits);
	  true_rand(&a, bits);
	  ssh_mp_abs(&a, &a);

	  if (ssh_mp_next_prime(&a, &a) == FALSE)
	    continue;

	  printf("    - probable prime found\n");
	  print_int("      =", &a);
		  
	  printf("    - testing modular sqrt\n");
	  for (l = 0; l < 10; l++)
	    {
	      true_rand(&b, bits);
	      ssh_mp_abs(&b, &b);
	      
	      if (ssh_mp_mod_sqrt(&d, &b, &a) == FALSE)
		continue;
	      ssh_mp_mod(&b, &b, &a);
	      ssh_mp_square(&c, &d);
	      ssh_mp_mod(&c, &c, &a);
	      if (ssh_mp_cmp(&c, &b) != 0)
		{
		  printf("error: modular sqrt failed.\n");
		  print_int(" b =", &b);
		  print_int(" c =", &c);
		  print_int(" d =", &d);
		  printf(" Kronecker says: %d\n",
			 ssh_mp_kronecker(&b, &a));
		  exit(1);
		}
	    }
	}
    }

  if (flag)
    {
      printf(" * square tests\n");
      for (j = 0; j < 1000; j++)
	{
	  true_rand(&a, bits);

	  ssh_mp_square(&b, &a);

	  if (ssh_mp_is_perfect_square(&b) == 0)
	    {
	      printf("error: square/perfect square failed.\n");
	      print_int("a = ", &a);
	      print_int("a^2 = ", &b);
	      ssh_mp_sqrt(&c, &b);
	      print_int("a' = ", &c);
	      exit(1);
	    }
	}
    }

  if (flag)
    {
      printf(" * gcd/gcdext tests\n");
      for (j = 0; j < 1000; j++)
	{
	  true_rand(&a, bits);
	  true_rand(&b, bits);
	  
	  if (ssh_mp_cmp_ui(&a, 0) == 0 ||
	      ssh_mp_cmp_ui(&b, 0) == 0)
	    continue;
      
	  ssh_mp_abs(&a, &a);
	  ssh_mp_abs(&b, &b);
      
	  ssh_mp_gcd(&c, &a, &b);
	  if (ssh_mp_cmp_ui(&c, 1) == 0)
	    {
	      ssh_mp_gcdext(&d, &e, &f, &a, &b);
	      
	      if (ssh_mp_cmp(&d, &c) != 0)
		{
		  printf("error: gcd/gcdext failed.\n");
		  exit(1);
		}
	      
	      ssh_mp_mul(&e, &a, &e);
	      ssh_mp_mul(&f, &b, &f);
	      ssh_mp_add(&f, &f, &e);
	      if (ssh_mp_cmp(&f, &d) != 0)
		{
		  printf("error: gcdext failed.\n");
		  exit(1);
		}
	    }
	}
    }

  printf(" * conversion testing.\n");
  for (i = 0; i < 1000; i++)
    {
      char *str;
      int base;

      do
	{
	  base = random() % 65;
	}
      while (base < 2);
      
      true_rand(&a, bits);

      str = ssh_mp_get_str(NULL, base, &a);
      ssh_mp_set_str(&b, str, base);

      if (ssh_mp_cmp(&a, &b) != 0)
	{
	  printf("error: conversion to integer failed in base %d.\n", base);
	  print_int("a = ", &a);
	  ssh_mp_dump(&a);
	  print_int("b = ", &b);
	  ssh_mp_dump(&b);
	  printf("Output: %s\n", str);
	  ssh_xfree(str);
	  exit(1);
	}

      ssh_xfree(str);

      /* Test for automatic recognition. */
      
      switch (random() % 3)
	{
	case 0:
	  base = 8;
	  break;
	case 1:
	  base = 10;
	  break;
	case 2:
	  base = 16;
	  break;
	}
      
      str = ssh_mp_get_str(NULL, base, &a);
      ssh_mp_set_str(&b, str, 0);

      if (ssh_mp_cmp(&a, &b) != 0)
	{
	  printf("error: automatic recognition of base %d.\n", base);
	  print_int("a = ", &a);
	  ssh_mp_dump(&a);
	  print_int("b = ", &b);
	  ssh_mp_dump(&b);
	  printf("Output: %s\n", str);
	  ssh_xfree(str);
	  exit(1);
	}
      ssh_xfree(str);
      
    }
  
  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&c);
  ssh_mp_clear(&d);
  ssh_mp_clear(&e);
  ssh_mp_clear(&f);
}

void test_mod(int flag, int bits)
{
  /* Montgomery testing. */
  SshIntModQ a0, b0, c0;
  SshInt  a1, b1, c1, m1, d;
  SshIntModuli m0;
  int i;
  Boolean rv1, rv2;

  ssh_mp_init(&a1);
  ssh_mp_init(&b1);
  ssh_mp_init(&c1);
  ssh_mp_init(&m1);
  ssh_mp_init(&d);

  printf(" * random moduli search\n");

  do
    {
      ssh_mp_rand(&m1, bits);
      while (ssh_mp_next_prime(&m1, &m1) == FALSE)
	ssh_mp_rand(&m1, bits);
    }
  while (ssh_mpm_init_m(&m0, &m1) == FALSE);

  ssh_mpm_init(&a0, &m0);
  ssh_mpm_init(&b0, &m0);
  ssh_mpm_init(&c0, &m0);

  print_int ("m1 = ", &m1);

  /* Additions. */
  printf(" * addition test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mpm_add(&c0, &a0, &b0);

      ssh_mp_add(&c1, &a1, &b1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1      = ", &a1);
	  print_int ("  b1      = ", &b1);
	  print_int ("  a1 + b1 = ", &c1);
	  print_mont("  a0      = ", &a0);
	  print_mont("  b0      = ", &b0);
	  print_mont("  a0 + b0 = ", &c0);
	  exit(1);
	}
    }
  
  /* Subtractions. */
  printf(" * subtraction test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mpm_sub(&c0, &a0, &b0);

      ssh_mp_sub(&c1, &a1, &b1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1      = ", &a1);
	  print_int ("  b1      = ", &b1);
	  print_int ("  a1 - b1 = ", &c1);
	  print_mont("  a0      = ", &a0);
	  print_mont("  b0      = ", &b0);
	  print_mont("  a0 - b0 = ", &c0);
	  exit(1);
	}
    }

  /* Multiplications. */
  printf(" * multiplication test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);
      my_rand_mod(&b0, &b1, bits);

      ssh_mpm_mul(&c0, &a0, &b0);

      ssh_mp_mul(&c1, &a1, &b1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1      = ", &a1);
	  print_int ("  b1      = ", &b1);
	  print_int ("  a1 * b1 = ", &c1);
	  print_mont("  a0      = ", &a0);
	  print_mont("  b0      = ", &b0);
	  print_mont("  a0 * b0 = ", &c0);
	  ssh_mpm_dump(&c0);
	  exit(1);
	}
    }

  /* Squarings. */
  printf(" * squaring test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_square(&c0, &a0);

      ssh_mp_square(&c1, &a1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1   = ", &a1);
	  print_int ("  a1^2 = ", &c1);
	  print_mont("  a0   = ", &a0);
	  print_mont("  a0^2 = ", &c0);
	  exit(1);
	}
    }

  printf(" * inversion test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      rv1 = ssh_mpm_invert(&c0, &a0);
      rv2 = ssh_mp_invert(&c1, &a1, &m1);

      if (rv1 == FALSE && rv2 == FALSE)
	continue;

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1    = ", &a1);
	  print_int ("  a1^-1 = ", &c1);
	  print_mont("  a0    = ", &a0);
	  print_mont("  a0^-1 = ", &c0);
	  exit(1);
	}
    }

  printf(" * mul ui test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_mul_ui(&c0, &a0, i + 1);

      ssh_mp_mul_ui(&c1, &a1, i + 1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1     = ", &a1);
	  print_int ("  a1 * u = ", &c1);
	  print_mont("  a0     = ", &a0);
	  print_mont("  a0 * u = ", &c0);
	  exit(1);
	}
    }

  printf(" * mul 2exp test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_mul_2exp(&c0, &a0, (i % 50) + 1);

      ssh_mp_mul_2exp(&c1, &a1, (i % 50) + 1);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1       = ", &a1);
	  print_int ("  a1 * 2^u = ", &c1);
	  print_mont("  a0       = ", &a0);
	  print_mont("  a0 * 2^u = ", &c0);
	  exit(1);
	}
    }

  printf(" * div 2exp test\n");
  for (i = 0; i < 1000; i++)
    {
      my_rand_mod(&a0, &a1, bits);

      ssh_mpm_div_2exp(&c0, &a0, (i % 5));

      ssh_mp_set_ui(&d, 1 << (i % 5));
      ssh_mp_invert(&d, &d, &m1);
      ssh_mp_mul(&c1, &a1, &d);
      ssh_mp_mod(&c1, &c1, &m1);

      if (check_mod(&c0, &c1) != 0)
	{
	  printf("error: mismatch at iteration %u\n", i);
	  print_int ("  a1     = ", &a1);
	  print_int ("  a1 * u = ", &c1);
	  print_mont("  a0     = ", &a0);
	  print_mont("  a0 * u = ", &c0);
	  exit(1);
	}
    }


  
  ssh_mpm_clear(&a0);
  ssh_mpm_clear(&b0);
  ssh_mpm_clear(&c0);
  ssh_mpm_clear_m(&m0);

  ssh_mp_clear(&a1);
  ssh_mp_clear(&b1);
  ssh_mp_clear(&c1);
  ssh_mp_clear(&m1);
  ssh_mp_clear(&d);
}

void test_gf2n(int flag, int bits)
{
  printf("error: not yet implemented.\n");
  exit(1);
}

void test_bpoly(int flag, int bits)
{
  /* Write these before GF(2^n) routines just in case. */
  printf("error: not yet implemented.\n");
  exit(1);
}

void test_gf2n_poly(int flag, int bits)
{
  printf("error: not yet implemented.\n");
  exit(1);
}


/* Elliptic curve stuff. First the prime case. */

void print_ecp_point(const char *str, const SshECPPoint *P)
{
  printf("%s \n{   ", str);
  ssh_mp_out_str(NULL, 10, &P->x);
  printf(", \n    ");
  ssh_mp_out_str(NULL, 10, &P->y);
  printf(", %u }\n", P->z);
}

void print_ec2n_point(const char *str, const SshEC2nPoint *P)
{
  printf("%s \n{  ", str);
  ssh_gf2n_hex_dump(&P->x);
  printf(", \n    ");
  ssh_gf2n_hex_dump(&P->y);
  printf(", %u }\n", P->z);
}


/* Table of parameters. */

typedef struct
{
  const char *q;
  const char *a;
  const char *b;
  const char *c;
  const char *px, *py;
  const char *n;
} SshECPFixedParams;

/* This set of parameters is intented for testing purposes only. */
const SshECPFixedParams ssh_ecp_fixed_params[] =
{
  {
    /* 155 bits */
    "31407857097127860965216287356072559134859825543",
    "2731256435122317801261871679028549091389013906",
    "10714317566020843022911894761291265613594418240",
    "31407857097127860965216427618348169229298502938",
    "16392655484387136812157475999461840857228033620",
    "2799086322187201568878931628895797117411224036",
    "402664834578562320066877277158309861914083371"
  },
  {
    /* 155 bits */
    "36297272659662506860980360407302074284133162871",
    "27124701431231299400484722496484295443330204918",
    "30301737350042067130127502794912132619158043000",
    "36297272659662506860980147341067393239091873883",
    "11711116373547979507936212029780235644179397805",
    "32762560063802500788917178597259173957396445450",
    "33640575491381625732043477771053949671671",
  },
  {
    /* 175 bits */
    "40950177705606685781046242922154881607956178336371883",
    "24746273018219762494198595506743299332378325756031886",
    "6503278719366954296567774236884439158775557920331547",
    "40950177705606685781046243158324028591251169648712266",
    "6408402137441767794969170236925842559451119808358974", 
    "39032544798419387403330432854399185547513580950826190",
    "2750918830149582546086674940099692905498533497831",
  },
  {
    /* 175 bits */
    "25133914800611099026082727697808480710160935689515477",
    "17146225641958545872320149903955451167573508624853931",
    "21261641208097867800497328477718361404177050434117193",
    "25133914800611099026082727581231133979322149086167579",
    "8738002582171225345779025855668373615175447647735275",
    "6530642698522393684297998663212006319191306125962008",
    "474718057534367152656837489904956793301367209",
  },
  { NULL },
};

void ssh_ecp_set_param(const SshECPFixedParams *params,
		       SshECPCurve *E, SshECPPoint *P, SshInt *n)
{
  ssh_ecp_init_curve(E);
  ssh_mp_set_str(&E->q, params->q, 0);
  ssh_mp_set_str(&E->a, params->a, 0);
  ssh_mp_set_str(&E->b, params->b, 0);
  ssh_mp_set_str(&E->c, params->c, 0);

  ssh_ecp_init_point(P, E);
  ssh_mp_set_str(&P->x, params->px, 0);
  ssh_mp_set_str(&P->y, params->py, 0);
  P->z = 1; /* Set to a finite point. */
  ssh_mp_set_str(n, params->n, 0);  
}

void test_ecp(int flag, int bits)
{
  SshECPCurve E;
  SshECPPoint P, Q, R, T;
  SshInt n, k;
  int i, j, s;

  printf(" * elliptic curves over finite field (mod p) tests\n");
  
  for (i = 0; ssh_ecp_fixed_params[i].q != NULL; i++)
    {
      printf("  # Curve %u\n", i + 1);

      ssh_mp_init(&n);
      ssh_mp_init(&k);
      ssh_ecp_set_param(&ssh_ecp_fixed_params[i],
			&E, &P, &n);
      ssh_ecp_init_point(&R, &E);
      ssh_ecp_init_point(&Q, &E);
      ssh_ecp_init_point(&T, &E);

      /* Now verify that the order is correct. */
      ssh_ecp_generic_mul(&R, &P, &n, &E);
      if (R.z != 0)
	{
	  printf("error: failed at ecp values, index %u. "
		 "Cardinality did not match.\n", i);
	  exit(1);
	}

      /* Test the another multiplier if n is prime. */
      if (ssh_mp_is_probable_prime(&n, 10))
	{
	  printf("  # Testing the efficient multiply routine\n");
      
	  for (j = 0; j < 100; j++)
	    {
	      ssh_mp_rand(&k, ssh_mp_get_size(&n, 2));
	      ssh_mp_mod(&k, &k, &n);
	      ssh_ecp_generic_mul(&Q, &P, &k, &E);
	      ssh_ecp_mul(&T, &P, &k, &E);
	      if (ssh_ecp_compare_points(&Q, &T) == FALSE)
		{
		  printf("error: "
			 "multiplication routines are not equivalent.\n");
		  exit(1);
		}
	    }
	}
	  
      printf("  # Random point tests\n");

      /* Now do some additional testing. */
      ssh_mp_div_q(&k, &E.c, &n);
      if (ssh_mp_cmp_ui(&k, 0) <= 0)
	{
	  printf("error: parameters in correct.\n");
	  exit(1);
	}

      for (s = 0; s < 10; s++)
	{
	  for (j = 0; j < 1000; j++)
	    {
	      ssh_ecp_random_point(&Q, &E);
	      ssh_ecp_generic_mul(&R, &Q, &k, &E);
	      if (R.z == 1)
		break;
	    }
	  
	  if (j >= 1000)
	    {
	      printf("error: looped %i times, did not find a point.\n", i);
	      exit(1);
	    }
	  
	  ssh_ecp_generic_mul(&Q, &R, &n, &E);
	  if (Q.z != 0)
	    {
	      printf("error: did not find point of correct order.\n");
	      exit(1);
	    }
	  
	  /* Do a addition.
	   */
	  ssh_ecp_negate_point(&T, &P, &E);
	  ssh_ecp_add(&Q, &P, &T, &E);
	  if (Q.z != 0)
	    {
	      printf("error: when added P and -P together.\n");
	      exit(1);
	    }

	  ssh_ecp_add(&Q, &R, &P, &E);
	  ssh_ecp_add(&T, &P, &R, &E);
	  if (ssh_ecp_compare_points(&T, &Q) == FALSE)
	    {
	      printf("error: addition order is meaningful.\n");
	      exit(1);
	    }
	  
	  ssh_ecp_negate_point(&T, &P, &E);
	  ssh_ecp_add(&Q, &R, &T, &E);
	  ssh_ecp_add(&Q, &Q, &T, &E);
	  ssh_ecp_add(&Q, &Q, &P, &E);
	  ssh_ecp_add(&Q, &Q, &P, &E);
	  
	  if (ssh_ecp_compare_points(&Q, &R) == FALSE)
	    {
	      printf("error: points are not equal.\n");
	      print_ecp_point(" P = ", &P);
	      print_ecp_point(" Q = ", &Q);
	      print_ecp_point(" T = ", &T);
	      print_ecp_point(" R = ", &R);
	      ssh_ecp_add(&T, &Q, &R, &E);
	      print_ecp_point(" T = ", &T);
	      exit(1);
	    }
	}
      
      ssh_ecp_clear_curve(&E);
      ssh_ecp_clear_point(&P);
      ssh_ecp_clear_point(&R);
      ssh_ecp_clear_point(&Q);
      ssh_ecp_clear_point(&T);

      ssh_mp_clear(&n);
      ssh_mp_clear(&k);
    }
}

/* Now the GF(2^n) case. */

typedef struct
{
  const char *q;
  const char *a;  
  const char *b;
  const char *c;
  const char *px, *py;
  const char *n;
} SshEC2nFixedParams;

const SshEC2nFixedParams ssh_ec2n_fixed_params[] =
{
  {
    "0x20000000000000000000000000201",
    "0x1",
    "0x1",
    "0x1fffffffffffffffb7f235edbd4e6",
    "0x1667979a40ba497e5d5c270780617",
    "0xf44b4af1ecc2630e08785cebcc15",
    "0xfffffffffffffffdbf91af6dea73"
  },
  {
    "0x0800000000000000000000004000000000000001",
    "0x0",
    "0x07338f",
    "0x0800000000000000000057db5698537193aef944",
    "0x7b",
    "0x1c8", 
    "0x2aaaaaaaaaaaaaaaaaac7f3c7881bd0868fa86c"
  },
  {
    "0x020000000000000000000000000000200000000000000001",
    "0x0",
    "0x1ee9",
    "0x01ffffffffffffffffffffffdbf2f889b73e484175f94ebc",
    "0x18",
    "0xd", 
    "0xffffffffffffffffffffffedf97c44db9f2420bafca75e"
  },
  {
    "0x020000000000000000000000000000200000000000000001",
    "0x0",
    "0x1ee9",
    "0x01ffffffffffffffffffffffdbf2f889b73e484175f94ebc",
    "0x039a936dc2047c0af0d2c51dbda3b35ec6bfcd879aafc4e", 
    "0x0cf2fdc81f9cc7f20049c7b3a84e78b42aae58a845f0f3f",
    "0x7FFFFFFFFFFFFFFFFFFFFFF6FCBE226DCF92105D7E53AF"
  },
  /* Following curve was generated by me, with Weil Theorem. */
  {
    "0x20000000000000000000000000000000000000429",
    "0x0",
    "0x1097bc0a943cc086616bb6b01b5888fcb22bceaa6",
    "2923003274661805836407372573348800143210639166336",
    "0x55db99798ee4d0767f0ffff71a75537706383c97",
    "0x1903da472c320fa72026f9b86cc5c3e20834c6ac2",
    "237753262223400119698618395082588065662663"
    /* cofactor: 12294272 */
    /* subcurve: a = 0, b = 2 trace 1 q = x^7 + x + 1 */
  },

  {
    "0x2000000000000000000000000000000000000004d",
    "0x1",
    "0x15f2cfac886236e8a5b71770c03d9bfad3ea77856",
    "2923003274661805836407369949559181215285310366262",
    "0x9ea98612b180925958fda625f4bf34d4a0dff0f1",
    "0x2ee153a4e3154d213fae36c6383e1231801809b9",
    "1201439539922929189314863773822319851873"
    /* cofactor: 2432917494 */
    /* subcurve: a = 1, b = 25 trace 3 q = x^7 + x + 1 */
  },

  {
    "0x2000000000000000000000000000000000000004d",
    "0x1ef3e17e0ce4b9683ec91445feb80e7d21202ad07",
    "0x1ec1ab6e3dfbe482993989a355bf6d3e07ac3600f",
    "2923003274661805836407369949559181215285310366262",
    "0x19afaea78bfe895a0cb427cf519255f5f5eb6c953",
    "0x67b203c24d799e6c3553169ecb56ce4b686121d4",
    "1201439539922929189314863773822319851873",
    /* cofactor: 2432917494 */
    /* subcurve: a = 67, b = 25, trace = 3, q = x^7 + x + 1 */
  },
  /* I have not been able to verify these. */

#if 0
  {
    "0x800000000000000000000000000000000000000C9",
    "0x23AA0F25B12388DE8A10FF9554F90AFBAA9A08B6F",
    "0x4DFA8D4FAE77C4A9CA2DEB14EAA8169DD9DA43647",
    "23384026197294446691258953860395195925217681645164",
    "0xBBB949D3D5B393DE4F5F02A9AC41EEF6501E43FA",
    "0x4DE2AD998E55B65000BA7C260D7F8E5D06F87048A",
    "5846006549323611672814738465098798981304420411291"
  },
  {
    "0x800000000000000000004000000000000000000000000000000000000001",
    "0x4F0E193BE91357A5091FD679B55D9CAC6EE2BC27B83BD66F18446B10D567",
    "0x70755A7735113F34FA488C2510F22DC1E54BA8BFE0B33CB7A15B92B11701",
    "883423532389192164791648750371459259394803559854882009882453269604383276",
    "0x53986A165E814AD03D242D490933FE786FA6FBD40B8175B82C0ACC56132E",
    "0x68A7846741E0E093DCAD2B8D6FD3201E2450E9D8DDD3A844B3D473EEC11B",
    "220855883097298041197912187592864814848700889963720502470613317401095819"
  },
#endif
  
  { NULL }
};

const SshEC2nFixedParams ssh_extra_params[] =
{
  {
    "113", /* 0x20000000000000000000000000201 */
    "1",
    "1",
    "2",
    "0x1 6679 79a4 0ba4 97e5 d5c2 7078 0617",
    "0x0 f44b 4af1 ecc2 630e 0878 5ceb cc15",
    "0x0 ffff ffff ffff fffd bf91 af6d ea73"
  },
  {
    "163",
    "1",
    "1",
    "2",
    "0x0bbb 949d 3d5b 393d e4f5 f02a 9ac4 1eef 6501 e43f a",
    "0x4de2 ad99 8e55 b650 00ba 7c26 0d7f 8e5d 06f8 7048 a",
    "0x4000 0000 0000 0000 0000 2010 8a2e 0cc0 d99f 8a5e f"
  }
};

void solve_y(SshEC2nPoint *P, SshEC2nCurve *E, SshInt *n)
{
  SshGF2nPoly f, g, h, u;
  SshGF2nElement a, b, y;
  SshEC2nPoint R;
  
  /* Initialize. */
  ssh_gf2n_poly_init(&f, &E->q);
  ssh_gf2n_poly_init(&g, &E->q);
  ssh_gf2n_poly_init(&h, &E->q);
  ssh_gf2n_poly_init(&u, &E->q);

  ssh_ec2n_init_point(&R, E);
  
  ssh_gf2n_init(&a, &E->q);
  ssh_gf2n_init(&b, &E->q);
  ssh_gf2n_init(&y, &E->q);
  
  /* Build a suitable polynomial. */
  ssh_gf2n_set(&a, &E->a);
  ssh_gf2n_set(&y, &P->y);

  /* Do a little computation. */
  ssh_gf2n_square(&b, &y);
  ssh_gf2n_add(&b, &b, &E->b);
  
  ssh_gf2n_poly_setall(&f,
		       SSH_GF2N_POLY_UI, 3, 1,
		       SSH_GF2N_POLY_GF2N, 2, &a,
		       SSH_GF2N_POLY_GF2N, 1, &y,
		       SSH_GF2N_POLY_GF2N, 0, &b,
		       SSH_GF2N_POLY_END);

  /* Compute the roots polynomial. */
  /*printf(" Polynomial = ");
  ssh_gf2n_poly_print(&f);
  printf("\n");
  */
  ssh_gf2n_poly_roots(&g, &f);
  /*
  printf(" Roots polynomial = ");
  ssh_gf2n_poly_print(&g);
  printf("\n");

  printf("All roots: \n");*/
  do
    {
      if (ssh_gf2n_poly_is_irreducible(&g) &&
	  ssh_gf2n_poly_deg(&g) > 2)
	{
	  /*printf("Irreducible thus cannot find any more roots.\n");*/
	  break;
	}
      
      if (ssh_gf2n_poly_deg(&g) > 2)
	{
	  ssh_gf2n_poly_monic(&g);
	  ssh_gf2n_poly_random_root(&a, &g);
	  ssh_gf2n_poly_set_zero(&u);
	  ssh_gf2n_poly_setall(&u,
			       SSH_GF2N_POLY_GF2N, 0, &a,
			       SSH_GF2N_POLY_UI, 1, 1,
			       SSH_GF2N_POLY_END);

	  /*printf(" Factor: ");
	  ssh_gf2n_poly_print(&u);
	  printf("\n");*/
	  ssh_gf2n_poly_div(&h, &f, &g, &u);
	  /*printf(" Divides? ");
	  ssh_gf2n_poly_print(&f);
	  printf("\n");	  */
	  ssh_gf2n_poly_set(&g, &h);
	}
      else
	{
	  ssh_gf2n_poly_monic(&g);
	  /*printf(" Factor: ");
	  ssh_gf2n_poly_print(&g);
	  printf("\n");*/
	  ssh_gf2n_poly_getall(&g,
			       SSH_GF2N_POLY_GF2N, 0, &a,
			       SSH_GF2N_POLY_END);
	  ssh_gf2n_poly_set_zero(&g);
	}

      /*
      printf(" Remaining: ");
      ssh_gf2n_poly_print(&g);
      printf("\n");*/
      
      ssh_gf2n_set(&P->x, &a);
      /* Compute with elliptic curves. */
      ssh_ec2n_generic_mul(&R, P, n, E);
      if (R.z == 0)
	{
	  printf("Good point found = \n");
	  printf("  x = ");
	  ssh_gf2n_hex_dump(&P->x);
	  printf("\n");
	  printf("  y = ");
	  ssh_gf2n_hex_dump(&P->y);
	  printf("\n");
	}
    }
  while (ssh_gf2n_poly_deg(&g) > 1);
  
  /* Free. */
  ssh_gf2n_poly_clear(&f);
  ssh_gf2n_poly_clear(&g);
  ssh_gf2n_poly_clear(&h);
  ssh_gf2n_poly_clear(&u);

  ssh_ec2n_clear_point(&R);
  
  ssh_gf2n_clear(&a);
  ssh_gf2n_clear(&b);
  ssh_gf2n_clear(&y);
}

void extra_test1(int idx, int *bits, int bits_count)
{
  SshEC2nCurve E;
  SshEC2nPoint P, R;
  SshInt q, a, b, c, px, py, n;
  int i;
  
  ssh_mp_init(&q);
  ssh_mp_init(&a);
  ssh_mp_init(&b);
  ssh_mp_init(&c);
  ssh_mp_init(&px);
  ssh_mp_init(&py);
  ssh_mp_init(&n);

  /* This is a kludge. */
  for (i = 0; i < bits_count; i++)
    ssh_mp_set_bit(&q, bits[i]);

  ssh_mp_set_str(&a, ssh_extra_params[idx].a, 0);
  ssh_mp_set_str(&b, ssh_extra_params[idx].b, 0);
  ssh_mp_set_str(&px, ssh_extra_params[idx].px, 0);
  ssh_mp_set_str(&py, ssh_extra_params[idx].py, 0);
  ssh_mp_set_str(&n, ssh_extra_params[idx].n, 0);
  ssh_mp_set_str(&c, ssh_extra_params[idx].c, 0);

  /* Compute the full order. */
#if 0
  ssh_mp_mul(&c, &c, &n);

  printf(" { ");
  ssh_mp_out_str(NULL, 16, &a);
  printf(", \n");
  ssh_mp_out_str(NULL, 16, &b);
  printf(", \n");
  ssh_mp_out_str(NULL, 16, &px);
  printf(", \n");
  ssh_mp_out_str(NULL, 16, &py);
  printf(", \n");
  ssh_mp_out_str(NULL, 16, &n);
  printf(", \n");
  ssh_mp_out_str(NULL, 16, &c);
  printf(", \n");
  ssh_mp_out_str(NULL, 10, &c);
  printf(" }\n");

  printf(" bit size %u\n", ssh_mp_get_size(&c, 2));
  
  exit(1);
#endif
  
  /* Now set the thing up. */
  ssh_ec2n_set_curve_mp(&E, &q, &a, &b, &c);
  ssh_ec2n_init_point(&P, &E);
  ssh_ec2n_set_point_mp(&P, &px, &py, 1);
  ssh_ec2n_init_point(&R, &E);

  /* Generate the missing component? */
  if (ssh_ec2n_restore_y(&P, &E, 0) == FALSE)
    printf("error: cannot restore y for this polynomial!\n");
  else
    {
      ssh_ec2n_generic_mul(&R, &P, &n, &E);
      if (R.z == 0)
	{
	  /* This is the curve! */
	  printf(" !!! Found a suitable alteration of the point.\n");
	  printf("    x = ");
	  ssh_gf2n_hex_dump(&P.x);
	  printf("\n    y = ");
	  ssh_gf2n_hex_dump(&P.y);
	  printf("\n    p = ");
	  ssh_mp_out_str(NULL, 16, &q);
	  printf("\n");
	}
    }

  /* Another try! */
  if (ssh_ec2n_restore_y(&P, &E, 1) == FALSE)
    printf("error: cannot restore y for this polynomial!\n");
  else
    {
      ssh_ec2n_generic_mul(&R, &P, &n, &E);
      if (R.z == 0)
	{
	  /* This is the curve! */
	  printf(" !!! Found a suitable alteration of the point.\n");
	  printf("    x = ");
	  ssh_gf2n_hex_dump(&P.x);
	  printf("\n    y = ");
	  ssh_gf2n_hex_dump(&P.y);
	  printf("\n    p = ");
	  ssh_mp_out_str(NULL, 16, &q);
	  printf("\n");
	}
    }
  /* Try to restore the x! This is slightly more complicated. */
  ssh_ec2n_set_point_mp(&P, &px, &py, 1);
  solve_y(&P, &E, &n);

  ssh_ec2n_clear_point(&P);
  ssh_ec2n_clear_point(&R);
  ssh_ec2n_clear_curve(&E);
  
  ssh_mp_clear(&q);
  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&c);
  ssh_mp_clear(&px);
  ssh_mp_clear(&py);
  ssh_mp_clear(&n);
}

void extra_test()
{
  int size[3] = { 113, 163 };
  int i, j, idx, bits_count;
  int bits[20];
  SshBPoly m;

  ssh_bpoly_init(&m);

  /* NOTE: add this irreducible searching into the gf2n.c it would be
     very useful in many occasions. */
  for (idx = 1; idx < 2; idx++)
    {
      for (bits_count = 3; bits_count < 16; bits_count += 2)
	{
	  bits[0] = 0;
	  for (i = 1; i < bits_count - 1; i++)
	    bits[i] = i;
	  bits[bits_count - 1] = size[idx]/2;
	  
	  while (1)
	    {
	      ssh_bpoly_set_ui(&m, 0);
	      bits[bits_count - 1] = size[idx];
	      for (i = 0; i < bits_count; i++)
		ssh_bpoly_set_bit(&m, bits[i]);
	      if (ssh_bpoly_is_irreducible(&m) == TRUE)
		{
		  printf("  Irreducible: ");
		  ssh_bpoly_pretty_print(&m);
		  printf("\n");
		  extra_test1(idx, bits, bits_count);
		}
	      bits[bits_count - 1] = size[idx]/2;
	      
	      for (i = 1; i < bits_count - 1; i++)
		if (bits[i] + 1 < bits[i + 1])
		  {
		    for (j = 1; j < i; j++)
		      bits[j] = j;
		    bits[i]++;
		    break;
		  }
	      if (i >= bits_count - 1)
		break;
	    }
	}
#if 0
	  
	  
      /* Search first for trinomials. */
      bits[0] = 0;
      bits[2] = size[i];
      for (bits[1] = bits[0] + 1; bits[1] < bits[2] - 32; bits[1]++)
	{
	  ssh_bpoly_set_ui(&m, 0);
	  ssh_bpoly_set_bit(&m, bits[0]);
	  ssh_bpoly_set_bit(&m, bits[1]);
	  ssh_bpoly_set_bit(&m, bits[2]);
	  if (ssh_bpoly_is_irreducible(&m) == TRUE)
	    {
	      printf("  Irreducible: ");
	      ssh_bpoly_pretty_print(&m);
	      printf("\n");
	      extra_test1(i, bits, 3);
	    }
	}

      /* Then for pentanomials. */
      bits[0] = 0;
      bits[4] = size[i];
      bits[1] = 1;
      bits[2] = 2;
      for (bits[3] = 3; bits[3] < bits[4] - 32; bits[3]++)
	for (bits[2] = 2; bits[2] < bits[3] - 1; bits[2]++)
	  for (bits[1] = 1; bits[1] < bits[2] - 1; bits[1]++)
	    {
	      ssh_bpoly_set_ui(&m, 0);
	      ssh_bpoly_set_bit(&m, bits[0]);
	      ssh_bpoly_set_bit(&m, bits[1]);
	      ssh_bpoly_set_bit(&m, bits[2]);
	      ssh_bpoly_set_bit(&m, bits[3]);
	      ssh_bpoly_set_bit(&m, bits[4]);
	      if (ssh_bpoly_is_irreducible(&m) == TRUE)
		{
		  printf("  Irreducible: ");
		  ssh_bpoly_pretty_print(&m);
		  printf("\n");
		  extra_test1(i, bits, 5);
		}
	    }
#endif
    }
}

void ssh_ec2n_set_param(const SshEC2nFixedParams *params,
			SshEC2nCurve *E, SshEC2nPoint *P, SshInt *n)
{
  SshInt t0, t1, t2, t3;

  /* Some temps. */
  ssh_mp_init(&t0);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);
  ssh_mp_init(&t3);
  
  ssh_mp_set_str(&t0, params->q, 0);
  ssh_mp_set_str(&t1, params->a, 0);
  ssh_mp_set_str(&t2, params->b, 0);
  ssh_mp_set_str(&t3, params->c, 0);

  /* Set the curve. */
  if (ssh_ec2n_set_curve_mp(E, &t0, &t1, &t2, &t3) == 0)
    {
      printf("error: failed to initialize parameter set.\n");
      exit(1);
    }
  
  ssh_mp_set_str(&t0, params->px, 0);
  ssh_mp_set_str(&t1, params->py, 0);

  /* Set the point. */
  ssh_ec2n_init_point(P, E);
  ssh_ec2n_set_point_mp(P, &t0, &t1, 1);

  /* Read the point order. */
  ssh_mp_set_str(n, params->n, 0);

  ssh_mp_clear(&t0);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);
  ssh_mp_clear(&t3);
}

void test_ec2n(int flag, int bits)
{
  SshEC2nCurve E;
  SshEC2nPoint P, Q, R, T;
  SshInt n, k;
  int i, j, s;

  printf(" * elliptic curves over GF(2^n) tests\n");

  for (i = 0; ssh_ec2n_fixed_params[i].q != NULL; i++)
    {
      printf("  # Curve %u\n", i+ 1);

      ssh_mp_init(&n);
      ssh_mp_init(&k);
      ssh_ec2n_set_param(&ssh_ec2n_fixed_params[i],
			 &E, &P, &n);
      ssh_ec2n_init_point(&R, &E);
      ssh_ec2n_init_point(&Q, &E);
      ssh_ec2n_init_point(&T, &E);

      /* Now verify that the order is correct. */
      ssh_ec2n_generic_mul(&R, &P, &n, &E);
      if (R.z != 0)
	{
	  printf("error: failed at ec2n values, index %u. "
		 "Cardinality did not match.\n", i);
	  exit(1);
	}

      /* Test the another multiplier if n is prime. */
      if (ssh_mp_is_probable_prime(&n, 10))
	{
	  printf("  # Testing the efficient multiply routine\n");
      
	  for (j = 0; j < 100; j++)
	    {
	      ssh_mp_rand(&k, ssh_mp_get_size(&n, 2));
	      ssh_mp_mod(&k, &k, &n);
	      ssh_ec2n_generic_mul(&Q, &P, &k, &E);
	      ssh_ec2n_mul(&T, &P, &k, &E);
	      if (ssh_ec2n_compare_points(&Q, &T) == FALSE)
		{
		  printf("error: "
			 "multiplication routines are not equivalent.\n");
		  exit(1);
		}
	    }
	}
      
      printf("  # Random point tests\n");

      /* Now do some additional testing. */
      ssh_mp_div_q(&k, &E.c, &n);
      if (ssh_mp_cmp_ui(&k, 0) <= 0)
	{
	  printf("error: parameters in correct.\n");
	  exit(1);
	}

      for (s = 0; s < 10; s++)
	{
	  for (j = 0; j < 1000; j++)
	    {
	      ssh_ec2n_random_point(&Q, &E);
	      ssh_ec2n_generic_mul(&R, &Q, &k, &E);
	      if (R.z == 1)
		break;
	    }
	  
	  if (j >= 1000)
	    {
	      printf("error: looped %i times, did not find a point.\n", j);
	      exit(1);
	    }
	  
	  ssh_ec2n_generic_mul(&Q, &R, &n, &E);
	  if (Q.z != 0)
	    {
	      printf("error: did not find point of correct order.\n");
	      exit(1);
	    }
	  
	  /* Do a addition. */
	  ssh_ec2n_negate_point(&T, &P, &E);
	  ssh_ec2n_add(&Q, &R, &P, &E);
	  ssh_ec2n_add(&Q, &Q, &P, &E);
	  ssh_ec2n_add(&Q, &Q, &T, &E);
	  ssh_ec2n_add(&Q, &Q, &T, &E);
	  
	  if (ssh_ec2n_compare_points(&Q, &R) == FALSE)
	    {
	      printf("error: points are not equal.\n");
	      print_ec2n_point(" P = ", &P);
	      print_ec2n_point(" T = ", &T);
	      print_ec2n_point(" R = ", &R);
	      exit(1);
	    }
	}
      
      ssh_ec2n_clear_curve(&E);
      ssh_ec2n_clear_point(&P);
      ssh_ec2n_clear_point(&R);
      ssh_ec2n_clear_point(&Q);
      ssh_ec2n_clear_point(&T);

      ssh_mp_clear(&n);
      ssh_mp_clear(&k);
    }
}

void test_fec2n(int flag, int bits)
{
  SshEC2nCurve E;
  SshEC2nPoint P, Q, R, T;
  SshSieve sieve;
  SshInt n, k;
  int i, j, s, size;

  /* Some moduli sizes that lead to good results. */
  int moduli_sizes[7] =
  { 155, 163, 177, 233, 239, 277, 283 };

  printf(" * Frobenius (Koblitz, Mueller) elliptic curves over GF(2^n) tests\n");

  /* Allocate a sieve. */
  ssh_sieve_allocate(&sieve, 100000);
  
  for (i = 0; i < 10; i++)
    {
      printf("  # Trying to generate an elliptic curve for testing.\n");
      /* Generation of the curve. (Quite random!) */
      size = (random() % 70) + 150; 
      printf("    ~ searching for curve with %u bit irreducible polynomial\n",
	     size);
      if (ssh_ec2n_generate_frobenius_curve(&E, size) == 0)
	{
	  printf("  # Retrying...\n");
	  continue;
	}
      
      printf("  # Curve %u generated\n", i + 1);

      if (E.f_q == 1)
	printf("   ~ Koblitz' ABC (Anamolous Binary Curve)\n");
      else
	printf("   ~ Mueller's Frobenius Curve\n"); 
      
      /* Must figure out if can factor the order! */
      ssh_mp_init(&n);
      ssh_mp_set(&n, &E.c);
      printf("  # Factoring the number of points\n");
      for (j = 2; j; j = ssh_sieve_next_prime(j, &sieve))
	while (ssh_mp_mod_ui(&n, j) == 0)
	  {
	    printf("    ~ factor %u\n", j);
	    ssh_mp_div_ui(&n, &n, j);
	  }

      /* Check for primality. */
      if (ssh_mp_is_probable_prime(&n, 10) == 0)
	{
	  printf("  # Could not factor fully.\n");
	  ssh_mp_clear(&n);
	  ssh_ec2n_clear_curve(&E);
	  continue;
	}

      printf("  # Seeking for point of order: \n    ");
      ssh_mp_out_str(NULL, 10, &n);
      printf("\n");
      
      ssh_ec2n_init_point(&P, &E);

      if (ssh_ec2n_random_point_of_prime_order(&P, &n,
					       &E) == FALSE)
	{
	  printf("error: could not find a random point of prime order.\n");
	  exit(1);
	}
      
      ssh_ec2n_init_point(&R, &E);
      ssh_ec2n_init_point(&Q, &E);
      ssh_ec2n_init_point(&T, &E);
      
      /* Now verify that the order is correct. */
      ssh_ec2n_generic_mul(&R, &P, &n, &E);
      if (R.z != 0)
	{
	  printf("error: failed at ec2n values, index %u. "
		 "Cardinality did not match.\n", i);
	  exit(1);
	}

      /* Test the another multiplier if n is prime. */
      printf("  # Testing the very efficient multiplication routine\n");
      ssh_mp_init(&k);
      for (j = 0; j < 100; j++)
	{
	  /*printf(".");
	  fflush(stdout); */
	  ssh_mp_rand(&k, ssh_mp_get_size(&n, 2) + 1);
	  ssh_mp_mod(&k, &k, &n);
	  ssh_ec2n_generic_mul(&Q, &P, &k, &E);

	  /* This should launch the Frobenius multiplication now! */
	  ssh_ec2n_mul(&T, &P, &k, &E);
	  if (ssh_ec2n_compare_points(&Q, &T) == FALSE)
	    {
	      printf(" Case %u \n", j + 1);
	      printf("error: "
		     "multiplication routines are not equivalent.\n");
	      exit(1);
	    }
	}
      
      printf("  # Random point tests\n");

      /* Now do some additional testing. */
      ssh_mp_div_q(&k, &E.c, &n);
      if (ssh_mp_cmp_ui(&k, 0) <= 0)
	{
	  printf("error: parameters in correct.\n");
	  exit(1);
	}

      for (s = 0; s < 10; s++)
	{
	  for (j = 0; j < 1000; j++)
	    {
	      ssh_ec2n_random_point(&Q, &E);
	      ssh_ec2n_generic_mul(&R, &Q, &k, &E);
	      if (R.z == 1)
		break;
	    }
	  
	  if (j >= 1000)
	    {
	      printf("error: looped %i times, did not find a point.\n", j);
	      exit(1);
	    }
	  
	  ssh_ec2n_generic_mul(&Q, &R, &n, &E);
	  if (Q.z != 0)
	    {
	      printf("error: did not find point of correct order.\n");
	      exit(1);
	    }
	  
	  /* Do a addition. */
	  ssh_ec2n_negate_point(&T, &P, &E);
	  ssh_ec2n_add(&Q, &R, &P, &E);
	  ssh_ec2n_add(&Q, &Q, &P, &E);
	  ssh_ec2n_add(&Q, &Q, &T, &E);
	  ssh_ec2n_add(&Q, &Q, &T, &E);
	  
	  if (ssh_ec2n_compare_points(&Q, &R) == FALSE)
	    {
	      printf("error: points are not equal.\n");
	      print_ec2n_point(" P = ", &P);
	      print_ec2n_point(" T = ", &T);
	      print_ec2n_point(" R = ", &R);
	      exit(1);
	    }
	}
      
      ssh_ec2n_clear_point(&P);
      ssh_ec2n_clear_point(&R);
      ssh_ec2n_clear_point(&Q);
      ssh_ec2n_clear_point(&T);
      ssh_ec2n_clear_curve(&E);

      ssh_mp_clear(&n);
      ssh_mp_clear(&k);
    }

  ssh_sieve_free(&sieve);
}

#if 1

int hw_search(SshInt *out, SshInt *d, SshInt *phi)
{
  SshWord k, min_k, max_k;
  SshInt t;
  int w;
  double min, max, weight, orig;
  int mask, end_square, i, j, bits;

#define BLOCK_BITS 5

  ssh_mp_init(&t);
  
  ssh_mp_set(&t, d);
  for (k = 0, max = 0, min = ssh_mp_get_size(&t, 2); k < (1 << 16); k++)
    {
      if (k)
	ssh_mp_add(&t, &t, phi);

      /* Compute the strange hamming weight. */
      bits = ssh_mp_get_size(&t, 2);
      for (weight = 0.0, i = bits; i; )
	{
	  for (j = 0; j < BLOCK_BITS && i; j++, i--)
	    {
	      mask <<= 1;
	      mask |= ssh_mp_get_bit(&t, i - 1);
	    }
	  /* Why do I do this here? */
	  for (end_square = 0; (mask & 0x1) == 0; )
	    {
	      mask >>= 1;
	      end_square++;
	    }
	  weight++;
	  weight += BLOCK_BITS * 0.5;
	  while (i && ssh_mp_get_bit(&t, i - 1) == 0)
	    {
	      i--;
	      weight += 0.5;
	    }
	}

      /* Compare. */
      if (weight < min)
	{
	  min = weight;
	  min_k = k;
	}
      if (weight > max)
	{
	  max = weight;
	  max_k = k;
	}

      if (k == 0)
	orig = weight;
    }

  printf("  * weight min %4.2lf max %4.2lf original %4.2lf\n",
	 min, max, orig); 
  
  /* Finish off. */
#if 1
  ssh_mp_mul_ui(&t, phi, min_k);
  ssh_mp_add(out, &t, d);
#else
  ssh_mp_set(out, d);
#endif
  ssh_mp_clear(&t);
 
  
  return min;
}

/* Simple so-called fast RSA exponentiation test. */
void test_rsa_kphi()
{
  SshInt p1, q1, phi, n, p, q, e, d, m, c, t, dp, dq, p2, q2, u;
  int i, j, weight;
  TimeIt tmit;
  
  ssh_mp_init(&p1);
  ssh_mp_init(&q1);
  ssh_mp_init(&phi);
  ssh_mp_init(&n);
  ssh_mp_init(&p);
  ssh_mp_init(&q);
  ssh_mp_init(&e);
  ssh_mp_init(&d);
  ssh_mp_init(&m);
  ssh_mp_init(&c);
  ssh_mp_init(&t);
  ssh_mp_init(&u);
  ssh_mp_init(&dp);
  ssh_mp_init(&dq);
  ssh_mp_init(&p2);
  ssh_mp_init(&q2);

  /* This test runs the RSA decryption/signature operation
     with different keys trying to decide whether there is a
     way to exploit the fact that d == d + phi(n)*k, which means
     that one can actually reduce the Hamming weight of the
     exponent. */
     
  for (i = 0; i < 100; i++)
    {
      printf("RSA test no %u\n", i + 1);
      /* Random primes. */
      ssh_mp_rand(&p, 512);
      ssh_mp_next_prime(&p, &p);
      ssh_mp_rand(&q, 512);
      ssh_mp_next_prime(&q, &q);

      /* Compute n. */
      ssh_mp_mul(&n, &p, &q);

      /* Compute phi. */
      ssh_mp_sub_ui(&p1, &p, 1);
      ssh_mp_sub_ui(&q1, &q, 1);
      ssh_mp_mul(&phi, &q1, &p1);

      /* Compute something. */
      ssh_mp_gcd(&c, &q1, &p1);
      ssh_mp_div_q(&m, &phi, &c);

      /* Finish up with the encryption exponent. */
      ssh_mp_set_ui(&e, 1);
      ssh_mp_mul_2exp(&e, &e, 16);
      ssh_mp_sub_ui(&e, &e, 1);
      do
	{
	  ssh_mp_add_ui(&e, &e, 2);
	  ssh_mp_gcd(&t, &e, &phi);
	}
      while (ssh_mp_cmp_ui(&t, 1) != 0);

      ssh_mp_invert(&d, &e, &m);
      /* Compute the u. */
      ssh_mp_invert(&u, &p, &q);
      
      ssh_mp_mod(&dp, &d, &p1);
      ssh_mp_mod(&dq, &d, &q1);

      printf(" - searching for k1...\n");
      /* Do the searching! */
      weight = hw_search(&dp, &dp, &p1);

      printf(" - searching for k2...\n");
      /* Do the searching! */
      weight += hw_search(&dq, &dq, &q1);

      printf(" - doing test decryptions...\n");
      
      start_timing(&tmit);
      for (j = 0; j < 100; j++)
	{
	  /* Generate random. */
	  ssh_mp_rand(&t, 1024);

	  /* Do the RSA with CRT. */
	  ssh_mp_powm(&p2, &t, &dp, &p);
	  ssh_mp_powm(&q2, &t, &dq, &q);
	  ssh_mp_sub(&t, &q2, &p2);
	  ssh_mp_mul(&t, &t, &u);
	  ssh_mp_mod(&t, &t, &q);
	  ssh_mp_mul(&t, &t, &p);
	  ssh_mp_add(&t, &t, &p2);
	}
      /* Result is in t. */
      /* But we dont use it. */
      
      check_timing(&tmit);

      printf(" - RSA d weight %u time %4.2f secs %u decryptions\n",
	     weight, tmit.real_secs, j);
    }
  
  ssh_mp_clear(&p1);
  ssh_mp_clear(&q1);
  ssh_mp_clear(&phi);
  ssh_mp_clear(&n);
  ssh_mp_clear(&p);
  ssh_mp_clear(&q);
  ssh_mp_clear(&e);
  ssh_mp_clear(&d);
  ssh_mp_clear(&m);
  ssh_mp_clear(&c);
  ssh_mp_clear(&t);
  ssh_mp_clear(&u);
  ssh_mp_clear(&dp);
  ssh_mp_clear(&dq);
  ssh_mp_clear(&p2);
  ssh_mp_clear(&q2);

  exit(0);
}
#endif

/* Speed tests of some sort. */

void timing_int(int bits)
{
  SshInt a, b, c, d, e, f[100];
  TimeIt tmit;
  unsigned int i, j, k;

  ssh_mp_init(&a);
  ssh_mp_init(&b);
  ssh_mp_init(&c);
  ssh_mp_init(&d);
  ssh_mp_init(&e);
  
  printf("Timing integer arithmetic.\n");

  printf("Bits = %u\n", bits);

  for (i = 0; i < 100; i++)
    {
      ssh_mp_init(&f[i]);
      ssh_mp_rand(&f[i], bits);
      if ((ssh_mp_get_ui(&f[i]) & 0x1) == 0)
	ssh_mp_add_ui(&f[i], &f[i], 1);
    }

  printf("Timing multiplication [%u * %u = %u] \n",
	 bits, bits, bits + bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits);
      for (j = 0; j < 100; j++)
	ssh_mp_mul(&a, &f[j], &b);
    }
  check_timing(&tmit);

  printf("  * %g multiplications per sec\n",
	 ((double)50*100)/(tmit.real_secs));
  
  printf("Timing divisions [%u / %u = %u] \n",
	 bits + bits, bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits*2);
      for (j = 0; j < 100; j++)
	ssh_mp_div(&a, &c, &b, &f[j]);
    }
  check_timing(&tmit);

  printf("  * %g divisions per sec\n",
	 ((double)50*100)/(tmit.real_secs));

  
  printf("Timing modular reductions [%u % %u = %u] \n",
	 bits + bits, bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits*2);
      for (j = 0; j < 100; j++)
	ssh_mp_mod(&a, &b, &f[j]);
    }
  check_timing(&tmit);

  printf("  * %g modular reductions per sec\n",
	 ((double)50*100)/(tmit.real_secs));

  
  printf("Timing squarings [%u^2 = %u] \n",
	 bits, bits, bits + bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mp_rand(&b, bits);
      for (j = 0; j < 100; j++)
	ssh_mp_square(&a, &b);
    }
  check_timing(&tmit);

  printf("  * %g squarings per sec\n",
	 ((double)50*100)/(tmit.real_secs));

  printf("Timing modexp [%u^%u %% %u = %u] \n",
	 bits, bits, bits, bits);
  start_timing(&tmit);
  for (j = 0, i = 0; i < 10; i++, j += 2)
    {
      ssh_mp_rand(&b, bits);
      ssh_mp_powm(&a, &b, &f[j + 1], &f[j + 2]);
    }
  check_timing(&tmit);

  printf("  * %g modexps per sec\n",
	 ((double)10)/(tmit.real_secs));

  ssh_mp_clear(&a);
  ssh_mp_clear(&b);
  ssh_mp_clear(&c);
  ssh_mp_clear(&d);
  ssh_mp_clear(&e);

  for (i = 0; i < 100; i++)
    ssh_mp_clear(&f[i]);
}

void timing_modular(int bits)
{
  SshIntModQ b, c, d, e, f[100];
  SshIntModuli m;
  SshInt a;
  int i, j, k;
  TimeIt tmit;
  
  ssh_mp_init(&a);

  do
    {
      ssh_mp_rand(&a, bits);
      while (ssh_mp_next_prime(&a, &a) == FALSE)
	ssh_mp_rand(&a, bits);
    }
  while (ssh_mp_get_size(&a, 2) < bits - 1);

  printf("Timing modular arithmetic.\n");
  if (ssh_mpm_init_m(&m, &a) == FALSE)
    ssh_fatal("timing_modular: could not initialize modular arithmetic.");

  printf("Bits = %u\n", bits);

  ssh_mpm_init(&b, &m);
  ssh_mpm_init(&c, &m);
  ssh_mpm_init(&d, &m);
  ssh_mpm_init(&e, &m);
  
  for (i = 0; i < 100; i++)
    {
      ssh_mpm_init(&f[i], &m);
      ssh_mp_rand(&a, bits);
      ssh_mpm_set_mp(&f[i], &a);
    }

  printf("Timing multiplication [%u * %u = %u] \n",
	 bits, bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    {
      ssh_mpm_set(&b, &f[i]);
      for (j = 0; j < 100; j++)
	ssh_mpm_mul(&c, &f[j], &b);
    }
  check_timing(&tmit);

  printf("  * %g multiplications per sec\n",
	 ((double)50*100)/(tmit.real_secs));
  
  printf("Timing squarings [%u^2 = %u] \n",
	 bits, bits);
  start_timing(&tmit);
  for (i = 0; i < 50; i++)
    for (j = 0; j < 100; j++)
      ssh_mpm_square(&b, &f[j]);
  check_timing(&tmit);

  printf("  * %g squarings per sec\n",
	 ((double)50*100)/(tmit.real_secs));

  ssh_mpm_clear(&b);
  ssh_mpm_clear(&c);
  ssh_mpm_clear(&d);
  ssh_mpm_clear(&e);

  for (i = 0; i < 100; i++)
    ssh_mpm_clear(&f[i]);
  ssh_mpm_clear_m(&m);
  ssh_mp_clear(&a);  
}

/* Routines for handling the arguments etc. */

typedef struct CommandRec
{
  char *name;
  int  type;
  int  args;
} Command;

#define C_NONE    -1
#define C_HELP    0
#define C_ALL     1
#define C_ITR     2
#define C_GF2N    3
#define C_INT     4
#define C_MOD     5
#define C_BIN     6
#define C_POLY2N  7
#define C_ECP     8
#define C_EC2N    9
#define C_FEC2N   10

#define C_BITS     20
#define C_BITS_ADV 21

#define C_TIMING   30

const Command commands[] =
{
  { "-h", C_HELP, 0 },
  { "--help", C_HELP, 0 },

  { "-a", C_ALL, 0 },
  { "--all", C_ALL, 0 },

  { "-i", C_ITR, 1 },
  { "--iterations", C_ITR, 1 },

  { "-b", C_BITS, 1 },
  { "--bits", C_BITS, 1 },
  { "-ba", C_BITS_ADV, 1 },
  { "--bits-advance", C_BITS_ADV, 1 },

  { "-t", C_TIMING, 0 },
  { "--timing", C_TIMING, 0 },
  
  /* General classes of tests. */
  { "--gf2n", C_GF2N, 1 },
  { "--integer", C_INT, 1 },
  { "--modular", C_MOD, 1 },
  { "--binary", C_BIN, 1 },
  { "--gf2npoly", C_POLY2N, 1 },
  { "--ecp", C_ECP, 1 },
  { "--ec2n", C_EC2N, 1 },
  { "--fec2n", C_FEC2N, 1 },
  
  { NULL }
};

int check_arg(char *str, int *args)
{
  int i;

  for (i = 0; commands[i].name; i++)
    if (strcmp(str, commands[i].name) == 0)
      {
	*args = commands[i].args;
	return commands[i].type;
      }
  
  *args = 0;
  return C_NONE;
}

void usage()
{
  printf("usage: t-mathtest [options]\n"
	 "options:\n"
	 " -a     run all tests (might take longer)\n"
	 " -t     run also timings for modules\n"
	 " -i xx  run all tests xx times (will use different random seeds)\n"
	 " -h     this help.\n"
	 "advanced options: \n"
	 " --integer [on|off] sets the integer arithmetic testing on/off.\n"
	 " --modular [on|off] sets the (mod p) arithmetic testing on/off.\n"
	 " --ec2n    [on|off] sets the elliptic curve GF(2^n) testing on/off.\n"
	 " --ecp     [on|off] sets the elliptic curve (mod p) testing on/off.\n"
	 " --fec2n   [on|off] sets the fast elliptic curve GF(2^n) testing on/off.\n"
	 " --gf2n    [on|off] sets the GF(2^n) testing on/off.\n"
	 " --bpoly   [on|off] sets the binary polynomial testing on/off.\n"
	 " --gf2npoly [on|off] sets the GF(2^n) polynomial testing on/off.\n");
  exit(1);
}

int on_off(char *str)
{
  if (strcmp(str, "on") == 0)
    return 1;
  if (strcmp(str, "off") == 0)
    return 0;

  printf("error: '%s' should be 'on' or 'off'.\n", str);
  exit(1);
}

int main(int ac, char *av[])
{
  int i, all, itr, type, args;
  int gf2n, mod, integer, ecp, ec2n, fec2n, poly2n, bpoly,
    bits, bits_advance, timing;

  printf("Arithmetic library test suite\n"
	 "Copyright (C) 1998 SSH Communications Security, Ltd.\n"
	 "              All rights reserved.\n"
	 "\n"
	 "Features: \n"
	 "  - integer arithmetic\n"
	 "  - finite field arithmetic (mod p)\n"
	 "  - Galois field arithmetic GF(2^n)\n"
	 "  - binary polynomial arithmetic\n"
	 "  - Polynomials over GF(2^n) arithmetic\n"
	 "  - elliptic curves over GF(2^n) arithmetic\n"
	 "  - elliptic curves over finite field (mod p) arithmetic\n"
	 "\n");
  
  /* Randomize the random number generator. */
  srandom(time(NULL));

  /* Don't use this if you want to test the mathlibrary :) */
  /*extra_test(); */
  /*test_rsa_kphi(); */
  
  all = 0;
  itr = 1;

  timing = 0;
  
  bits = 512;
  bits_advance = 128;
  
  gf2n     = 0;
  integer  = 1;
  mod      = 0;
  bpoly    = 0;
  ecp      = 0;
  ec2n     = 0;
  fec2n    = 0;
  poly2n   = 0;
  
  for (i = 1; i < ac; i++)
    {
      type = check_arg(av[i], &args);
      if (args >= ac - i)
	{
	  printf("error: not enough arguments for '%s'.\n",
		 av[i]);
	  exit(1);
	}

      switch (type)
	{
	case C_INT:
	  integer = on_off(av[i + 1]);
	  i++;
	  break;
	case C_GF2N:
	  gf2n = on_off(av[i + 1]);
	  i++;
	  break;
	case C_MOD:
	  mod = on_off(av[i + 1]);
	  i++;
	  break;
	case C_BIN:
	  bpoly = on_off(av[i + 1]);
	  i++;
	  break;
	case C_POLY2N:
	  poly2n = on_off(av[i + 1]);
	  i++;
	  break;
	case C_ECP:
	  ecp = on_off(av[i + 1]);
	  i++;
	  break;
	case C_EC2N:
	  ec2n = on_off(av[i + 1]);
	  i++;
	  break;
	case C_FEC2N:
	  fec2n = on_off(av[i + 1]);
	  i++;
	  break;

	case C_BITS:
	  bits = atoi(av[i + 1]);
	  i++;
	  break;
	case C_BITS_ADV:
	  bits_advance = atoi(av[i + 1]);
	  i++;
	  break;
	  
	case C_HELP:
	  usage();
	  break;
	case C_ALL:
	  all = 1;
	  break;
	case C_TIMING:
	  timing = 1;
	  break;
	case C_ITR:
	  itr = atoi(av[i + 1]);
	  i++;
	  break;
	case C_NONE:
	  printf("error: '%s' not a valid option.\n",
		 av[i]);
	  usage();
	  break;
	}
    }

  if (itr <= 0)
    itr = 1;

  if (bits < 10)
    bits = 10;

  for (i = 0; i < itr; i++, bits += bits_advance)
    {
      if (bits < 10)
	bits = 512;
      
      if (integer)
	{
	  test_int(all, bits);
	  if (timing)
	    timing_int(bits);
	}
      if (mod)
	{
	  test_mod(all, bits);
	  if (timing)
	    timing_modular(bits);
	}
      if (gf2n)
	{
	  test_gf2n(all, bits);
	  if (timing)
	    ;
	}
      if (bpoly)
	{
	  test_bpoly(all, bits);
	  if (timing)
	    ;
	}
      if (poly2n)
	{
	  test_gf2n_poly(all, bits);
	  if (timing)
	    ;
	}
      if (ecp)
	{
	  test_ecp(all, bits);
	  if (timing)
	    ;
	}
      if (ec2n)
	{
	  test_ec2n(all, bits);
	  if (timing)
	    ;
	}
      if (fec2n)
	{
	  test_fec2n(all, bits);
	  if (timing)
	    ;
	}
    }

  return 0;
}
