/*

  sshgmp.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Wed Jan 28 17:58:56 1998 [mkojo]

  GMP 2.0 like interface for SSH BigNum library. The list of supported
  functions is not entire, that is some GMP routines are not supported.
  However, these are all that are needed in usual SSH places. 

  */

/*
 * $Id: gmp.h,v 1.4 1998/06/24 13:26:00 kivinen Exp $
 * $Log: gmp.h,v $
 * $EndLog$
 */

#ifndef SSHGMP_H
#define SSHGMP_H

#include "sshmath-types.h"
#include "sshmp.h"

/* The types of GMP have direct analogues in Ssh MP library. */
typedef SshInt MP_INT;
typedef SshInt mpz_t[1];

/* Routines which are currently supported. */

/* Initialization, and clearing. */
#define mpz_init        ssh_mp_init
#define mpz_clear       ssh_mp_clear

/* Initialization with assignment. Note that all small integers are
   thought as unsigned int's and signed int's. */
#define mpz_init_set_ui ssh_mp_init_set_ui
#define mpz_init_set_si ssh_mp_init_set_si
#define mpz_init_set    ssh_mp_init_set
#define mpz_init_set_str ssh_mp_init_set_str

/* Routines for getting information from large integers. */
#define mpz_get_ui      ssh_mp_get_ui
#define mpz_sizeinbase  ssh_mp_get_size
#define mpz_get_si      ssh_mp_get_si
#define mpz_get_limbn   ssh_mp_get_word

/* Assigning values to large integers. */
#define mpz_set         ssh_mp_set
#define mpz_set_ui      ssh_mp_set_ui
#define mpz_set_si      ssh_mp_set_si
#define mpz_set_bit     ssh_mp_set_bit

/* Routine which clears one bit. */
#define mpz_clrbit      ssh_mp_clr_bit

/* Basic sign manipulation. */
#define mpz_neg         ssh_mp_neg
#define mpz_abs         ssh_mp_abs

/* Basic comparison functions. */
#define mpz_cmp         ssh_mp_cmp
#define mpz_cmp_ui      ssh_mp_cmp_ui
#define mpz_cmp_si      ssh_mp_cmp_si

/* Arithmetic. Addition and subtraction. */
#define mpz_add         ssh_mp_add
#define mpz_add_ui      ssh_mp_add_ui
#define mpz_sub         ssh_mp_sub
#define mpz_sub_ui      ssh_mp_sub_ui

/* Multiplication. */
#define mpz_mul         ssh_mp_mul
#define mpz_mul_ui      ssh_mp_mul_ui

/* Sorry, but these are not entirely compatible with GMP routines. The
   problems will undoubtedly arise when using negative divisors etc. However,
   in most occasions these should work just fine. */

/* Basic division with remainder. */
#define mpz_fdiv_qr     ssh_mp_div
#define mpz_cdiv_qr     ssh_mp_div
#define mpz_tdiv_qr     ssh_mp_div

/* Division without a remainder. */
#define mpz_div         ssh_mp_div_q
#define mpz_fdiv_q      ssh_mp_div_q
#define mpz_cdiv_q      ssh_mp_div_q
#define mpz_tdiv_q      ssh_mp_div_q

/* Modular operation, note, that this is not entirely compatible with
   GMP. */
#define mpz_mod         ssh_mp_mod
#define mpz_cdiv_r      ssh_mp_mod
#define mpz_fdiv_r      ssh_mp_mod
#define mpz_tdiv_r      ssh_mp_mod

/* This should be the mathematical modulo, however, it is not in this
   implementation. Although, given _positive_ modulus it will behave
   similarly. */
#define mpz_mmod        ssh_mp_mod

/* Dividing with small values. */
#define mpz_div_ui      ssh_mp_div_ui
#define mpz_fdiv_q_ui   ssh_mp_div_ui
#define mpz_cdiv_q_ui   ssh_mp_div_ui
#define mpz_tdiv_q_ui   ssh_mp_div_ui
#define mpz_cdiv_r_ui   ssh_mp_mod_ui2
#define mpz_fdiv_r_ui   ssh_mp_mod_ui2
#define mpz_tdiv_r_ui   ssh_mp_mod_ui2
#define mpz_fdiv_r_ui   ssh_mp_mod_ui2
#define mpz_mod_ui      ssh_mp_mod_ui2

/* Computation of GCD, Extended GCD and inverting modulo a large integer */
#define mpz_gcd         ssh_mp_gcd
#define mpz_gcdext      ssh_mp_gcdext
#define mpz_invert      ssh_mp_invert

/* Exponentiation modulo an integer. */
#define mpz_powm_ui     ssh_mp_powm_expui
#define mpz_powm        ssh_mp_powm

/* Computation of legendre and jacobi symbols. */
#define mpz_legendre    ssh_mp_legendre
#define mpz_jacobi      ssh_mp_jacobi

/* Computing sqrt's of integers. */
#define mpz_sqrt        ssh_mp_sqrt
#define mpz_sqrtrem     ssh_mp_sqrtrem

/* Checking for perfect square root. */
#define mpz_perfect_square_p ssh_mp_perfect_square

/* Boolean operation, note that GMP doesn't have mpz_xor although here we
   give one. Also ior is not entirely compatible because it doesn't handle
   negative values correctly, nor does none of these. */
#define mpz_and         ssh_mp_and
#define mpz_ior         ssh_mp_or
#define mpz_xor         ssh_mp_xor
#define mpz_com         ssh_mp_com

/* Operations with 2^n. */
#define mpz_mul_2exp    ssh_mp_mul_2exp
#define mpz_mod_2exp    ssh_mp_mod_2exp
#define mpz_div_2exp    ssh_mp_div_2exp

/* String conversions. */
#define mpz_get_str     ssh_mp_get_str
#define mpz_set_str     ssh_mp_set_str
#define mpz_out_str     ssh_mp_out_str

/* Checking a value to see if it is a probable prime. */
#define mpz_probab_prime_p ssh_mp_is_probable_prime

/* Scan functions which are slow, but should be compatible. */
#define mpz_scan0       ssh_mp_scan0
#define mpz_scan1       ssh_mp_scan1

#endif /* SSHGMP_H */
