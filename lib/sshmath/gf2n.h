/*

  gf2n.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Fri Jan  2 23:53:19 1998 [mkojo]

  This file includes efficient GF(2^n) routines, and some reasonably
  efficient binary polynomial routines and also polynomials over
  GF(2^n).

  These routines have been optimized to work in 32-bit processors.
  However, these are general purpose and should perform well under
  almost all circumstances. 

  TODO:

    clean this code a lot, figure what needs to be done to make it
    work correctly. Optimize if necessary, some changes have been made
    that might affect the speed.

    Write test programs.

    Write a lot of commentation here.
    
  
  */

/*
 * $Id: gf2n.h,v 1.8 1998/06/24 13:25:52 kivinen Exp $
 * $Log: gf2n.h,v $
 * $EndLog$
 */

#ifndef GF2N_H
#define GF2N_H

#include "sshmath-types.h"

/******************** GF(2^n) code **************************/

/* This set of functions implements a fast way of doing arithmetic in
   Galois fields GF(2^n). Following restrictions are needed to make
   the arithmetic especially fast:

     - the distance between most significant bit in modulus and
       next significant bit must be more than the word length
       used (SSH_WORD_SIZE).

   Below we give also routines for handling the general set of
   binary polynomials.
   */

/* Gf(2^n) routines */
typedef struct
{
  /* Number of bits. */
  int bits;
  /* Bits given in some nice order. */
  /* Words. */
  int *w, *wn;
  /* Bits. */
  int *b, *bn;
  /* In straight order as computed. */
  int *n, *nn;

  /* Working space. */
  /* Maximum size in limbs. */
  int allocated;
  /* The actual allocated working space that is about 6 * allocated. */
  SshWord *work;
} SshGF2nModuli;

typedef struct
{
  /* The number of used limbs. */
  int n;
  /* The limbs. */
  SshWord *v;
  /* The moduli associated with this element. */
  const SshGF2nModuli *m;
} SshGF2nElement;

/* Functions. */

/* Initialize the modulus. We present here several ways to do it. Most
   of them are useful. */
int ssh_gf2n_init_mod_ui(SshGF2nModuli *m, unsigned int u);
/* The buffer must be in least significant word first order. */
int ssh_gf2n_init_mod_raw(SshGF2nModuli *m, const SshWord *buf, int buf_len);
/* The bits must be sorted into least significant bit first order. */
int ssh_gf2n_init_mod_bits(SshGF2nModuli *m, const int *bits, int bits_count);
/* The basic integer type. */
int ssh_gf2n_init_mod_mp(SshGF2nModuli *m, const SshInt *mp);
/* Initialization by another moduli. */
int ssh_gf2n_init_mod_mod(SshGF2nModuli *m, const SshGF2nModuli *mm);

/* Clear the initialized moduli. */
void ssh_gf2n_clear_mod(SshGF2nModuli *m);

/* Initialize an element, you need to have initialized moduli available. */
void ssh_gf2n_init(SshGF2nElement *e, const SshGF2nModuli *m);
/* Inheric the moduli from another element. Occasionally useful. */
void ssh_gf2n_init_inherit(SshGF2nElement *e, const SshGF2nElement *b);

/* Clear the element. */
void ssh_gf2n_clear(SshGF2nElement *e);

/* Degree computation. For consistency, we will also here give the
   degree one off the real degree. E.g. these functions return t, such
   that 2^t > input and 2^{t - 1} <= input. */
/* Compute the degree of the element. */ 
int ssh_gf2n_deg(const SshGF2nElement *e);
/* Compute the degree of the moduli. */
int ssh_gf2n_deg_mod(const SshGF2nModuli *m);
/* Inherit the moduli and compute it's degree. */
int ssh_gf2n_deg_mod_inherit(const SshGF2nElement *e);

/* Compare element and unsigned integer. Returns 0 if equal, 1 if
   element is larger and -1 if element is smaller. */
int ssh_gf2n_cmp_ui(const SshGF2nElement *e, unsigned int u);
/* Compare two elements. */
int ssh_gf2n_cmp(const SshGF2nElement *a, const SshGF2nElement *b);
/* Compare two moduli. */
int ssh_gf2n_cmp_mod(const SshGF2nModuli *a, const SshGF2nModuli *b);

/* Set an unsigned integer to element. */
void ssh_gf2n_set_ui(SshGF2nElement *e, unsigned int u);
/* Get unsigned integer (the least significant bits) of the element. */
unsigned int ssh_gf2n_get_ui(SshGF2nElement *e);
/* Set another element to ret. */
void ssh_gf2n_set(SshGF2nElement *ret, const SshGF2nElement *e);

/* The basic buffer routines. */
void ssh_gf2n_get_buf(unsigned char *buf, size_t buf_length,
		      const SshGF2nElement *op);
void ssh_gf2n_set_buf(SshGF2nElement *ret, const unsigned char *buf,
		      size_t buf_length);

/* Basic arithmetics */

/* Compute: ret = a*b (mod moduli). */
void ssh_gf2n_mul(SshGF2nElement *ret, const SshGF2nElement *a,
		  const SshGF2nElement *b);
/* Add u to a. That is, ret = a + u. */
void ssh_gf2n_add_ui(SshGF2nElement *ret, const SshGF2nElement *a,
		     unsigned int u);
/* Compute: ret = a + b */
void ssh_gf2n_add(SshGF2nElement *ret, const SshGF2nElement *a,
		  const SshGF2nElement *b);
/* Compute: inv = b^-1 (mod moduli). */
void ssh_gf2n_invert(SshGF2nElement *inv, const SshGF2nElement *b);
/* Compute: ret = a^2 (mod moduli). */
void ssh_gf2n_square(SshGF2nElement *ret, const SshGF2nElement *a);

/* Random values, which are reasonably good, but not cryptographically
   usable. */
void ssh_gf2n_poor_rand(SshGF2nElement *ret);

/* Compute: a = b^(2^e) (mod moduli). */
void ssh_gf2n_exp_2exp(SshGF2nElement *a,
		       const SshGF2nElement *b, unsigned int e);

/* Compute the trace of a. trace = Tr(a). */
void ssh_gf2n_trace(SshGF2nElement *trace, const SshGF2nElement *a);
/* Compute the half-trace of a. trace = Half-Tr(a). */
void ssh_gf2n_half_trace(SshGF2nElement *trace, const SshGF2nElement *a);
/* Solve the equation z^2 + z = b, for z. */
Boolean ssh_gf2n_quad_solve(SshGF2nElement *z, const SshGF2nElement *b);

/* Conversion routines. */

/* Convert a moduli to an integer. */
void ssh_mp_set_gf2n_mod(SshInt *mp, const SshGF2nModuli *m);
/* Convert an integer to an element. */
void ssh_gf2n_set_mp(SshGF2nElement *e, const SshInt *mp);
/* Convert an element to an integer. */
void ssh_mp_set_gf2n(SshInt *mp, const SshGF2nElement *e);

/* XXX Some dumper routines. To be excluded... */
void ssh_gf2n_hex_dump(const SshGF2nElement *e);
void ssh_gf2n_pretty_print(const SshGF2nElement *e);
void ssh_gf2n_mod_pretty_print(const SshGF2nModuli *m);

/***************** Binary Polynomial code ***********************/

/* Following code is the binary polynomial arithmetic routines. This
   code is slower than the above one in GF(2^n) computations, although
   can emulate the operations fully. */

/* Notice that these routines do not have the restrictions that the
   above routines have. These are also much more flexible. However,
   you cannot have such a speed with these are those above give you. */

/* The main data structure here. */
typedef struct
{
  /* Number of words allocated. */
  int m;
  /* Number of words used. */
  int n;
  /* The words containing binary polynomial. */
  SshWord *v;
} SshBPoly;

/* Initialization of a binary polynomial. */
void ssh_bpoly_init(SshBPoly *e);
/* Frees the contents of a binary polynomial. */
void ssh_bpoly_clear(SshBPoly *e);

/* Set the contents of the binary polynomial to zero. */
void ssh_bpoly_set_zero(SshBPoly *e);

/* Compare binary polynomial and unsigned int. */
int ssh_bpoly_cmp_ui(const SshBPoly *e, unsigned int u);
/* Compare two binary polynomials. */
int ssh_bpoly_cmp(const SshBPoly *e, const SshBPoly *h);

/* Set src to dest. */
void ssh_bpoly_set(SshBPoly *dest, const SshBPoly *src);
/* Set u to ret. */
void ssh_bpoly_set_ui(SshBPoly *ret, unsigned int u);

/* Get least significant bits of the input op. */
unsigned int ssh_bpoly_get_ui(const SshBPoly *op);

/* Set u to ret. */
void ssh_bpoly_set_word(SshBPoly *ret, SshWord u);

/* Get least significant bits of the input op. */
SshWord ssh_bpoly_get_word(const SshBPoly *op);

/* The basic buffer routines. */
void ssh_bpoly_get_buf(unsigned char *buf, size_t buf_length,
		       const SshBPoly *op);
void ssh_bpoly_set_buf(SshBPoly *ret, const unsigned char *buf,
		       size_t buf_length);

/* Shift e up by m bits. */
void ssh_bpoly_mul_2exp(SshBPoly *ret, const SshBPoly *e, unsigned int m);
/* Shift e down by m bits, m least significant bits are lost. */
void ssh_bpoly_div_2exp(SshBPoly *ret, const SshBPoly *e, unsigned int m);

/* NOTE: deg function returns 0 only for zero polynomials, and the
   degree actually is thus ssh_bpoly_deg(x) - 1. This may change
   in future to comply with the gf2n version. */

/* Compute the degree of the binary polynomial. */
unsigned int ssh_bpoly_deg(const SshBPoly *ret);

/* Get the bit at position m of ret. */
unsigned int ssh_bpoly_get_bit(const SshBPoly *ret, unsigned int m);
/* Set a bit into position x^m to ret. */
void ssh_bpoly_set_bit(SshBPoly *ret, unsigned int m);

/* Compute: ret = a + u */
void ssh_bpoly_add_ui(SshBPoly *ret, const SshBPoly *a, unsigned int u);
/* Compute: ret = a + b */
void ssh_bpoly_add(SshBPoly *ret, const SshBPoly *a, const SshBPoly *b);

/* Generate a random binary polynomial modulo q. */
void ssh_bpoly_poor_rand(SshBPoly *ret, const SshBPoly *q);

/* Multiplication: ret = a * b */
void ssh_bpoly_mul(SshBPoly *ret, const SshBPoly *a, const SshBPoly *b);
/* Compute: ret = a^2 */
void ssh_bpoly_square(SshBPoly *ret, const SshBPoly *a);
/* Compute: a = b*q + r */
void ssh_bpoly_div(SshBPoly *q, SshBPoly *r,
		   const SshBPoly *a, const SshBPoly *b);
/* Compute: r = a (mod b) */
void ssh_bpoly_mod(SshBPoly *r,
		   const SshBPoly *a, const SshBPoly *b);

/* Computation gcd and extended gcd. */
/* Compute: gcd = gcd(a, b) */
void ssh_bpoly_gcd(SshBPoly *gcd, const SshBPoly *a, const SshBPoly *b);
/* Compute: gcd = sx*gx + t*hx XXX */
void ssh_bpoly_gcdext(SshBPoly *gcd, SshBPoly *sx,
		      const SshBPoly *gx, const SshBPoly *hx);

/* Inversion: inv = a^-1 (mod b). Doesn't use extended euclidean
   algorithm. Instead uses faster binary based method. */
int ssh_bpoly_invert(SshBPoly *inv, const SshBPoly *a, const SshBPoly *b);

/* Trace e.g. trace = Tr(a). */
void ssh_bpoly_trace(SshBPoly *trace, const SshBPoly *a, const SshBPoly *b);
/* Half-trace. trace = Half-Tr(a). */
void ssh_bpoly_half_trace(SshBPoly *trace, const SshBPoly *a,
			  const SshBPoly *b);
/* Relative trace. */
void ssh_bpoly_relative_trace(SshBPoly *trace, const SshBPoly *a,
			      unsigned int exp, const SshBPoly *b);

/* Some powering modulo a irreducible (or not) polynomial. */
void ssh_bpoly_powm_2exp(SshBPoly *a, const SshBPoly *b,
			 unsigned int e, const SshBPoly *m);
void ssh_bpoly_powm(SshBPoly *a, const SshBPoly *b,
		    const SshInt *e, const SshBPoly *m);

/* Find a solution to z^2 + z = b, solving for z. */
Boolean ssh_bpoly_quad_solve(SshBPoly *z, const SshBPoly *b,
			     const SshBPoly *m);

/* Check for irreducibility. This function checks whether op is
   "polynomial prime" e.g. irreducible polynomial. If it is then
   there does not exists any other polynomial (mod 2) that divides
   it (except 1 and the polynomial op itself). */
Boolean ssh_bpoly_is_irreducible(const SshBPoly *op);

/* Find a small irreducible polynomial (mod 2). It will return
   the first small irreducible of the given size. */
unsigned int ssh_bpoly_find_small_irreducible(unsigned int size);

/* Find a irreducible polynomial of fixed number of terms. The
   bits contains the bits outputed. If first is set, then the
   searching will happen from smallest to largest irreducible. If
   first is not set, then the searching happens in any suitable order.

   One should be careful to use either first = 1, or set bits into
   some meaningful values. Also note, the bits are assume to be
   in rising order! The least significant bit in bits[0] and most
   significant in bits[bits_count - 1]. The bits[0] should be set
   to 0, otherwise there is no chance of finding irreducibles, of
   course. */
int ssh_bpoly_find_irreducible(unsigned int size, unsigned int first,
			       int *bits, unsigned int bits_count);

/* Check whether op is a primitive element. */
Boolean ssh_bpoly_is_primitive(const SshBPoly *op, const SshBPoly *m);

/* Some dumber routines :) */
void ssh_bpoly_hex_dump(const SshBPoly *e);
void ssh_bpoly_pretty_print(const SshBPoly *e);

/* Some conversion routines. Fix them use SshInt instead! */
void ssh_bpoly_set_mp(SshBPoly *ret, const SshInt *a);
void ssh_mp_set_bpoly(SshInt *ret, const SshBPoly *b);

void ssh_bpoly_set_gf2n(SshBPoly *ret, const SshGF2nElement *e); 
void ssh_bpoly_set_gf2n_mod(SshBPoly *ret, const SshGF2nModuli *m); 

void ssh_gf2n_set_bpoly(SshGF2nElement *e, const SshBPoly *b);
void ssh_gf2n_mod_set_bpoly(SshGF2nModuli *m, const SshBPoly *b);

/* XXX This initialization is out of place. */
int ssh_gf2n_init_mod_bpoly(SshGF2nModuli *m, const SshBPoly *b);

/**********************************************************************/

/* Polynomials over GF(2^n). These have not been tested much. Straight
   derivation from my older polynomial routines. Misses Karatsuba
   routines... Also one should implement the fast cases with my
   trinomial routines.

   These can be used in general, but have most use with elliptic curve
   code. E.g. Weil theorem and Schoof's algorithm. 

   TODO:

     Write general multiple unknown polynomial routines which allows
     usage of characteristic 2, 3, or > 3.

     This code needs optimization, and also one should write the
     faster multiplication and division?!
     
   */

typedef struct
{
  unsigned int m;
  unsigned int n;
  const SshGF2nModuli *moduli;
  SshGF2nElement *c;
} SshGF2nPoly;

/* for setall and getall routines. (Format pos value) */
#define SSH_GF2N_POLY_UI     1
#define SSH_GF2N_POLY_GF2N   2
#define SSH_GF2N_POLY_BPOLY  3
#define SSH_GF2N_POLY_MP     4
#define SSH_GF2N_POLY_END    100

/* We don't use much comments. Everything you need to know is in some other
   file. Sorry. */
void ssh_gf2n_poly_init(SshGF2nPoly *p, const SshGF2nModuli *m);
void ssh_gf2n_poly_clear(SshGF2nPoly *p);

void ssh_gf2n_poly_set_zero(SshGF2nPoly *a);
int ssh_gf2n_poly_is_zero(const SshGF2nPoly *a);
void ssh_gf2n_poly_set(SshGF2nPoly *a, const SshGF2nPoly *b);

void ssh_gf2n_poly_setall(SshGF2nPoly *a, ...);
void ssh_gf2n_poly_getall(const SshGF2nPoly *a, ...);

void ssh_gf2n_poly_print(const SshGF2nPoly *p);
void ssh_gf2n_poly_evaluate(SshGF2nElement *ret, const SshGF2nPoly *f,
			    const SshGF2nElement *v);

/* Some basic operations that should be use for testing. */

unsigned int ssh_gf2n_poly_deg(const SshGF2nPoly *a);

void ssh_gf2n_poly_add(SshGF2nPoly *a, const SshGF2nPoly *b);
void ssh_gf2n_poly_sub(SshGF2nPoly *a, const SshGF2nPoly *b);

/* Compare two polynomials. */
int ssh_gf2n_poly_cmp(const SshGF2nPoly *a, const SshGF2nPoly *b);

/* Multiplication by x^exp. That is, shifting up the coefficients. */
void ssh_gf2n_poly_mulx(SshGF2nPoly *ret, unsigned int exp);
/* Division by x^exp. That is, shifting down the coefficients. */
void ssh_gf2n_poly_divx(SshGF2nPoly *ret, unsigned int exp);

/* Plain multiplication, should only be used to test other multiplication
   routines. */
void ssh_gf2n_poly_mul_plain(SshGF2nPoly *ret, const SshGF2nPoly *a,
			     const SshGF2nPoly *b);
void ssh_gf2n_poly_square_plain(SshGF2nPoly *ret, const SshGF2nPoly *a);
void ssh_gf2n_poly_div_plain(SshGF2nPoly *q, SshGF2nPoly *r,
			     const SshGF2nPoly *a, const SshGF2nPoly *b);
void ssh_gf2n_poly_mod_plain(SshGF2nPoly *r, const SshGF2nPoly *a,
			     const SshGF2nPoly *b);
void ssh_gf2n_poly_powm_plain(SshGF2nPoly *r, const SshGF2nPoly *g,
			      const SshInt *e,
			      const SshGF2nPoly *p);

#define ssh_gf2n_poly_mul     ssh_gf2n_poly_mul_plain
#define ssh_gf2n_poly_square  ssh_gf2n_poly_square_plain
#define ssh_gf2n_poly_div     ssh_gf2n_poly_div_plain
#define ssh_gf2n_poly_mod     ssh_gf2n_poly_mod_plain
#define ssh_gf2n_poly_powm    ssh_gf2n_poly_powm_plain

int ssh_gf2n_poly_weight(const SshGF2nPoly *a);
void ssh_gf2n_poly_monic(SshGF2nPoly *a);

void ssh_gf2n_poly_gcd(SshGF2nPoly *gcd, const SshGF2nPoly *p,
		       const SshGF2nPoly *q);
void ssh_gf2n_poly_gcdext(SshGF2nPoly *g, SshGF2nPoly *s,
			  SshGF2nPoly *t,
			  const SshGF2nPoly *a, const SshGF2nPoly *b);
int ssh_gf2n_poly_invert(SshGF2nPoly *inv, const SshGF2nPoly *p0,
			 const SshGF2nPoly *m);

int ssh_gf2n_poly_is_irreducible(const SshGF2nPoly *f);
int ssh_gf2n_poly_roots(SshGF2nPoly *ret, const SshGF2nPoly *f);
void ssh_gf2n_poly_factor(SshGF2nPoly *ret, const SshGF2nPoly *f,
			  int degree);
void ssh_gf2n_poly_random_root(SshGF2nElement *ret,
			       const SshGF2nPoly *f);
void ssh_gf2n_poly_random(SshGF2nPoly *f, unsigned int deg);
void ssh_gf2n_poly_find_irreducible(SshGF2nPoly *f, unsigned int deg);

#endif /* GF2N_H */
