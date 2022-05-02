/*

  ecpmath.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sun Nov 10 16:11:45 1996 [mkojo]

  The basis of an implement for elliptic curve cryptosystem. This
  is basically over F_p, where p is prime.

  Curve is of form

    y^2 = x^3 + ax + b (mod p)

  Functions here implemented allow very fast multiplication (or
  exponentiation which ever suits your imagination), and thus is suitable
  for cryptography. 
    
  */

/*
 * $Id: ecpmath.h,v 1.3 1998/06/10 08:37:38 tmo Exp $
 * $Log: ecpmath.h,v $
 * $EndLog$
 */

#ifndef ECPMATH_H
#define ECPMATH_H

/* Definitions of arithmetic elements for elliptic curve cryptosystems. */

/* Elliptic curve affine point. */

typedef struct
{
  /* If z = 0 then point at infinity. */
  SshInt x, y;
  int z;
} SshECPPoint;

/* Elliptic curve (of form y^2 = x^3 + ax + b). */

typedef struct
{
  /* Field modulus. */
  SshInt q;
  /* Defining constants. */
  SshInt a, b;
  /* Cardinality, useful in verification and possibly when generating
     new prime order points. */
  SshInt c;
} SshECPCurve;

/* Prototypes of public functions. */

/* Auxliary curve handling functions. */

/* Initialize a curve structure. Initialized the curve with invalid
   values. */
void ssh_ecp_init_curve(SshECPCurve *E);

/* Set curve to some specific values. Values given should be correct in
   that

      q     is the field modulus (a prime number)
      a, b  define an elliptic curve x^3 + ax + b = y^2
            (this is trivial, because it happens always, but the following
	     restriction is real).
      c     is the cardinality of the curve that is curve has this
            many distinct points (x, y).
	    We give one trivial algorithm for computing the number of
	    points in ecpaux.c, see for future reference. 
   */
void ssh_ecp_set_curve(SshECPCurve *E, const SshInt *q, const SshInt *a,
		       const SshInt *b, const SshInt *c);

/* Clean memory used by the curve. */
void ssh_ecp_clear_curve(SshECPCurve *E);

/* Compare two curves, this returns TRUE if equal, FALSE if not. */
Boolean ssh_ecp_compare_curves(SshECPCurve *E0, SshECPCurve *E1);

/* Copy curve E_src to E_dest. */
void ssh_ecp_copy_curve(SshECPCurve *E_dest, const SshECPCurve *E_src);

/* Auxliary functions for points. */

/* Init a point with a point at infinity. */
void ssh_ecp_init_point(SshECPPoint *P, const SshECPCurve *E);

/* Clear point (i.e. delete memory allocated by point). */
void ssh_ecp_clear_point(SshECPPoint *P);

/* Set to identity (i.e. z = 0). */
void ssh_ecp_set_identity(SshECPPoint *P);

/* Set point to selected values. x and y must satisfy the relation
   x^3 + ax + b = y^2. Also z must be 1 if point at infinity is not
   desired. */
void ssh_ecp_set_point(SshECPPoint *P, const SshInt *x, const SshInt *y,
		       int z);

/* Copy P to Q. */
void ssh_ecp_copy_point(SshECPPoint *Q, const SshECPPoint *P);

/* Negate a point  (i.e. Q = -P). */
void ssh_ecp_negate_point(SshECPPoint *Q,
			  const SshECPPoint *P, const SshECPCurve *E);

/* Compare Q and P, returns TRUE if equal and FALSE if not. */
Boolean ssh_ecp_compare_points(const SshECPPoint *P, const SshECPPoint *Q);

/* Add two points together using affine coordinates, this is not fast
   although in occasional use there is no faster. */
void ssh_ecp_add(SshECPPoint *R, const SshECPPoint *Q, const SshECPPoint *P,
		 const SshECPCurve *E);

/* Compute multiple k of P. Generic version in that this will handle
   every value k can have nicely. (If not contact author ;) */
void ssh_ecp_generic_mul(SshECPPoint *R, const SshECPPoint *P,
			 const SshInt *k,
			 const SshECPCurve *E);

/* Compute multiple k of P, where P has prime order and 0 <= k < #P.
   If the order of P is not know use the ssh_ecp_generic_mul instead.
   This works faster due few small optimizations. However, at greater
   risk of failing (is guaranteed to fail if k >= #P, however if used
   properly this should give only the utmost speed). */
void ssh_ecp_mul(SshECPPoint *R, const SshECPPoint *P, const SshInt *k,
		 const SshECPCurve *E);

/* Compute y = sqrt(x^3 + ax + b) mod q. Where a, b and q define the curve
   and field and x is the x-coordinate of a valid point on the elliptic
   curve. */
Boolean ssh_ecp_compute_y_from_x(SshInt *y, const SshInt *x,
				 const SshECPCurve *E);

/* Function to reconstruct a point P which contains only x coordinate.
   'bit' denotes the least significant bit of y coordinate. Puts
   reconstructed y to P, if succeeds and returns TRUE, otherwise
   returns FALSE. (Reconstruction takes few moments so it isn't suggested
   to use point compression if speed is neccessary.) */ 

Boolean ssh_ecp_restore_y(SshECPPoint *P, const SshECPCurve *E,
			  Boolean bit);

/* Generate a random elliptic curve point. */

void ssh_ecp_random_point(SshECPPoint *P, const SshECPCurve *E);

/* In point generation it is assumed that the elliptic curve point
   counting has been performed. */

/* Generate a random elliptic curve point of prime order. These points are
   valuable for all cryptosystems. */

Boolean ssh_ecp_random_point_of_prime_order(SshECPPoint *P, const SshInt *n,
					    const SshECPCurve *E);

/* The first point, in the sense that the components are as small as
   possible, of the given order. */
Boolean ssh_ecp_first_point_of_order(SshECPPoint *P, const SshInt *n,
				     const SshECPCurve *E);

/* Check whether a given curve is supersingular. */

Boolean ssh_ecp_is_supersingular(const SshECPCurve *E);

/* Compute the count of elliptic curve points exhaustively, i.e. in
   time exponential. There exists polynomial time algorithm due to R. Schoof
   (with enhancements by many). */

void ssh_ecp_brute_point_count(SshECPCurve *E);

/* Verify quickly that given parameters are correct (within reasonable
   assumptions). Returns TRUE if all tests passed and FALSE otherwise.

   XXX Should this be moved to cryptolibrary.
   XXX Should this use SshRandomState, i.e. SSH random number generator?
   */
Boolean ssh_ecp_verify_param(const SshECPCurve *E,
			     const SshECPPoint *P,
			     const SshInt      *n);


unsigned int ssh_mp_transform_mo(const SshInt *k, char **transform_table);
unsigned int ssh_mp_transform_binary(const SshInt *k, char **transform_table);
unsigned int ssh_mp_transform_kmov(const SshInt *k, char **transform_table);

#endif /* ECPMATH_H */
