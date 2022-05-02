/*

  ec2nmath.h
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov 29 06:07:00 1997 [mkojo]

  Elliptic curve over GF(2^n) arithmetics.

  This implementation does not support normal basis elliptic curves, you
  have to have conversion. Normal basis arithmetic might be implemented
  later.
  
  */

/*
 * $Id: ec2nmath.h,v 1.4 1998/06/24 13:25:29 kivinen Exp $
 * $Log: ec2nmath.h,v $
 * $EndLog$
 */

#ifndef EC2NMATH_H
#define EC2NMATH_H

/* Definitions for GF(2^n) points and curves. */

typedef struct
{
  SshGF2nElement x, y;
  int z;
} SshEC2nPoint;

typedef struct
{
  /* Information about the elliptic curve (extended). */
  SshGF2nElement a, b;
  SshGF2nModuli q;
  SshInt c;

  /* ABC curve r^m - 1. */
  SshInt u_m, u_m1;
  
  /* The definition elliptic curve, if available. */
  int f_c;
  unsigned int f_q, f_k, f_n, f_a, f_b;
} SshEC2nCurve;

/* Basic operations with points and curves. */

/* NOTE: due the different nature of our basic arithmetic and a different
   style of implementation, some of the interfaces are a bit different to
   the case of ECP. However, mostly operation is similar and
   equivalent at this level. */

/* The basic elliptic curve operations. */

/* Initialize and set up an elliptic curve with SshInt's. You should
   use some other interface to set up the Frobenius (or ABC) values.

   Return 1 if success, and 0 if failed. It might very well, be that the
   routine fails given reasonably varying (somewhat random) input. Thus
   you should usually check the return value. 
   */
int ssh_ec2n_set_curve_mp(SshEC2nCurve *E, const SshInt *q, const SshInt *a,
			  const SshInt  *b, const SshInt *c);

/* XXX not yet implemented. The values not included are computed
   on-the-fly. */
int ssh_ec2n_set_curve_mp_frobenius(SshEC2nCurve *E,
				    const SshInt *q, const SshInt *a,
				    const SshInt *b, 
				    int f_c,
				    unsigned int f_q,
				    unsigned int f_a,
				    unsigned int f_b);

/* Clear an elliptic curve. */
void ssh_ec2n_clear_curve(SshEC2nCurve *E);

/* Compare two curve parameters. */
Boolean ssh_ec2n_compare_curves(const SshEC2nCurve *E0,
				const SshEC2nCurve *E1);

/* Copy curve parameters. */
void ssh_ec2n_copy_curve(SshEC2nCurve *E_dest,
			 const SshEC2nCurve *E_src);

/* Elliptic curve point operations. */

/* Initialize a point. Notice that here we need the elliptic curve. */
void ssh_ec2n_init_point(SshEC2nPoint *P, const SshEC2nCurve *E);

/* Clear (and delete allocated space) of an elliptic curve point. */
void ssh_ec2n_clear_point(SshEC2nPoint *P);

/* Set point to (0:1:0) e.g. point at infinity. */
void ssh_ec2n_set_identity(SshEC2nPoint *P);

/* Set point to some selected MP_INT values. No verifications are made
   to verify that it indeed is a point. */
void ssh_ec2n_set_point_mp(SshEC2nPoint *P,
			   const SshInt *x, const SshInt *y,
			   int z);

/* Copy an elliptic curve point. */
void ssh_ec2n_copy_point(SshEC2nPoint *Q, const SshEC2nPoint *P);

/* Make the point negative (e.g. invert a point). Doesn't actually need
   the curve! */
void ssh_ec2n_negate_point(SshEC2nPoint *Q, const SshEC2nPoint *P,
			   const SshEC2nCurve *E);

/* Compare two points. */
Boolean ssh_ec2n_compare_points(const SshEC2nPoint *P,
				const SshEC2nPoint *Q);

/* General addittion of two points. */
void ssh_ec2n_add(SshEC2nPoint *R, const SshEC2nPoint *Q,
		  const SshEC2nPoint *P, const SshEC2nCurve *E);

/* General multiplication of an elliptic curve point and a scalar
   k. This function will work with all values of k. */
void ssh_ec2n_generic_mul(SshEC2nPoint *R, const SshEC2nPoint *P,
			  const SshInt *k,
			  const SshEC2nCurve *E);

/* Multiplication of an elliptic curve point with a scalar k. The scalar
   must be less than #P = prime. */
void ssh_ec2n_mul(SshEC2nPoint *R, const SshEC2nPoint *P,
		  const SshInt *k,
		  const SshEC2nCurve *E);

/* Restore the y component of the point from the x component and the
   elliptic curve. */
Boolean ssh_ec2n_restore_y(SshEC2nPoint *P, const SshEC2nCurve *E,
			   int bit);

/* Generate a random point P. */
void ssh_ec2n_random_point(SshEC2nPoint *P, const SshEC2nCurve *E);

/* In point generation it is assumed that the elliptic curve point
   counting has been performed. */

/* Generate a random point P of prime order. */
Boolean ssh_ec2n_random_point_of_prime_order(SshEC2nPoint *P, const SshInt *n,
					     const SshEC2nCurve *E);

/* The first point, in the sense that the components are as small as
   possible, of the given order. This operation might take
   some time. */
Boolean ssh_ec2n_first_point_of_order(SshEC2nPoint *P, const SshInt *n,
				      const SshEC2nCurve *E);

/* Check if curve is bad. Not necessary supersingular. Change the
   name later. XXX Write this? */
Boolean ssh_ec2n_is_supersingular(const SshEC2nCurve *E);

/* Generate a Frobenius curve in random. This function generate the
   curve with Weil theorem, and results in curves which are closely
   related (actually extensions of) the Koblitz curves.

   The given curve E will be initialized if and only if the function
   is successful. In case of success the function returns 1.

   Notice, that you must be quite knowledgeable with the selection of the
   size parameter. If the size is too large or too small the
   operation will fail. Also, some particular cases are not good.
   The function will deduce reasonably good way of interpreting the
   size and if possible then generates the curve.

   After calling this function, you should check if you can factor
   the point count and if you can, then generate a point of the
   order of the largest factor.

   There are some security implications with these curves that might
   make the Koblitz, and Frobenius, curves weaker than the more
   ordinary curves. However, there does not exist publicly known
   attacks that are significantly faster for these curves. */
int ssh_ec2n_generate_frobenius_curve(SshEC2nCurve *E,
				      unsigned int size);


/* XXX We don't give here a brute force point counting method, because
   the implementation is not suitable for such an approach. However,
   we give below (XXX write it) some code for the same task with
   slightly different interface. */

/* Verification of the parameters.
   XXX Should this be moved to cryptolibrary? */
Boolean ssh_ec2n_verify_param(const SshEC2nCurve *E,
			      const SshEC2nPoint *P,
			      const SshInt       *n);
#endif /* EC2NMATH_H */

