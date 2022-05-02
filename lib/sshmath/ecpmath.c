/*

  ecpmath.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sun Nov 10 16:11:59 1996 [mkojo]

  Implementation of basic arithmetic on elliptic curves over Fp. These
  routines are suitable for use in cryptosystems.

  NEW VERSION!

  TODO:

    convert to modular representation as much as possible!

    Test that these routines are faster than the previous ones, no sense
    using these if slower :(
    
  */

/*
 * $Id: ecpmath.c,v 1.5 1998/06/11 19:35:25 mkojo Exp $
 * $Log: ecpmath.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmath-types.h"
#include "sshmp.h"
#include "ecpmath.h"

/* Elliptic curve arithmetics. */

/* Auxliary functions for elliptic curve definition. */

/* Initialize curve */
void ssh_ecp_init_curve(SshECPCurve *E)
{
  ssh_mp_init_set_ui(&E->q, 0);
  ssh_mp_init_set_ui(&E->a, 0);
  ssh_mp_init_set_ui(&E->b, 0);
  ssh_mp_init_set_ui(&E->c, 0);
}

/* Set curve. */
void ssh_ecp_set_curve(SshECPCurve *E,
		       const SshInt *q, const SshInt *a, const SshInt *b,
		       const SshInt *c)
{
  ssh_mp_init_set(&E->q, q);
  ssh_mp_init_set(&E->a, a);
  ssh_mp_init_set(&E->b, b);
  ssh_mp_init_set(&E->c, c);
} 

/* Clean up the elliptic curve from memory. */
void ssh_ecp_clear_curve(SshECPCurve *E)
{
  ssh_mp_clear(&E->q);
  ssh_mp_clear(&E->a);
  ssh_mp_clear(&E->b);
  ssh_mp_clear(&E->c);
}

/* Copy curve. */
void ssh_ecp_copy_curve(SshECPCurve *E_dest, const SshECPCurve *E_src)
{
  ssh_mp_set(&E_dest->q, &E_src->q);
  ssh_mp_set(&E_dest->a, &E_src->a);
  ssh_mp_set(&E_dest->b, &E_src->b);
  ssh_mp_set(&E_dest->c, &E_src->c);  
}

Boolean ssh_ecp_compare_curves(SshECPCurve *E0, SshECPCurve *E1)
{
  if (ssh_mp_cmp(&E0->a, &E1->a) != 0 ||
      ssh_mp_cmp(&E0->b, &E1->b) != 0 ||
      ssh_mp_cmp(&E0->c, &E1->c) != 0 ||
      ssh_mp_cmp(&E0->q, &E1->q) != 0)
    return FALSE;
  return TRUE;
}

/* Affine case. */

/* Auxliary functions for points */

/* Initialize affine point to point at infinity. The elliptic curve
   is included for compatibility towards future enhancements. */
void ssh_ecp_init_point(SshECPPoint *P, const SshECPCurve *E)
{
  ssh_mp_init_set_ui(&P->x, 0);
  ssh_mp_init_set_ui(&P->y, 0);
  P->z = 0;
}

/* Delete affine points context. */
void ssh_ecp_clear_point(SshECPPoint *P)
{
  ssh_mp_clear(&P->x);
  ssh_mp_clear(&P->y);
  P->z = 0;
}

/* Set affine point to point at infinity (the identity element). */
void ssh_ecp_set_identity(SshECPPoint *P)
{
  ssh_mp_set_ui(&P->x, 1);
  ssh_mp_set_ui(&P->y, 1);
  P->z = 0;
}

/* Set affine point to MP integer values. */
void ssh_ecp_set_point(SshECPPoint *P, const SshInt *x, const SshInt *y,
		       int z)
{
  ssh_mp_set(&P->x, x);
  ssh_mp_set(&P->y, y);

  P->z = (z != 0) ? 1 : 0;
}

/* Copy affine point to another affine point */
void ssh_ecp_copy_point(SshECPPoint *Q, const SshECPPoint *P)
{
  ssh_mp_set(&Q->x, &P->x);
  ssh_mp_set(&Q->y, &P->y);
  Q->z = P->z;
}

/* Negate affine point (probably for subtraction). */
void ssh_ecp_negate_point(SshECPPoint *Q, const SshECPPoint *P,
			  const SshECPCurve *E)
{
  ssh_mp_set(&Q->x, &P->x);
  ssh_mp_sub(&Q->y, &E->q, &P->y);
  Q->z = P->z;
}

/* Compare Q to P for equality. */
Boolean ssh_ecp_compare_points(const SshECPPoint *P, const SshECPPoint *Q)
{
  if (P->z != Q->z)
    return FALSE;
  if (P->z == 0 && Q->z == 0)
    return TRUE;

  if (ssh_mp_cmp(&P->x, &Q->x) != 0)
    return FALSE;
  if (ssh_mp_cmp(&P->y, &Q->y) != 0)
    return FALSE;

  return TRUE;
}     

/* Add affine points. Full addition (for general use). */
void ssh_ecp_add(SshECPPoint *R, const SshECPPoint *Q, const SshECPPoint *P,
		 const SshECPCurve *E)
{
  SshInt lambda, t1, t2, t3, rx;

  /* Identity checks. */
  if (P->z == 0)
    {
      ssh_ecp_copy_point(R, Q);
      return;
    }
  if (Q->z == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }
  
  if (ssh_mp_cmp(&P->x, &Q->x) == 0)
    {
      /* If P = -Q then set R = "point at infinity". */
      if (ssh_mp_cmp(&P->y, &Q->y) != 0 || ssh_mp_cmp_ui(&P->y, 0) == 0)
	{
	  /* Must be thus that P = -Q. */
	  ssh_ecp_set_identity(R);
	  return;
	}

      /* Doubling a point. */
      
      /* Initialize temporary variables */
      ssh_mp_init(&lambda);
      ssh_mp_init(&t1);
      ssh_mp_init(&t2);
      ssh_mp_init(&t3);
      ssh_mp_init(&rx);

      /* Calculate the lambda = (3x1^2 + a)/2y1 */
      ssh_mp_mul(&t1, &P->x, &P->x);
      ssh_mp_mul_ui(&t1, &t1, 3);
      ssh_mp_add(&t1, &t1, &E->a);
      ssh_mp_mod(&t1, &t1, &E->q);
      ssh_mp_mul_2exp(&t2, &P->y, 1);
      ssh_mp_mod(&t2, &t2, &E->q);
    }
  else
    {
      /* Initialize temporary variables */
      ssh_mp_init(&lambda);
      ssh_mp_init(&t1);
      ssh_mp_init(&t2);
      ssh_mp_init(&t3);
      ssh_mp_init(&rx);
      
      /* Calculate the lambda  = (y2 - y1)/(x2 - x1) */
      ssh_mp_sub(&t1, &Q->y, &P->y);
      ssh_mp_sub(&t2, &Q->x, &P->x);
      ssh_mp_mod(&t2, &t2, &E->q);
    }

  /* We don't want to throw negative values to this function. */
  ssh_mp_invert(&t3, &t2, &E->q);
  ssh_mp_mul(&lambda, &t1, &t3);
  ssh_mp_mod(&lambda, &lambda, &E->q);
      
  /* Calculate result x3 = lambda^2 - x1 - x2. */
  ssh_mp_square(&t1, &lambda);
  ssh_mp_mod(&t1, &t1, &E->q);
  ssh_mp_sub(&t1, &t1, &P->x);
  ssh_mp_sub(&t1, &t1, &Q->x);
  ssh_mp_mod(&rx, &t1, &E->q);
      
  /* Calculate result y3 = lambda(x1 - x3) - y1. */
  ssh_mp_sub(&t1, &P->x, &rx);
  ssh_mp_mul(&t1, &lambda, &t1);
  ssh_mp_sub(&t1, &t1, &P->y);

  /* Set results to R. */
  ssh_mp_mod(&R->y, &t1, &E->q);
  ssh_mp_set(&R->x, &rx);
  R->z = 1;
  
  /* Clear temporary variables */
  ssh_mp_clear(&t3);
  ssh_mp_clear(&t2);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&lambda);
  ssh_mp_clear(&rx);  
}
  
/* Projective coordinate cases. */

/* Elliptic curve projective point. */

typedef struct
{
  /* If z = 0 then point at infinity. */
  SshInt x, y, z;
} SshECPProjectivePoint;

/* Projective point initialization. */
void ssh_ecp_init_projective_point(SshECPProjectivePoint *P,
				   const SshECPCurve *E)
{
  ssh_mp_init_set_ui(&P->x, 1);
  ssh_mp_init_set_ui(&P->y, 1);
  ssh_mp_init_set_ui(&P->z, 0);
}

/* Set projective point to the identity (z = 0). */
void ssh_ecp_set_projective_identity(SshECPProjectivePoint *P)
{
  ssh_mp_init_set_ui(&P->x, 1);
  ssh_mp_init_set_ui(&P->y, 1);
  ssh_mp_init_set_ui(&P->z, 0);
}
  
/* Free projective point. */
void ssh_ecp_clear_projective_point(SshECPProjectivePoint *P)
{
  ssh_mp_clear(&P->x);
  ssh_mp_clear(&P->y);
  ssh_mp_clear(&P->z);
}

/* Projective point copy P to Q. */
void ssh_ecp_copy_projective_point(SshECPProjectivePoint *Q,
				   const SshECPProjectivePoint *P)
{
  ssh_mp_set(&Q->x, &P->x);
  ssh_mp_set(&Q->y, &P->y);
  ssh_mp_set(&Q->z, &P->z);
}

/* Negate projective point -P = Q. */
void ssh_ecp_negate_projective_point(SshECPProjectivePoint *Q,
				     const SshECPProjectivePoint *P,
				     const SshECPCurve *E)
{
  ssh_mp_set(&Q->x, &P->x);
  ssh_mp_sub(&Q->y, &E->q, &P->y);
  ssh_mp_set(&Q->z, &P->z);
}

/* Conversion between affine (normal) and projective coordinates. */

/* Convert from affine to projective coordinate system. */
void ssh_ecp_affine_to_projective(SshECPProjectivePoint *R,
				  const SshECPPoint *P)
{
  /* Checking for identity. */
  if (!P->z)
    {
      /* This is the actual point at the infinity. */
      ssh_ecp_set_projective_identity(R);
    }
  else
    {
      ssh_mp_set(&R->x, &P->x);
      ssh_mp_set(&R->y, &P->y);      
      ssh_mp_set_ui(&R->z, 1);
    }
}

/* Convert from projective to affine coordinate system. */
void ssh_ecp_projective_to_affine(SshECPPoint *R,
				  const SshECPProjectivePoint *P,
				  const SshECPCurve *E)
{
  SshInt t1, t2;

  /* Initialize temporary variables. */
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);

  /* Check for point at infinity */
  if (ssh_mp_cmp_ui(&P->z, 0) == 0)
    {
      ssh_ecp_set_identity(R);
    }
  else
    { 
      /* Compute the inverse of z */
      ssh_mp_invert(&t1, &P->z, &E->q);
      ssh_mp_square(&t2, &t1);
      
      /* Compute x*(1/z)^2 mod q */
      ssh_mp_mul(&R->x, &P->x, &t2);
      ssh_mp_mod(&R->x, &R->x, &E->q);

      ssh_mp_mul(&t2, &t2, &t1);
      
      /* Compute y*(1/z)^3 mod q */
      ssh_mp_mul(&R->y, &P->y, &t2);
      ssh_mp_mod(&R->y, &R->y, &E->q);
      
      R->z = 1;
    }
  /* Clear temporary variables. */
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);
}

/* Definition of temporary structure. */

typedef struct
{
  /* General temporary registers. */
  SshInt t1, t2, t3, t4, t5, t6, t7;
} SshECPProjectiveTemp;

void ssh_ecp_init_projective_temp(SshECPProjectiveTemp *t)
{
  ssh_mp_init(&t->t1);
  ssh_mp_init(&t->t2);
  ssh_mp_init(&t->t3);
  ssh_mp_init(&t->t4);
  ssh_mp_init(&t->t5);
  ssh_mp_init(&t->t6);
  ssh_mp_init(&t->t7);
}

void ssh_ecp_clear_projective_temp(SshECPProjectiveTemp *t)
{
  ssh_mp_clear(&t->t1);
  ssh_mp_clear(&t->t2);
  ssh_mp_clear(&t->t3);
  ssh_mp_clear(&t->t4);
  ssh_mp_clear(&t->t5);
  ssh_mp_clear(&t->t6);
  ssh_mp_clear(&t->t7);
}

/* Projective doubling of a point.
   This is after the P1363 draft. November 1996. These formulas can be
   acquired from the original paper by Chudnovsky and Chudnovsky (reference
   in P1363).

   One optimization problem is to know how many consecutive multiplications
   can one let be performed before reducing with the modulus. That is, to
   gain optimal performance. My guess is that with GMP routines reduction
   should be performed after the values is about three (3) times the length
   of the modulus for optimal performance. 

   */

void ssh_ecp_projective_double(SshECPProjectivePoint *R,
			       const SshECPProjectivePoint *P,
			       const SshECPCurve *E,
			       SshECPProjectiveTemp *t)
{
  ssh_mp_set(&t->t1, &P->x);
  ssh_mp_set(&t->t2, &P->y);
  ssh_mp_set(&t->t3, &P->z);

  /* Case a = -3 mod q could be included here.

     That is we could write the 3x^2 + az^4 as

     3x^2 - 3z_4 = 3(x - z^2)(x + z^2)

     if a = - 3 mod q. Which should be possible to set for half of elliptic
     curves. This is not currently forced though and thus not currently
     done, but maybe later.
   */
  
  ssh_mp_square(&t->t5, &t->t3);
  ssh_mp_square(&t->t5, &t->t5);
  ssh_mp_mod(&t->t5, &t->t5, &E->q);

  ssh_mp_mul(&t->t5, &t->t5, &E->a);
  
  ssh_mp_square(&t->t4, &t->t1);
  ssh_mp_mul_ui(&t->t4, &t->t4, 3);
  ssh_mp_add(&t->t4, &t->t4, &t->t5);

  ssh_mp_mul(&t->t3, &t->t2, &t->t3);
  ssh_mp_mul_2exp(&t->t3, &t->t3, 1);
  ssh_mp_mod(&t->t3, &t->t3, &E->q);

  ssh_mp_square(&t->t2, &t->t2);
  ssh_mp_mul(&t->t5, &t->t1, &t->t2);
  ssh_mp_mul_2exp(&t->t5, &t->t5, 2);
  ssh_mp_mod(&t->t5, &t->t5, &E->q);

  ssh_mp_square(&t->t1, &t->t4);

  ssh_mp_sub(&t->t1, &t->t1, &t->t5);
  ssh_mp_sub(&t->t1, &t->t1, &t->t5);
  ssh_mp_mod(&t->t1, &t->t1, &E->q);
  
  ssh_mp_square(&t->t2, &t->t2);
  ssh_mp_mul_2exp(&t->t2, &t->t2, 3);

  ssh_mp_sub(&t->t5, &t->t5, &t->t1);
  ssh_mp_mul(&t->t5, &t->t4, &t->t5);
  ssh_mp_sub(&t->t2, &t->t5, &t->t2);
  ssh_mp_mod(&t->t2, &t->t2, &E->q);
  
  ssh_mp_set(&R->x, &t->t1);
  ssh_mp_set(&R->y, &t->t2);
  ssh_mp_set(&R->z, &t->t3);
}
  
/* Projective addition of distinct points. Q = (x_0, y_0, z_0) and
   P = (x_1, y_1, 1). This is the preferred addition, because no nonsense
   compares, does just the job as fast as possible (I think). */

void ssh_ecp_projective_add(SshECPProjectivePoint *R,
			    const SshECPProjectivePoint *Q,
			    const SshECPProjectivePoint *P,
			    const SshECPCurve *E, SshECPProjectiveTemp *t)
{

  ssh_mp_set(&t->t1, &Q->x);
  ssh_mp_set(&t->t2, &Q->y);
  ssh_mp_set(&t->t3, &Q->z);
  ssh_mp_set(&t->t4, &P->x);
  ssh_mp_set(&t->t5, &P->y);

  ssh_mp_square(&t->t6, &t->t3);
  ssh_mp_mul(&t->t4, &t->t4, &t->t6);
  ssh_mp_mul(&t->t6, &t->t3, &t->t6);
  ssh_mp_mod(&t->t6, &t->t6, &E->q);
  
  ssh_mp_mul(&t->t5, &t->t5, &t->t6);
  ssh_mp_add(&t->t1, &t->t1, &t->t4);
  ssh_mp_add(&t->t2, &t->t2, &t->t5);
  ssh_mp_mul_2exp(&t->t4, &t->t4, 1);
  ssh_mp_sub(&t->t4, &t->t1, &t->t4);
  ssh_mp_mul_2exp(&t->t5, &t->t5, 1);
  ssh_mp_sub(&t->t5, &t->t2, &t->t5);

  ssh_mp_mul(&t->t3, &t->t3, &t->t4);
  ssh_mp_mod(&t->t3, &t->t3, &E->q);
  
  ssh_mp_square(&t->t6, &t->t4);
  ssh_mp_mul(&t->t4, &t->t4, &t->t6);
  ssh_mp_mul(&t->t6, &t->t1, &t->t6);
  ssh_mp_square(&t->t1, &t->t5);
  ssh_mp_sub(&t->t1, &t->t1, &t->t6);
  ssh_mp_mod(&t->t1, &t->t1, &E->q);
  
  ssh_mp_sub(&t->t6, &t->t6, &t->t1);
  ssh_mp_sub(&t->t6, &t->t6, &t->t1);
  ssh_mp_mul(&t->t5, &t->t5, &t->t6);
  ssh_mp_mul(&t->t4, &t->t2, &t->t4);
  ssh_mp_sub(&t->t2, &t->t5, &t->t4);

  /* Compute t*2^-1 mod q (note that here 2^-1 is the multiplicative
     inverse and division by 2 is not!)

     We get q = (q-1)/2 * 2 + 1 <=>
            2q - (q-1)/2*2 = q + 1 <=>
	    (q+1)/2 * 2 = q + 1 <=>
	    2^-1 = (q+1)/2.

     (Same result could be gotten by noticing that
       2^-1 * 2 = 1 (mod q)
       =>
       2^-1 * 2 = q + 1 <=>
       2^-1 = (q + 1)/2.
       There is no other possible value for 2^-1 < q that
       2^-1 * 2 = 1 (mod q).)

     This gives us the formula for computing 2^-1 * n (mod q).

     We can derive the method thus
     
     case t even
       ((q + 1) * t) / 2 (mod q) = qt/2 + t/2 (mod q) = t/2 (mod q).
     case t odd
       ((q + 1) * t) / 2 (mod q) = (t' + 1)(q + 1)/2 (mod q) =
        (t'q + t' + q + 1)/2 (mod q) = (t' + q + 1)/2 (mod q) =
	(t + q) / 2 (mod q).
	
   */
  if (ssh_mp_get_ui(&t->t2) & 0x1)
    ssh_mp_add(&t->t2, &t->t2, &E->q);

  ssh_mp_div_2exp(&t->t2, &t->t2, 1);
  ssh_mp_mod(&t->t2, &t->t2, &E->q);
  
  ssh_mp_set(&R->x, &t->t1);
  ssh_mp_set(&R->y, &t->t2);
  ssh_mp_set(&R->z, &t->t3);
}
  
/* Projective addition of distinct points. Q = (x_0, y_0, z_0) and
   P = (x_1, y_1, z_1). */

void ssh_ecp_projective_add2(SshECPProjectivePoint *R,
			     const SshECPProjectivePoint *Q,
			     const SshECPProjectivePoint *P,
			     const SshECPCurve *E, SshECPProjectiveTemp *t)
{

  ssh_mp_set(&t->t1, &Q->x);
  ssh_mp_set(&t->t2, &Q->y);
  ssh_mp_set(&t->t3, &Q->z);
  ssh_mp_set(&t->t4, &P->x);
  ssh_mp_set(&t->t5, &P->y);

  if (ssh_mp_cmp_ui(&P->z, 1) != 0)
    {
      ssh_mp_set(&t->t7, &P->z);
      ssh_mp_square(&t->t6, &t->t7);
      ssh_mp_mul(&t->t1, &t->t1, &t->t6);
      ssh_mp_mul(&t->t6, &t->t7, &t->t6);
      ssh_mp_mul(&t->t2, &t->t2, &t->t6);
    }
  
  ssh_mp_square(&t->t6, &t->t3);
  ssh_mp_mul(&t->t4, &t->t4, &t->t6);
  ssh_mp_mul(&t->t6, &t->t3, &t->t6);
  ssh_mp_mod(&t->t6, &t->t6, &E->q);
  
  ssh_mp_mul(&t->t5, &t->t5, &t->t6);
  ssh_mp_add(&t->t1, &t->t1, &t->t4);
  ssh_mp_add(&t->t2, &t->t2, &t->t5);
  ssh_mp_mul_2exp(&t->t4, &t->t4, 1);
  ssh_mp_sub(&t->t4, &t->t1, &t->t4);
  ssh_mp_mul_2exp(&t->t5, &t->t5, 1);
  ssh_mp_sub(&t->t5, &t->t2, &t->t5);

  if (ssh_mp_cmp_ui(&P->z, 1) != 0)
    ssh_mp_mul(&t->t3, &t->t3, &t->t7);
  
  ssh_mp_mul(&t->t3, &t->t3, &t->t4);
  ssh_mp_mod(&t->t3, &t->t3, &E->q);
  
  ssh_mp_square(&t->t6, &t->t4);
  ssh_mp_mul(&t->t4, &t->t4, &t->t6);
  ssh_mp_mul(&t->t6, &t->t1, &t->t6);
  ssh_mp_square(&t->t1, &t->t5);
  ssh_mp_sub(&t->t1, &t->t1, &t->t6);
  ssh_mp_mod(&t->t1, &t->t1, &E->q);
  
  ssh_mp_sub(&t->t6, &t->t6, &t->t1);
  ssh_mp_sub(&t->t6, &t->t6, &t->t1);
  ssh_mp_mul(&t->t5, &t->t5, &t->t6);
  ssh_mp_mul(&t->t4, &t->t2, &t->t4);
  ssh_mp_sub(&t->t2, &t->t5, &t->t4);

  if (ssh_mp_get_ui(&t->t2) & 0x1)
    ssh_mp_add(&t->t2, &t->t2, &E->q);

  ssh_mp_div_2exp(&t->t2, &t->t2, 1);
  ssh_mp_mod(&t->t2, &t->t2, &E->q);
  
  ssh_mp_set(&R->x, &t->t1);
  ssh_mp_set(&R->y, &t->t2);
  ssh_mp_set(&R->z, &t->t3);
}

/* Generic double. */

void ssh_ecp_projective_generic_double(SshECPProjectivePoint *R,
				       const SshECPProjectivePoint *P,
				       const SshECPCurve *E,
				       SshECPProjectiveTemp *t)
{
  if (ssh_mp_cmp_ui(&P->z, 0) == 0)
    {
      ssh_ecp_set_projective_identity(R);
      return;
    }

  ssh_ecp_projective_double(R, P, E, t);
}

/* For cases Q = (x_0, y_0, z_0) and P = (x_1, y_1, 1). */
  
void ssh_ecp_projective_generic_add(SshECPProjectivePoint *R,
				    const SshECPProjectivePoint *Q,
				    const SshECPProjectivePoint *P,
				    const SshECPCurve *E,
				    SshECPProjectiveTemp *t)
{
  if (ssh_mp_cmp_ui(&Q->z, 0) == 0)
    {
      ssh_ecp_copy_projective_point(R, P);
      return;
    }

  ssh_mp_square(&t->t1, &Q->z);
  ssh_mp_mul(&t->t2, &P->x, &t->t1);
  ssh_mp_mod(&t->t2, &t->t2, &E->q);

  if (ssh_mp_cmp(&t->t2, &Q->x) != 0)
    {
      ssh_ecp_projective_add(R, Q, P, E, t);
      return;
    }

  ssh_mp_mul(&t->t2, &P->y, &t->t1);
  ssh_mp_mul(&t->t2, &t->t2, &Q->z);
  ssh_mp_mod(&t->t2, &t->t2, &E->q);

  if (ssh_mp_cmp(&t->t2, &Q->y) == 0)
    {
      ssh_ecp_projective_double(R, P, E, t);
      return;
    }
  ssh_ecp_set_projective_identity(R);
}

/* Transform computations. */

/* Computation of signed bit representation as in Morain & Olivos. */

unsigned int ssh_mp_transform_mo(const SshInt *k, char **transform_table)
{
  unsigned int maxbit, bit, scanbit, b, end, transform_index;
  char *transform;
  
  /* Seek the maximum number of bits. */

  maxbit = ssh_mp_get_size(k, 2);

  /* Set up scanning. */
  
  bit = 0;
  scanbit = 1;
  b = 0;
  end = 0;
  transform_index = 0;

  /* Allocate and compute transform bit table.
     As suggested by Morain & Olivos. (This is equal to the P1363 method.)
     */

  transform = ssh_xmalloc(maxbit + 3);
  
  while (!end)
    {
      scanbit = ssh_mp_scan1(k, bit);
      if (scanbit >= maxbit)
	break;

      while (bit < scanbit)
	{
	  if (b == 11)
	    {
	      b = 1;
	    }
	  else
	    {
	      if (b == 1)
		{
		  transform[transform_index++] = 1;
		  b = 0;
		}
	      transform[transform_index++] = 0;
	    }
	  bit++;	  
	}

      scanbit = ssh_mp_scan0(k, bit);
      if (scanbit >= maxbit)
	{
	  scanbit = maxbit;
	  end = 1;
	}

      while (bit < scanbit)
	{
	  if (b == 0)
	    {
	      b = 1;
	    }
	  else
	    {
	      if (b == 1)
		{
		  transform[transform_index++] = -1; 
		  b = 11;
		}
	      transform[transform_index++] = 0;
	    }
	  bit++;
	}
    }

  /* Set the highest bit. */
  transform[transform_index] = 1;

  /* Return with transform index and table. */
  *transform_table = transform;
  return transform_index + 1;
}

unsigned int ssh_mp_transform_binary(const SshInt *k, char **transform_table)
{
  unsigned int maxbit, bit, scanbit, end, transform_index;
  char *transform;
  
  /* Seek the maximum number of bits. */

  maxbit = ssh_mp_get_size(k, 2);

  /* Set up scanning. */
  
  bit = 0;
  scanbit = 1;
  end = 0;
  transform_index = 0;

  transform = ssh_xmalloc(maxbit + 3);

  while (!end)
    {
      scanbit = ssh_mp_scan1(k, bit);
      if (scanbit >= maxbit)
	break;

      while (bit < scanbit)
	{
	  transform[transform_index++] = 0;
	  bit++;
	}

      scanbit = ssh_mp_scan0(k, bit);
      if (scanbit >= maxbit)
	end = 1;
      
      while (bit < scanbit)
	{
	  transform[transform_index++] = 1;
	  bit++;
	}
    }

  /* Return with transform index and table. */
  *transform_table = transform;
  return transform_index;
}

/* Unoptimized. */
unsigned int ssh_mp_transform_kmov(const SshInt *k, char **transform_table)
{
  char *B, *T;
  int m, j, y, x, u, v, w, z;
  unsigned int log_d;
  
  log_d = ssh_mp_transform_binary(k, &B);
  T = ssh_xmalloc(log_d + 3);
  
  m = j = y = x = u = v = w = z = 0;

  /* Koyama and Tsuruoka method for computing signed representation. */
  
  while (x < log_d - 1)
    {
      if (B[x] == 1)
	y++;
      else
	y--;
      x++;

      if (m == 0)
	{
	  if (y - z >= 3)
	    {
	      while (j < w)
		{
		  T[j] = B[j];
		  j++;
		}
	      T[j] = -1;
	      j++;
	      v = y;
	      u = x;
	      m = 1;
	    }
	  else
	    {
	      if (y < z)
		{
		  z = y;
		  w = x;
		}
	    }
	}
      else
	{
	  if (v - y >= 3)
	    {
	      while (j < u)
		{
		  T[j] = B[j] - 1;
		  j++;
		}
	      T[j] = 1;
	      j++;
	      z = y;
	      w = x;
	      m = 0;
	    }
	  else
	    {
	      if (y > v)
		{
		  v = y;
		  u = x;
		}
	    }
	}
    }
  if (m == 0 || (m == 1 && v <= y))
    {
      while (j < x)
	{
	  T[j] = B[j] - m;
	  j++;
	}
      T[j] = 1 - m;
      if (m)
	{
	  j++;
	  T[j] = m;
	}
    }
  else
    {
      while (j < u)
	{
	  T[j] = B[j] - 1;
	  j++;
	}
      T[j] = 1;
      j++;
      while (j < x)
	{
	  T[j] = B[j];
	  j++;
	}
      T[j] = 1;
    }
  
  *transform_table = T;
  ssh_xfree(B);
  return j + 1;
}
  
/* Computation of multiples of point P. Generic case. */

void ssh_ecp_generic_mul(SshECPPoint *R, const SshECPPoint *P, const SshInt *k,
			 const SshECPCurve *E)
{
  SshECPProjectiveTemp t;
  SshECPProjectivePoint T, H, I;
  char *transform;
  int i;

  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }

  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }
  
  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&H, E);
  ssh_ecp_init_projective_point(&I, E);

  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t);

  /* Transform scalar multiplier to a signed representation. */
  i = ssh_mp_transform_mo(k, &transform) - 1;

  /* Set temporary projective points. */
  
  ssh_ecp_affine_to_projective(&H, P);
  ssh_ecp_copy_projective_point(&T, &H);
  ssh_ecp_negate_projective_point(&I, &H, E);

  /* Multiply using transform bit-vector. */

  for (; i; i--)
    {
      ssh_ecp_projective_generic_double(&T, &T, E, &t);
      if (transform[i - 1])
	{
	  if (transform[i - 1] == -1)
	    ssh_ecp_projective_generic_add(&T, &T, &I, E, &t);
	  else
	    ssh_ecp_projective_generic_add(&T, &T, &H, E, &t);
	}
    }

  /* Convert to affine coordinates. */
  
  ssh_ecp_projective_to_affine(R, &T, E);

  /* Clear temporary space. */

  ssh_xfree(transform);
  
  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&H);
  ssh_ecp_clear_projective_point(&I);

  ssh_ecp_clear_projective_temp(&t);
}

#if 0

/* Specialized multiplication for points P of prime order, where
   0 <= k < #P. */

void ssh_ecp_mul(SshECPPoint *R, const SshECPPoint *P, const SshInt *k,
		 const SshECPCurve *E)
{
  SshECPProjectiveTemp t;
  SshECPProjectivePoint T, H, I;
  char *transform;
  int i;
  
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }
  
  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&H, E);
  ssh_ecp_init_projective_point(&I, E);

  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t);

  /* Transform scalar multiplier to signed representation. */
  i = ssh_mp_transform_mo(k, &transform) - 1;
  
  /* Set temporary projective points. */
  
  ssh_ecp_affine_to_projective(&H, P);
  ssh_ecp_copy_projective_point(&T, &H);
  ssh_ecp_negate_projective_point(&I, &H, E);
  
  /* Multiply using transform bit-vector. */
  
  for (; i; i--)
    {
      ssh_ecp_projective_double(&T, &T, E, &t);
      if (transform[i - 1])
	{
	  if (transform[i - 1] == -1)
	    ssh_ecp_projective_add(&T, &T, &I, E, &t);
	  else
	    ssh_ecp_projective_add(&T, &T, &H, E, &t);
	}
    }
  
  /* Convert to affine coordinates. */
  
  ssh_ecp_projective_to_affine(R, &T, E);
  
  /* Clear temporary space. */

  ssh_xfree(transform);
  
  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&H);
  ssh_ecp_clear_projective_point(&I);

  ssh_ecp_clear_projective_temp(&t);
}

#else
#if 0

/* Specialized multiplication for points P of prime order, where
   0 <= k < #P. This version also features basic 2^k-ary computation
   which of course "should" (but doesn't) speed computation. */

void ssh_ecp_mul(SshECPPoint *R, const SshECPPoint *P, const SshInt *k,
		 const SshECPCurve *E)
{
  SshECPProjectiveTemp t;
#define K_ARY      4
#define K_ARY_SIZE (1 << K_ARY)
  SshECPProjectivePoint T, H[K_ARY_SIZE], N;
  unsigned char b[K_ARY_SIZE];
  char *transform;
  unsigned int transform_index;
  unsigned int i, j, n, stack, negate, post_doubles;
  int m;
  
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }
  
  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&N, E);
  for (i = 0; i < K_ARY_SIZE; i++)
    ssh_ecp_init_projective_point(&H[i], E);
  memset(b, 0, K_ARY_SIZE);
  
  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t);

  /* Transform scalar multiplier into signed representation. */
  transform_index = ssh_mp_transform_kmov(k, &transform) - 1;
  
  /* Set temporary projective points. */
  
  ssh_ecp_affine_to_projective(&H[1], P);

  /* Set up table indicators. */
  b[0] = 0;
  b[1] = 1;
  
  /* Multiply using transform bit-vector. */

  /* 2^k-ary case. */

  ssh_ecp_copy_projective_point(&T, &H[1]);

  /* Do the binary sliding window part. */
  while (transform_index)
    {
      /* Slide along the transform table. */
      if (transform[transform_index - 1] == 0)
	{
	  ssh_ecp_projective_double(&T, &T, E, &t);

	  /* Move down the transform table. */
	  transform_index--;
	  continue;
	}

      /* Select number of bits to view. */
      n = K_ARY;
      if (transform_index < n)
	n = transform_index;

      /* Create index. */
      for (j = 0, m = 0; j < n; j++)
	{
	  m <<= 1;
	  m += transform[transform_index - j - 1];
	}

      if (m)
	{
	  /* Check the size and range. */
	  if (m > 0)
	    {
	      m &= (K_ARY_SIZE - 1);
	      negate = 0;
	    }
	  else
	    {
	      m = (-m) & (K_ARY_SIZE - 1);
	      negate = 1;
	    }

	  /* Force odd. */
	  post_doubles = 0;
	  while ((m & 0x1) == 0)
	    {
	      m >>= 1;
	      n--;
	      post_doubles++;
	    }

	  /* Move down the transform table. */
	  transform_index -= n;

	  /* Do the doubling here (addition later). */
	  for (i = 0; i < n; i++)
	    ssh_ecp_projective_double(&T, &T, E, &t);
	  
	  /* Build tables as we go along. */

	  /* Compute bits of m. Or more correctly, find smallest n such that
	     2^n < m < 2^(n + 1). */
	  for (n = 1; n <= m; n <<= 1)
	    ;
	  n >>= 1;

	  /* Loop and build tables (storing middle results). */
	  for (stack = 0;;)
	    {
	      if (b[m] == 0)
		{
		  /* Build powers of 2, which will allow quicker computation
		     later. */
		  for (i = n; b[i] == 0; i >>= 1)
		    ;

		  for (; i < n;)
		    {
		      j = i << 1;
		      ssh_ecp_projective_double(&H[j], &H[i], E, &t);
		      b[j] = 1;
		      i = j;
		    }
		  if (m == 0)
		    ssh_fatal("ssh_ecp_mul: internal error.");
		  /* Get rid of zeroes. */
		  while ((m & n) == 0)
		    {
		      stack <<= 1;
		      n >>= 1;
		    }
		  /* One found. */
		  stack = (stack << 1) | 1;
		  m = m & (n - 1);
		  n >>= 1;
		}
	      else
		{
		  /* We can quit due nothing to do here. */
		  if (stack == 0)
		    break;
		  
		  /* Get zeroes of stack (stack must contain something). */
		  while ((stack & 0x1) == 0)
		    {
		      n <<= 1;
		      stack >>= 1;
		    }

		  /* Get the next index which we want to compute. */
		  n <<= 1;
		  i = m | n;
		  stack >>= 1;

		  /* Compute it (we know all the ingredients). */
		  ssh_ecp_projective_add2(&H[i],
					  &H[m], &H[n], E, &t);
		  b[i] = 1;
		  
		  /* Go to the next index. */
		  m = i;

		  /* Hey, we can quit now. Stack is empty and no more to
		     do. */
		  if (stack == 0)
		    break;
		}
	    }
	  
	  /* Handle addition. */
	  if (negate)
	    {
	      ssh_ecp_negate_projective_point(&N, &H[m], E);
	      ssh_ecp_projective_add2(&T, &T, &N, E, &t);
	    }
	  else
	    {
	      ssh_ecp_projective_add2(&T, &T, &H[m], E, &t);
	    }

	  /* Double up the zeros. */
	  transform_index -= post_doubles;
	  while (post_doubles)
	    {
	      ssh_ecp_projective_double(&T, &T, E, &t);
	      post_doubles--;
	    }
	}
    }

  /* Convert to affine coordinates. */
  
  ssh_ecp_projective_to_affine(R, &T, E);
  
  /* Clear temporary space. */

  ssh_xfree(transform);
   
  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&N);
  for (i = 0; i < K_ARY_SIZE; i++)
    ssh_ecp_clear_projective_point(&H[i]);

  ssh_ecp_clear_projective_temp(&t);

#undef K_ARY
#undef K_ARY_SIZE
}

#else

/* NOTE!

   This function is a million time simpler than the above one, and should
   be somewhat faster too. The problem with the above construction is
   that the method is too complicated and although in theory good,
   in practice hard to get working right. Although it does that too.  */

/* Specialized multiplication for points P of prime order, where
   0 <= k < #P. This version also features basic 2^k-ary computation
   which of course "should" (but doesn't) speed computation. */

void ssh_ecp_mul(SshECPPoint *R, const SshECPPoint *P, const SshInt *k,
		 const SshECPCurve *E)
{
  SshECPProjectiveTemp t;
#define K_ARY      4
#define K_ARY_SIZE (1 << K_ARY)
  SshECPProjectivePoint T, H[K_ARY_SIZE], N;
  char *transform;
  unsigned int transform_index;
  unsigned int i, j;
  int first, mask, zeros, steps;
  
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ecp_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ecp_copy_point(R, P);
      return;
    }
  
  /* Initialize points. */

  ssh_ecp_init_projective_point(&T, E);
  ssh_ecp_init_projective_point(&N, E);
  for (i = 0; i < K_ARY_SIZE/2; i++)
    ssh_ecp_init_projective_point(&H[i], E);
  
  /* Initialize temporary variables. */

  ssh_ecp_init_projective_temp(&t);

  /* Transform scalar multiplier into signed representation. */
  transform_index = ssh_mp_transform_kmov(k, &transform) - 1;
  
  /* Set temporary projective points. */

  /* Compute P, 3P, 5P, 7P, ...
     It would be advantageous to transform the points from (X, Y, Z)
     to (X/Z, Y/Z, 1) e.g. back to affine format. However, it seems
     to take one inverse always?! But not exactly, because we could
     use the trick of Dr. Peter Montgomery to do it with just one
     inversion and about 4 multiplications per point. This is to be
     done later. XXX */
  ssh_ecp_affine_to_projective(&H[0], P);
  ssh_ecp_projective_double(&T, &H[0], E, &t);
  for (i = 1; i < K_ARY_SIZE/2; i++)
    ssh_ecp_projective_add2(&H[i], &H[i - 1], &T, E, &t);
  
  /* Multiply using transform bit-vector. */

  /* 2^k-ary case. */

  ssh_ecp_copy_projective_point(&T, &H[0]);

  /* Do the main looping. */
  for (first = 1, i = transform_index + 1; i;)
    {
      for (j = 0, mask = zeros = steps = 0; j < K_ARY && i; j++, i--)
	{
	  if (transform[i - 1])
	    {
	      steps += zeros;
	      /* Multiply by 2, if necessary. */
	      if (mask)
		{
		  while (zeros)
		    {
		      mask <<= 1;
		      zeros--;
		    }
		  /* The base case. */
		  mask <<= 1;
		}
	      mask += transform[i - 1];
	      steps++;
	    }
	  else
	    zeros++;
	}

      if (mask == 0)
	ssh_fatal("ssh_ecp_mul: failure in handling the multiplier.");

      /* Handle the actual elliptic curve operations. */
      if (!first)
	{
	  for (j = 0; j < steps; j++)
	    ssh_ecp_projective_double(&T, &T, E, &t);

	  /* Notice, that we have tabulate all values nP where, n is
	     odd. Here we must have mask odd, and thus we can happily
	     get the correct place by shifting down by one. */
	  if (mask < 0)
	    {
	      ssh_ecp_negate_projective_point(&N, &H[(-mask) >> 1], E);
	      ssh_ecp_projective_add2(&T, &T, &N, E, &t);
	    }
	  else
	    ssh_ecp_projective_add2(&T, &T, &H[mask >> 1], E, &t);
	}
      else
	{
	  if (mask < 0)
	    {
	      ssh_ecp_negate_projective_point(&N, &H[(-mask) >> 1], E);
	      ssh_ecp_copy_projective_point(&T, &N);
	    }
	  else
	    ssh_ecp_copy_projective_point(&T, &H[mask >> 1]);
	  first = 0;
	}

      /* Now do the doubling phase. */
      while (zeros)
	{
	  ssh_ecp_projective_double(&T, &T, E, &t);
	  zeros--;
	}

      while (i && transform[i - 1] == 0)
	{
	  ssh_ecp_projective_double(&T, &T, E, &t);
	  i--;
	  zeros++;
	}
    }
  
  /* Convert to affine coordinates. */
  
  ssh_ecp_projective_to_affine(R, &T, E);
  
  /* Clear temporary space. */

  ssh_xfree(transform);
   
  ssh_ecp_clear_projective_point(&T);
  ssh_ecp_clear_projective_point(&N);
  for (i = 0; i < K_ARY_SIZE/2; i++)
    ssh_ecp_clear_projective_point(&H[i]);

  ssh_ecp_clear_projective_temp(&t);

#undef K_ARY
#undef K_ARY_SIZE
}
#endif
#endif

/* XXX This code used to be in ecpaux.c now I have made this one single
   large file from all this. */

/* Point compression. */

Boolean ssh_ecp_compute_y_from_x(SshInt *y, const SshInt *x,
				 const SshECPCurve *E)
{
  SshInt t1, t2;
  Boolean rv = FALSE;

  ssh_mp_init(&t1);
  ssh_mp_init(&t2);

  ssh_mp_mul(&t1, x, x);
  ssh_mp_mul(&t1, &t1, x);
  ssh_mp_mod(&t1, &t1, &E->q);

  ssh_mp_mul(&t2, x, &E->a);
  ssh_mp_add(&t2, &t2, &E->b);
  ssh_mp_add(&t1, &t1, &t2);

  ssh_mp_mod(&t1, &t1, &E->q);

  if (ssh_mp_mod_sqrt(y, &t1, &E->q))
    rv = TRUE;
  else
    rv = FALSE;

  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);
  
  return rv;
}

Boolean ssh_ecp_restore_y(SshECPPoint *P, const SshECPCurve *E,
			  Boolean bit)
{
  if (ssh_ecp_compute_y_from_x(&P->y, &P->x, E) == FALSE)
    return FALSE;
  if (bit != (ssh_mp_get_ui(&P->y) & 0x1))
    ssh_mp_sub(&P->y, &E->q, &P->y);
  return TRUE;
}

/* Select a random point from E(Fq). */

void ssh_ecp_random_point(SshECPPoint *P, const SshECPCurve *E)
{
  while (1)
    {
      /* Get a random point from Fq. */
      ssh_mp_rand(&P->x, ssh_mp_get_size(&E->q, 2) + 1);
      ssh_mp_mod(&P->x, &P->x, &E->q);

      if (ssh_ecp_compute_y_from_x(&P->y, &P->x, E))
	{
	  P->z = 1;
	  break;
	}
    }
}

/* Find a point of a prime order. This function needs to know the
   largest prime divisor of the cardinality of the given curve.

   Be careful when giving the prime factor that it really is the largest
   factor, this function does not check it.

   Return value FALSE means that the cardinality, point or curve is not
   correct.
   */
   
Boolean ssh_ecp_random_point_of_prime_order(SshECPPoint *P, const SshInt *n,
					    const SshECPCurve *E)
{
  SshInt t, r;
  SshECPPoint Q;
  
  ssh_mp_init(&t);
  ssh_mp_init(&r);
  
  /* n must be factor of cardinality, either trivial or non-trivial. */
  ssh_mp_div(&t, &r, &E->c, n);

  if (ssh_mp_cmp_ui(&r, 0) != 0)
    {
      ssh_mp_clear(&t);
      ssh_mp_clear(&r);
      return FALSE;
    }
    
  /* Because we cannot use the time to factor we have restricted this
     function to primes (probable primes more accurately). */
  if (!ssh_mp_is_probable_prime(n, 25))
    {
      ssh_mp_clear(&t);
      ssh_mp_clear(&r);
      return FALSE;
    }
  
  ssh_ecp_init_point(&Q, E);
  
  while (1)
    {
      /* Select a random point */
      ssh_ecp_random_point(&Q, E);
      ssh_ecp_generic_mul(P, &Q, &t, E);

      if (P->z)
	break;
    }

  ssh_ecp_generic_mul(&Q, P, n, E);

  if (Q.z)
    {
      ssh_mp_clear(&t);
      ssh_mp_clear(&r);
      return FALSE;
    }
  
  ssh_mp_clear(&t);
  ssh_mp_clear(&r);

  return TRUE;
}
  
/* Check whether parameters define supersingular curve. Returns TRUE if
   curve is supersingular. I.e. return value FALSE is good for our purposes.

   Let E be an elliptic curve over finite field and #E(Fq) = q + 1 - t
   then E is supersingular if

   t^2 = 0, q, 2q, 3q or 4q.

   */
Boolean ssh_ecp_is_supersingular(const SshECPCurve *E)
{
  SshInt t, temp;
  Boolean rv = TRUE;
  
  ssh_mp_init(&t);
  ssh_mp_init(&temp);

  /* Compute t from #E(Fq) = q + 1 - t */
  ssh_mp_add_ui(&temp, &E->q, 1);
  ssh_mp_sub(&t, &temp, &E->c);

  /* Compute t^2 */
  ssh_mp_mul(&t, &t, &t);
  
  /* Check whether t = 0, q, 2q, 3q or 4q. */
  
  if (ssh_mp_cmp_ui(&t, 0) == 0)
    goto end;
  
  ssh_mp_set(&temp, &E->q);
  if (ssh_mp_cmp(&t, &temp) == 0)
    goto end;

  ssh_mp_add(&temp, &temp, &E->q);
  if (ssh_mp_cmp(&t, &temp) == 0)
    goto end;

  ssh_mp_add(&temp, &temp, &E->q);
  if (ssh_mp_cmp(&t, &temp) == 0)
    goto end;

  ssh_mp_add(&temp, &temp, &E->q);
  if (ssh_mp_cmp(&t, &temp) == 0)
    goto end;

  rv = FALSE;

end:

  ssh_mp_clear(&t);
  ssh_mp_clear(&temp);

  return rv;
}
  
/* Brute force #E(Fq), i.e. counting points in elliptic curve over
   finite field Fq. Uses the fact that for every x there lies at most
   two y coordinates in Fq.

   This is not a general purpose counting algorithm because it is
   infeasible after about q > 10^5 which is not very great.

   There exists polynomial time algorithm due to R. Schoof and also method
   called complex multiplication; use either of those or some other similar
   method for actual cardinality computations.
   */
void ssh_ecp_brute_point_count(SshECPCurve *E)
{
  SshInt x, y, t1, t2;
  
  /* Temporary variables. */
  ssh_mp_init_set_ui(&x, 0);
  ssh_mp_init(&y);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);
  
  /* Clear the counter */
  ssh_mp_set_ui(&E->c, 0);

  /* Set up t2 = b */
  ssh_mp_set(&t2, &E->b);
  
  for (;ssh_mp_cmp(&x, &E->q) < 0; ssh_mp_add_ui(&x, &x, 1))
    {
      /* This should say:
	 (t2) + 3x + (3x^2) + a + 1. */
      ssh_mp_mul_ui(&t1, &x, 3);
      ssh_mp_add(&t2, &t2, &t1);
      ssh_mp_mul(&t1, &t1, &x);
      ssh_mp_add(&t2, &t2, &t1);
      ssh_mp_add(&t2, &t2, &E->a);
      ssh_mp_add_ui(&t2, &t2, 1);

      if (ssh_mp_cmp(&t2, &E->q) >= 0)
	ssh_mp_mod(&t2, &t2, &E->q);
      
      ssh_mp_add_ui(&E->c, &E->c, ssh_mp_legendre(&t2, &E->q) + 1);
    }
  /* And the point at the infinity! */
  ssh_mp_add_ui(&E->c, &E->c, 1);
  
  ssh_mp_clear(&x);
  ssh_mp_clear(&y);
}

/* Check the Menezes, Okamoto and Vanstone elliptic curve reduction attack
   possibility. */

Boolean ssh_ecp_mov_condition(const SshInt *op_b, const SshInt *op_q,
			      const SshInt *op_r)
{
  SshInt t, i;
  Boolean mov_condition = FALSE;
  
  /* Initialize temporary variables. */
  ssh_mp_init_set_ui(&t, 1);
  ssh_mp_init_set(&i, op_b);

  /* Iterate the mov condition */
  while (ssh_mp_cmp_ui(&i, 0) != 0)
    {
      ssh_mp_mul(&t, &t, op_q);
      ssh_mp_mod(&t, &t, op_r);
      if (ssh_mp_cmp_ui(&t, 1) == 0)
	{
	  mov_condition = TRUE;
	  break;
	}
      ssh_mp_sub_ui(&i, &i, 1);
    }

  /* Clear temporary variables. */
  ssh_mp_clear(&t);
  ssh_mp_clear(&i);
  return mov_condition;
}

/* Verify that the curve is (probably) good. */

Boolean ssh_ecp_verify_param(const SshECPCurve *E,
			     const SshECPPoint *P,
			     const SshInt      *n)
{
  SshECPPoint Q;
  SshInt t1, t2;
  unsigned int i;
  
  /* Checks for the field modulus. */
  
  if (ssh_mp_cmp_ui(&E->q, 0) <= 0)
    return FALSE;

  /* Checks for the order of the point. */

  if (ssh_mp_cmp_ui(n, 0) <= 0)
    return FALSE;

  /* Trivial check for strength. */
  if (ssh_mp_get_size(n, 2) < 100)
    return FALSE;

  if (ssh_mp_cmp(n, &E->q) >= 0)
    return FALSE;

  /* Test lower limits. */
  
  if (ssh_mp_cmp_ui(&E->a, 0) <= 0)
    return FALSE;
  if (ssh_mp_cmp_ui(&E->b, 0) <= 0)
    return FALSE;
  if (ssh_mp_cmp_ui(&P->x, 0) < 0)
    return FALSE;
  if (ssh_mp_cmp_ui(&P->y, 0) < 0)
    return FALSE;

  /* Check for point at infinity. */
  if (P->z != 1)
    return FALSE;

  /* Check higher limits. */

  if (ssh_mp_cmp(&E->a, &E->q) >= 0)
    return FALSE;
  if (ssh_mp_cmp(&E->b, &E->q) >= 0)
    return FALSE;
  if (ssh_mp_cmp(&E->c, &E->q) >= 0)
    return FALSE;
  if (ssh_mp_cmp(&P->x, &E->q) >= 0)
    return FALSE;
  if (ssh_mp_cmp(&P->y, &E->q) >= 0)
    return FALSE;

  /* Check that n divides the cardinality of the curve. */

  ssh_mp_init(&t1);  
  ssh_mp_mod(&t1, &E->c, n);
  if (ssh_mp_cmp_ui(&t1, 0) != 0)
    {
      ssh_mp_clear(&t1);
      return FALSE;
    }
  ssh_mp_clear(&t1);
  
  /* Trivial checks are done, checking primalities. This can take some
     time, which is not so good. */

  if (!ssh_mp_is_probable_prime(&E->q, 25))
    return FALSE;

  if (!ssh_mp_is_probable_prime(n, 25))
    return FALSE;

  /* Check that the curve and point are really correct. */

  if (ssh_ecp_is_supersingular(E))
    return FALSE;

  /* Check that the curve is not anomalous. E.g. the attack by
     Smart (and Satoh et al.) doesn't apply. */

  if (ssh_mp_cmp(&E->c, &E->q) == 0 ||
      ssh_mp_cmp(n, &E->q) == 0)
    return FALSE;
  
  ssh_mp_init(&t1);

  /* MOV condition threshold. 500 about = 1/8 * log 60 digit number.
     XXX Use the tables from P1363 appendix.
   */
  ssh_mp_set_ui(&t1, 500);  
  
  if (ssh_ecp_mov_condition(&t1, &E->q, n))
    {
      ssh_mp_clear(&t1);
      return FALSE;
    }
  
  ssh_mp_init(&t2);

  /* Test that 4a^3 + 27b^2 != 0 */
  ssh_mp_square(&t1, &E->a);
  ssh_mp_mod(&t1, &t1, &E->q);
  ssh_mp_mul(&t1, &t1, &E->a);
  ssh_mp_mod(&t1, &t1, &E->q);
  ssh_mp_mul_ui(&t1, &t1, 4);

  ssh_mp_square(&t2, &E->b);
  ssh_mp_mod(&t2, &t2, &E->q);
  ssh_mp_mul_ui(&t2, &t2, 27);

  ssh_mp_add(&t1, &t1, &t2);
  ssh_mp_mod(&t1, &t1, &E->q);

  if (ssh_mp_cmp_ui(&t1, 0) == 0)
    {
      ssh_mp_clear(&t1);
      ssh_mp_clear(&t2);
      return FALSE;
    }

  /* Test that y^2 = x^3 + ax + b */
  ssh_mp_mul(&t1, &P->y, &P->y);
  ssh_mp_mul(&t2, &P->x, &P->x);
  ssh_mp_mul(&t2, &P->x, &t2);
  ssh_mp_mod(&t2, &t2, &E->q);
  ssh_mp_sub(&t1, &t1, &t2);
  ssh_mp_mul(&t2, &P->x, &E->a);
  ssh_mp_mod(&t2, &t2, &E->q);
  ssh_mp_sub(&t1, &t1, &t2);
  ssh_mp_sub(&t1, &t1, &E->b);
  ssh_mp_mod(&t1, &t1, &E->q);

  if (ssh_mp_cmp_ui(&t1, 0) != 0)
    {
      ssh_mp_clear(&t1);
      ssh_mp_clear(&t2);
      return FALSE;
    }

  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2);
  
  /* Check that the order of the point is correct. */

  ssh_ecp_init_point(&Q, E);
  ssh_ecp_generic_mul(&Q, P, n, E);
  if (Q.z != 0)
    {
      ssh_ecp_clear_point(&Q);
      return FALSE;
    }

  /* For completeness check that the cardinality is correct. */

  ssh_mp_init(&t1);
  ssh_mp_div_q(&t1, &E->c, n);

  /* Try four different points and see if point at infinity will be
     found. */
  for (i = 0; i < 4; i++)
    {
      /* Generate a random point. */
      ssh_ecp_random_point(&Q, E);
      ssh_ecp_generic_mul(&Q, &Q, &t1, E);
      if (Q.z != 0)
	{
	  /* This must get to point at infinity or something is wrong. */
	  ssh_ecp_generic_mul(&Q, &Q, n, E);
	  if (Q.z != 0)
	    {
	      ssh_mp_clear(&t1);
	      ssh_ecp_clear_point(&Q);
	      return FALSE;
	    }
	}
    }
  ssh_mp_clear(&t1);
  ssh_ecp_clear_point(&Q);

  /* We have found that the curve satisfies all our tests. */
  return TRUE;
}

/* ecpmath.c */

