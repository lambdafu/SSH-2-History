/*

  ec2nmath.c
  
  Author: Mika Kojo <mkojo@ssh.fi>

  Copyright (C) 1996,1997 SSH Communications Security Oy, Espoo, Finland
  All rights reserved.

  Created: Sat Nov 29 06:07:00 1997 [mkojo]

  Elliptic curve GF(2^n) arithmetics.

  We include several improvements introduced by Koblitz, Mueller,
  and Solinas. However, one might like to use the standard implementation
  most of the time, because that should be most robust against attacks.
  
  */

/*
 * $Id: ec2nmath.c,v 1.6 1998/06/24 13:25:19 kivinen Exp $
 * $Log: ec2nmath.c,v $
 * $EndLog$
 */

#include "sshincludes.h"
#include "sshmath-types.h"
#include "sshmp.h"
#include "gf2n.h"
#include "ecpmath.h" /* XXX */
#include "ec2nmath.h"
#include "sieve.h"

/* These function are here only for simplicity. XXX */

/* Compute the cardinality of the embedded curve using lucas sequence.
   This is pretty trivial implementation. */
void ssh_ec2n_expand_small_curve_trace(SshInt *card, int c, unsigned int n,
				       unsigned int k)
{
  SshInt c1, c2, t1, t2;
  int i;

  /* Compute trivially with Lucas sequence. */

  ssh_mp_init(&c1);
  ssh_mp_init(&c2);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);

  ssh_mp_set_si(card, c);
  ssh_mp_set_ui(&c1, 2);
  ssh_mp_set(&c2, card);
  
  for (i = 2; i <= k; i++)
    {
      ssh_mp_mul(&t1, &c2, card);
      ssh_mp_mul_ui(&t2, &c1, (1 << n));
      ssh_mp_set(&c1, &c2);
      ssh_mp_sub(&c2, &t1, &t2);
    }

  /* Compute the cardinality of the resultant curve. */
  ssh_mp_set_ui(card, 1);
  ssh_mp_mul_2exp(card, card, k*n);
  ssh_mp_add_ui(card, card, 1);
  ssh_mp_sub(card, card, &c2);
  
  ssh_mp_clear(&c1); 
  ssh_mp_clear(&c2);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2); 
}

/* Compute r^m - 1 as an expression of the form r + sr. */
void ssh_ec2n_compute_radic_values(SshInt *u_m, SshInt *u_m1,
				   unsigned int a, unsigned int n)
{
  SshInt c1, c2, t1, t2;
  int i;

  /* Compute trivially with Lucas sequence. */

  ssh_mp_init(&c1);
  ssh_mp_init(&c2);
  ssh_mp_init(&t1);
  ssh_mp_init(&t2);

  ssh_mp_set_ui(&c1, 0);
  ssh_mp_set_ui(&c2, 1);
  
  for (i = 2; i <= n; i++)
    {
      if (a == 0)
	ssh_mp_neg(&t1, &c2);
      else
	ssh_mp_set(&t1, &c2);
      ssh_mp_mul_2exp(&t2, &c1, 1);
      
      ssh_mp_set(&c1, &c2);
      ssh_mp_sub(&c2, &t1, &t2);
    }

  /* Compute the cardinality of the resultant curve. */

  /*
  printf(" u_m = ");
  ssh_mp_out_str(NULL, 10, &c2);
  printf(" u_m1 = ");
  ssh_mp_out_str(NULL, 10, &c1);
  printf("\n");*/

  ssh_mp_set(u_m, &c2);
  ssh_mp_mul_2exp(&c1, &c1, 1);
  ssh_mp_add_ui(&c1, &c1, 1);
  ssh_mp_neg(u_m1, &c1);

  /*
  printf(" u_m = ");
  ssh_mp_out_str(NULL, 10, u_m);
  printf(" u_m1 = ");
  ssh_mp_out_str(NULL, 10, u_m1);
  printf("\n");*/
  
  ssh_mp_clear(&c1); 
  ssh_mp_clear(&c2);
  ssh_mp_clear(&t1);
  ssh_mp_clear(&t2); 
}

/* Some curve handling. */

/* Curve management routines. */
int ssh_ec2n_set_curve_mp(SshEC2nCurve *E, const SshInt *q, const SshInt *a,
			  const SshInt *b, const SshInt *c)
{
  if (ssh_gf2n_init_mod_mp(&E->q, q) == 0)
    return 0;
  ssh_gf2n_init(&E->a, &E->q);
  ssh_gf2n_init(&E->b, &E->q);
  ssh_mp_init_set(&E->c, c);
  ssh_gf2n_set_mp(&E->a, a);
  ssh_gf2n_set_mp(&E->b, b);

  /* ABC variables. */
  ssh_mp_init_set_ui(&E->u_m, 0);
  ssh_mp_init_set_ui(&E->u_m1, 0);
  
  /* The frobenius variables. */
  E->f_c = 0;
  E->f_q = 0;
  E->f_k = 0;
  E->f_n = 0;
  E->f_a = 0;
  E->f_b = 0;
  return 1;
}

/* Curve management routines. */
int ssh_ec2n_set_curve_mp_frobenius(SshEC2nCurve *E, const SshInt *q,
				    const SshInt *a,
				    const SshInt *b,
				    int f_c,
				    unsigned int f_q,
				    unsigned int f_a,
				    unsigned int f_b)
{
  unsigned int k;

  k = ssh_mp_get_size(q, 2) - 1;
  if ((k % f_q) != 0)
    return 0;
  
  if (ssh_gf2n_init_mod_mp(&E->q, q) == 0)
    return 0;
  ssh_gf2n_init(&E->a, &E->q);
  ssh_gf2n_init(&E->b, &E->q);
  ssh_gf2n_set_mp(&E->a, a);
  ssh_gf2n_set_mp(&E->b, b);

  /* The frobenius variables. */
  E->f_c = f_c;
  E->f_q = f_q;
  E->f_k = k / f_q;
  E->f_n = E->f_k * E->f_q;
  E->f_a = f_a;
  E->f_b = f_b;

  /* ABC variables. */
  ssh_mp_init(&E->u_m);
  ssh_mp_init(&E->u_m1);
  ssh_ec2n_compute_radic_values(&E->u_m, &E->u_m1, E->f_a, E->f_k);
  
  /* Compute the cardinality. */  
  ssh_mp_init(&E->c);
  ssh_ec2n_expand_small_curve_trace(&E->c, E->f_c, E->f_q, E->f_k);
  return 1;
}

void ssh_ec2n_clear_curve(SshEC2nCurve *E)
{
  ssh_gf2n_clear(&E->a);
  ssh_gf2n_clear(&E->b);
  ssh_gf2n_clear_mod(&E->q);
  ssh_mp_clear(&E->c);

  ssh_mp_clear(&E->u_m);
  ssh_mp_clear(&E->u_m1);
  
  E->f_c = 0;
  E->f_q = 0;
  E->f_k = 0;
  E->f_n = 0;
  E->f_a = 0;
  E->f_b = 0;
}

Boolean ssh_ec2n_compare_curves(const SshEC2nCurve *E0,
				const SshEC2nCurve *E1)
{
  if (ssh_gf2n_cmp_mod(&E0->q, &E1->q) != 0)
    return FALSE;

  /* This is not exactly necessary. That is, we could just
     test with c, a, b and skip the rest. If the rest are different,
     that they are. But if the curves do work, it doesn't matter if
     we are computing it the fast way or the slow. */
  if (ssh_mp_cmp(&E0->c, &E1->c) != 0 ||
      ssh_gf2n_cmp(&E0->a, &E1->a) != 0 ||
      ssh_gf2n_cmp(&E0->b, &E1->b) != 0 ||
      ssh_mp_cmp(&E0->u_m, &E1->u_m) != 0 ||
      ssh_mp_cmp(&E0->u_m1, &E1->u_m1) != 0 ||
      E0->f_c != E1->f_c ||
      E0->f_q != E1->f_q ||
      E0->f_k != E1->f_k ||
      E0->f_n != E1->f_n ||
      E0->f_a != E1->f_a ||
      E0->f_b != E1->f_b)
    return FALSE;
  return TRUE;
}

void ssh_ec2n_copy_curve(SshEC2nCurve *E_dest,
			 const SshEC2nCurve *E_src)
{
  ssh_gf2n_init_mod_mod(&E_dest->q, &E_src->q);
  ssh_gf2n_init(&E_dest->a, &E_dest->q);
  ssh_gf2n_init(&E_dest->b, &E_dest->q);
  ssh_mp_init_set(&E_dest->c, &E_src->c);
  ssh_gf2n_set(&E_dest->a, &E_src->a);
  ssh_gf2n_set(&E_dest->b, &E_src->b);
  ssh_mp_init_set(&E_dest->u_m, &E_src->u_m);
  ssh_mp_init_set(&E_dest->u_m1, &E_src->u_m1);
  E_dest->f_q = E_src->f_q;
  E_dest->f_c = E_src->f_c;
  E_dest->f_k = E_src->f_k;
  E_dest->f_n = E_src->f_n;
  E_dest->f_a = E_src->f_a;
  E_dest->f_b = E_src->f_b;
}

/* Following routines implement EC over GF(2^n). Interface is a bit different
   from the case of EC over GF(p). */

void ssh_ec2n_init_point(SshEC2nPoint *P, const SshEC2nCurve *E)
{
  ssh_gf2n_init(&P->x, &E->q);
  ssh_gf2n_init(&P->y, &E->q);
  ssh_gf2n_set_ui(&P->x, 0);
  ssh_gf2n_set_ui(&P->y, 0);
  P->z = 0;
}

void ssh_ec2n_clear_point(SshEC2nPoint *P)
{
  ssh_gf2n_clear(&P->x);
  ssh_gf2n_clear(&P->y);
  P->z = 0;
}

void ssh_ec2n_set_identity(SshEC2nPoint *P)
{
  ssh_gf2n_set_ui(&P->x, 0);
  ssh_gf2n_set_ui(&P->y, 0);
  P->z = 0;
}

void ssh_ec2n_set_point_mp(SshEC2nPoint *P,
			   const SshInt *x, const SshInt *y,
			   int z)
{
  ssh_gf2n_set_mp(&P->x, x);
  ssh_gf2n_set_mp(&P->y, y);
  P->z = (z == 0 ? 0 : 1);
}

void ssh_ec2n_copy_point(SshEC2nPoint *Q, const SshEC2nPoint *P)
{
  ssh_gf2n_set(&Q->x, &P->x);
  ssh_gf2n_set(&Q->y, &P->y);
  Q->z = P->z;
}

void ssh_ec2n_negate_point(SshEC2nPoint *Q, const SshEC2nPoint *P,
			   const SshEC2nCurve *E)
{
  ssh_gf2n_set(&Q->x, &P->x);
  ssh_gf2n_add(&Q->y, &P->y, &P->x);
  Q->z = P->z;
}

Boolean ssh_ec2n_compare_points(const SshEC2nPoint *P, const SshEC2nPoint *Q)
{
  if (Q->z != P->z)
    return FALSE;

  if (P->z == 0)
    return TRUE;
  
  if (ssh_gf2n_cmp(&P->x, &Q->x) == 0 &&
      ssh_gf2n_cmp(&P->y, &Q->y) == 0)
    return TRUE;

  return FALSE;
}

/* We'll need the following to keep temporary context for additions. */
typedef struct
{
  SshGF2nElement t1, t2, t3, t4;
} SshEC2nContext;

void ssh_ec2n_init_context(SshEC2nContext *ctx, const SshEC2nCurve *E)
{
  ssh_gf2n_init(&ctx->t1, &E->q);
  ssh_gf2n_init(&ctx->t2, &E->q);
  ssh_gf2n_init(&ctx->t3, &E->q);
  ssh_gf2n_init(&ctx->t4, &E->q);
}

void ssh_ec2n_clear_context(SshEC2nContext *ctx)
{
  ssh_gf2n_clear(&ctx->t1);
  ssh_gf2n_clear(&ctx->t2);
  ssh_gf2n_clear(&ctx->t3);
  ssh_gf2n_clear(&ctx->t4);
}

/* It is my current belief that the doubling and addition routines are
   fast and sufficient. Indeed, I don't see any need for projective
   coordinate implementation. Nor normal basis nor other similar stuff. */

void ssh_ec2n_double(SshEC2nPoint *R, const SshEC2nPoint *P,
		     const SshEC2nCurve *E,
		     SshEC2nContext *ctx)
{
  /* Doubling a point */
  ssh_gf2n_invert(&ctx->t1, &P->x);
  ssh_gf2n_mul(&ctx->t2, &ctx->t1, &P->y);
  ssh_gf2n_add(&ctx->t2, &ctx->t2, &P->x);
  
  /* t2 is now the lambda */
  ssh_gf2n_square(&ctx->t1, &ctx->t2);
  ssh_gf2n_add(&ctx->t1, &ctx->t1, &ctx->t2);
  ssh_gf2n_add(&ctx->t1, &ctx->t1, &E->a);
  
  ssh_gf2n_square(&ctx->t3, &P->x);
  ssh_gf2n_add_ui(&ctx->t2, &ctx->t2, 1);
  ssh_gf2n_mul(&ctx->t4, &ctx->t2, &ctx->t1);
  ssh_gf2n_add(&ctx->t3, &ctx->t3, &ctx->t4);
  
  /* Output */
  ssh_gf2n_set(&R->x, &ctx->t1);
  ssh_gf2n_set(&R->y, &ctx->t3);
  R->z = 1;
}  

void ssh_ec2n_addition(SshEC2nPoint *R, const SshEC2nPoint *P,
		       const SshEC2nPoint *Q, const SshEC2nCurve *E,
		       SshEC2nContext *ctx)
{
  /* Compute lambda */
  ssh_gf2n_add(&ctx->t1, &P->x, &Q->x);
  ssh_gf2n_invert(&ctx->t2, &ctx->t1);

  ssh_gf2n_add(&ctx->t1, &P->y, &Q->y);
  ssh_gf2n_mul(&ctx->t3, &ctx->t1, &ctx->t2);

  /* Compute x */
  ssh_gf2n_square(&ctx->t1, &ctx->t3);
  ssh_gf2n_add(&ctx->t1, &ctx->t1, &ctx->t3);
  ssh_gf2n_add(&ctx->t1, &ctx->t1, &P->x);
  ssh_gf2n_add(&ctx->t1, &ctx->t1, &Q->x);
  ssh_gf2n_add(&ctx->t1, &ctx->t1, &E->a);

  /* Compute y */
  ssh_gf2n_add(&ctx->t2, &P->x, &ctx->t1);
  ssh_gf2n_mul(&ctx->t4, &ctx->t2, &ctx->t3);
  ssh_gf2n_add(&ctx->t4, &ctx->t4, &ctx->t1);
  ssh_gf2n_add(&ctx->t4, &ctx->t4, &P->y);

  /* Set for output */
  ssh_gf2n_set(&R->x, &ctx->t1);
  ssh_gf2n_set(&R->y, &ctx->t4);
  R->z = 1;
}

void ssh_ec2n_double_internal(SshEC2nPoint *R, const SshEC2nPoint *P,
			      const SshEC2nCurve *E,
			      SshEC2nContext *ctx)
{
  if (P->z == 0 || ssh_gf2n_cmp_ui(&P->x, 0) == 0)
    {
      ssh_ec2n_set_identity(R);
      return;
    }
  ssh_ec2n_double(R, P, E, ctx);
}

/* Addition with no allocation. */
void ssh_ec2n_add_internal(SshEC2nPoint *R, const SshEC2nPoint *P,
			   const SshEC2nPoint *Q,
			   const SshEC2nCurve *E, SshEC2nContext *ctx)
{
  if (P->z == 0)
    {
      ssh_gf2n_set(&R->x, &Q->x);
      ssh_gf2n_set(&R->y, &Q->y);
      R->z = Q->z;
      return;
    }
  if (Q->z == 0)
    {
      ssh_gf2n_set(&R->x, &P->x);
      ssh_gf2n_set(&R->y, &P->y);
      R->z = P->z;
      return;
    }

  if (ssh_gf2n_cmp(&P->x, &Q->x) == 0)
    {
      if (ssh_gf2n_cmp(&P->y, &Q->y) != 0 || ssh_gf2n_cmp_ui(&P->x, 0) == 0)
	{
	  R->z = 0;
	  return;
	}
      ssh_ec2n_double(R, P, E, ctx);
      return;
    }
  ssh_ec2n_addition(R, P, Q, E, ctx);
}

/* General addition, with the context initialization within. */
void ssh_ec2n_add(SshEC2nPoint *R, const SshEC2nPoint *P,
		  const SshEC2nPoint *Q, const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
  ssh_ec2n_init_context(&ctx, E);
  ssh_ec2n_add_internal(R, P, Q, E, &ctx);
  ssh_ec2n_clear_context(&ctx);
}

/* Generic multiplication. But then again, with GF(2^n) one can probably
   live with just the generic one? */
void ssh_ec2n_generic_mul(SshEC2nPoint *R, const SshEC2nPoint *P,
			  const SshInt *k,
			  const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
  SshEC2nPoint T, H, I;
  char *transform;
  int i;

  /* As with ECP case, obviously. */
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ec2n_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      return;
    }

  /* Initialize. */
  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&H, E);
  ssh_ec2n_init_point(&I, E);

  /* Initialize temporary variables. */
  ssh_ec2n_init_context(&ctx, E);

  /* Transform scalar multiplier to a signed representation. */
  i = ssh_mp_transform_mo(k, &transform) - 1;

  /* Set temporary projective points. */
  ssh_ec2n_copy_point(&H, P);
  ssh_ec2n_copy_point(&T, P);
  ssh_ec2n_negate_point(&I, &H, E);

  /* Multiply using transform bit-vector. */
  
  for (; i; i--)
    {
      ssh_ec2n_double_internal(&T, &T, E, &ctx);
      if (transform[i - 1])
	{
	  if (transform[i - 1] == -1)
	    ssh_ec2n_add_internal(&T, &T, &I, E, &ctx);
	  else
	    ssh_ec2n_add_internal(&T, &T, &H, E, &ctx);
	}
    }

  ssh_ec2n_copy_point(R, &T);

  /* Clear temporary space. */

  ssh_xfree(transform);
  
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&H);
  ssh_ec2n_clear_point(&I);

  ssh_ec2n_clear_context(&ctx);
}

/* Division in the ring Z[r] */
void ssh_ec2n_div_r(SshInt *w, SshInt *z, SshInt *x, SshInt *y,
		    const SshInt *u, const SshInt *v,
		    const SshInt *r, const SshInt *s,
		    int a)
{
  SshInt t, l, k, h;

  /* Initialize the needed number of temps. */
  ssh_mp_init(&t);
  ssh_mp_init(&l);
  ssh_mp_init(&k);
  ssh_mp_init(&h);

#if 0
  printf(" u = ");
  ssh_mp_out_str(NULL, 10, u);
  printf(" v = ");
  ssh_mp_out_str(NULL, 10, v);
  printf(" r = ");
  ssh_mp_out_str(NULL, 10, r);
  printf(" s = ");
  ssh_mp_out_str(NULL, 10, s);
  printf("\n");
#endif
  
  /* Compute: k = ru + su + 2sv and l = rv - su */
  ssh_mp_mul(&k,  r, u);
  ssh_mp_mul(&l,  r, v);
  ssh_mp_mul(&t,  s, u);
  ssh_mp_sub(&l, &l, &t);
  ssh_mp_add(&k, &k, &t);
  
  ssh_mp_mul(&t, s, v);
  ssh_mp_mul_2exp(&t, &t, 1);
  ssh_mp_add(&k, &k, &t);

  /* h = r^2 - (-1)^(1 - a)rs + 2s^2 */
  ssh_mp_square(&h, r);
  ssh_mp_square(&t, s);
  ssh_mp_mul_2exp(&t, &t, 1);
  ssh_mp_add(&h, &h, &t);
  ssh_mp_mul(&t, r, s);
  if (a)
    ssh_mp_sub(&h, &h, &t);
  else
    ssh_mp_add(&h, &h, &t);

  /* w = k/h, z = l/h */
  ssh_mp_div(w, &t, &k, &h);
  if (ssh_mp_signum(&t) < 0)
    ssh_mp_sub_ui(w, w, 1);
  ssh_mp_div(z, &t, &l, &h);
  if (ssh_mp_signum(&t) < 0)
    ssh_mp_sub_ui(z, z, 1);

  /* x = u - rw + 2sz, y = v - sw - rz - (-1)^(1 - a)sz */
  ssh_mp_mul(&t, r, w);
  ssh_mp_sub(x,  u, &t);
  
  ssh_mp_mul(&t, s, z);
  if (a == 0)
    ssh_mp_sub(y,  v, &t);
  else
    ssh_mp_add(y,  v, &t);
  ssh_mp_mul_2exp(&t, &t, 1);
  ssh_mp_add(x,  x, &t);

  ssh_mp_mul(&t, r, z);
  ssh_mp_sub(y,  y, &t);
  ssh_mp_mul(&t, s, w);
  ssh_mp_sub(y,  y, &t);

#if 0
  printf(" w = ");
  ssh_mp_out_str(NULL, 10, w);
  printf(" z = ");
  ssh_mp_out_str(NULL, 10, z);
  printf(" x = ");
  ssh_mp_out_str(NULL, 10, x);
  printf(" y = ");
  ssh_mp_out_str(NULL, 10, y);
  printf("\n");
#endif
  
  /* Free the temporary variables. */
  ssh_mp_clear(&t);
  ssh_mp_clear(&k);
  ssh_mp_clear(&h);
  ssh_mp_clear(&l);
}

/* Compute the non-adjacent form. */
int ssh_ec2n_radic_naf(char *table, unsigned int table_len,
		       SshInt *x0, SshInt *y0,
		       int a)
{
  SshInt x, y, swap;
  unsigned int i;
  int u, t, k;
  
  ssh_mp_init(&x);
  ssh_mp_init(&y);
  ssh_mp_init(&swap);

  ssh_mp_set(&x, x0);
  ssh_mp_set(&y, y0);

  for (i = 0; i < table_len &&
	 (ssh_mp_cmp_ui(&x, 0) != 0 ||
	  ssh_mp_cmp_ui(&y, 0) != 0); i++)
    {
      /*printf(" x = ");
      ssh_mp_out_str(NULL, 10, &x);
      printf(" y = ");
      ssh_mp_out_str(NULL, 10, &y);
      printf("\n"); */
      if ((ssh_mp_get_ui(&x) & 0x1) == 0)
	u = 0;
      else
	{
	  t = ssh_mp_get_ui(&x) & 3;
	  if (ssh_mp_signum(&x) < 0)
	    t = 4 - t;
	  k = (ssh_mp_get_ui(&y) & 1);
	  if (ssh_mp_signum(&y) < 0)
	    k = 2 - k;
	  k <<= 1;
	  u = 2 - ((t + 4 - k) & 3);
	}
      if (u < 0)
	ssh_mp_add_ui(&x, &x, -u);
      else
	ssh_mp_sub_ui(&x, &x, u);

      /*printf(" x = ");
      ssh_mp_out_str(NULL, 10, &x);
      printf(" y = ");
      ssh_mp_out_str(NULL, 10, &y);
      printf(" u = %d", u);
      printf("\n");*/
      table[i] = u;
      
      ssh_mp_div_2exp(&x, &x, 1);
      if (a)
	ssh_mp_sub(&y, &y, &x);
      else
	ssh_mp_add(&y, &y, &x);
      ssh_mp_neg(&x, &x);
      /* Swap. */
      ssh_mp_set(&swap, &x);
      ssh_mp_set(&x, &y);
      ssh_mp_set(&y, &swap);
    }
  /*printf("\n"); */
  
  ssh_mp_clear(&x);
  ssh_mp_clear(&y);
  ssh_mp_clear(&swap);
  
  /* Check for error. */
  if (i >= table_len)
    return 0;

  /* Return the table length. */
  return i;
}

/* Here we implement the fast Frobenius multiplication, when the
   curve is based on curve over small field. In fact, this is
   even fast Anomalous Binary Curve implementation, which uses the
   ideas by J. Solinas. */

void ssh_ec2n_mul_abc(SshEC2nPoint *R, const SshEC2nPoint *P,
		      const SshInt *k,
		      const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
  SshEC2nPoint T, I;
  SshInt w, z, x, y, v;
  unsigned int table_len;
  char *table;
  int i;

  /* As with ECP case, obviously. */
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      R->z = 0;
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      return;
    }

  /* Initialize. */
  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&I, E);

  /* Initialize temporary variables. */
  ssh_ec2n_init_context(&ctx, E);

  /* Compute the r-adic NAF (non-adjacent form). */
  
  ssh_mp_init(&w);
  ssh_mp_init(&z);
  ssh_mp_init(&x);
  ssh_mp_init(&y);
  ssh_mp_init(&v);

  /* Divide by U_m r - (2 U_m-1 + 1) */
  /* This can probably be optimized! */
  ssh_mp_set_ui(&v, 0);
  ssh_ec2n_div_r(&w, &z, &x, &y,
		 k, &v, &E->u_m1, &E->u_m,
		 1 - E->f_a);
  
  /* Compute the non-adjacent form. The amount of memory necessary is
     something like min(2*log_2 k + 1, log_2 #E(GF(2^n))). We are
     currently working with the worst case. */
  table_len = ssh_mp_get_size(k, 2)*2 + 10;
  table = ssh_xmalloc(table_len);
  i = ssh_ec2n_radic_naf(table, table_len,
			 &x, &y, 1 - E->f_a);
  if (i == 0)
    ssh_fatal("ssh_ec2n_mul_abc: allocated too little space.");
  
  /* Set up. */
  ssh_ec2n_negate_point(&I, P, E);
  if (i && table[i - 1])
    {
      /* printf("First = %d\n", table[i - 1]); */
      if (table[i - 1] == -1)
	ssh_ec2n_copy_point(&T, &I);
      else
	ssh_ec2n_copy_point(&T, P);
      i--;
    }

  /* Do the actual multiplication phase here. */
  for (; i; i--)
    {
      /* Do the Frobenius here. */
      if (T.z == 1)
	{
	  /* printf(" square\n"); */
	  ssh_gf2n_square(&T.x, &T.x);
	  ssh_gf2n_square(&T.y, &T.y);
	}
      /* printf(" %d \n", table[i - 1]); */
      if (table[i - 1])
	{
	  if (table[i - 1] == -1)
	    ssh_ec2n_addition(&T, &T, &I, E, &ctx);
	  else
	    ssh_ec2n_addition(&T, &T, P, E, &ctx);
	}
    }

  ssh_ec2n_copy_point(R, &T);

  /* Free everything! */

  ssh_xfree(table);
  
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&I);

  ssh_ec2n_clear_context(&ctx);

  ssh_mp_clear(&w);
  ssh_mp_clear(&z);
  ssh_mp_clear(&x);
  ssh_mp_clear(&y);
  ssh_mp_clear(&v);
}

void ssh_ec2n_mul_abc_2k_ary(SshEC2nPoint *R, const SshEC2nPoint *P,
			     const SshInt *k,
			     const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
#define K_ARY       4
  SshEC2nPoint T, I, H[5];
  SshInt w, z, x, y, v;
  unsigned int table_len;
  char *table;
  int i, mask, first, steps, zeros, j;

  /* As with ECP case, obviously. */
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      R->z = 0;
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      return;
    }

  /* Initialize. */
  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&I, E);

  /* Initialize temporary variables. */
  ssh_ec2n_init_context(&ctx, E);

  /* Compute the r-adic NAF (non-adjacent form). */
  
  ssh_mp_init(&w);
  ssh_mp_init(&z);
  ssh_mp_init(&x);
  ssh_mp_init(&y);
  ssh_mp_init(&v);

  /* Divide by U_m r - (2 U_m-1 + 1) */
  /* This can probably be optimized! */
  ssh_mp_set_ui(&v, 0);
  ssh_ec2n_div_r(&w, &z, &x, &y,
		 k, &v, &E->u_m1, &E->u_m,
		 1 - E->f_a);
  
  /* Compute the non-adjacent form. The amount of memory necessary is
     something like min(2*log_2 k + 1, log_2 #E(GF(2^n))). We are
     currently working with the worst case. */
  table_len = ssh_mp_get_size(k, 2)*2 + 10;
  table = ssh_xmalloc(table_len);
  i = ssh_ec2n_radic_naf(table, table_len,
			 &x, &y, 1 - E->f_a);
  if (i == 0)
    ssh_fatal("ssh_ec2n_mul_abc: allocated too little space.");

  /* Compute the table of multiples of points. */

  /* We have unrolled this because here we have to compute the
     NAF's and they are from somewhere beyond. */
  ssh_ec2n_init_point(&H[0], E);
  ssh_ec2n_copy_point(&H[0], P);
  ssh_ec2n_negate_point(&I, P, E);
  ssh_ec2n_copy_point(&T, P);
  if (T.z != 0)
    {
      ssh_gf2n_square(&T.x, &T.x);
      ssh_gf2n_square(&T.y, &T.y);

      ssh_gf2n_square(&T.x, &T.x);
      ssh_gf2n_square(&T.y, &T.y);
    }
  /* 3 */
  ssh_ec2n_init_point(&H[1], E);
  ssh_ec2n_addition(&H[1], &T, &I, E, &ctx);
  /* 5 */
  ssh_ec2n_init_point(&H[2], E);
  ssh_ec2n_addition(&H[2], &T, P, E, &ctx);
  /* r */
  if (T.z != 0)
    {
      ssh_gf2n_square(&T.x, &T.x);
      ssh_gf2n_square(&T.y, &T.y);
    }
  /* 7 */
  ssh_ec2n_init_point(&H[3], E);
  ssh_ec2n_addition(&H[3], &T, &I, E, &ctx);
  /* 9 */
  ssh_ec2n_init_point(&H[4], E);
  ssh_ec2n_addition(&H[4], &T, P, E, &ctx);
  
  /* Do the 2^k-ary binary sliding window phase! */
  for (first = 1; i;)
    {
      for (j = 0, mask = zeros = steps = 0; j < K_ARY && i; j++, i--)
	{
	  /* This is the usual algorithm. */
	  if (table[i - 1])
	    {
	      steps += zeros;
	      if (mask)
		{
		  while (zeros)
		    {
		      mask <<= 1;
		      zeros--;
		    }
		  mask <<= 1;
		}
	      mask += (int)table[i - 1];
	      steps++;
	    }
	  else
	    zeros++;
	}

      if (mask == 0)
	ssh_fatal("ssh_ec2n_mul_abc_2k_ary: failure in masking.");

      if (!first)
	{
	  for (j = 0; j < steps; j++)
	    if (T.z == 1)
	      {
		ssh_gf2n_square(&T.x, &T.x);
		ssh_gf2n_square(&T.y, &T.y);
	      }
	  if (mask < 0)
	    {
	      ssh_ec2n_negate_point(&I, &H[(-mask) >> 1], E);
	      ssh_ec2n_addition(&T, &T, &I, E, &ctx);
	    }
	  else
	    ssh_ec2n_addition(&T, &T, &H[mask >> 1], E, &ctx);
	}
      else
	{
	  if (mask < 0)
	    {
	      ssh_ec2n_negate_point(&I, &H[(-mask) >> 1], E);
	      ssh_ec2n_copy_point(&T, &I);
	    }
	  else
	    ssh_ec2n_copy_point(&T, &H[mask >> 1]);
	  first = 0;
	}

      /* Now do the double phase, with Frobenius! */
      while (zeros)
	{
	  if (T.z == 1)
	    {
	      ssh_gf2n_square(&T.x, &T.x);
	      ssh_gf2n_square(&T.y, &T.y);
	    }
	  zeros--;
	}

      while (i && table[i - 1] == 0)
	{
	  if (T.z == 1)
	    {
	      ssh_gf2n_square(&T.x, &T.x);
	      ssh_gf2n_square(&T.y, &T.y);
	    }
	  i--;
	}
    }
#if 0
  /* Old stuff. */
  
  /* Set up. */
  ssh_ec2n_negate_point(&I, P, E);
  if (i && table[i - 1])
    {
      /* printf("First = %d\n", table[i - 1]); */
      if (table[i - 1] == -1)
	ssh_ec2n_copy_point(&T, &I);
      else
	ssh_ec2n_copy_point(&T, P);
      i--;
    }

  /* Do the actual multiplication phase here. */
  for (; i; i--)
    {
      /* Do the Frobenius here. */
      if (T.z == 1)
	{
	  /* printf(" square\n"); */
	  ssh_gf2n_square(&T.x, &T.x);
	  ssh_gf2n_square(&T.y, &T.y);
	}
      /* printf(" %d \n", table[i - 1]); */
      if (table[i - 1])
	{
	  if (table[i - 1] == -1)
	    ssh_ec2n_addition(&T, &T, &I, E, &ctx);
	  else
	    ssh_ec2n_addition(&T, &T, P, E, &ctx);
	}
    }
#endif
  
  ssh_ec2n_copy_point(R, &T);

  /* Free everything! */

  ssh_xfree(table);

  for (i = 0; i < 5; i++)
    ssh_ec2n_clear_point(&H[i]);

#undef K_ARY
#undef K_ARY_SIZE
  
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&I);

  ssh_ec2n_clear_context(&ctx);

  ssh_mp_clear(&w);
  ssh_mp_clear(&z);
  ssh_mp_clear(&x);
  ssh_mp_clear(&y);
  ssh_mp_clear(&v);
}

/* This works only for curves defined also over small field.
   (Actually Frobenius endomorphism works for all, but this code
    fragment assumes E->f_q set, thus doesn't work correctly
    otherwise.) */
void ssh_ec2n_frobenius(SshEC2nPoint *R, const SshEC2nPoint *P,
			const SshEC2nCurve *E)
{
  unsigned int i;
  if (P->z == 0)
    {
      R->z = 0;
      return;
    }
  if (R != P)
    ssh_ec2n_copy_point(R, P);
  for (i = 0; i < E->f_q; i++)
    {
      ssh_gf2n_square(&R->x, &R->x);
      ssh_gf2n_square(&R->y, &R->y);
    }
}

/* Frobenius multiplication as invented by Volker Mueller. */
void ssh_ec2n_mul_frobenius(SshEC2nPoint *R, const SshEC2nPoint *P,
			    const SshInt *k,
			    const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
  SshEC2nPoint T, I;
  SshEC2nPoint *F;
  SshInt n, h, s1, s2;
  unsigned int q;
  int *r;
  int i, t, max;

  ssh_mp_init(&n);
  /* First reduce to suitable residue, just in case. */
  ssh_mp_mod(&n, k, &E->c);

  /* As with ECP case, obviously. */
  if (P->z == 0 || ssh_mp_cmp_ui(&n, 0) == 0)
    {
      R->z = 0;
      ssh_mp_clear(&n);
      return;
    }
  if (ssh_mp_cmp_ui(&n, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      ssh_mp_clear(&n);
      return;
    }

  /* Initialize. */
  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&I, E);

  /* Initialize temporary variables. */
  ssh_ec2n_init_context(&ctx, E);

  /* printf("nP table initialization.\n"); */
  
  /* Compute large enough table. */
  q = (1 << E->f_q);
  F = ssh_xmalloc(sizeof(SshEC2nPoint) * (q/2 + 1));
  ssh_ec2n_init_point(&F[0], E);
  ssh_ec2n_init_point(&F[1], E);
  ssh_ec2n_copy_point(&F[1], P);
  /* Special case the doubling of a point. */
  if (q/2 >= 2)
    {
      ssh_ec2n_init_point(&F[2], E);
      ssh_ec2n_double(&F[2], P, E, &ctx);
    }
  /* Other cases, here we can use the addition. */
  for (i = 3; i <= q/2; i++)
    {
      ssh_ec2n_init_point(&F[i], E);
      ssh_ec2n_addition(&F[i], &F[i - 1], P, E, &ctx);
    }

  /* Build Frobenius represenation of the exponent. */
  ssh_mp_init(&s1);
  ssh_mp_init(&s2);
  ssh_mp_init(&h);

  ssh_mp_set(&s1, &n);
  ssh_mp_set_ui(&s2, 0);

  /* Mueller says that most of time this is enough, but for some
     certain curves this might not be correct. */
  max = ssh_mp_get_size(&n, 2) + 10;
  r = ssh_xmalloc(sizeof(int) * max);
  for (i = 0; i < max; i++)
    {
      /* Check for the termination of this loop. */
      ssh_mp_abs(&n, &s1);
      ssh_mp_abs(&h, &s2);
      if (ssh_mp_cmp_ui(&n, q/2) <= 0 && 
	  ssh_mp_cmp_ui(&h, 1)   <= 0)
	break;

      ssh_mp_mod_2exp(&n, &s1, E->f_q);
      if (ssh_mp_cmp_ui(&n, 0) < 0)
	ssh_mp_add_ui(&n, &n, q);
      r[i] = ssh_mp_get_si(&n);
      if (r[i] > q/2)
	r[i] -= q;

      ssh_mp_set_si(&n, r[i]);
      ssh_mp_sub(&n, &n, &s1);
      ssh_mp_div_2exp(&n, &n, E->f_q);

      /* XXX Optimize this! */
      ssh_mp_set_si(&h, E->f_c);
      ssh_mp_mul(&h, &h, &n);
      ssh_mp_sub(&s1, &s2, &h);
      ssh_mp_set(&s2, &n);
    }

  if (i >= max)
    ssh_fatal("ssh_ec2n_mul_frobenius: allocated too small area.");

  /* Set the T. */
  t = ssh_mp_get_si(&s1);
  max = 0;
  if (t != 0)
    {
      if (t < 0)
	ssh_ec2n_negate_point(&T, &F[-t], E);
      else
	ssh_ec2n_copy_point(&T, &F[t]);
    }
  else
    max = 1;
  t = ssh_mp_get_si(&s2);
  if (t != 0)
    {
      ssh_ec2n_frobenius(&I, P, E);
      if (t < 0)
	ssh_ec2n_negate_point(&I, &I, E);
      ssh_ec2n_add_internal(&T, &T, &I, E, &ctx);
    }
  else
    max ++;

  /* Multiply using Frobenius transform vector. */
  
  /* Handle the case of T = point at infinity. */
  if (max == 2)
    {
      /* Skip all zero values at top. */
      for (; i && r[i - 1] == 0; i--)
	;
      if (i)
	{
	  t = r[i - 1];
	  if (t < 0)
	    {
	      ssh_ec2n_negate_point(&I, &F[-t], E);
	      ssh_ec2n_add_internal(&T, &T, &I, E, &ctx);
	    }
	  else
	    ssh_ec2n_add_internal(&T, &T, &F[t], E, &ctx);
	  i--;
	}
    }
  
  for (; i; i--)
    {
      ssh_ec2n_frobenius(&T, &T, E);
      t = r[i - 1];
      if (t)
	{
	  if (t < 0)
	    {
	      ssh_ec2n_negate_point(&I, &F[-t], E);
	      ssh_ec2n_addition(&T, &T, &I, E, &ctx);
	    }
	  else
	    ssh_ec2n_addition(&T, &T, &F[t], E, &ctx);
	}
    }
  
  ssh_ec2n_copy_point(R, &T);

  /* Clear temporary space. */

  ssh_mp_clear(&s1);
  ssh_mp_clear(&s2);
  ssh_mp_clear(&h);
  ssh_mp_clear(&n);
  
  ssh_xfree(r);
  for (i = 0; i <= q/2; i++)
    ssh_ec2n_clear_point(&F[i]);
  ssh_xfree(F);
  
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&I);
  ssh_ec2n_clear_context(&ctx);
}

#if 0
/* Specialized multiplication for points P of prime order, where
   0 <= k < #P. */

void ssh_ec2n_mul(SshEC2nPoint *R, const SshEC2nPoint *P,
		  const SshInt *k,
		  const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
  SshEC2nPoint T, H, I;
  char *transform;
  int i;
 
  /* Direct the computation to the faster Frobenius code, if possible. */
  switch (E->f_q)
    {
    case 0:
      break;
    case 1:
      ssh_ec2n_mul_abc_2k_ary(R, P, k, E);
      return;
    default:
      ssh_ec2n_mul_frobenius(R, P, k, E);
      return;
    }
  
  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ec2n_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      return;
    }
  
  /* Initialize points. */

  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&H, E);
  ssh_ec2n_init_point(&I, E);

  /* Initialize temporary variables. */

  ssh_ec2n_init_context(&ctx, E);

  /* Transform scalar multiplier to signed representation. */
  i = ssh_mp_transform_mo(k, &transform) - 1;
  
  /* Set temporary projective points. */
  
  ssh_ec2n_copy_point(&H, P);
  ssh_ec2n_copy_point(&T, &H);
  ssh_ec2n_negate_point(&I, &H, E);
  
  /* Multiply using transform bit-vector. */
  
  for (; i; i--)
    {
      ssh_ec2n_double(&T, &T, E, &ctx);
      if (transform[i - 1])
	{
	  if (transform[i - 1] == -1)
	    ssh_ec2n_addition(&T, &T, &I, E, &ctx);
	  else
	    ssh_ec2n_addition(&T, &T, &H, E, &ctx);
	}
    }
  
  /* Convert to affine coordinates. */
  
  ssh_ec2n_copy_point(R, &T);
  
  /* Clear temporary space. */

  ssh_xfree(transform);
  
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&H);
  ssh_ec2n_clear_point(&I);

  ssh_ec2n_clear_context(&ctx);
}

#else
#if 0
/* Doesn't work if k >= #P = some prime.

   NOTE, it seems that this function doesn't work if #P is not a prime!
   Actually I suspect that the problem is in doubling points and infact
   if the #P is divisible by 2 this doesn't work. Works is #P is prime.
   */

void ssh_ec2n_mul(SshEC2nPoint *R, const SshEC2nPoint *P,
		  const SshInt *k,
		  const SshEC2nCurve *E)
{
  SshEC2nContext ctx;
#define K_ARY      4
#define K_ARY_SIZE (1 << K_ARY)
  SshEC2nPoint T, H[K_ARY_SIZE], N;
  unsigned char b[K_ARY_SIZE];
  char *transform;
  unsigned int transform_index;
  unsigned int i, j, n, stack, negate, post_doubles;
  int m;
 
  /* Direct the computation to the faster Frobenius code, if possible. */
  switch (E->f_q)
    {
    case 0:
      break;
    case 1:
      ssh_ec2n_mul_abc_2k_ary(R, P, k, E);
      return;
    default:
      ssh_ec2n_mul_frobenius(R, P, k, E);
      return;
    }

  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ec2n_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      return;
    }
  
  /* Initialize points. */

  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&N, E);
  for (i = 0; i < K_ARY_SIZE; i++)
    ssh_ec2n_init_point(&H[i], E);
  memset(b, 0, K_ARY_SIZE);
  
  /* Initialize temporary variables. */

  ssh_ec2n_init_context(&ctx, E);

  /* Transform scalar multiplier into signed representation. */
  transform_index = ssh_mp_transform_kmov(k, &transform) - 1;
  
  /* Set temporary projective points. */

  ssh_ec2n_copy_point(&H[1], P);

  /* Set up table indicators. */
  b[0] = 0;
  b[1] = 1;
  
  /* Multiply using transform bit-vector. */

  /* 2^k-ary case. */

  ssh_ec2n_copy_point(&T, &H[1]);

  /* Do the binary sliding window part. */
  while (transform_index)
    {
      /* Slide along the transform table. */
      if (transform[transform_index - 1] == 0)
	{
	  ssh_ec2n_double(&T, &T, E, &ctx);

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
	    ssh_ec2n_double(&T, &T, E, &ctx);
	  
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
		      ssh_ec2n_double(&H[j], &H[i], E, &ctx);
		      b[j] = 1;
		      i = j;
		    }
		  if (m == 0)
		    ssh_fatal("ssh_ec2n_mul: internal error.");
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
		  ssh_ec2n_addition(&H[i],
				    &H[m], &H[n], E, &ctx);
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
	      ssh_ec2n_negate_point(&N, &H[m], E);
	      ssh_ec2n_addition(&T, &T, &N, E, &ctx);
	    }
	  else
	    {
	      ssh_ec2n_addition(&T, &T, &H[m], E, &ctx);
	    }

	  /* Double up the zeros. */
	  transform_index -= post_doubles;
	  while (post_doubles)
	    {
	      ssh_ec2n_double(&T, &T, E, &ctx);
	      post_doubles--;
	    }
	}
    }

  /* Convert to affine coordinates. */
  
  ssh_ec2n_copy_point(R, &T);
  
  /* Clear temporary space. */

  ssh_xfree(transform);
   
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&N);
  for (i = 0; i < K_ARY_SIZE; i++)
    ssh_ec2n_clear_point(&H[i]);

  ssh_ec2n_clear_context(&ctx);

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

void ssh_ec2n_mul(SshEC2nPoint *R, const SshEC2nPoint *P, const SshInt *k,
		  const SshEC2nCurve *E)
{
  SshEC2nContext t;
#define K_ARY      5
#define K_ARY_SIZE (1 << K_ARY)
  SshEC2nPoint T, H[K_ARY_SIZE/2], N;
  char *transform;
  unsigned int transform_index;
  unsigned int i, j, steps, zeros;
  int mask, first;

  /* Direct the computation to the faster Frobenius code, if possible. */
  switch (E->f_q)
    {
    case 0:
      break;
    case 1:
      ssh_ec2n_mul_abc_2k_ary(R, P, k, E);
      return;
    default:
      ssh_ec2n_mul_frobenius(R, P, k, E);
      return;
    }

  if (P->z == 0 || ssh_mp_cmp_ui(k, 0) == 0)
    {
      ssh_ec2n_set_identity(R);
      return;
    }
  if (ssh_mp_cmp_ui(k, 1) == 0)
    {
      ssh_ec2n_copy_point(R, P);
      return;
    }

  /* Initialize temporary variables. */
  ssh_ec2n_init_context(&t, E);
  
  /* Initialize points. */
  ssh_ec2n_init_point(&T, E);
  ssh_ec2n_init_point(&N, E);

  /* Set and initialize temporary projective points. */
  ssh_ec2n_init_point(&H[0], E);
  ssh_ec2n_copy_point(&H[0], P);
  ssh_ec2n_double(&T, &H[0], E, &t);
  for (i = 1; i < K_ARY_SIZE/2; i++)
    {
      ssh_ec2n_init_point(&H[i], E);
      ssh_ec2n_addition(&H[i], &H[i - 1], &T, E, &t);
    }

  /* Transform scalar multiplier into signed representation. */
  transform_index = ssh_mp_transform_kmov(k, &transform) - 1;
  
  /* Multiply using transform bit-vector. */

  ssh_ec2n_copy_point(&T, &H[0]);
  
  /* Do the main looping. */
  for (first = 1, i = transform_index + 1; i;)
    {
      for (j = 0, mask = zeros = steps = 0; j < K_ARY && i; j++, i--)
	{
	  if (transform[i - 1])
	    {
	      steps += zeros;
	      /* Check if multiply by 2 is necessary. */
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
	ssh_fatal("ssh_ec2n_mul: failure in handling the multiplier.");
      
      /* Handle the actual elliptic curve operations. */
      if (!first)
	{
	  for (j = 0; j < steps; j++)
	    ssh_ec2n_double(&T, &T, E, &t);

	  /* Notice, that we have tabulate all values nP where, n is
	     odd. Here we must have mask odd, and thus we can happily
	     get the correct place by shifting down by one. */
	  if (mask < 0)
	    {
	      ssh_ec2n_negate_point(&N, &H[(-mask) >> 1], E);
	      ssh_ec2n_addition(&T, &T, &N, E, &t);
	    }
	  else
	    ssh_ec2n_addition(&T, &T, &H[mask >> 1], E, &t);
	}
      else
	{
	  if (mask < 0)
	    {
	      ssh_ec2n_negate_point(&N, &H[(-mask) >> 1], E);
	      ssh_ec2n_copy_point(&T, &N);
	    }
	  else
	    ssh_ec2n_copy_point(&T, &H[mask >> 1]);
	  first = 0;
	}

      /* Now do the doubling phase. */
      while (zeros)
	{
	  ssh_ec2n_double(&T, &T, E, &t);
	  zeros--;
	}

      while (i && transform[i - 1] == 0)
	{
	  ssh_ec2n_double(&T, &T, E, &t);
	  i--;
	}
    }
  
  /* Convert to affine coordinates. */
  
  ssh_ec2n_copy_point(R, &T);
  
  /* Clear temporary space. */

  ssh_xfree(transform);
   
  ssh_ec2n_clear_point(&T);
  ssh_ec2n_clear_point(&N);
  for (i = 0; i < K_ARY_SIZE/2; i++)
    ssh_ec2n_clear_point(&H[i]);
  ssh_ec2n_clear_context(&t);

#undef K_ARY
#undef K_ARY_SIZE
}
#endif
#endif

/* XXX This following code used to be ec2naux.c now here! */

Boolean ssh_ec2n_restore_y(SshEC2nPoint *P, const SshEC2nCurve *E,
			   int bit)
{
  SshGF2nElement t1, t2, t3, t4;
  unsigned int size;
  Boolean rv = TRUE;
  
  ssh_gf2n_init(&t1, &E->q);
  ssh_gf2n_init(&t2, &E->q);
  ssh_gf2n_init(&t3, &E->q);
  ssh_gf2n_init(&t4, &E->q);

  size = ssh_gf2n_deg_mod(&E->q);
  
  if (ssh_gf2n_cmp_ui(&P->x, 0) == 0)
    {
      ssh_gf2n_exp_2exp(&P->y, &E->b, size - 1);
      goto finished;
    }

  ssh_gf2n_square(&t1, &P->x);
      
  ssh_gf2n_mul(&t2, &t1, &P->x);
  ssh_gf2n_mul(&t3, &t1, &E->a);
  ssh_gf2n_add(&t2, &t2, &t3);

  ssh_gf2n_add(&t2, &t2, &E->b);
  
  if (ssh_gf2n_cmp_ui(&t2, 0) == 0)
    {
      ssh_gf2n_set_ui(&P->y, 0);
      goto finished;
    }
  
  ssh_gf2n_invert(&t1, &P->x);
  ssh_gf2n_square(&t3, &t1);
  
  ssh_gf2n_mul(&t4, &t3, &t2);

  if (ssh_gf2n_quad_solve(&t1, &t4) == TRUE)
    {
      ssh_gf2n_add_ui(&t1, &t1,
		      (ssh_gf2n_get_ui(&t1) & 0x1) ^ (bit & 0x1));
      ssh_gf2n_mul(&P->y, &P->x, &t1);
      goto finished;
    }

  rv = FALSE;
finished:
  
  ssh_gf2n_clear(&t1);
  ssh_gf2n_clear(&t2);
  ssh_gf2n_clear(&t3);
  ssh_gf2n_clear(&t4);
  return rv;
}

void ssh_ec2n_random_point(SshEC2nPoint *P, const SshEC2nCurve *E)
{
  SshGF2nElement t1, t2, t3, t4;
  
  ssh_gf2n_init(&t1, &E->q);
  ssh_gf2n_init(&t2, &E->q);
  ssh_gf2n_init(&t3, &E->q);
  ssh_gf2n_init(&t4, &E->q);

  while (1)
    {
      /* Find random number */
      ssh_gf2n_poor_rand(&P->x);
      if (ssh_ec2n_restore_y(P, E, random() & 0x1) == TRUE)
	{
	  P->z = 1;
	  break;
	}
    }

  ssh_gf2n_clear(&t1);
  ssh_gf2n_clear(&t2);
  ssh_gf2n_clear(&t3);
  ssh_gf2n_clear(&t4);
}

Boolean ssh_ec2n_random_point_of_prime_order(SshEC2nPoint *P,
					     const SshInt *n,
					     const SshEC2nCurve *E)
{
  SshInt t;
  SshEC2nPoint Q;

  ssh_mp_init(&t);

  /* n must be factor of cardinality, either trivial or non-trivial. */
  ssh_mp_mod(&t, &E->c, n);

  if (ssh_mp_cmp_ui(&t, 0) != 0)
    {
      ssh_mp_clear(&t);
      return FALSE;
    }

  ssh_mp_div_q(&t, &E->c, n);

  /* Force to be a prime. Takes probably the most time in this routine. */
  if (!ssh_mp_is_probable_prime(n, 25))
    {
      ssh_mp_clear(&t);
      return FALSE;
    }

  ssh_ec2n_init_point(&Q, E);

  while (1)
    {
      /* Select a random point. */
      ssh_ec2n_random_point(&Q, E);
      ssh_ec2n_generic_mul(P, &Q, &t, E);
      if (P->z)
	break;
    }

  /* Verify that everything went fine (if it didn't then the curve
     must be invalid!) */
  ssh_ec2n_generic_mul(&Q, P, n, E);
  if (Q.z)
    {
      ssh_ec2n_clear_point(&Q);
      ssh_mp_clear(&t);
      return FALSE;
    }

  ssh_ec2n_clear_point(&Q);
  ssh_mp_clear(&t);
  return TRUE;
}

/* Brute force computation of the order of very small elliptic
   curve. Notice, that we are using the binary polynomials here, because
   our implementation of the standard polynomials basic GF(2^n) uses
   an optimizations which makes it fail here. */
unsigned int ssh_ec2n_small_curve_point_count(unsigned int iq, unsigned int ia,
					      unsigned int ib, unsigned int n)
{

  SshBPoly a, b, q, x, t1, t2, trace;
  unsigned int i, c, trace_a;

  ssh_bpoly_init(&a);
  ssh_bpoly_init(&b);
  ssh_bpoly_init(&q);
  ssh_bpoly_init(&x);
  ssh_bpoly_init(&t1);  
  ssh_bpoly_init(&t2);
  ssh_bpoly_init(&trace);

  /* Set it up. */
  ssh_bpoly_set_ui(&q, iq);
  ssh_bpoly_set_ui(&a, ia);
  ssh_bpoly_set_ui(&b, ib);
  
  /* The curve is:

     y^2 + xy = x^3 + ax^2 + b,

     thus

     (y/x)^2 + (y/x) = x + a + (b/x^2).

     We know that for

     z^2 + z = b, there exist a solution in z only if
     Tr(b) = 0. Thus we should compute

     Tr(x + a + (b/x^2)) and see whether it is zero or not.

     Also it is easily seen that

     Tr(x + a + (b/x^2)) = Tr(a) + Tr(x + (b/x^2)).

     The number of points in E is

     (0, sqrt{b}) + point at infinity +

     all such x for which Tr(x + a + (b/x^2)) = 0. 

     */

  ssh_bpoly_trace(&trace, &a, &q);
  if (ssh_bpoly_cmp_ui(&trace, 0) == 0)
    trace_a = 0;
  else
    trace_a = 1;
  
  for (i = 1, c = 0; i < (1 << n); i++)
    {
      /* Compute: x + b/x^2 */
      ssh_bpoly_set_ui(&x, i);
      ssh_bpoly_square(&t1, &x);
      ssh_bpoly_mod(&t1, &t1, &q);
      ssh_bpoly_invert(&t2, &t1, &q);
      ssh_bpoly_mul(&t2, &b, &t2);
      ssh_bpoly_mod(&t2, &t2, &q);
      ssh_bpoly_add(&t2, &t2, &x);

      /* Compute trace. */
      ssh_bpoly_trace(&trace, &t2, &q);
      if (ssh_bpoly_cmp_ui(&trace, 0) == 0)
	c++;
      else
	c--;
    }

  if (trace_a == 1)
    c = -c;
  c += 1 + (1 << n);
  
  ssh_bpoly_clear(&a);
  ssh_bpoly_clear(&b);
  ssh_bpoly_clear(&q);
  ssh_bpoly_clear(&x);
  ssh_bpoly_clear(&t1);
  ssh_bpoly_clear(&t2);
  ssh_bpoly_clear(&trace);
  
  return c;
}

/* This routine computes the embedding from the smaller elliptic curve
   to the larger one. The input is given in SshBPoly rather than
   in SshGF2nElement's because they are easier to manipulate. */
int ssh_ec2n_extension_embedding(SshGF2nElement *r1, SshGF2nElement *r2,
				 SshBPoly *e1, SshBPoly *e2,
				 SshBPoly *p, SshGF2nModuli *m)
{
  SshGF2nPoly f;
  SshGF2nElement gf_lambda, gfu, u, v, tv;
  unsigned int i;
  int rv = 1;

  /* Initialize a lot of variables. */
  ssh_gf2n_init(&gf_lambda, m);
  ssh_gf2n_init(&gfu, m);
  ssh_gf2n_init(&v, m);
  ssh_gf2n_init(&u, m);
  ssh_gf2n_init(&tv, m);

  ssh_gf2n_poly_init(&f, m);

  /* Convert the input field element to bigger polynomial. */
  for (i = 0; i < ssh_bpoly_deg(p); i++)
    if (ssh_bpoly_get_bit(p, i))
      ssh_gf2n_poly_setall(&f, SSH_GF2N_POLY_UI, i, 1, SSH_GF2N_POLY_END);

  /* Compute one random root of the polynomial. */
  ssh_gf2n_poly_random_root(&gf_lambda, &f);

  /* Verify that the root is really from the correct polynomial. */
  ssh_gf2n_poly_evaluate(&gfu, &f, &gf_lambda);
  if (ssh_gf2n_cmp_ui(&gfu, 0) != 0)
    rv = 0;
  /* If we failed we try anyway something. But return a sensible
     warning. */
  
  ssh_gf2n_set_ui(&u, 1);
  ssh_gf2n_set_ui(&v, 0);
  ssh_gf2n_set_ui(&tv, 0);
  
  for (i = 0; i < ssh_bpoly_deg(p) - 1; i++)
    {
      if (ssh_bpoly_get_bit(e1, i))
	ssh_gf2n_add(&v, &v, &u);
      if (ssh_bpoly_get_bit(e2, i))
	ssh_gf2n_add(&tv, &tv, &u);
      ssh_gf2n_mul(&u, &u, &gf_lambda);
    }

  ssh_gf2n_set(r1, &v);
  ssh_gf2n_set(r2, &tv);

  /* Free some stuff. */

  ssh_gf2n_poly_clear(&f);

  ssh_gf2n_clear(&u);
  ssh_gf2n_clear(&v);
  ssh_gf2n_clear(&tv);
  ssh_gf2n_clear(&gf_lambda);
  ssh_gf2n_clear(&gfu);
  return rv;
}

/* Here will be magic of generating curve over f_q and over f_q^n. That is
   this will compute the a, b for the elliptic curve over the smaller
   curve. It will transform the a, b of the smaller curve to that of
   the embedded curve. */
int ssh_ec2n_generate_frobenius_curve_internal(SshEC2nCurve *E,
					       unsigned int n, unsigned int k,
					       unsigned int a, unsigned int b)
{
  unsigned int q;
  SshBPoly p, x, y;
  int rv;
  
  if (n == 0 || k == 0 || b == 0)
    return 0;

  q = ssh_bpoly_find_small_irreducible(k);
  if (q == 0)
    return 0;

  ssh_bpoly_init(&p);
  ssh_bpoly_init(&x);
  ssh_bpoly_init(&y);
  
  ssh_bpoly_set_ui(&p, q);

  /* Now we'd like to compute the order of the elliptic curve
     over GF(2^n).
     */
  
  /* Compute the order (actually the trace) of the given curve. */
  E->f_q = k;
  E->f_c = (1 << k) + 1 - ssh_ec2n_small_curve_point_count(q, a, b, k);
  E->f_k = n;
  E->f_n = k * n;
  E->f_a = a;
  E->f_b = b;
  
  /* Now extend this trace to E(GF(2^(n*k))). */

  ssh_ec2n_expand_small_curve_trace(&E->c, E->f_c, k, n);
  
  /* Do the embedding! */
  ssh_bpoly_set_ui(&x, a);
  ssh_bpoly_set_ui(&y, b);

  /* Hope for success. */
  rv = 1;
  
  ssh_gf2n_init(&E->a, &E->q);
  ssh_gf2n_init(&E->b, &E->q);
  if (ssh_ec2n_extension_embedding(&E->a, &E->b, &x, &y, &p, &E->q) == 0)
    {
      ssh_gf2n_clear(&E->a);
      ssh_gf2n_clear(&E->b);
      rv = 0;
    }

  if (E->f_q == 1)
    {
      ssh_mp_init(&E->u_m);
      ssh_mp_init(&E->u_m1);
      ssh_ec2n_compute_radic_values(&E->u_m, &E->u_m1, E->f_a, E->f_k);
    }
  
  ssh_bpoly_clear(&x);
  ssh_bpoly_clear(&y);
  ssh_bpoly_clear(&p);
  return rv;
}

/* Generate a Frobenius curve. */
int ssh_ec2n_generate_frobenius_curve(SshEC2nCurve *E,
				      unsigned int size)
{
  unsigned int k, n, a, b;
  int bits[10], bits_count;
  SshSieve sieve;

  /* First make sure that the size is not something impossible to use!
     These bounds are given for now, and should be changed later!
     XXX */
  if (size <= SSH_WORD_BITS && size > 512)
    return 0;
  
  /* Try to factor the size. */
  ssh_sieve_allocate_ui(&sieve, size, 65536);
  for (k = 2, n = 0; k; k = ssh_sieve_next_prime(k, &sieve))
    if ((size % k) == 0)
      n = k;
  ssh_sieve_free(&sieve);

  /* Now divide out k. */
  if (n == 0)
    {
      /* size was a prime number, which is good. */
      n = size;
      k = 1;
    }
  else
    {
      k = size / n;
      /* Check whether k is way too large for fast Frobenius! */
      if (k > 7)
	return 0;
    }

  /* Now we have figured out nice values for n and k. */

  /* Seek for good irreducible polynomial! */

  /* First hope for trinomial. */
  bits_count = 3;
  if (ssh_bpoly_find_irreducible(size, 1,
				 bits, bits_count) == 0)
    {
      /* Doesn't exists. Then try pentanomial. */
      bits_count = 5;
      if (ssh_bpoly_find_irreducible(size, 1,
				     bits, bits_count) == 0)
	{
	  /* Doesn't exists either! This is impossible.
	     XXX Depends on the size one is searching for. 
	   */
	  return 0;
	}
    }

  /* We have now figured out a nice correct size irreducible. */
  ssh_gf2n_init_mod_bits(&E->q, bits, bits_count);

  /* Now randomly choose a and b. */
  a = random() % (1 << k);
  do
    b = random() % (1 << k);
  while (b == 0);
  
  ssh_mp_init(&E->c);
  ssh_mp_init(&E->u_m);
  ssh_mp_init(&E->u_m1);
  /* Then do the curve generation. */
  if (ssh_ec2n_generate_frobenius_curve_internal(E,
						 n, k,
						 a, b) == 0)
    {
      ssh_mp_clear(&E->c);
      ssh_mp_clear(&E->u_m);
      ssh_mp_clear(&E->u_m1);
      ssh_gf2n_clear_mod(&E->q);
      return 0;
    }
  
  return 1;
}

Boolean ssh_ec2n_verify_param(const SshEC2nCurve *E,
			      const SshEC2nPoint *P,
			      const SshInt       *n)
{
  /* To be written. */
  return TRUE;
}

/* ec2nmath.c */
