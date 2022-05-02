/*

sshwindist.h

Author: Samuli Mattila <vecna@ssh.fi>


Copyright (c) 1998 SSH Communications Security, Finland
                   All rights reserved

Library distribution defines in Windows environment. 

XXX These should be generated automatically from unix automakefiles.
    Currently they are generated manually

*/
#ifndef SSHWINDIST_H
#define SSHWINDIST_H


/////////////////////////////////////////////////////
// Distribution-time conditionals for the crypto library


// Hash functions.  GENHASH is needed if any are to be supported
#define SSHDIST_CRYPT_GENHASH
#define SSHDIST_CRYPT_MD5
#define SSHDIST_CRYPT_SHA
#define SSHDIST_CRYPT_RIPEMD160

// Symmetric ciphers.  GENCIPH is needed if any are to be supported.
// Requires SHA hash.
#define SSHDIST_CRYPT_GENCIPH
// includes both des and 3des
#define SSHDIST_CRYPT_DES
#define SSHDIST_CRYPT_BLOWFISH
#define SSHDIST_CRYPT_ARCFOUR
#define SSHDIST_CRYPT_CAST	
#define SSHDIST_CRYPT_IDEA
#define WITH_IDEA
#undef SSHDIST_CRYPT_SEAL
#undef SSHDIST_CRYPT_SAFER
#undef SSHDIST_CRYPT_RC5
#undef SSHDIST_CRYPT_DESX

// MAC (Message Authentication Code) algorithms.  GENMAC needed if any supported
#define SSHDIST_CRYPT_GENMAC
#define SSHDIST_CRYPT_HMAC
#undef SSHDIST_CRYPT_SSHMACS

// Public key algorithms.  GENPKCS needed if any supported
#define SSHDIST_CRYPT_GENPKCS
#define SSHDIST_CRYPT_RSA
#define WITH_RSA
// Discrete logarithm algorithms.  DL needed if any supported
#define SSHDIST_CRYPT_DL
#define SSHDIST_CRYPT_DSA
#define SSHDIST_CRYPT_DH
// Various key exchanges (requires DH).
#define SSHDIST_CRYPT_DLKEX
// Elliptic curves in prime fields
#undef SSHDIST_CRYPT_ECP

// Enable assembler optimizations in the crypto library. ASM needed if
// asm for any processors supported
#define SSHDIST_CRYPT_ASM
#define SSHDIST_CRYPT_ASM_I386

// Include secret sharing in crypto library
#define SSHDIST_CRYPT_SECRETSHARING

// Include compression support in crypto library
#define SSHDIST_CRYPT_COMPRESS

// IPSEC defines
#undef SSHDIST_IPSEC_TESTSUITE

// IPSEC Functional components
#undef SSHDIST_IPSEC_NAT
#undef SSHDIST_IPSEC_IPCOMP
#undef SSHDIST_IPSEC_LIAR

// IPSEC Platform support
#undef SSHDIST_IPSEC_NETBSD
#undef SSHDIST_IPSEC_SOLARIS
#define SSHDIST_IPSEC_WINNT

// Additional flags required by windows compilation
#define DEBUG_LIGHT
#define SSHDIST_WINDOWS
#define TCL_SIMPLE_ONLY
#define SSHDIST_WINDOWS
#define SSHDIST_ISAKMP_CFG_MODE
#define SSHIPSEC

#endif /* SSHWINDIST_H */
