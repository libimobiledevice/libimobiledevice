/*
 * Copyright (c) 1997-2007  The Stanford SRP Authentication Project
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY 
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * IN NO EVENT SHALL STANFORD BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Redistributions in source or binary form must retain an intact copy
 * of this copyright notice.
 */

#ifndef SRP_AUX_H
#define SRP_AUX_H

#include "cstr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* BigInteger abstraction API */

#ifndef MATH_PRIV
typedef void * BigInteger;
typedef void * BigIntegerCtx;
typedef void * BigIntegerModAccel;
#endif

/*
 * Some functions return a BigIntegerResult.
 * Use BigIntegerOK to test for success.
 */
#define BIG_INTEGER_SUCCESS 0
#define BIG_INTEGER_ERROR -1
#define BigIntegerOK(v) ((v) == BIG_INTEGER_SUCCESS)
typedef int BigIntegerResult;

_TYPE( BigInteger ) BigIntegerFromInt P((unsigned int number));
_TYPE( BigInteger ) BigIntegerFromBytes P((const unsigned char * bytes,
					   int length));
#define BigIntegerByteLen(X) ((BigIntegerBitLen(X)+7)/8)
_TYPE( int ) BigIntegerToBytes P((BigInteger src,
				  unsigned char * dest, int destlen));
_TYPE( BigIntegerResult ) BigIntegerToCstr P((BigInteger src, cstr * dest));
_TYPE( BigIntegerResult ) BigIntegerToCstrEx P((BigInteger src, cstr * dest, int len));
_TYPE( BigIntegerResult ) BigIntegerToHex P((BigInteger src,
					     char * dest, int destlen));
_TYPE( BigIntegerResult ) BigIntegerToString P((BigInteger src,
						char * dest, int destlen,
						unsigned int radix));
_TYPE( int ) BigIntegerBitLen P((BigInteger b));
_TYPE( int ) BigIntegerCmp P((BigInteger c1, BigInteger c2));
_TYPE( int ) BigIntegerCmpInt P((BigInteger c1, unsigned int c2));
_TYPE( BigIntegerResult ) BigIntegerLShift P((BigInteger result, BigInteger x,
					      unsigned int bits));
_TYPE( BigIntegerResult ) BigIntegerAdd P((BigInteger result,
					   BigInteger a1, BigInteger a2));
_TYPE( BigIntegerResult ) BigIntegerAddInt P((BigInteger result,
					      BigInteger a1, unsigned int a2));
_TYPE( BigIntegerResult ) BigIntegerSub P((BigInteger result,
					   BigInteger s1, BigInteger s2));
_TYPE( BigIntegerResult ) BigIntegerSubInt P((BigInteger result,
					      BigInteger s1, unsigned int s2));
/* For BigIntegerMul{,Int}: result != m1, m2 */
_TYPE( BigIntegerResult ) BigIntegerMul P((BigInteger result, BigInteger m1,
					   BigInteger m2, BigIntegerCtx ctx));
_TYPE( BigIntegerResult ) BigIntegerMulInt P((BigInteger result,
					      BigInteger m1, unsigned int m2,
					      BigIntegerCtx ctx));
_TYPE( BigIntegerResult ) BigIntegerDivInt P((BigInteger result,
					      BigInteger d, unsigned int m,
					      BigIntegerCtx ctx));
_TYPE( BigIntegerResult ) BigIntegerMod P((BigInteger result, BigInteger d,
					   BigInteger m, BigIntegerCtx ctx));
_TYPE( unsigned int ) BigIntegerModInt P((BigInteger d, unsigned int m,
					  BigIntegerCtx ctx));
_TYPE( BigIntegerResult ) BigIntegerModMul P((BigInteger result,
					      BigInteger m1, BigInteger m2,
					      BigInteger m, BigIntegerCtx ctx));
_TYPE( BigIntegerResult ) BigIntegerModExp P((BigInteger result,
					      BigInteger base, BigInteger expt,
					      BigInteger modulus,
					      BigIntegerCtx ctx,
					      BigIntegerModAccel accel));
_TYPE( int ) BigIntegerCheckPrime P((BigInteger n, BigIntegerCtx ctx));

_TYPE( BigIntegerResult ) BigIntegerFree P((BigInteger b));
_TYPE( BigIntegerResult ) BigIntegerClearFree P((BigInteger b));

_TYPE( BigIntegerCtx ) BigIntegerCtxNew();
_TYPE( BigIntegerResult ) BigIntegerCtxFree P((BigIntegerCtx ctx));

_TYPE( BigIntegerModAccel ) BigIntegerModAccelNew P((BigInteger m,
						     BigIntegerCtx ctx));
_TYPE( BigIntegerResult ) BigIntegerModAccelFree P((BigIntegerModAccel accel));

_TYPE( BigIntegerResult ) BigIntegerInitialize();
_TYPE( BigIntegerResult ) BigIntegerFinalize();

_TYPE( BigIntegerResult ) BigIntegerUseEngine P((const char * engine));
_TYPE( BigIntegerResult ) BigIntegerReleaseEngine();

/* Miscellaneous functions - formerly in t_pwd.h */

/*
 * "t_random" is a cryptographic random number generator, which is seeded
 *   from various high-entropy sources and uses a one-way hash function
 *   in a feedback configuration.
 * "t_sessionkey" is the interleaved hash used to generate session keys
 *   from a large integer.
 * "t_mgf1" is an implementation of MGF1 using SHA1 to generate session
 *   keys from large integers, and is preferred over the older
 *   interleaved hash, and is used with SRP6.
 * "t_getpass" reads a password from the terminal without echoing.
 */
_TYPE( void ) t_random P((unsigned char *, unsigned));
_TYPE( void ) t_stronginitrand();
_TYPE( unsigned char * )
  t_sessionkey P((unsigned char *, unsigned char *, unsigned));
_TYPE( void ) t_mgf1 P((unsigned char *, unsigned,
			const unsigned char *, unsigned));
_TYPE( int ) t_getpass P((char *, unsigned, const char *));

#ifdef __cplusplus
}
#endif

#endif /* SRP_AUX_H */
