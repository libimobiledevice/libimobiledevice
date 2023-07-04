#ifndef T_SHA_H
#define T_SHA_H

#if     !defined(P)
#ifdef  __STDC__
#define P(x)    x
#else
#define P(x)    ()
#endif
#endif

#define SHA_DIGESTSIZE 20

#ifdef OPENSSL
#define OPENSSL_SHA 1
#endif

#ifdef TOMCRYPT
# include <tomcrypt.h>
# ifdef SHA1
#  define TOMCRYPT_SHA 1
# endif
#endif

#ifdef CRYPTOLIB
/* The SHA (shs) implementation in CryptoLib 1.x breaks when Update
 * is called multiple times, so we still use our own code.
 * Uncomment below if you think your copy of CryptoLib is fixed. */
/*#define CRYPTOLIB_SHA 1*/
#endif

#ifdef GCRYPT
# define GCRYPT_SHA 1
#endif

#ifdef MBEDTLS
# define MBEDTLS_SHA 1
#endif

#ifdef OPENSSL_SHA
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>

typedef EVP_MD_CTX* SHA1_CTX;
#define SHA1Init SHA1Init_openssl
#define SHA1Update SHA1Update_openssl
#define SHA1Final SHA1Final_openssl

typedef EVP_MD_CTX* SHA512_CTX;
#define SHA512Init SHA512Init_openssl
#define SHA512Update SHA512Update_openssl
#define SHA512Final SHA512Final_openssl

void SHA1Init_openssl(SHA1_CTX *ctx);
void SHA1Update_openssl(SHA1_CTX *ctx, const void *data, unsigned int len);
void SHA1Final_openssl(unsigned char digest[20], SHA1_CTX *ctx);

void SHA512Init_openssl(SHA512_CTX *ctx);
void SHA512Update_openssl(SHA512_CTX *ctx, const void *data, unsigned int len);
void SHA512Final_openssl(unsigned char digest[64], SHA1_CTX *ctx);
#else /* for OpenSSL < 3.0 */
#include <openssl/sha.h>

typedef SHA_CTX SHA1_CTX;
#define SHA1Init SHA1_Init
#define SHA1Update SHA1_Update
#define SHA1Final SHA1_Final

#define SHA512Init SHA512_Init
#define SHA512Update SHA512_Update
#define SHA512Final SHA512_Final
#endif /* for OpenSSL < 3.0 */
#elif defined(TOMCRYPT_SHA)
/* mycrypt.h already included above */

typedef hash_state SHA1_CTX;
#define SHA1Init sha1_init
#define SHA1Update sha1_process
#define SHA1Final(D,C) sha1_done(C,D)

#elif defined(GCRYPT_SHA)
#include "gcrypt.h"

typedef gcry_md_hd_t SHA1_CTX;
#define SHA1Init SHA1Init_gcry
#define SHA1Update SHA1Update_gcry
#define SHA1Final SHA1Final_gcry
typedef gcry_md_hd_t SHA512_CTX;
#define SHA512Init SHA512Init_gcry
#define SHA512Update SHA512Update_gcry
#define SHA512Final SHA512Final_gcry

void SHA1Init_gcry(SHA1_CTX * ctx);
void SHA1Update_gcry(SHA1_CTX * ctx, const void *data, unsigned int len);
void SHA1Final_gcry(unsigned char digest[20], SHA1_CTX * ctx);

void SHA512Init_gcry(SHA512_CTX * ctx);
void SHA512Update_gcry(SHA512_CTX * ctx, const void *data, unsigned int len);
void SHA512Final_gcry(unsigned char digest[64], SHA512_CTX * ctx);

#elif defined(MBEDTLS_SHA)
#include <mbedtls/md.h>

typedef mbedtls_md_context_t SHA1_CTX;
#define SHA1Init SHA1Init_mbed
#define SHA1Update SHA1Update_mbed
#define SHA1Final SHA1Final_mbed

typedef mbedtls_md_context_t SHA512_CTX;
#define SHA512Init SHA512Init_mbed
#define SHA512Update SHA512Update_mbed
#define SHA512Final SHA512Final_mbed

void SHA1Init_mbed(SHA1_CTX * ctx);
void SHA1Update_mbed(SHA1_CTX * ctx, const void *data, unsigned int len);
void SHA1Final_mbed(unsigned char digest[20], SHA1_CTX * ctx);

void SHA512Init_mbed(SHA512_CTX * ctx);
void SHA512Update_mbed(SHA512_CTX * ctx, const void *data, unsigned int len);
void SHA512Final_mbed(unsigned char digest[64], SHA512_CTX * ctx);

#elif defined(CRYPTOLIB_SHA)
#include "libcrypt.h"

typedef SHS_CTX SHA1_CTX;
#define SHA1Init shsInit
#define SHA1Update shsUpdate
#define SHA1Final shsFinalBytes

void shsFinalBytes P((unsigned char digest[20], SHS_CTX* context));

#else
typedef unsigned int uint32;

typedef struct {
    uint32 state[5];
    uint32 count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init P((SHA1_CTX* context));
void SHA1Update P((SHA1_CTX* context, const unsigned char* data, unsigned int len));
void SHA1Final P((unsigned char digest[20], SHA1_CTX* context));
#endif /* !OPENSSL && !CRYPTOLIB */

#endif /* T_SHA_H */
