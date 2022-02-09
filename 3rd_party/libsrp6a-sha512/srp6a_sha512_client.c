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
#include "t_defines.h"
#include "srp.h"
#include "t_sha.h"

/*
 * SRP-6/6a has two minor refinements relative to SRP-3/RFC2945:
 * 1. The "g^x" value is multipled by three in the client's
 *    calculation of its session key.
 *    SRP-6a: The "g^x" value is multiplied by the hash of
 *            N and g in the client's session key calculation.
 * 2. The value of u is taken as the hash of A and B,
 *    instead of the top 32 bits of the hash of B.
 *    This eliminates the old restriction where the
 *    server had to receive A before it could send B.
 */

/****************************/
#define SHA512_DIGESTSIZE 64
#define SRP6_SHA512_KEY_LEN 64

/*
 * The client keeps track of the running hash
 * state via SHA512_CTX structures pointed to by the
 * meth_data pointer.  The "hash" member is the hash value that
 * will be sent to the other side; the "ckhash" member is the
 * hash value expected from the other side.
 */
struct sha512_client_meth_st {
  SHA512_CTX hash;
  SHA512_CTX ckhash;
  unsigned char k[SRP6_SHA512_KEY_LEN];
};

#define SHA512_CLIENT_CTXP(srp)    ((struct sha512_client_meth_st *)(srp)->meth_data)

static SRP_RESULT
srp6a_sha512_client_init(SRP * srp)
{
  srp->magic = SRP_MAGIC_CLIENT;
  srp->flags = SRP_FLAG_MOD_ACCEL | SRP_FLAG_LEFT_PAD;
  srp->meth_data = malloc(sizeof(struct sha512_client_meth_st));
  SHA512Init(&SHA512_CLIENT_CTXP(srp)->hash);
  SHA512Init(&SHA512_CLIENT_CTXP(srp)->ckhash);
  return SRP_SUCCESS;
}

static SRP_RESULT
srp6_sha512_client_finish(SRP * srp)
{
  if(srp->meth_data) {
    memset(srp->meth_data, 0, sizeof(struct sha512_client_meth_st));
    free(srp->meth_data);
  }
  return SRP_SUCCESS;
}

static SRP_RESULT
srp6_sha512_client_params(SRP * srp, const unsigned char * modulus, int modlen,
		   const unsigned char * generator, int genlen,
		   const unsigned char * salt, int saltlen)
{
  int i;
  unsigned char buf1[SHA512_DIGESTSIZE], buf2[SHA512_DIGESTSIZE];
  SHA512_CTX ctxt;

  /* Fields set by SRP_set_params */

  /* Update hash state */
  SHA512Init(&ctxt);
  SHA512Update(&ctxt, modulus, modlen);
  SHA512Final(buf1, &ctxt);	/* buf1 = H(modulus) */

  SHA512Init(&ctxt);
  SHA512Update(&ctxt, generator, genlen);
  SHA512Final(buf2, &ctxt);	/* buf2 = H(generator) */

  for(i = 0; i < sizeof(buf1); ++i)
    buf1[i] ^= buf2[i];		/* buf1 = H(modulus) xor H(generator) */

  /* hash: H(N) xor H(g) */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash, buf1, sizeof(buf1));

  SHA512Init(&ctxt);
  SHA512Update(&ctxt, srp->username->data, srp->username->length);
  SHA512Final(buf1, &ctxt);	/* buf1 = H(user) */

  /* hash: (H(N) xor H(g)) | H(U) */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash, buf1, sizeof(buf1));

  /* hash: (H(N) xor H(g)) | H(U) | s */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash, salt, saltlen);

  return SRP_SUCCESS;
}

static SRP_RESULT
srp6_sha512_client_auth(SRP * srp, const unsigned char * a, int alen)
{
  /* On the client, the authenticator is the raw password-derived hash */
  srp->password = BigIntegerFromBytes(a, alen);

  /* verifier = g^x mod N */
  srp->verifier = BigIntegerFromInt(0);
  BigIntegerModExp(srp->verifier, srp->generator, srp->password, srp->modulus, srp->bctx, srp->accel);

  return SRP_SUCCESS;
}

static SRP_RESULT
srp6_sha512_client_passwd(SRP * srp, const unsigned char * p, int plen)
{
  SHA512_CTX ctxt;
  unsigned char dig[SHA512_DIGESTSIZE];
  int r;

  SHA512Init(&ctxt);
  SHA512Update(&ctxt, srp->username->data, srp->username->length);
  SHA512Update(&ctxt, ":", 1);
  SHA512Update(&ctxt, p, plen);
  SHA512Final(dig, &ctxt);	/* dig = H(U | ":" | P) */

  SHA512Init(&ctxt);
  SHA512Update(&ctxt, srp->salt->data, srp->salt->length);
  SHA512Update(&ctxt, dig, sizeof(dig));
  SHA512Final(dig, &ctxt);	/* dig = H(s | H(U | ":" | P)) */
  memset(&ctxt, 0, sizeof(ctxt));

  r = SRP_set_authenticator(srp, dig, sizeof(dig));
  memset(dig, 0, sizeof(dig));

  return r;
}

static SRP_RESULT
srp6_sha512_client_genpub(SRP * srp, cstr ** result)
{
  cstr * astr;
  int slen = (SRP_get_secret_bits(BigIntegerBitLen(srp->modulus)) + 7) / 8;

  if(result == NULL)
    astr = cstr_new();
  else {
    if(*result == NULL)
      *result = cstr_new();
    astr = *result;
  }

  cstr_set_length(astr, BigIntegerByteLen(srp->modulus));
  t_random((unsigned char*)astr->data, slen);
  srp->secret = BigIntegerFromBytes((const unsigned char*)astr->data, slen);
  /* Force g^a mod n to "wrap around" by adding log[2](n) to "a". */
  BigIntegerAddInt(srp->secret, srp->secret, BigIntegerBitLen(srp->modulus));
  /* A = g^a mod n */
  srp->pubkey = BigIntegerFromInt(0);
  BigIntegerModExp(srp->pubkey, srp->generator, srp->secret, srp->modulus, srp->bctx, srp->accel);
  BigIntegerToCstr(srp->pubkey, astr);

  /* hash: (H(N) xor H(g)) | H(U) | s | A */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash, astr->data, astr->length);
  /* ckhash: A */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->ckhash, astr->data, astr->length);

  if(result == NULL)	/* astr was a temporary */
    cstr_clear_free(astr);

  return SRP_SUCCESS;
}

static SRP_RESULT
srp6_sha512_client_key_ex(SRP * srp, cstr ** result,
		   const unsigned char * pubkey, int pubkeylen, BigInteger k)
{
  SHA512_CTX ctxt;
  unsigned char dig[SHA512_DIGESTSIZE];
  BigInteger gb, e;
  cstr * s;
  int modlen;

  modlen = BigIntegerByteLen(srp->modulus);
  if(pubkeylen > modlen)
    return SRP_ERROR;

  /* Compute u from client's and server's values */
  SHA512Init(&ctxt);
  /* Use s as a temporary to store client's value */
  s = cstr_new();
  if(srp->flags & SRP_FLAG_LEFT_PAD) {
    BigIntegerToCstrEx(srp->pubkey, s, modlen);
    SHA512Update(&ctxt, s->data, s->length);
    if(pubkeylen < modlen) {
      memcpy(s->data + (modlen - pubkeylen), pubkey, pubkeylen);
      memset(s->data, 0, modlen - pubkeylen);
      SHA512Update(&ctxt, s->data, modlen);
    }
    else
      SHA512Update(&ctxt, pubkey, pubkeylen);
  }
  else {
    BigIntegerToCstr(srp->pubkey, s);
    SHA512Update(&ctxt, s->data, s->length);
    SHA512Update(&ctxt, pubkey, pubkeylen);
  }
  SHA512Final(dig, &ctxt);
  srp->u = BigIntegerFromBytes(dig, SHA512_DIGESTSIZE);

  /* hash: (H(N) xor H(g)) | H(U) | s | A | B */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash, pubkey, pubkeylen);

  gb = BigIntegerFromBytes(pubkey, pubkeylen);
  /* reject B == 0, B >= modulus */
  if(BigIntegerCmp(gb, srp->modulus) >= 0 || BigIntegerCmpInt(gb, 0) == 0) {
    BigIntegerFree(gb);
    cstr_clear_free(s);
    return SRP_ERROR;
  }
  e = BigIntegerFromInt(0);
  srp->key = BigIntegerFromInt(0);
  /* unblind g^b (mod N) */
  BigIntegerSub(srp->key, srp->modulus, srp->verifier);
  /* use e as temporary, e == -k*v (mod N) */
  BigIntegerMul(e, k, srp->key, srp->bctx);
  BigIntegerAdd(e, e, gb);
  BigIntegerMod(gb, e, srp->modulus, srp->bctx);

  /* compute gb^(a + ux) (mod N) */
  BigIntegerMul(e, srp->password, srp->u, srp->bctx);
  BigIntegerAdd(e, e, srp->secret);	/* e = a + ux */

  BigIntegerModExp(srp->key, gb, e, srp->modulus, srp->bctx, srp->accel);
  BigIntegerClearFree(e);
  BigIntegerClearFree(gb);

  /* convert srp->key into a session key, update hash states */
  BigIntegerToCstr(srp->key, s);
  SHA512Init(&ctxt);
  SHA512Update(&ctxt, s->data, s->length);
  SHA512Final((unsigned char*)&SHA512_CLIENT_CTXP(srp)->k, &ctxt);
  cstr_clear_free(s);

  /* hash: (H(N) xor H(g)) | H(U) | s | A | B | K */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash, SHA512_CLIENT_CTXP(srp)->k, SRP6_SHA512_KEY_LEN);
  /* hash: (H(N) xor H(g)) | H(U) | s | A | B | K | ex_data */
  if(srp->ex_data->length > 0)
    SHA512Update(&SHA512_CLIENT_CTXP(srp)->hash,
	       srp->ex_data->data, srp->ex_data->length);
  if(result) {
    if(*result == NULL)
      *result = cstr_new();
    cstr_setn(*result, (const char*)SHA512_CLIENT_CTXP(srp)->k, SRP6_SHA512_KEY_LEN);
  }

  return SRP_SUCCESS;
}

static SRP_RESULT
srp6a_sha512_client_key(SRP * srp, cstr ** result,
		 const unsigned char * pubkey, int pubkeylen)
{
  SRP_RESULT ret;
  BigInteger k;
  cstr * s;
  SHA512_CTX ctxt;
  unsigned char dig[SHA512_DIGESTSIZE];

  SHA512Init(&ctxt);
  s = cstr_new();
  BigIntegerToCstr(srp->modulus, s);
  SHA512Update(&ctxt, s->data, s->length);
  if(srp->flags & SRP_FLAG_LEFT_PAD)
    BigIntegerToCstrEx(srp->generator, s, s->length);
  else
    BigIntegerToCstr(srp->generator, s);
  SHA512Update(&ctxt, s->data, s->length);
  SHA512Final(dig, &ctxt);
  cstr_free(s);

  k = BigIntegerFromBytes(dig, SHA512_DIGESTSIZE);
  if(BigIntegerCmpInt(k, 0) == 0)
    ret = SRP_ERROR;
  else
    ret = srp6_sha512_client_key_ex(srp, result, pubkey, pubkeylen, k);
  BigIntegerClearFree(k);
  return ret;
}

static SRP_RESULT
srp6_sha512_client_verify(SRP * srp, const unsigned char * proof, int prooflen)
{
  unsigned char expected[SHA512_DIGESTSIZE];

  SHA512Final(expected, &SHA512_CLIENT_CTXP(srp)->ckhash);
  if(prooflen == SHA512_DIGESTSIZE && memcmp(expected, proof, prooflen) == 0)
    return SRP_SUCCESS;
  else
    return SRP_ERROR;
}

static SRP_RESULT
srp6_sha512_client_respond(SRP * srp, cstr ** proof)
{
  if(proof == NULL)
    return SRP_ERROR;

  if(*proof == NULL)
    *proof = cstr_new();

  /* proof contains client's response */
  cstr_set_length(*proof, SHA512_DIGESTSIZE);
  SHA512Final((unsigned char*)(*proof)->data, &SHA512_CLIENT_CTXP(srp)->hash);

  /* ckhash: A | M | K */
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->ckhash, (*proof)->data, (*proof)->length);
  SHA512Update(&SHA512_CLIENT_CTXP(srp)->ckhash, SHA512_CLIENT_CTXP(srp)->k, SRP6_SHA512_KEY_LEN);
  return SRP_SUCCESS;
}

static SRP_METHOD srp6a_sha512_client_meth = {
  "SRP-6a sha512 client (tjw)",
  srp6a_sha512_client_init,
  srp6_sha512_client_finish,
  srp6_sha512_client_params,
  srp6_sha512_client_auth,
  srp6_sha512_client_passwd,
  srp6_sha512_client_genpub,
  srp6a_sha512_client_key,
  srp6_sha512_client_verify,
  srp6_sha512_client_respond,
  NULL
};

_TYPE( SRP_METHOD * )
SRP6a_sha512_client_method()
{
  return &srp6a_sha512_client_meth;
}
