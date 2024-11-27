/*
 * lockdown-cu.c
 * com.apple.mobile.lockdownd service CU additions
 *
 * Copyright (c) 2021 Nikias Bassen, All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#define _GNU_SOURCE 1
#define __USE_GNU 1
#include <stdio.h>
#include <ctype.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

#include <plist/plist.h>

#include "idevice.h"
#include "lockdown.h"
#include "common/debug.h"

#ifdef HAVE_WIRELESS_PAIRING

#include <libimobiledevice-glue/utils.h>
#include <libimobiledevice-glue/socket.h>
#include <libimobiledevice-glue/opack.h>
#include <libimobiledevice-glue/tlv.h>

#if defined(HAVE_OPENSSL)
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#if defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x2030200fL)
#include <openssl/chacha.h>
#include <openssl/poly1305.h>
#endif
#elif defined(HAVE_GCRYPT)
#include <gcrypt.h>
#elif defined(HAVE_MBEDTLS)
#include <mbedtls/md.h>
#include <mbedtls/chachapoly.h>
#endif

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
#endif

#include "property_list_service.h"
#include "common/userpref.h"

#include "endianness.h"

#include "srp.h"
#include "ed25519.h"

/* {{{ SRP6a parameters */
static const unsigned char kSRPModulus3072[384] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
	0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
	0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
	0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
	0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
	0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
	0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11, 0x7c, 0x4b, 0x1f, 0xe6,
	0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d, 0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05,
	0x98, 0xda, 0x48, 0x36, 0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
	0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56, 0x20, 0x85, 0x52, 0xbb,
	0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d, 0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04,
	0xf1, 0x74, 0x6c, 0x08, 0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
	0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2, 0xec, 0x07, 0xa2, 0x8f,
	0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9, 0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18,
	0x39, 0x95, 0x49, 0x7c, 0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
	0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d, 0x04, 0x50, 0x7a, 0x33,
	0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64, 0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a,
	0x8a, 0xea, 0x71, 0x57, 0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
	0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0, 0x4a, 0x25, 0x61, 0x9d,
	0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b, 0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64,
	0xd8, 0x76, 0x02, 0x73, 0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
	0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0, 0xba, 0xd9, 0x46, 0xe2,
	0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31, 0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e,
	0x4b, 0x82, 0xd1, 0x20, 0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static const unsigned char kSRPGenerator5 = 5;
/* }}} */

/* {{{ HKDF */
#if defined(HAVE_OPENSSL)
#define MD_ALGO_SHA512 EVP_sha512()
typedef const EVP_MD* MD_ALGO_TYPE_T;
#define MD_ALGO_DIGEST_SIZE EVP_MD_size
#define MD_MAX_DIGEST_SIZE EVP_MAX_MD_SIZE

#elif defined(HAVE_GCRYPT)
#define MD_ALGO_SHA512 GCRY_MD_SHA512
typedef int MD_ALGO_TYPE_T;
#define MD_ALGO_DIGEST_SIZE gcry_md_get_algo_dlen
#define MD_MAX_DIGEST_SIZE 64

static void HMAC(MD_ALGO_TYPE_T md, unsigned char* key, unsigned int key_len, unsigned char* data, unsigned int data_len, unsigned char* out, unsigned int* out_len)
{
	gcry_md_hd_t hd;
	if (gcry_md_open(&hd, md, GCRY_MD_FLAG_HMAC)) {
		debug_info("gcry_md_open() failed");
		return;
	}
	if (gcry_md_setkey(hd, key, key_len)) {
		gcry_md_close (hd);
		debug_info("gcry_md_setkey() failed");
		return;
	}
	gcry_md_write(hd, data, data_len);

	unsigned char* digest = gcry_md_read(hd, md);
	if (!digest) {
		gcry_md_close(hd);
		debug_info("gcry_md_read() failed");
		return;
	}

	*out_len = gcry_md_get_algo_dlen(md);
	memcpy(out, digest, *out_len);
	gcry_md_close(hd);
}
#elif defined(HAVE_MBEDTLS)
#define MD_ALGO_SHA512 MBEDTLS_MD_SHA512
typedef mbedtls_md_type_t MD_ALGO_TYPE_T;
#define MD_ALGO_DIGEST_SIZE(x) mbedtls_md_get_size(mbedtls_md_info_from_type(x))
#define MD_MAX_DIGEST_SIZE MBEDTLS_MD_MAX_SIZE

static void HMAC(MD_ALGO_TYPE_T md, unsigned char* key, unsigned int key_len, unsigned char* data, unsigned int data_len, unsigned char* out, unsigned int* out_len)
{
	mbedtls_md_context_t mdctx;
	mbedtls_md_init(&mdctx);
	int mr = mbedtls_md_setup(&mdctx, mbedtls_md_info_from_type(md), 1);
	if (mr != 0) {
		debug_info("mbedtls_md_setup() failed: %d", mr);
		return;
	}

	mr = mbedtls_md_hmac_starts(&mdctx, key, key_len);
	if (mr != 0) {
		mbedtls_md_free(&mdctx);
		debug_info("mbedtls_md_hmac_starts() failed: %d", mr);
		return;
	}

	mbedtls_md_hmac_update(&mdctx, data, data_len);

	mr = mbedtls_md_hmac_finish(&mdctx, out);
	if (mr == 0) {
		*out_len = mbedtls_md_get_size(mbedtls_md_info_from_type(md));
	} else {
		debug_info("mbedtls_md_hmac_finish() failed: %d", mr);
	}
	mbedtls_md_free(&mdctx);
}
#endif

static void hkdf_md_extract(MD_ALGO_TYPE_T md, unsigned char* salt, unsigned int salt_len, unsigned char* input_key_material, unsigned int input_key_material_len, unsigned char* out, unsigned int* out_len)
{
	unsigned char empty_salt[MD_MAX_DIGEST_SIZE];
	if (!md || !out || !out_len || !*out_len) return;
	if (salt_len == 0) {
		salt_len = MD_ALGO_DIGEST_SIZE(md);
		salt = (unsigned char*)empty_salt;
	}
	HMAC(md, salt, salt_len, input_key_material, input_key_material_len, out, out_len);
}

static void hkdf_md_expand(MD_ALGO_TYPE_T md, unsigned char* prk, unsigned int prk_len, unsigned char* info, unsigned int info_len, unsigned char* out, unsigned int* out_len)
{
	if (!md || !out || !out_len || !*out_len) return;
	unsigned int md_size = MD_ALGO_DIGEST_SIZE(md);
	if (*out_len > 255 * md_size) {
		*out_len = 0;
		return;
	}
	int blocks_needed = (*out_len) / md_size;
	if (((*out_len) % md_size) != 0) blocks_needed++;
	unsigned int okm_len = 0;
	unsigned char okm_block[MD_MAX_DIGEST_SIZE];
	unsigned int okm_block_len = 0;
	int i;
	for (i = 0; i < blocks_needed; i++) {
		unsigned int output_block_len = okm_block_len + info_len + 1;
		unsigned char* output_block = malloc(output_block_len);
		if (okm_block_len > 0) {
			memcpy(output_block, okm_block, okm_block_len);
		}
		memcpy(output_block + okm_block_len, info, info_len);
		output_block[okm_block_len + info_len] = (uint8_t)(i+1);

		HMAC(md, prk, prk_len, output_block, output_block_len, okm_block, &okm_block_len);
		if (okm_len < *out_len) {
			memcpy(out + okm_len, okm_block, (okm_len + okm_block_len > *out_len) ? *out_len - okm_len : okm_block_len);
		}
		okm_len += okm_block_len;
		free(output_block);
	}
}

static void hkdf_md(MD_ALGO_TYPE_T md, unsigned char* salt, unsigned int salt_len, unsigned char* info, unsigned int info_len, unsigned char* initial_key_material, unsigned int initial_key_material_size, unsigned char* out, unsigned int *out_len)
{
	if (!md || !initial_key_material || !out || !out_len || !*out_len) return;

	unsigned char prk[MD_MAX_DIGEST_SIZE];
	unsigned int prk_len = MD_ALGO_DIGEST_SIZE(md);

	hkdf_md_extract(md, salt, salt_len, initial_key_material, initial_key_material_size, prk, &prk_len);
	if (prk_len > 0) {
		hkdf_md_expand(md, prk, prk_len, info, info_len, out, out_len);
	} else {
		*out_len = 0;
	}
}
/* }}} */

/* {{{ chacha20 poly1305 encryption/decryption */
#if defined(HAVE_OPENSSL) && defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x2030200fL)
/* {{{ From: OpenBSD's e_chacha20poly1305.c */
/*
 * Copyright (c) 2015 Reyk Floter <reyk@openbsd.org>
 * Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static void
poly1305_update_with_length(poly1305_state *poly1305,
    const unsigned char *data, size_t data_len)
{
	size_t j = data_len;
	unsigned char length_bytes[8];
	unsigned i;

	for (i = 0; i < sizeof(length_bytes); i++) {
		length_bytes[i] = j;
		j >>= 8;
	}

	if (data != NULL)
		CRYPTO_poly1305_update(poly1305, data, data_len);
	CRYPTO_poly1305_update(poly1305, length_bytes, sizeof(length_bytes));
}

static void
poly1305_update_with_pad16(poly1305_state *poly1305,
    const unsigned char *data, size_t data_len)
{
	static const unsigned char zero_pad16[16];
	size_t pad_len;

	CRYPTO_poly1305_update(poly1305, data, data_len);

	/* pad16() is defined in RFC 7539 2.8.1. */
	if ((pad_len = data_len % 16) == 0)
		return;

	CRYPTO_poly1305_update(poly1305, zero_pad16, 16 - pad_len);
}
/* }}} */
#endif

static void chacha20_poly1305_encrypt_96(unsigned char* key, unsigned char* nonce, unsigned char* ad, size_t ad_len, unsigned char* in, size_t in_len, unsigned char* out, size_t* out_len)
{
#if defined(HAVE_OPENSSL)
#if defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x3050000fL)
#if (LIBRESSL_VERSION_NUMBER >= 0x2040000fL)
	const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
	EVP_AEAD_CTX ctx;
	EVP_AEAD_CTX_init(&ctx, aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
	EVP_AEAD_CTX_seal(&ctx, out, out_len, *out_len, nonce, 12, in, in_len, ad, ad_len);
#else
	unsigned char poly1305_key[32];
	poly1305_state poly1305;
	uint64_t ctr = (uint64_t)(nonce[0] | nonce[1] << 8 | nonce[2] << 16 | nonce[3] << 24) << 32;
	const unsigned char* iv = nonce + 4;

	memset(poly1305_key, 0, sizeof(poly1305_key));
	CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), key, iv, ctr);

	CRYPTO_poly1305_init(&poly1305, poly1305_key);
	poly1305_update_with_pad16(&poly1305, ad, ad_len);
	CRYPTO_chacha_20(out, in, in_len, key, iv, ctr + 1);
	poly1305_update_with_pad16(&poly1305, out, in_len);
	poly1305_update_with_length(&poly1305, NULL, ad_len);
	poly1305_update_with_length(&poly1305, NULL, in_len);

	CRYPTO_poly1305_finish(&poly1305, out + in_len);

	*out_len = in_len + 16;
#endif
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	int outl = 0;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);
	EVP_EncryptUpdate(ctx, out, &outl, in, in_len);
	*out_len = outl;
	outl = 0;
	EVP_EncryptFinal_ex(ctx, out + *out_len, &outl);
	*out_len += outl;
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + *out_len);
	EVP_CIPHER_CTX_free(ctx);
	*out_len += 16;
#else
#error Please use a newer version of OpenSSL (>= 1.1.0)
#endif
#elif defined(HAVE_GCRYPT)
#if defined(GCRYPT_VERSION_NUMBER) && (GCRYPT_VERSION_NUMBER >= 0x010700)
	gcry_cipher_hd_t hd;
	if (gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0)) {
		debug_info("gcry_cipher_open() failed");
		return;
	}
	gcry_cipher_setkey(hd, key, 32);
	gcry_cipher_setiv(hd, nonce, 12);
	gcry_cipher_authenticate(hd, ad, ad_len);
	*out_len = in_len + 16;
	if (gcry_cipher_encrypt(hd, out, *out_len, in, in_len)) {
		*out_len = 0;
	}
	gcry_cipher_gettag(hd, out+in_len, 16);
	gcry_cipher_close(hd);
#else
#error Please use a newer version of libgcrypt (>= 1.7.0)
#endif
#elif defined (HAVE_MBEDTLS)
	mbedtls_chachapoly_context ctx;
	mbedtls_chachapoly_init(&ctx);
	mbedtls_chachapoly_setkey(&ctx, key);
	if (mbedtls_chachapoly_encrypt_and_tag(&ctx, in_len, nonce, ad, ad_len, in, out, out+in_len) != 0) {
		*out_len = 0;
	}
	mbedtls_chachapoly_free(&ctx);
#else
#error chacha20_poly1305_encrypt_96 is not implemented
#endif
}

static void chacha20_poly1305_encrypt_64(unsigned char* key, unsigned char* nonce, unsigned char* ad, size_t ad_len, unsigned char* in, size_t in_len, unsigned char* out, size_t* out_len)
{
	unsigned char _nonce[12];
	*(uint32_t*)(&_nonce[0]) = 0;
	memcpy(&_nonce[4], nonce, 8);
	chacha20_poly1305_encrypt_96(key, _nonce, ad, ad_len, in, in_len, out, out_len);
}

static void chacha20_poly1305_decrypt_96(unsigned char* key, unsigned char* nonce, unsigned char* ad, size_t ad_len, unsigned char* in, size_t in_len, unsigned char* out, size_t* out_len)
{
#if defined(HAVE_OPENSSL)
#if defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x3050000fL)
#if (LIBRESSL_VERSION_NUMBER >= 0x2040000fL)
	const EVP_AEAD *aead = EVP_aead_chacha20_poly1305();
	EVP_AEAD_CTX ctx;
	EVP_AEAD_CTX_init(&ctx, aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH, NULL);
	EVP_AEAD_CTX_open(&ctx, out, out_len, *out_len, nonce, 12, in, in_len, ad, ad_len);
#else
	unsigned char mac[16];
	unsigned char poly1305_key[32];
	poly1305_state poly1305;
	size_t plaintext_len = in_len - 16;
	uint64_t ctr = (uint64_t)(nonce[0] | nonce[1] << 8 | nonce[2] << 16 | nonce[3] << 24) << 32;
	const unsigned char *iv = nonce + 4;

	memset(poly1305_key, 0, sizeof(poly1305_key));
	CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), key, iv, ctr);

	CRYPTO_poly1305_init(&poly1305, poly1305_key);
	poly1305_update_with_pad16(&poly1305, ad, ad_len);
	poly1305_update_with_pad16(&poly1305, in, plaintext_len);
	poly1305_update_with_length(&poly1305, NULL, ad_len);
	poly1305_update_with_length(&poly1305, NULL, plaintext_len);

	CRYPTO_poly1305_finish(&poly1305, mac);

	if (memcmp(mac, in + plaintext_len, 16) != 0) {
		*out_len = 0;
		return;
	}

	CRYPTO_chacha_20(out, in, plaintext_len, key, iv, ctr + 1);
	*out_len = plaintext_len;
#endif
#elif defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	int outl = 0;
	size_t plaintext_len = in_len - 16;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, in + plaintext_len);
	EVP_DecryptUpdate(ctx, out, &outl, in, plaintext_len);
	*out_len = outl;
	outl = 0;
	if (EVP_DecryptFinal_ex(ctx, out + *out_len, &outl) == 1) {
		*out_len += outl;
	} else {
		*out_len = 0;
	}
	EVP_CIPHER_CTX_free(ctx);
#else
#error Please use a newer version of OpenSSL (>= 1.1.0)
#endif
#elif defined(HAVE_GCRYPT)
#if defined(GCRYPT_VERSION_NUMBER) && (GCRYPT_VERSION_NUMBER >= 0x010700)
	gcry_cipher_hd_t hd;
	if (gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0)) {
		debug_info("gcry_cipher_open() failed");
		return;
	}
	gcry_cipher_setkey(hd, key, 32);
	gcry_cipher_setiv(hd, nonce, 12);
	gcry_cipher_authenticate(hd, ad, ad_len);
	unsigned int plaintext_len = in_len - 16;
	gcry_cipher_decrypt(hd, out, *out_len, in, plaintext_len); 
	if (gcry_cipher_checktag(hd, in + plaintext_len, 16) == 0) {
		*out_len = plaintext_len;
	} else {
		*out_len = 0;
	}
	gcry_cipher_close(hd);
#else
#error Please use a newer version of libgcrypt (>= 1.7.0)
#endif
#elif defined(HAVE_MBEDTLS)
	mbedtls_chachapoly_context ctx;
	mbedtls_chachapoly_init(&ctx);
	mbedtls_chachapoly_setkey(&ctx, key);
	unsigned int plaintext_len = in_len - 16;
	if (mbedtls_chachapoly_auth_decrypt(&ctx, plaintext_len, nonce, ad, ad_len, in + plaintext_len, in, out) == 0) {
		*out_len = plaintext_len;
	} else {
		*out_len = 0;
	}
	mbedtls_chachapoly_free(&ctx);
#else
#error chacha20_poly1305_decrypt_96 is not implemented
#endif
}

static void chacha20_poly1305_decrypt_64(unsigned char* key, unsigned char* nonce, unsigned char* ad, size_t ad_len, unsigned char* in, size_t in_len, unsigned char* out, size_t* out_len)
{
	unsigned char _nonce[12];
	*(uint32_t*)(&_nonce[0]) = 0;
	memcpy(&_nonce[4], nonce, 8);
	chacha20_poly1305_decrypt_96(key, _nonce, ad, ad_len, in, in_len, out, out_len);
}
/* }}} */

#define PAIRING_ERROR(x) \
	debug_info(x); \
	if (pairing_callback) { \
		pairing_callback(LOCKDOWN_CU_PAIRING_ERROR, cb_user_data, (char*)x, NULL); \
	}

#define PAIRING_ERROR_FMT(...) \
	sprintf(tmp, __VA_ARGS__); \
	debug_info(tmp); \
	if (pairing_callback) { \
		pairing_callback(LOCKDOWN_CU_PAIRING_ERROR, cb_user_data, tmp, NULL); \
	}

#endif /* HAVE_WIRELESS_PAIRING */

lockdownd_error_t lockdownd_cu_pairing_create(lockdownd_client_t client, lockdownd_cu_pairing_cb_t pairing_callback, void* cb_user_data, plist_t host_info, plist_t acl)
{
#ifdef HAVE_WIRELESS_PAIRING
	if (!client || !pairing_callback || (host_info && plist_get_node_type(host_info) != PLIST_DICT) || (acl && plist_get_node_type(acl) != PLIST_DICT))
		return LOCKDOWN_E_INVALID_ARG;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	if (client->device && client->device->version == 0) {
		plist_t p_version = NULL;
		if (lockdownd_get_value(client, NULL, "ProductVersion", &p_version) == LOCKDOWN_E_SUCCESS) {
			int vers[3] = {0, 0, 0};
			char *s_version = NULL;
			plist_get_string_val(p_version, &s_version);
			if (s_version && sscanf(s_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
				client->device->version = DEVICE_VERSION(vers[0], vers[1], vers[2]);
			}
			free(s_version);
		}
		plist_free(p_version);
	}

	char* pairing_uuid = NULL;
	if (host_info) {
		plist_t accountid = plist_dict_get_item(host_info, "accountID");
		if (accountid && plist_get_node_type(accountid) == PLIST_STRING) {
			plist_get_string_val(accountid, &pairing_uuid);
		}
	}
	if (!pairing_uuid) {
		userpref_read_system_buid(&pairing_uuid);
	}
	if (!pairing_uuid) {
		pairing_uuid = generate_uuid();
	}
	unsigned int pairing_uuid_len = strlen(pairing_uuid);

	SRP_initialize_library();

	SRP* srp = SRP_new(SRP6a_sha512_client_method());
	if (!srp) {
		PAIRING_ERROR("Failed to initialize SRP")
		return LOCKDOWN_E_UNKNOWN_ERROR;
	}

	char tmp[256];
	plist_t dict = NULL;
	uint8_t current_state = 0;
	uint8_t final_state = 6;

	unsigned char* salt = NULL;
	unsigned int salt_size = 0;
	unsigned char* pubkey = NULL;
	unsigned int pubkey_size = 0;

	unsigned char setup_encryption_key[32];

	cstr *thekey = NULL;

	do {
		current_state++;

		dict = plist_new_dict();
		plist_dict_set_item(dict, "Request", plist_new_string("CUPairingCreate"));
		if (current_state == 1) {
			plist_dict_set_item(dict, "Flags", plist_new_uint(1));
		} else {
			plist_dict_set_item(dict, "Flags", plist_new_uint(0));
		}

		tlv_buf_t tlv = tlv_buf_new();

		if (current_state == 1) {
			/* send method */
			tlv_buf_append(tlv, 0x00, 1, (void*)"\x00"); // 0x00 (Method), 1 bytes, 00
		} else if (current_state == 3) {
			/* generate public key */
			cstr* own_pub = NULL;
			SRP_gen_pub(srp, &own_pub);

			if (!own_pub) {
				PAIRING_ERROR("[SRP] Failed to generate public key")
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			/* compute key from remote's public key */
			if (SRP_compute_key(srp, &thekey, pubkey, pubkey_size) != 0) {
				cstr_free(own_pub);
				PAIRING_ERROR("[SRP] Failed to compute key")
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			/* compute response */
			cstr *response = NULL;
			SRP_respond(srp, &response);

			/* send our public key + response */
			tlv_buf_append(tlv, 0x03, own_pub->length, own_pub->data);
			tlv_buf_append(tlv, 0x04, response->length, response->data);
			cstr_free(response);
			cstr_free(own_pub);
		} else if (current_state == 5) {
			/* send encrypted info */

			static const char PAIR_SETUP_ENCRYPT_SALT[] = "Pair-Setup-Encrypt-Salt";
			static const char PAIR_SETUP_ENCRYPT_INFO[] = "Pair-Setup-Encrypt-Info";
			static const char PAIR_SETUP_CONTROLLER_SIGN_SALT[] = "Pair-Setup-Controller-Sign-Salt";
			static const char PAIR_SETUP_CONTROLLER_SIGN_INFO[] = "Pair-Setup-Controller-Sign-Info";

			// HKDF with above computed key (SRP_compute_key) + Pair-Setup-Encrypt-Salt + Pair-Setup-Encrypt-Info
			// result used as key for chacha20-poly1305
			unsigned int setup_encryption_key_len = sizeof(setup_encryption_key);
			hkdf_md(MD_ALGO_SHA512, (unsigned char*)PAIR_SETUP_ENCRYPT_SALT, sizeof(PAIR_SETUP_ENCRYPT_SALT)-1, (unsigned char*)PAIR_SETUP_ENCRYPT_INFO, sizeof(PAIR_SETUP_ENCRYPT_INFO)-1, (unsigned char*)thekey->data, thekey->length, setup_encryption_key, &setup_encryption_key_len);

			unsigned char ed25519_pubkey[32];
			unsigned char ed25519_privkey[64];
			unsigned char ed25519seed[32];
			ed25519_create_seed(ed25519seed);

			ed25519_create_keypair(ed25519_pubkey, ed25519_privkey, ed25519seed);

			unsigned int signbuf_len = pairing_uuid_len + 64;
			unsigned char* signbuf = malloc(signbuf_len);
			unsigned int hkdf_len = 32;
			// HKDF with above computed key (SRP_compute_key) + Pair-Setup-Controller-Sign-Salt + Pair-Setup-Controller-Sign-Info
			hkdf_md(MD_ALGO_SHA512, (unsigned char*)PAIR_SETUP_CONTROLLER_SIGN_SALT, sizeof(PAIR_SETUP_CONTROLLER_SIGN_SALT)-1, (unsigned char*)PAIR_SETUP_CONTROLLER_SIGN_INFO, sizeof(PAIR_SETUP_CONTROLLER_SIGN_INFO)-1, (unsigned char*)thekey->data, thekey->length, signbuf, &hkdf_len);

			memcpy(signbuf + 32, pairing_uuid, pairing_uuid_len);
			memcpy(signbuf + 32 + pairing_uuid_len, ed25519_pubkey, 32);

        		unsigned char ed_sig[64];
			ed25519_sign(ed_sig, signbuf, 0x64, ed25519_pubkey, ed25519_privkey);

			tlv_buf_t tlvbuf = tlv_buf_new();
			tlv_buf_append(tlvbuf, 0x01, pairing_uuid_len, (void*)pairing_uuid);
			tlv_buf_append(tlvbuf, 0x03, sizeof(ed25519_pubkey), ed25519_pubkey);
			tlv_buf_append(tlvbuf, 0x0a, sizeof(ed_sig), ed_sig);

			/* ACL */
			unsigned char* odata = NULL;
			unsigned int olen = 0;
			if (acl) {
				opack_encode_from_plist(acl, &odata, &olen);
			} else {
				/* defaut ACL */
				plist_t acl_plist = plist_new_dict();
				plist_dict_set_item(acl_plist, "com.apple.ScreenCapture", plist_new_bool(1));	
				plist_dict_set_item(acl_plist, "com.apple.developer", plist_new_bool(1));
				opack_encode_from_plist(acl_plist, &odata, &olen);
				plist_free(acl_plist);
			}
			tlv_buf_append(tlvbuf, 0x12, olen, odata);
			free(odata);

			/* HOST INFORMATION */
			char hostname[256];
#if defined(__APPLE__) && !defined(TARGET_OS_IPHONE)
			CFStringRef cname = SCDynamicStoreCopyComputerName(NULL, NULL);
			CFStringGetCString(cname, hostname, sizeof(hostname), kCFStringEncodingUTF8);
			CFRelease(cname);
#else
#ifdef _WIN32
			DWORD hostname_len = sizeof(hostname);
			GetComputerName(hostname, &hostname_len);
#else
			gethostname(hostname, sizeof(hostname));
#endif
#endif

			char modelname[256];
			modelname[0] = '\0';
#ifdef __APPLE__
			size_t len = sizeof(modelname);
			sysctlbyname("hw.model", &modelname, &len, NULL, 0);
#endif
			if (strlen(modelname) == 0) {
				strcpy(modelname, "HackbookPro13,37");
			}

			unsigned char primary_mac_addr[6] = { 0, 0, 0, 0, 0, 0 };
			if (get_primary_mac_address(primary_mac_addr) != 0) {
				debug_info("Failed to get primary mac address");
			}
			debug_info("Primary mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", primary_mac_addr[0], primary_mac_addr[1], primary_mac_addr[2], primary_mac_addr[3], primary_mac_addr[4], primary_mac_addr[5]);

			// "OPACK" encoded device info
			plist_t info_plist = plist_new_dict();
			//plist_dict_set_item(info_plist, "altIRK", plist_new_data((char*)altIRK, 16));
			plist_dict_set_item(info_plist, "accountID", plist_new_string(pairing_uuid));
			plist_dict_set_item(info_plist, "model", plist_new_string(modelname));
			plist_dict_set_item(info_plist, "name", plist_new_string(hostname));
			plist_dict_set_item(info_plist, "mac", plist_new_data((char*)primary_mac_addr, 6));
			if (host_info) {
				plist_dict_merge(&info_plist, host_info);
			}
			opack_encode_from_plist(info_plist, &odata, &olen);
			plist_free(info_plist);
			tlv_buf_append(tlvbuf, 0x11, olen, odata);
			free(odata);

			size_t encrypted_len = tlvbuf->length + 16;
			unsigned char* encrypted_buf = (unsigned char*)malloc(encrypted_len);

			chacha20_poly1305_encrypt_64(setup_encryption_key, (unsigned char*)"PS-Msg05", NULL, 0, tlvbuf->data, tlvbuf->length, encrypted_buf, &encrypted_len);

			tlv_buf_free(tlvbuf);

			tlv_buf_append(tlv, 0x05, encrypted_len, encrypted_buf);
			free(encrypted_buf);
		} else {
			tlv_buf_free(tlv);
			PAIRING_ERROR("[SRP] Invalid state");
			ret = LOCKDOWN_E_PAIRING_FAILED;
			break;
		}
		tlv_buf_append(tlv, 0x06, 1, &current_state);
		plist_dict_set_item(dict, "Payload", plist_new_data((char*)tlv->data, tlv->length));
		tlv_buf_free(tlv);

		plist_dict_set_item(dict, "Label", plist_new_string(client->label));
		plist_dict_set_item(dict, "ProtocolVersion", plist_new_uint(2));

		ret = lockdownd_send(client, dict);
		plist_free(dict);
		dict = NULL;

		if (ret != LOCKDOWN_E_SUCCESS) {
			break;
		}

		current_state++;

		ret = lockdownd_receive(client, &dict);
		if (ret != LOCKDOWN_E_SUCCESS) {
			break;
		}
		ret = lockdown_check_result(dict, "CUPairingCreate");
		if (ret != LOCKDOWN_E_SUCCESS) {
			break;
		}

		plist_t extresp = plist_dict_get_item(dict, "ExtendedResponse");
		if (!extresp) {
			ret = LOCKDOWN_E_PLIST_ERROR;
			break;
		}
		plist_t blob = plist_dict_get_item(extresp, "Payload");
		if (!blob) {
			ret = LOCKDOWN_E_PLIST_ERROR;
			break;
		}
		uint64_t data_len = 0;
		const char* data = plist_get_data_ptr(blob, &data_len);

		uint8_t state = 0;
		if (!tlv_data_get_uint8(data, data_len, 0x06, &state)) {
			PAIRING_ERROR("[SRP] ERROR: Could not find state in response");
			ret = LOCKDOWN_E_PAIRING_FAILED;
			break;
		}
		if (state != current_state) {
			PAIRING_ERROR_FMT("[SRP] ERROR: Unexpected state %d, expected %d", state, current_state);
			ret = LOCKDOWN_E_PAIRING_FAILED;
			break;
		}

		unsigned int errval = 0;
		uint64_t u64val = 0;
		tlv_data_get_uint(data, data_len, 0x07, &u64val);
debug_buffer(data, data_len);
		errval = (unsigned int)u64val;
		if (errval > 0) {
			if (errval == 3) {
				u64val = 0;
				tlv_data_get_uint(data, data_len, 0x08, &u64val);
				if (u64val > 0) {
					uint32_t retry_delay = (uint32_t)u64val;
					PAIRING_ERROR_FMT("[SRP] Pairing is blocked for another %u seconds", retry_delay)
					ret = LOCKDOWN_E_PAIRING_FAILED;
					break;
				}
			} else if (errval == 2 && state == 4) {
				PAIRING_ERROR_FMT("[SRP] Invalid PIN")
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			} else {
				PAIRING_ERROR_FMT("[SRP] Received error %u in state %d.", errval, state);
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}
		}

		if (state == 2) {
			/* receive salt and public key */
			if (!tlv_data_copy_data(data, data_len, 0x02, (void**)&salt, &salt_size)) {
				PAIRING_ERROR("[SRP] ERROR: Could not find salt in response");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}
			if (!tlv_data_copy_data(data, data_len, 0x03, (void**)&pubkey, &pubkey_size)) {
				PAIRING_ERROR("[SRP] ERROR: Could not find public key in response");

				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			const char PAIR_SETUP[] = "Pair-Setup";
			if (SRP_set_user_raw(srp, (const unsigned char*)PAIR_SETUP, sizeof(PAIR_SETUP)-1) != 0) {
				PAIRING_ERROR("[SRP] Failed to set SRP user");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			/* kSRPParameters_3072_SHA512 */
			if (SRP_set_params(srp, kSRPModulus3072, sizeof(kSRPModulus3072), &kSRPGenerator5, 1, salt, salt_size) != 0) {
				PAIRING_ERROR("[SRP] Failed to set SRP parameters");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;

			}

			if (pairing_callback) {
				char pin[64];
				unsigned int pin_len = sizeof(pin);
				pairing_callback(LOCKDOWN_CU_PAIRING_PIN_REQUESTED, cb_user_data, pin, &pin_len);

				SRP_set_auth_password_raw(srp, (const unsigned char*)pin, pin_len);
			}
		} else if (state == 4) {
			/* receive proof */
			unsigned char* proof = NULL;
			unsigned int proof_len = 0;

			if (!tlv_data_copy_data(data, data_len, 0x04, (void**)&proof, &proof_len)) {
				PAIRING_ERROR("[SRP] ERROR: Could not find proof data in response");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			/* verify */
			int vrfy_result = SRP_verify(srp, proof, proof_len);
			free(proof);

			if (vrfy_result == 0) {
				debug_info("[SRP] PIN verified successfully");
			} else {
				PAIRING_ERROR("[SRP] PIN verification failure");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

		} else if (state == 6) {
			int srp_pair_success = 0;
			plist_t node = plist_dict_get_item(extresp, "doSRPPair");
			if (node) {
				const char* strv = plist_get_string_ptr(node, NULL);
				if (strcmp(strv, "succeed") == 0) {
					srp_pair_success = 1;
				}
			}
			if (!srp_pair_success) {
				PAIRING_ERROR("SRP Pairing failed");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			/* receive encrypted info */
			unsigned char* encrypted_buf = NULL;
			unsigned int enc_len = 0;
			if (!tlv_data_copy_data(data, data_len, 0x05, (void**)&encrypted_buf, &enc_len)) {
				PAIRING_ERROR("[SRP] ERROR: Could not find encrypted data in response");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}
			size_t plain_len = enc_len-16;
			unsigned char* plain_buf = malloc(plain_len);
			chacha20_poly1305_decrypt_64(setup_encryption_key, (unsigned char*)"PS-Msg06", NULL, 0, encrypted_buf, enc_len, plain_buf, &plain_len);
			free(encrypted_buf);
			
			unsigned char* dev_info = NULL;
			unsigned int dev_info_len = 0;
			int res = tlv_data_copy_data(plain_buf, plain_len, 0x11, (void**)&dev_info, &dev_info_len);
			free(plain_buf);
			if (!res) {
				PAIRING_ERROR("[SRP] ERROR: Failed to locate device info in response");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}
			plist_t device_info = NULL;
			opack_decode_to_plist(dev_info, dev_info_len, &device_info);
			free(dev_info);

			if (!device_info) {
				PAIRING_ERROR("[SRP] ERROR: Failed to parse device info");
				ret = LOCKDOWN_E_PAIRING_FAILED;
				break;
			}

			if (pairing_callback) {
				pairing_callback(LOCKDOWN_CU_PAIRING_DEVICE_INFO, cb_user_data, device_info, NULL);
			}
			plist_free(device_info);			
		} else {
			PAIRING_ERROR("[SRP] ERROR: Invalid state");
			ret = LOCKDOWN_E_PAIRING_FAILED;
			break;
		}
		plist_free(dict);
		dict = NULL;

	} while (current_state != final_state);

	plist_free(dict);

	free(salt);
	free(pubkey);

	SRP_free(srp);
	srp = NULL;

	if (ret != LOCKDOWN_E_SUCCESS) {
		if (thekey) {
			cstr_free(thekey);
		}
		return ret;
	}

	free(client->cu_key);
	client->cu_key = malloc(thekey->length);
	memcpy(client->cu_key, thekey->data, thekey->length);
	client->cu_key_len = thekey->length;
	cstr_free(thekey);

	return LOCKDOWN_E_SUCCESS;
#else
	debug_info("not supported");
	return LOCKDOWN_E_UNKNOWN_ERROR;
#endif
}

lockdownd_error_t lockdownd_cu_send_request_and_get_reply(lockdownd_client_t client, const char* request, plist_t request_payload, plist_t* reply)
{
#ifdef HAVE_WIRELESS_PAIRING
	if (!client || !request)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->cu_key)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	/* derive keys */
	unsigned char cu_write_key[32];
	unsigned int cu_write_key_len = sizeof(cu_write_key);
	static const char WRITE_KEY_SALT_MDLD[] = "WriteKeySaltMDLD";
	static const char WRITE_KEY_INFO_MDLD[] = "WriteKeyInfoMDLD";
	hkdf_md(MD_ALGO_SHA512, (unsigned char*)WRITE_KEY_SALT_MDLD, sizeof(WRITE_KEY_SALT_MDLD)-1, (unsigned char*)WRITE_KEY_INFO_MDLD, sizeof(WRITE_KEY_INFO_MDLD)-1, client->cu_key, client->cu_key_len, cu_write_key, &cu_write_key_len);

	unsigned char cu_read_key[32];
	unsigned int cu_read_key_len = sizeof(cu_write_key);
	static const char READ_KEY_SALT_MDLD[] = "ReadKeySaltMDLD";
	static const char READ_KEY_INFO_MDLD[] = "ReadKeyInfoMDLD";
	hkdf_md(MD_ALGO_SHA512, (unsigned char*)READ_KEY_SALT_MDLD, sizeof(READ_KEY_SALT_MDLD)-1, (unsigned char*)READ_KEY_INFO_MDLD, sizeof(READ_KEY_INFO_MDLD)-1, client->cu_key, client->cu_key_len, cu_read_key, &cu_read_key_len);

	// Starting with iOS/tvOS 11.2 and WatchOS 4.2, this nonce is random and sent along with the request. Before, the request doesn't have a nonce and it uses hardcoded nonce "sendone01234".
	unsigned char cu_nonce[12] = "sendone01234"; // guaranteed to be random by fair dice troll
        if (client->device->version >= DEVICE_VERSION(11,2,0)) {
#if defined(HAVE_OPENSSL)
		RAND_bytes(cu_nonce, sizeof(cu_nonce));
#elif defined(HAVE_GCRYPT)
		gcry_create_nonce(cu_nonce, sizeof(cu_nonce));
#endif
	}

	debug_plist(request_payload);

	/* convert request payload to binary */
	uint32_t bin_len = 0;
	char* bin = NULL;
	plist_to_bin(request_payload, &bin, &bin_len);

	/* encrypt request */
	size_t encrypted_len = bin_len + 16;
	unsigned char* encrypted_buf = malloc(encrypted_len);
	chacha20_poly1305_encrypt_96(cu_write_key, cu_nonce, NULL, 0, (unsigned char*)bin, bin_len, encrypted_buf, &encrypted_len);
	free(bin);
	bin = NULL;

	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict,"Request", plist_new_string(request));
	plist_dict_set_item(dict, "Payload", plist_new_data((char*)encrypted_buf, encrypted_len));
	free(encrypted_buf);
	plist_dict_set_item(dict, "Nonce", plist_new_data((char*)cu_nonce, sizeof(cu_nonce)));
	plist_dict_set_item(dict, "Label", plist_new_string(client->label));
	plist_dict_set_item(dict, "ProtocolVersion", plist_new_uint(2));

	/* send to device */
	ret = lockdownd_send(client, dict);
	plist_free(dict);
	dict = NULL;

	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	/* Now get device's answer */
	ret = lockdownd_receive(client, &dict);
	if (ret != LOCKDOWN_E_SUCCESS)
		return ret;

	ret = lockdown_check_result(dict, request);
	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(dict);
		return ret;
	}

	/* get payload */
	plist_t blob = plist_dict_get_item(dict, "Payload");
	if (!blob) {
		plist_free(dict);
		return LOCKDOWN_E_DICT_ERROR;
	}

	uint64_t dl = 0;
	const char* dt = plist_get_data_ptr(blob, &dl);

	/* see if we have a nonce */
	blob = plist_dict_get_item(dict, "Nonce");
	const unsigned char* rnonce = (unsigned char*)"receiveone01";
	if (blob) {
		uint64_t rl = 0;
		rnonce = (const unsigned char*)plist_get_data_ptr(blob, &rl);
	}

	/* decrypt payload */
	size_t decrypted_len = dl-16;
	unsigned char* decrypted = malloc(decrypted_len);
	chacha20_poly1305_decrypt_96(cu_read_key, (unsigned char*)rnonce, NULL, 0, (unsigned char*)dt, dl, decrypted, &decrypted_len);
	plist_free(dict);
	dict = NULL;

	plist_from_memory((const char*)decrypted, decrypted_len, &dict, NULL);
	if (!dict) {
		ret = LOCKDOWN_E_PLIST_ERROR;
		debug_info("Failed to parse PLIST from decrypted payload:");
		debug_buffer((const char*)decrypted, decrypted_len);
		free(decrypted);
		return ret;	
	}
	free(decrypted);

	debug_plist(dict);

	if (reply) {
		*reply = dict;
	} else {
		plist_free(dict);
	}

	return LOCKDOWN_E_SUCCESS;
#else
	debug_info("not supported");
	return LOCKDOWN_E_UNKNOWN_ERROR;
#endif
}

lockdownd_error_t lockdownd_get_value_cu(lockdownd_client_t client, const char* domain, const char* key, plist_t* value)
{
#ifdef HAVE_WIRELESS_PAIRING
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->cu_key)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	lockdownd_error_t ret = LOCKDOWN_E_UNKNOWN_ERROR;

	plist_t request = plist_new_dict();
	if (domain) {
		plist_dict_set_item(request, "Domain", plist_new_string(domain));
	}
	if (key) {
		plist_dict_set_item(request, "Key", plist_new_string(key));
	}

	plist_t reply = NULL;
	ret = lockdownd_cu_send_request_and_get_reply(client, "GetValueCU", request, &reply);
	plist_free(request);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}

	plist_t value_node = plist_dict_get_item(reply, "Value");
	if (value_node) {
		debug_info("has a value");
		*value = plist_copy(value_node);
	}
	plist_free(reply);

	return ret;
#else
	debug_info("not supported");
	return LOCKDOWN_E_UNKNOWN_ERROR;
#endif
}

lockdownd_error_t lockdownd_pair_cu(lockdownd_client_t client)
{
#ifdef HAVE_WIRELESS_PAIRING
	if (!client)
		return LOCKDOWN_E_INVALID_ARG;

	if (!client->cu_key)
		return LOCKDOWN_E_NO_RUNNING_SESSION;

	lockdownd_error_t ret;

	plist_t wifi_mac = NULL;
	ret = lockdownd_get_value_cu(client, NULL, "WiFiAddress", &wifi_mac);
	if (ret != LOCKDOWN_E_SUCCESS) {
		return ret;
	}

	plist_t pubkey = NULL;
	ret = lockdownd_get_value_cu(client, NULL, "DevicePublicKey", &pubkey);
	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(wifi_mac);
		return ret;
	}	

	key_data_t public_key = { NULL, 0 };
	uint64_t data_len = 0;
	plist_get_data_val(pubkey, (char**)&public_key.data, &data_len);
	public_key.size = (unsigned int)data_len;
	plist_free(pubkey);	

	plist_t pair_record_plist = plist_new_dict();
	pair_record_generate_keys_and_certs(pair_record_plist, public_key);

	char* host_id = NULL;
	char* system_buid = NULL;

	/* set SystemBUID */
	userpref_read_system_buid(&system_buid);
	if (system_buid) {
		plist_dict_set_item(pair_record_plist, USERPREF_SYSTEM_BUID_KEY, plist_new_string(system_buid));
		free(system_buid);
	}

	/* set HostID */
	host_id = generate_uuid();
	pair_record_set_host_id(pair_record_plist, host_id);
	free(host_id);

	plist_t request_pair_record = plist_copy(pair_record_plist);
	/* remove stuff that is private */
	plist_dict_remove_item(request_pair_record, USERPREF_ROOT_PRIVATE_KEY_KEY);
	plist_dict_remove_item(request_pair_record, USERPREF_HOST_PRIVATE_KEY_KEY);

	plist_t request = plist_new_dict();
	plist_dict_set_item(request, "PairRecord", request_pair_record);
	plist_t pairing_opts = plist_new_dict();
	plist_dict_set_item(pairing_opts, "ExtendedPairingErrors", plist_new_bool(1));
	plist_dict_set_item(request, "PairingOptions", pairing_opts);

	plist_t reply = NULL;
	ret = lockdownd_cu_send_request_and_get_reply(client, "PairCU", request, &reply);
	plist_free(request);
	if (ret != LOCKDOWN_E_SUCCESS) {
		plist_free(wifi_mac);
		return ret;
	}

	char *s_udid = NULL;
	plist_t p_udid = plist_dict_get_item(reply, "UDID");
	if (p_udid) {
		plist_get_string_val(p_udid, &s_udid);
	}
	plist_t ebag = plist_dict_get_item(reply, "EscrowBag");
	if (ebag) {
		plist_dict_set_item(pair_record_plist, USERPREF_ESCROW_BAG_KEY, plist_copy(ebag));
	}
	plist_dict_set_item(pair_record_plist, USERPREF_WIFI_MAC_ADDRESS_KEY, wifi_mac);
	plist_free(reply);

	if (userpref_save_pair_record(s_udid, 0, pair_record_plist) != 0) {
		printf("Failed to save pair record for UDID %s\n", s_udid);
	}
	free(s_udid);
	s_udid = NULL;
	plist_free(pair_record_plist);

	ret = LOCKDOWN_E_SUCCESS;		

	return ret;
#else
	debug_info("not supported");
	return LOCKDOWN_E_UNKNOWN_ERROR;
#endif
}
