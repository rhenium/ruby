/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include RUBY_EXTCONF_H

#include <string.h> /* memcpy() */
#if !defined(OPENSSL_NO_ENGINE)
# include <openssl/engine.h>
#endif
#include <openssl/hmac.h>
#include <openssl/x509_vfy.h>

#include "openssl_missing.h"

/*** added in 0.9.8X ***/
#if !defined(HAVE_EVP_CIPHER_CTX_NEW)
EVP_CIPHER_CTX *
EVP_CIPHER_CTX_new(void)
{
    EVP_CIPHER_CTX *ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX));
    if (!ctx)
	return NULL;
    EVP_CIPHER_CTX_init(ctx);
    return ctx;
}
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_FREE)
void
EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
#endif

/*** added in 1.0.0 ***/
#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
/*
 * this function does not exist in OpenSSL yet... or ever?.
 * a future version may break this function.
 * tested on 0.9.7d.
 */
int
EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
{
    memcpy(out, in, sizeof(EVP_CIPHER_CTX));

#if !defined(OPENSSL_NO_ENGINE)
    if (in->engine) ENGINE_add(out->engine);
    if (in->cipher_data) {
	out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
	memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }
#endif

    return 1;
}
#endif

#if !defined(HAVE_HMAC_CTX_COPY)
int
HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in)
{
    memcpy(out, in, sizeof(HMAC_CTX));

    EVP_MD_CTX_copy(&out->md_ctx, &in->md_ctx);
    EVP_MD_CTX_copy(&out->i_ctx, &in->i_ctx);
    EVP_MD_CTX_copy(&out->o_ctx, &in->o_ctx);

    return 1;
}
#endif

/*** added in 1.0.1 ***/

/*** added in 1.0.2 ***/
#if !defined(HAVE_CRYPTO_MEMCMP)
int
CRYPTO_memcmp(const volatile void * volatile in_a,
	      const volatile void * volatile in_b,
	      size_t len)
{
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
	x |= a[i] ^ b[i];

    return x;
}
#endif

#if !defined(OPENSSL_NO_EC)
#if !defined(HAVE_EC_CURVE_NIST2NID)
static struct {
    const char *name;
    int nid;
} nist_curves[] = {
    {"B-163", NID_sect163r2},
    {"B-233", NID_sect233r1},
    {"B-283", NID_sect283r1},
    {"B-409", NID_sect409r1},
    {"B-571", NID_sect571r1},
    {"K-163", NID_sect163k1},
    {"K-233", NID_sect233k1},
    {"K-283", NID_sect283k1},
    {"K-409", NID_sect409k1},
    {"K-571", NID_sect571k1},
    {"P-192", NID_X9_62_prime192v1},
    {"P-224", NID_secp224r1},
    {"P-256", NID_X9_62_prime256v1},
    {"P-384", NID_secp384r1},
    {"P-521", NID_secp521r1}
};

int
EC_curve_nist2nid(const char *name)
{
    size_t i;
    for (i = 0; i < (sizeof(nist_curves) / sizeof(nist_curves[0])); i++) {
	if (!strcmp(nist_curves[i].name, name))
	    return nist_curves[i].nid;
    }
    return NID_undef;
}
#endif
#endif

/*** added in 1.1.0 ***/
#if !defined(HAVE_HMAC_CTX_NEW)
HMAC_CTX *
HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = OPENSSL_malloc(sizeof(HMAC_CTX));
    HMAC_CTX_reset(ctx);
    if (!ctx)
	return NULL;
    return ctx;
}
#endif

#if !defined(HAVE_HMAC_CTX_FREE)
void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
#endif

#if !defined(HAVE_HMAC_CTX_RESET)
int
HMAC_CTX_reset(HMAC_CTX *ctx)
{
    HMAC_CTX_init(ctx);
    return 0;
}
#endif

#if !defined(HAVE_X509_CRL_GET0_SIGNATURE)
void
X509_CRL_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_CRL *crl)
{
    if (psig != NULL)
	*psig = crl->signature;
    if (palg != NULL)
	*palg = crl->sig_alg;
}
#endif

#if !defined(HAVE_X509_REQ_GET0_SIGNATURE)
void
X509_REQ_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_REQ *req)
{
    if (psig != NULL)
	*psig = req->signature;
    if (palg != NULL)
	*palg = req->sig_alg;
}
#endif
