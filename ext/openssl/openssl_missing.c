/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include <ruby.h>

#include RUBY_EXTCONF_H
#include "openssl_missing.h"

/* OPENSSL_NO_EVP is not supported */
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>

/* added in -0.9.7 */
#if !defined(HAVE_CONF_GET1_DEFAULT_CONFIG_FILE)
#define OPENSSL_CONF "openssl.cnf"
char *
CONF_get1_default_config_file(void)
{
    char *file;
    int len;

    file = getenv("OPENSSL_CONF");
    if (file) return BUF_strdup(file);
    len = strlen(X509_get_default_cert_area());
#ifndef OPENSSL_SYS_VMS
    len++;
#endif
    len += strlen(OPENSSL_CONF);
    file = OPENSSL_malloc(len + 1);
    if (!file) return NULL;
    strcpy(file,X509_get_default_cert_area());
#ifndef OPENSSL_SYS_VMS
    strcat(file,"/");
#endif
    strcat(file,OPENSSL_CONF);

    return file;
}
#endif

#if !defined(HAVE_ASN1_PUT_EOC)
int
ASN1_put_eoc(unsigned char **pp)
{
    unsigned char *p = *pp;
    *p++ = 0;
    *p++ = 0;
    *pp = p;
    return 2;
}
#endif

#if !defined(HAVE_PEM_DEF_CALLBACK)
#define OSSL_PASS_MIN_LENGTH 4
int
PEM_def_callback(char *buf, int num, int w, void *key)
{
    int i,j;
    const char *prompt;

    if (key) {
	i = strlen(key);
	i = (i > num) ? num : i;
	memcpy(buf, key, i);
	return i;
    }

    prompt = EVP_get_pw_prompt();
    if (prompt == NULL) prompt = "Enter PEM pass phrase:";
    for (;;) {
	i = EVP_read_pw_string(buf, num, prompt, w);
	if (i != 0) {
	    memset(buf, 0, (unsigned int)num);
	    return(-1);
	}
	j = strlen(buf);
	if (j < OSSL_PASS_MIN_LENGTH) {
	    fprintf(stderr,
		    "phrase is too short, needs to be at least %d chars\n",
		    OSSL_PASS_MIN_LENGTH);
	}
	else break;
    }
    return j;
}
#endif

#if !defined(HAVE_BN_RAND_RANGE) || !defined(HAVE_BN_PSEUDO_RAND_RANGE)
static int
bn_rand_range(int pseudo, BIGNUM *r, const BIGNUM *range)
{
    int (*bn_rand)(BIGNUM *, int, int, int) = pseudo ? BN_pseudo_rand : BN_rand;
    int n;

    if (range->neg || BN_is_zero(range)) return 0;

    n = BN_num_bits(range);

    if (n == 1) {
	if (!BN_zero(r)) return 0;
    } else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
	do {
	    if (!bn_rand(r, n + 1, -1, 0)) return 0;
	    if (BN_cmp(r ,range) >= 0) {
		if (!BN_sub(r, r, range)) return 0;
		if (BN_cmp(r, range) >= 0)
		    if (!BN_sub(r, r, range)) return 0;
	    }
	} while (BN_cmp(r, range) >= 0);
    } else {
	do {
	    if (!bn_rand(r, n, -1, 0)) return 0;
	} while (BN_cmp(r, range) >= 0);
    }

    return 1;
}
#endif

#if !defined(HAVE_BN_RAND_RANGE)
int
BN_rand_range(BIGNUM *r, const BIGNUM *range)
{
    return bn_rand_range(0, r, range);
}
#endif

#if !defined(HAVE_BN_PSEUDO_RAND_RANGE)
int
BN_pseudo_rand_range(BIGNUM *r, const BIGNUM *range)
{
    return bn_rand_range(1, r, range);
}
#endif

#if !defined(HAVE_BN_NNMOD)
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    if (!BN_mod(r,m,d,ctx)) return 0;
    if (!r->neg) return 1;
    return (d->neg ? BN_sub : BN_add)(r, r, d);
}
#endif

#if !defined(HAVE_BN_MOD_ADD)
int
BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    if (!BN_add(r, a, b)) return 0;
    return BN_nnmod(r, r, m, ctx);
}
#endif

#if !defined(HAVE_BN_MOD_SUB)
int
BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
    if (!BN_sub(r, a, b)) return 0;
    return BN_nnmod(r, r, m, ctx);
}
#endif

#if !defined(HAVE_BN_MOD_SQR)
int
BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    if (!BN_sqr(r, (BIGNUM*)a, ctx)) return 0;
    return BN_mod(r, r, m, ctx);
}
#endif

#if !defined(OPENSSL_NO_HMAC)
#include <openssl/hmac.h>
#if !defined(HAVE_HMAC_INIT_EX)
int
HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
	     const EVP_MD *md, void *impl)
{
    if (impl)
	rb_bug("impl not supported");
    return HMAC_Init(ctx, key, key_len, md);
}
#endif
#endif

#if !defined(HAVE_X509_CRL_SET_NEXTUPDATE)
int
X509_CRL_set_nextUpdate(X509_CRL *x, const ASN1_TIME *tm)
{
    ASN1_TIME *in = M_ASN1_TIME_dup(tm);
    if (!in)
	return 0;
    x->crl->nextUpdate = in;
    return 1;
}
#endif

#if !defined(HAVE_X509_CRL_ADD0_REVOKED)
static int
OSSL_X509_REVOKED_cmp(const X509_REVOKED * const *a, const X509_REVOKED * const *b)
{
    return(ASN1_STRING_cmp(
		(ASN1_STRING *)(*a)->serialNumber,
		(ASN1_STRING *)(*b)->serialNumber));
}

int
X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev)
{
    X509_CRL_INFO *inf;

    inf = crl->crl;
    if (!inf->revoked)
	inf->revoked = sk_X509_REVOKED_new(OSSL_X509_REVOKED_cmp);
    if (!inf->revoked || !sk_X509_REVOKED_push(inf->revoked, rev))
	return 0;
    return 1;
}
#endif

#if !defined(HAVE_X509_CRL_SET_ISSUER_NAME)
int
X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name)
{
    if (x == NULL || x->crl == NULL) return 0;
    return X509_NAME_set(&x->crl->issuer, name);
}
#endif

#if !defined(HAVE_X509_CRL_SET_VERSION)
int
X509_CRL_set_version(X509_CRL *x, long version)
{
    if (x == NULL || x->crl == NULL) return 0;
    if (x->crl->version == NULL) {
	x->crl->version = M_ASN1_INTEGER_new();
	if (x->crl->version == NULL) return 0;
    }
    return ASN1_INTEGER_set(x->crl->version, version);
}
#endif

#if !defined(HAVE_X509_CRL_SORT)
int
X509_CRL_sort(X509_CRL *c)
{
    int i;
    X509_REVOKED *r;
    /* sort the data so it will be written in serial
     * number order */
    sk_X509_REVOKED_sort(c->crl->revoked);
    for (i=0; i<sk_X509_REVOKED_num(c->crl->revoked); i++) {
	r=sk_X509_REVOKED_value(c->crl->revoked, i);
	r->sequence=i;
    }
    return 1;
}
#endif

/*** added in 0.9.8 ***/
#if !defined(HAVE_BN_IS_PRIME_EX)
int BN_is_prime_ex(const BIGNUM *bn, int checks, BN_CTX *ctx, void *cb)
{
    if (cb)
	rb_bug("not supported");
    return BN_is_prime(bn, checks, NULL, ctx, NULL);
}
#endif

#if !defined(HAVE_BN_IS_PRIME_FASTTEST_EX)
int BN_is_prime_fasttestex(const BIGNUM *bn, int checks, BN_CTX *ctx,
	int do_trial_division, void *cb)
{
    if (cb)
	rb_bug("not supported");
    return BN_is_prime_fasttest(bn, checks, NULL, ctx, NULL, do_trial_division);
}
#endif

#if !defined(HAVE_BN_GENERATE_PRIME_EX)
int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
                         const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
{
    if (cb)
	rb_bug("not supported");
    return BN_generate_prime(ret, bits, safe, add, rem, NULL);
}
#endif

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

#if !defined(HAVE_SSL_SESSION_GET_ID)
const unsigned char *
SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len)
{
    if (len)
	*len = s->session_id_length;
    return s->session_id;
}
#endif

/*** added in 1.0.0 ***/
#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
#if defined(HAVE_ENGINE_ADD)
#  include <openssl/engine.h>
#endif
/*
 * this function does not exist in OpenSSL yet... or ever?.
 * a future version may break this function.
 * tested on 0.9.7d.
 */
int
EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
{
    memcpy(out, in, sizeof(EVP_CIPHER_CTX));

#if defined(HAVE_ENGINE_ADD)
    if (in->engine) ENGINE_add(out->engine);
    if (in->cipher_data) {
	out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
	memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }
#endif

    return 1;
}
#endif

#if !defined(OPENSSL_NO_HMAC)
#include <openssl/hmac.h>
#if !defined(HAVE_HMAC_CTX_COPY)
void
HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in)
{
    if (!out || !in) return;
    memcpy(out, in, sizeof(HMAC_CTX));

    EVP_MD_CTX_copy(&out->md_ctx, &in->md_ctx);
    EVP_MD_CTX_copy(&out->i_ctx, &in->i_ctx);
    EVP_MD_CTX_copy(&out->o_ctx, &in->o_ctx);
}
#endif
#endif

/*** added in 1.0.1 ***/
/*** added in 1.0.2 ***/
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

/*** added in 1.1.0 ***/
#if !defined(OPENSSL_NO_HMAC)
#include <openssl/hmac.h>
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
#if defined(HAVE_HMAC_CTX_CLEANUP)
    HMAC_CTX_cleanup(ctx);
#else /* 0.9.6 */
    EVP_MD_CTX_cleanup(&ctx->i_ctx);
    EVP_MD_CTX_cleanup(&ctx->o_ctx);
    EVP_MD_CTX_cleanup(&ctx->md_ctx);
#endif
    OPENSSL_free(ctx);
}
#endif

#if !defined(HAVE_HMAC_CTX_RESET)
#if !defined(HAVE_EVP_MD_CTX_INIT)
#include <string.h> /* memcpy() */
static void
EVP_MD_CTX_init(EVP_MD_CTX *ctx)
{
    memset(ctx, 0, sizeof(EVP_MD_CTX));
}
#endif

int
HMAC_CTX_reset(HMAC_CTX *ctx)
{
#if defined(HAVE_HMAC_CTX_INIT)
    HMAC_CTX_init(ctx);
#else /* 0.9.6 */
    EVP_MD_CTX_init(&ctx->i_ctx);
    EVP_MD_CTX_init(&ctx->o_ctx);
    EVP_MD_CTX_init(&ctx->md_ctx);
#endif
    return 0;
}
#endif
#endif

#if !defined(HAVE_EVP_MD_CTX_NEW)
EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
#if defined(HAVE_EVP_MD_CTX_CREATE)
    return EVP_MD_CTX_create();
#else /* 0.9.6 */
    EVP_MD_CTX *ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
    if (!ctx)
	return NULL;
    memset(ctx, 0, sizeof(EVP_MD_CTX));
    return ctx;
#endif
}
#endif

#if !defined(HAVE_EVP_MD_CTX_FREE)
void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
#if defined(HAVE_EVP_MD_CTX_DESTROY)
    EVP_MD_CTX_destroy(ctx);
#else /* 0.9.6 */
    /* EVP_MD_CTX_cleanup(ctx); */
    /* FIXME!!! */
    memset(ctx, 0, sizeof(EVP_MD_CTX));
    OPENSSL_free(ctx);
#endif
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

#if !defined(HAVE_X509_REVOKED_SET_SERIALNUMBER)
int
X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial)
{
    ASN1_INTEGER *in = x->serialNumber;
    if (in != serial)
        return ASN1_STRING_copy(in, serial);
    return 1;
}
#endif
