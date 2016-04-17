/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_OPENSSL_MISSING_H_)
#define _OSSL_OPENSSL_MISSING_H_

#include <openssl/ssl.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* added in -0.9.7 */
/* These functions are not included in headers of OPENSSL <= 0.9.6b */
#ifndef TYPEDEF_D2I_OF
typedef char *d2i_of_void(void **, const unsigned char **, long);
#endif
#ifndef TYPEDEF_I2D_OF
typedef int i2d_of_void(void *, unsigned char **);
#endif

#if !defined(PEM_read_bio_DSAPublicKey)
# define PEM_read_bio_DSAPublicKey(bp,x,cb,u) (DSA *)PEM_ASN1_read_bio( \
	(d2i_of_void *)d2i_DSAPublicKey,PEM_STRING_DSA_PUBLIC,(bp),(void **)(x),(cb),(u))
#endif

#if !defined(PEM_write_bio_DSAPublicKey)
# define PEM_write_bio_DSAPublicKey(bp,x) \
	PEM_ASN1_write_bio((i2d_of_void *)i2d_DSAPublicKey,\
		PEM_STRING_DSA_PUBLIC,\
		(bp),(char *)(x), NULL, NULL, 0, NULL, NULL)
#endif

#if !defined(DSAPrivateKey_dup)
# define DSAPrivateKey_dup(dsa) (DSA *)ASN1_dup((i2d_of_void *)i2d_DSAPrivateKey, \
	(d2i_of_void *)d2i_DSAPrivateKey,(char *)(dsa))
#endif

#if !defined(DSAPublicKey_dup)
# define DSAPublicKey_dup(dsa) (DSA *)ASN1_dup((i2d_of_void *)i2d_DSAPublicKey, \
	(d2i_of_void *)d2i_DSAPublicKey,(char *)(dsa))
#endif

#if !defined(X509_REVOKED_dup)
# define X509_REVOKED_dup(rev) (X509_REVOKED *)ASN1_dup((i2d_of_void *)i2d_X509_REVOKED, \
	(d2i_of_void *)d2i_X509_REVOKED, (char *)(rev))
#endif

#if !defined(PKCS7_SIGNER_INFO_dup)
#  define PKCS7_SIGNER_INFO_dup(si) (PKCS7_SIGNER_INFO *)ASN1_dup((i2d_of_void *)i2d_PKCS7_SIGNER_INFO, \
	(d2i_of_void *)d2i_PKCS7_SIGNER_INFO, (char *)(si))
#endif

#if !defined(PKCS7_RECIP_INFO_dup)
#  define PKCS7_RECIP_INFO_dup(ri) (PKCS7_RECIP_INFO *)ASN1_dup((i2d_of_void *)i2d_PKCS7_RECIP_INFO, \
	(d2i_of_void *)d2i_PKCS7_RECIP_INFO, (char *)(ri))
#endif


#if !defined(EVP_CIPHER_name)
#  define EVP_CIPHER_name(e) OBJ_nid2sn(EVP_CIPHER_nid(e))
#endif

#if !defined(EVP_MD_name)
#  define EVP_MD_name(e) OBJ_nid2sn(EVP_MD_type(e))
#endif

#if !defined(PKCS7_is_detached)
#  define PKCS7_is_detached(p7) (PKCS7_type_is_signed(p7) && PKCS7_get_detached(p7))
#endif

#if !defined(PKCS7_type_is_encrypted)
#  define PKCS7_type_is_encrypted(a) (OBJ_obj2nid((a)->type) == NID_pkcs7_encrypted)
#endif

/* start: checked by extconf.rb */
#if !defined(HAVE_OPENSSL_CLEANSE)
#define OPENSSL_cleanse(p, l) memset((p), 0, (l))
#endif

#if !defined(HAVE_ERR_PEEK_LAST_ERROR)
#endif

#if !defined(HAVE_CONF_GET1_DEFAULT_CONFIG_FILE)
char *CONF_get1_default_config_file(void);
#endif

#if !defined(HAVE_ASN1_PUT_EOC)
int ASN1_put_eoc(unsigned char **pp);
#endif

#if !defined(HAVE_OBJ_NAME_DO_ALL_SORTED)
#endif

#if !defined(HAVE_PEM_DEF_CALLBACK)
int PEM_def_callback(char *buf, int num, int w, void *key);
#endif

#if !defined(HAVE_BN_RAND_RANGE)
int BN_rand_range(BIGNUM *r, const BIGNUM *range);
#endif

#if !defined(HAVE_BN_PSEUDO_RAND_RANGE)
int BN_pseudo_rand_range(BIGNUM *r, const BIGNUM *range);
#endif

#if !defined(HAVE_BN_NNMOD)
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
#endif

#if !defined(HAVE_BN_MOD_ADD)
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
#endif

#if !defined(HAVE_BN_MOD_SUB)
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
#endif

#if !defined(HAVE_BN_MOD_SQR)
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
#endif

#if !defined(HAVE_MD_CTX_INIT)
#endif

#if !defined(HAVE_MD_CTX_CREATE)
#endif

#if !defined(HAVE_MD_CTX_DESTROY)
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_SET_PADDING)
#endif

#if !defined(HAVE_EVP_DIGESTINIT_EX)
#  define EVP_DigestInit_ex(ctx, md, engine) EVP_DigestInit((ctx), (md))
#endif

#if !defined(HAVE_EVP_DIGESTFINAL_EX)
#  define EVP_DigestFinal_ex(ctx, buf, len) EVP_DigestFinal((ctx), (buf), (len))
#endif

#if !defined(HAVE_EVP_CIPHERINIT_EX)
#  define EVP_CipherInit_ex(ctx, type, impl, key, iv, enc) EVP_CipherInit((ctx), (type), (key), (iv), (enc))
#endif

#if !defined(HAVE_EVP_CIPHERFINAL_EX)
#  define EVP_CipherFinal_ex(ctx, outm, outl) EVP_CipherFinal((ctx), (outm), (outl))
#endif

#if !defined(OPENSSL_NO_HMAC)
#if !defined(HAVE_HMAC_INIT_EX)
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, void *impl);
#endif

#if !defined(HAVE_HMAC_CTX_INIT)
#endif

#if !defined(HAVE_HMAC_CTX_CLEANUP)
#endif
#endif

#if !defined(HAVE_X509_CRL_SET_NEXTUPDATE)
int X509_CRL_set_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
#endif

#if !defined(HAVE_X509_CRL_ADD0_REVOKED)
int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
#endif

#if !defined(HAVE_X509_CRL_SET_ISSUER_NAME)
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
#endif

#if !defined(HAVE_X509_CRL_SET_VERSION)
int X509_CRL_set_version(X509_CRL *x, long version);
#endif

#if !defined(HAVE_X509_CRL_SORT)
int X509_CRL_sort(X509_CRL *c);
#endif

#if !defined(HAVE_X509_STORE_GET_EX_DATA)
#  define X509_STORE_get_ex_data(str, idx) \
	CRYPTO_get_ex_data(&(str)->ex_data, idx)
#endif

#if !defined(HAVE_X509_STORE_SET_EX_DATA)
#  define X509_STORE_set_ex_data(str, idx, data) \
	CRYPTO_set_ex_data(&(str)->ex_data, idx, data)
#endif

#if !defined(HAVE_X509V3_SET_NCONF)
#endif

#if !defined(HAVE_X509V3_EXT_NCONF_NID)
#endif

/* ENGINE related API can't be polyfilled */


/*** added in 0.9.8 ***/
#if !defined(HAVE_BN_IS_PRIME_EX)
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
#endif

#if !defined(HAVE_BN_IS_PRIME_FASTTEST_EX)
int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, int do_trial_division, BN_GENCB *cb);
#endif

#if !defined(HAVE_BN_GENERATE_PRIME_EX)
int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_NEW)
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_FREE)
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
#endif

#if !defined(HAVE_DH_GENERATE_PARAMETERS_EX)
#endif

#if !defined(HAVE_DSA_GENERATE_PARAMETERS_EX)
#endif

#if !defined(HAVE_RSA_GENERATE_KEY_EX)
#endif

#if !defined(HAVE_SSL_SESSION_GET_ID)
int SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len);
#endif

#if !defined(HAVE_SSL_CTX_SET_TMP_ECDH_CALLBACK)
#endif

#if !defined(HAVE_OCSP_SINGLERESP_DELETE_EXT)
#  define OCSP_SINGLERESP_delete_ext(s, loc) \
	sk_X509_EXTENSION_delete((s)->singleExtensions, (loc))
#endif

/*** added in 1.0.0 ***/
#if !defined(HAVE_CRYPTO_THREADID_PTR)
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
#endif

#if !defined(HAVE_EVP_PKEY_BASE_ID)
#  define EVP_PKEY_base_id(pkey) EVP_PKEY_type((pkey)->type)
#endif

#if !defined(HAVE_HMAC_CTX_COPY)
void HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in);
#endif

#if !defined(HAVE_PKCS5_PBKDF2_HMAC)
#endif

#if !defined(HAVE_X509_NAME_HASH_OLD)
#endif

#if !defined(HAVE_SSL_SET_TLSEXT_HOST_NAME)
#endif

/*** added in 1.0.1 ***/
#if !defined(HAVE_SSL_CTX_SET_NEXT_PROTO_SELECT_CB)
#endif

/*** added in 1.0.2 ***/
#if !defined(HAVE_EC_CURVE_NIST2NID)
int EC_curve_nist2nid(const char *str);
#endif

#if !defined(HAVE_SSL_CTX_SET_ALPN_SELECT_CB)
#endif

#if !defined(HAVE_SSL_CTX_SET1_CURVES_LIST)
#endif

#if !defined(HAVE_SSL_CTX_SET_ECDH_AUTO)
#endif

#if !defined(HAVE_SSL_GET_SERVER_TMP_KEY)
#endif

/*** added in 1.1.0 ***/
#if !defined(HAVE_BN_GENCB_NEW)
#  define BN_GENCB_new() ((BN_GENCB *)OPENSSL_malloc(sizeof(BN_GENCB)))
#endif

#if !defined(HAVE_BN_GENCB_FREE)
#  define BN_GENCB_free(cb) OPENSSL_free(cb)
#endif

#if !defined(HAVE_BN_GENCB_GET_ARG)
#  define BN_GENCB_get_arg(cb) (cb)->arg
#endif

#if !defined(HAVE_HMAC_CTX_NEW)
HMAC_CTX *HMAC_CTX_new(void);
#endif

#if !defined(HAVE_HMAC_CTX_FREE)
void HMAC_CTX_free(HMAC_CTX *ctx);
#endif

#if !defined(HAVE_HMAC_CTX_RESET)
int HMAC_CTX_reset(HMAC_CTX *ctx);
#endif

#if !defined(HAVE_EVP_MD_CTX_NEW)
EVP_MD_CTX *EVP_MD_CTX_new(void);
#endif

#if !defined(HAVE_EVP_MD_CTX_FREE)
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
#endif

/* reference counter */
#if !defined(HAVE_X509_UP_REF)
#  define X509_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509)
#  define X509_CRL_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509_CRL);
#  define X509_STORE_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509_STORE);
#  define SSL_SESSION_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_SSL_SESSION);
#  define EVP_PKEY_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif

#if !defined(HAVE_X509_CRL_GET0_SIGNATURE)
void X509_CRL_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_CRL *crl);
#endif

#if !defined(HAVE_X509_REQ_GET0_SIGNATURE)
void X509_REQ_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_REQ *req);
#endif

#if !defined(HAVE_X509_GET0_TBS_SIGALG)
#  define X509_get0_tbs_sigalg(x) ((x)->cert_info->signature)
#endif

#if !defined(HAVE_X509_REVOKED_GET0_SERIALNUMBER)
#  define X509_REVOKED_get0_serialNumber(x) ((x)->serialNumber)
#endif

#if !defined(HAVE_X509_REVOKED_SET_SERIALNUMBER)
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
#endif

#if !defined(HAVE_X509_REVOKED_GET0_REVOCATIONDATE)
#  define X509_REVOKED_get0_revocationDate(x) (x->revocationDate)
#endif

#if !defined(HAVE_TLS_METHOD)
#  define TLS_method SSLv23_method
#  define TLS_server_method SSLv23_server_method
#  define TLS_client_method SSLv23_client_method
#endif

#if !defined(HAVE_SSL_CTX_GET_CIPHERS)
static inline STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx) { return ctx->cipher_list; }
#endif

#if !defined(HAVE_SSL_CTX_GET_SECURITY_LEVEL)
#endif

#if !defined(HAVE_SSL_CTX_SET_SECURITY_LEVEL)
#endif

#if !defined(HAVE_OCSP_SINGLERESP_GET0_ID)
#  define OCSP_SINGLERESP_get0_id(s) (s)->certId
#endif

#if defined(HAVE_EVP_PKEY_TYPE) /* is not opaque */
static inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey) { return pkey->pkey.rsa; }
static inline DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey) { return pkey->pkey.dsa; }
static inline EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) { return pkey->pkey.ec; }
static inline DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey) { return pkey->pkey.dh; }

static inline void RSA_get0_key(RSA *rsa, BIGNUM **n, BIGNUM **e, BIGNUM **d) {
	if (n) *n = rsa->n;
	if (e) *e = rsa->e;
	if (d) *d = rsa->d; }
static inline int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	if (!n || !e) return 0;
	BN_free(rsa->n); rsa->n = n;
	BN_free(rsa->e); rsa->e = e;
	BN_free(rsa->d); rsa->d = d;
	return 1; }
static inline void RSA_get0_factors(RSA *rsa, BIGNUM **p, BIGNUM **q) {
	if (p) *p = rsa->p;
	if (q) *q = rsa->q; }
static inline int RSA_set0_factors(RSA *rsa, BIGNUM *p, BIGNUM *q) {
	if (!p || !q) return 0;
	BN_free(rsa->p); rsa->p = p;
	BN_free(rsa->q); rsa->q = q;
	return 1; }
static inline void RSA_get0_crt_params(RSA *rsa, BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp) {
	if (dmp1) *dmp1 = rsa->dmp1;
	if (dmq1) *dmq1 = rsa->dmq1;
	if (iqmp) *iqmp = rsa->iqmp; }
static inline int RSA_set0_crt_params(RSA *rsa, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
	if (!dmp1 || !dmq1 || !iqmp) return 0;
	BN_free(rsa->dmp1); rsa->dmp1 = dmp1;
	BN_free(rsa->dmq1); rsa->dmq1 = dmq1;
	BN_free(rsa->iqmp); rsa->iqmp = iqmp;
	return 1; }

static inline void DSA_get0_key(DSA *dsa, BIGNUM **pub_key, BIGNUM **priv_key) {
	if (pub_key) *pub_key = dsa->pub_key;
	if (priv_key) *priv_key = dsa->priv_key; }
static inline int DSA_set0_key(DSA *dsa, BIGNUM *pub_key, BIGNUM *priv_key) {
	if (!pub_key) return 0;
	BN_free(dsa->pub_key); dsa->pub_key = pub_key;
	BN_free(dsa->priv_key); dsa->priv_key = priv_key;
	return 1; }
static inline void DSA_get0_pqg(DSA *dsa, BIGNUM **p, BIGNUM **q, BIGNUM **g) {
	if (p) *p = dsa->p;
	if (q) *q = dsa->q;
	if (g) *g = dsa->g; }
static inline int DSA_set0_pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	if (!p || !q || !g) return 0;
	BN_free(dsa->p); dsa->p = p;
	BN_free(dsa->q); dsa->q = q;
	BN_free(dsa->g); dsa->g = g;
	return 1; }

static inline ENGINE *DH_get0_engine(DH *dh) { return dh->engine; }
static inline void DH_get0_key(DH *dh, BIGNUM **pub_key, BIGNUM **priv_key) {
	if (pub_key) *pub_key = dh->pub_key;
	if (priv_key) *priv_key = dh->priv_key; }
static inline int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key) {
	if (!pub_key) return 0;
	BN_free(dh->pub_key); dh->pub_key = pub_key;
	BN_free(dh->priv_key); dh->priv_key = priv_key;
	return 1; }
static inline void DH_get0_pqg(DH *dh, BIGNUM **p, BIGNUM **q, BIGNUM **g) {
	if (p) *p = dh->p;
	if (q) *q = dh->q;
	if (g) *g = dh->g; }
static inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	if (!p || !g) return 0;
	BN_free(dh->p); dh->p = p;
	BN_free(dh->q); dh->q = q;
	BN_free(dh->g); dh->g = g;
	return 1; }
#endif

#if defined(__cplusplus)
}
#endif
#endif /* _OSSL_OPENSSL_MISSING_H_ */
