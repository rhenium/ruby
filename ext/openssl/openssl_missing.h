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

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef TYPEDEF_D2I_OF
typedef char *d2i_of_void();
#endif
#ifndef TYPEDEF_I2D_OF
typedef int i2d_of_void();
#endif

/*
 * These functions are not included in headers of OPENSSL <= 0.9.6b
 */

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

#if !defined(HAVE_X509_CRL_SET_NEXTUPDATE)
int X509_CRL_set_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
#endif



#if !defined(HAVE_HMAC_CTX_NEW)
HMAC_CTX *HMAC_CTX_new(void);
#endif

#if !defined(HAVE_HMAC_CTX_FREE)
void HMAC_CTX_free(HMAC_CTX *ctx);
#endif

#if !defined(HAVE_HMAC_CTX_COPY)
void HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in);
#endif

#if !defined(HAVE_EVP_MD_CTX_NEW)
EVP_MD_CTX *EVP_MD_CTX_new(void);
#endif

#if !defined(HAVE_EVP_MD_CTX_FREE)
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_NEW)
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_FREE)
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, EVP_CIPHER_CTX *in);
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

#if !defined(HAVE_OPENSSL_CLEANSE)
#define OPENSSL_cleanse(p, l) memset((p), 0, (l))
#endif

#if !defined(HAVE_X509_STORE_GET_EX_DATA)
void *X509_STORE_get_ex_data(X509_STORE *str, int idx);
#endif

#if !defined(HAVE_X509_STORE_SET_EX_DATA)
int X509_STORE_set_ex_data(X509_STORE *str, int idx, void *data);
#endif

#if !defined(HAVE_X509_CRL_SET_VERSION)
int X509_CRL_set_version(X509_CRL *x, long version);
#endif

#if !defined(HAVE_X509_CRL_SET_ISSUER_NAME)
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
#endif

#if !defined(HAVE_X509_CRL_SORT)
int X509_CRL_sort(X509_CRL *c);
#endif

#if !defined(HAVE_X509_CRL_ADD0_REVOKED)
int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
#endif

#if !defined(HAVE_BN_MOD_SQR)
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
#endif

#if !defined(HAVE_BN_MOD_ADD)
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
#endif

#if !defined(HAVE_BN_MOD_SUB)
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
#endif

#if !defined(HAVE_BN_RAND_RANGE)
int BN_rand_range(BIGNUM *r, BIGNUM *range);
#endif

#if !defined(HAVE_BN_PSEUDO_RAND_RANGE)
int BN_pseudo_rand_range(BIGNUM *r, BIGNUM *range);
#endif

#if !defined(HAVE_CONF_GET1_DEFAULT_CONFIG_FILE)
char *CONF_get1_default_config_file(void);
#endif

#if !defined(HAVE_PEM_DEF_CALLBACK)
int PEM_def_callback(char *buf, int num, int w, void *key);
#endif

#if !defined(HAVE_ASN1_PUT_EOC)
int ASN1_put_eoc(unsigned char **pp);
#endif

#if !defined(HAVE_EVP_PKEY_id)
int EVP_PKEY_id(const EVP_PKEY *pkey);
#endif

#if !defined(X509_CRL_GET0_SIGNATURE)
void X509_CRL_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_CRL *crl);
#endif

#if !defined(X509_REQ_GET0_SIGNATURE)
void X509_REQ_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_REQ *req);
#endif

#if !defined(X509_REVOKED_GET0_SERIALNUMBER)
ASN1_INTEGER *X509_REVOKED_get0_serialNumber(X509_REVOKED *x);
#endif

#if !defined(X509_REVOKED_SET_SERIALNUMBER)
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
#endif

#if !defined(HAVE_EC_CURVE_NIST2NID) /* new in 1.0.2 */
int EC_curve_nist2nid(const char *str);
#endif

/*** new in 1.1.0 ***/
/* OCSP */
#if defined(HAVE_OPENSSL_OCSP_H)
#if !defined(HAVE_OCSP_ID_GET0_INFO)
int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash, ASN1_OBJECT **pmd,
		      ASN1_OCTET_STRING **pikeyHash,
		      ASN1_INTEGER **pserial, OCSP_CERTID *cid);
#endif

#if !defined(HAVE_OCSP_SINGLERESP_DELETE_EXT) /* for 0.9.6 */
#  define OCSP_SINGLERESP_delete_ext(s, loc) \
	sk_X509_EXTENSION_delete((s)->singleExtensions, (loc))
#endif

#if !defined(HAVE_OCSP_SINGLERESP_GET0_ID)
#  define OCSP_SINGLERESP_get0_id(s) (s)->certId
#endif
#endif /* HAVE_OPENSSL_OCSP_H */

/* SSL */
#include <openssl/ssl.h>
#if !defined(HAVE_SSL_SESSION_GET_ID)
int SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len);
#endif

#if !defined(HAVE_SSL_SESSION_CMP)
int SSL_SESSION_cmp(const SSL_SESSION *a,const SSL_SESSION *b);
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

/* EVP_PKEY */
#if !defined(HAVE_EVP_PKEY_ID)
#  define EVP_PKEY_id(pkey) (pkey->type)
#endif

#if defined(HAVE_EVP_PKEY_TYPE) /* is not opaque */
static inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey) { return pkey->pkey.rsa; }
static inline DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey) { return pkey->pkey.dsa; }
static inline EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) { return pkey->pkey.ec; }
static inline DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey) { return pkey->pkey.dh; }

static inline void RSA_get0_key(RSA *rsa, BIGNUM **pn, BIGNUM **pe, BIGNUM **pd) {
	if (pn) *pn = rsa->n;
	if (pe) *pe = rsa->e;
	if (pd) *pd = rsa->d; }
static inline void RSA_get0_factors(RSA *rsa, BIGNUM **pp, BIGNUM **pq) {
	if (pp) *pp = rsa->p;
	if (pq) *pq = rsa->q; }
static inline void RSA_get0_crt_params(RSA *rsa, BIGNUM **pdmp1, BIGNUM **pdmq1, BIGNUM **piqmp) {
	if (pdmp1) *pdmp1 = rsa->dmp1;
	if (pdmq1) *pdmq1 = rsa->dmq1;
	if (piqmp) *piqmp = rsa->iqmp; }

static inline void DSA_get0_key(DSA *dsa, BIGNUM **ppub_key, BIGNUM **ppriv_key) {
	if (ppub_key) *ppub_key = dsa->pub_key;
	if (ppriv_key) *ppriv_key = dsa->priv_key; }
static inline void DSA_get0_pqg(DSA *dsa, BIGNUM **pp, BIGNUM **pq, BIGNUM **pg) {
	if (pp) *pp = dsa->p;
	if (pq) *pq = dsa->q;
	if (pg) *pg = dsa->g; }

static inline ENGINE *DH_get0_engine(DH *dh) { return dh->engine; }
static inline void DH_get0_key(DH *dh, BIGNUM **ppub_key, BIGNUM **ppriv_key) {
	if (ppub_key) *ppub_key = dh->pub_key;
	if (ppriv_key) *ppriv_key = dh->priv_key; }
static inline void DH_get0_pqg(DH *dh, BIGNUM **pp, BIGNUM **pq, BIGNUM **pg) {
	if (pp) *pp = dh->p;
	if (pq) *pq = dh->q;
	if (pg) *pg = dh->g; }
#endif

/* HMAC */
#if !defined(HAVE_HMAC_CTX_RESET)
int HMAC_CTX_reset(HMAC_CTX *ctx);
#endif

#if !defined(HAVE_HMAC_INIT_EX)
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len, const EVP_MD *md, void *impl);
#endif

#if !defined(HAVE_HMAC_CTX_NEW)
HMAC_CTX *HMAC_CTX_new(void);
#endif

/* BN_GENCB */
#if !defined(HAVE_BN_GENCB_NEW)
#  define BN_GENCB_new() ((BN_GENCB *)OPENSSL_malloc(sizeof(BN_GENCB)))
#  define BN_GENCB_free(cb) OPENSSL_free(cb)
#  define BN_GENCB_get_arg(cb) cb->arg
#endif

/* X509 */
#if !defined(HAVE_X509_GET0_TBS_SIGALG)
#  define X509_get0_tbs_sigalg(x) (x->cert_info->signature)
#endif

#if !defined(HAVE_X509_REVOKED_GET0_SERIALNUMBER)
#  define X509_REVOKED_get0_serialNumber(x) (x->serialNumber)
#endif

#if !defined(HAVE_X509_REVOKED_GET0_REVOCATIONDATE)
#  define X509_REVOKED_get0_revocationDate(x) (x->revocationDate)
#endif




#if defined(__cplusplus)
}
#endif
#endif /* _OSSL_OPENSSL_MISSING_H_ */
