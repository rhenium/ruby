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

/* added in 0.9.8X */
#if !defined(HAVE_EVP_CIPHER_CTX_NEW)
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_FREE)
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
#endif

#if !defined(HAVE_SSL_CTX_CLEAR_OPTIONS)
# define SSL_CTX_clear_options(ctx, op) do \
	(ctx)->options &= ~(op); while (0)
#endif

/* added in 1.0.0 */
#if !defined(HAVE_EVP_PKEY_BASE_ID)
#  define EVP_PKEY_base_id(pkey) EVP_PKEY_type((pkey)->type)
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
#endif

#if !defined(HAVE_HMAC_CTX_COPY)
int HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in);
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_CURRENT_CRL)
#  define X509_STORE_CTX_get0_current_crl(x) ((x)->current_crl)
#endif

#if !defined(HAVE_X509_STORE_SET_VERIFY_CB)
#  define X509_STORE_set_verify_cb X509_STORE_set_verify_cb_func
#endif

#if !defined(HAVE_I2D_ASN1_SET_ANY)
#  define i2d_ASN1_SET_ANY(sk, x) i2d_ASN1_SET_OF_ASN1_TYPE((sk), (x), \
		i2d_ASN1_TYPE, V_ASN1_SET, V_ASN1_UNIVERSAL, 0)
#endif

/* added in 1.0.2 */
#if !defined(HAVE_CRYPTO_MEMCMP)
int CRYPTO_memcmp(const volatile void * volatile in_a, const volatile void * volatile in_b, size_t len);
#endif

#if !defined(OPENSSL_NO_EC)
#if !defined(HAVE_EC_CURVE_NIST2NID)
int EC_curve_nist2nid(const char *str);
#endif
#endif

#if !defined(HAVE_X509_REVOKED_DUP)
# define X509_REVOKED_dup(rev) (X509_REVOKED *)ASN1_dup((i2d_of_void *)i2d_X509_REVOKED, \
	(d2i_of_void *)d2i_X509_REVOKED, (char *)(rev))
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_STORE)
#  define X509_STORE_CTX_get0_store(x) ((x)->ctx)
#endif

#if !defined(HAVE_SSL_IS_SERVER)
#  define SSL_is_server(s) ((s)->server)
#endif

/* added in 1.1.0 */
#if !defined(HAVE_BN_GENCB_NEW)
#  define BN_GENCB_new() ((BN_GENCB *)OPENSSL_malloc(sizeof(BN_GENCB)))
#endif

#if !defined(HAVE_BN_GENCB_FREE)
#  define BN_GENCB_free(cb) OPENSSL_free(cb)
#endif

#if !defined(HAVE_BN_GENCB_GET_ARG)
#  define BN_GENCB_get_arg(cb) (cb)->arg
#endif

#if !defined(HAVE_EVP_MD_CTX_NEW)
#  define EVP_MD_CTX_new EVP_MD_CTX_create
#endif

#if !defined(HAVE_EVP_MD_CTX_FREE)
#  define EVP_MD_CTX_free EVP_MD_CTX_destroy
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

#if !defined(HAVE_X509_STORE_GET_EX_DATA)
#  define X509_STORE_get_ex_data(x, idx) \
	CRYPTO_get_ex_data(&(x)->ex_data, idx)
#endif

#if !defined(HAVE_X509_STORE_SET_EX_DATA)
#  define X509_STORE_set_ex_data(x, idx, data) \
	CRYPTO_set_ex_data(&(x)->ex_data, idx, data)
#  define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
	CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)
#endif

#if !defined(HAVE_X509_CRL_GET0_SIGNATURE)
void X509_CRL_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_CRL *crl);
#endif

#if !defined(HAVE_X509_REQ_GET0_SIGNATURE)
void X509_REQ_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, X509_REQ *req);
#endif

#if !defined(HAVE_X509_REVOKED_GET0_SERIALNUMBER)
#  define X509_REVOKED_get0_serialNumber(x) ((x)->serialNumber)
#endif

#if !defined(HAVE_X509_REVOKED_GET0_REVOCATIONDATE)
#  define X509_REVOKED_get0_revocationDate(x) ((x)->revocationDate)
#endif

#if !defined(HAVE_X509_GET0_TBS_SIGALG)
#  define X509_get0_tbs_sigalg(x) ((x)->cert_info->signature)
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_UNTRUSTED)
#  define X509_STORE_CTX_get0_untrusted(x) ((x)->untrusted)
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_CERT)
#  define X509_STORE_CTX_get0_cert(x) ((x)->cert)
#endif

#if !defined(HAVE_X509_STORE_CTX_GET0_CHAIN)
#  define X509_STORE_CTX_get0_chain(ctx) X509_STORE_CTX_get_chain(ctx)
#endif

#if !defined(HAVE_OCSP_SINGLERESP_GET0_ID)
#  define OCSP_SINGLERESP_get0_id(s) ((s)->certId)
#endif

#if !defined(HAVE_X509_UP_REF)
#  define X509_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509)
#endif

#if !defined(HAVE_X509_CRL_UP_REF)
#  define X509_CRL_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509_CRL);
#endif

#if !defined(HAVE_X509_STORE_UP_REF)
#  define X509_STORE_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_X509_STORE);
#endif

#if !defined(HAVE_SSL_CTX_GET_CIPHERS)
#  define SSL_CTX_get_ciphers(ctx) ((ctx)->cipher_list)
#endif

#if !defined(HAVE_SSL_SESSION_UP_REF)
#  define SSL_SESSION_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_SSL_SESSION);
#endif

#if !defined(HAVE_EVP_PKEY_UP_REF)
#  define EVP_PKEY_up_ref(x) \
	CRYPTO_add(&(x)->references, 1, CRYPTO_LOCK_EVP_PKEY);
#endif

#if !defined(HAVE_OPAQUE_OPENSSL)
#if !defined(OPENSSL_NO_RSA)
static inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey) { return pkey->pkey.rsa; }
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
#endif /* RSA */

#if !defined(OPENSSL_NO_DSA)
static inline DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey) { return pkey->pkey.dsa; }
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
#endif /* DSA */

#if !defined(OPENSSL_NO_DH)
static inline DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey) { return pkey->pkey.dh; }
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
#endif /* DH */

#if !defined(OPENSSL_NO_EC)
static inline EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey) { return pkey->pkey.ec; }
#endif
#endif

#endif /* _OSSL_OPENSSL_MISSING_H_ */
