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
#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
#endif

#if !defined(HAVE_HMAC_CTX_COPY)
int HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in);
#endif

/* added in 1.0.2 */
#if !defined(HAVE_CRYPTO_MEMCMP)
int CRYPTO_memcmp(const volatile void * volatile in_a, const volatile void * volatile in_b, size_t len);
#endif

#if !defined(HAVE_X509_REVOKED_DUP)
# define X509_REVOKED_dup(rev) (X509_REVOKED *)ASN1_dup((i2d_of_void *)i2d_X509_REVOKED, \
	(d2i_of_void *)d2i_X509_REVOKED, (char *)(rev))
#endif

#if !defined(HAVE_SSL_IS_SERVER)
#  define SSL_is_server(s) ((s)->server)
#endif

/* added in 1.1.0 */
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

#if !defined(HAVE_OCSP_SINGLERESP_GET0_ID)
#  define OCSP_SINGLERESP_get0_id(s) ((s)->certId)
#endif

#endif /* _OSSL_OPENSSL_MISSING_H_ */
