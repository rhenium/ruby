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

#if !defined(HAVE_HMAC_CTX_COPY)
void HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in);
#endif

#if !defined(HAVE_EVP_CIPHER_CTX_COPY)
int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in);
#endif

#if !defined(HAVE_X509_STORE_GET_EX_DATA)
void *X509_STORE_get_ex_data(X509_STORE *str, int idx);
#endif

#if !defined(HAVE_X509_STORE_SET_EX_DATA)
int X509_STORE_set_ex_data(X509_STORE *str, int idx, void *data);
#endif

#if !defined(HAVE_CRYPTO_MEMCMP)
int CRYPTO_memcmp(const volatile void * volatile in_a, const volatile void * volatile in_b, size_t len);
#endif

#if !defined(HAVE_SSL_CTX_CLEAR_OPTIONS)
# define SSL_CTX_clear_options(ctx, op) do \
	(ctx)->options &= ~(op); while (0)
#endif

#if !defined(HAVE_X509_REVOKED_DUP)
# define X509_REVOKED_dup(rev) (X509_REVOKED *)ASN1_dup((i2d_of_void *)i2d_X509_REVOKED, \
	(d2i_of_void *)d2i_X509_REVOKED, (char *)(rev))
#endif

#if defined(__cplusplus)
}
#endif

#endif /* _OSSL_OPENSSL_MISSING_H_ */
