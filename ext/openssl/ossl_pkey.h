/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_PKEY_H_)
#define _OSSL_PKEY_H_

extern VALUE mPKey;
extern VALUE cPKey;
extern VALUE ePKeyError;
extern ID id_private_q;
extern const rb_data_type_t ossl_evp_pkey_type;

#define OSSL_PKEY_SET_PRIVATE(obj) rb_iv_set((obj), "private", Qtrue)
#define OSSL_PKEY_SET_PUBLIC(obj)  rb_iv_set((obj), "private", Qfalse)
#define OSSL_PKEY_IS_PRIVATE(obj)  (rb_iv_get((obj), "private") == Qtrue)

#define NewPKey(klass) \
    TypedData_Wrap_Struct((klass), &ossl_evp_pkey_type, 0)
#define SetPKey(obj, pkey) do { \
    if (!(pkey)) { \
	rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!"); \
    } \
    RTYPEDDATA_DATA(obj) = (pkey); \
    OSSL_PKEY_SET_PUBLIC(obj); \
} while (0)
#define GetPKey(obj, pkey) do {\
    TypedData_Get_Struct((obj), EVP_PKEY, &ossl_evp_pkey_type, (pkey)); \
    if (!(pkey)) { \
	rb_raise(rb_eRuntimeError, "PKEY wasn't initialized!");\
    } \
} while (0)
#define SafeGetPKey(obj, pkey) do { \
    OSSL_Check_Kind((obj), cPKey); \
    GetPKey((obj), (pkey)); \
} while (0)

void ossl_generate_cb(int, int, void *);
#define HAVE_BN_GENCB defined(HAVE_RSA_GENERATE_KEY_EX) || defined(HAVE_DH_GENERATE_PARAMETERS_EX) || defined(HAVE_DSA_GENERATE_PARAMETERS_EX)
#if HAVE_BN_GENCB
struct ossl_generate_cb_arg {
    int yield;
    int stop;
    int state;
};
int ossl_generate_cb_2(int p, int n, BN_GENCB *cb);
void ossl_generate_cb_stop(void *ptr);
#endif

VALUE ossl_pkey_new(EVP_PKEY *);
VALUE ossl_pkey_new_from_file(VALUE);
EVP_PKEY *GetPKeyPtr(VALUE);
EVP_PKEY *DupPKeyPtr(VALUE);
EVP_PKEY *GetPrivPKeyPtr(VALUE);
EVP_PKEY *DupPrivPKeyPtr(VALUE);
void Init_ossl_pkey(void);

/*
 * RSA
 */
extern VALUE cRSA;
extern VALUE eRSAError;

VALUE ossl_rsa_new(EVP_PKEY *);
void Init_ossl_rsa(void);

/*
 * DSA
 */
extern VALUE cDSA;
extern VALUE eDSAError;

VALUE ossl_dsa_new(EVP_PKEY *);
void Init_ossl_dsa(void);

/*
 * DH
 */
extern VALUE cDH;
extern VALUE eDHError;

VALUE ossl_dh_new(EVP_PKEY *);
void Init_ossl_dh(void);

/*
 * EC
 */
extern VALUE cEC;
extern VALUE eECError;
extern VALUE cEC_GROUP;
extern VALUE eEC_GROUP;
extern VALUE cEC_POINT;
extern VALUE eEC_POINT;
VALUE ossl_ec_new(EVP_PKEY *);
void Init_ossl_ec(void);

/* yes this is very ugly :( */
#define OSSL_PKEY_BN_DEF_FUNC(keytype, type, name, b1, b2, b3, get, set)\
/*									\
 *  call-seq:								\
 *     key.##name -> aBN						\
 */									\
static VALUE ossl_##keytype##_get_##name(VALUE self)			\
{									\
	EVP_PKEY *pkey;							\
	BIGNUM *b1, *b2, *b3;						\
	type *obj;							\
									\
	GetPKey(self, pkey);						\
	obj = EVP_PKEY_get0_##type(pkey);				\
	get;								\
	return ossl_bn_new(name);					\
}									\
/*									\
 *  call-seq:								\
 *     key.##name = bn -> bn						\
 */									\
static VALUE ossl_##keytype##_set_##name(VALUE self, VALUE bignum)	\
{									\
	EVP_PKEY *pkey;							\
	BIGNUM *b1 = NULL, *b2 = NULL, *b3 = NULL;			\
	type *obj;							\
									\
	GetPKey(self, pkey);						\
	obj = EVP_PKEY_get0_##type(pkey);				\
	get; /* get current value */					\
	if (b1 && !(b1 = BN_dup(b1)))					\
		ossl_raise(eBNError, NULL);				\
	if (b2 && !(b2 = BN_dup(b2))) {					\
		if (b1) BN_clear_free(b1);				\
		ossl_raise(eBNError, NULL);				\
	}								\
	if (b3 && !(b3 = BN_dup(b3))) {					\
		if (b1) BN_clear_free(b1);				\
		if (b2) BN_clear_free(b2);				\
		ossl_raise(eBNError, NULL);				\
	}								\
	if (name) BN_clear_free(name);					\
	if (NIL_P(bignum))						\
		name = NULL;						\
	else if (!(name = BN_dup(GetBNPtr(bignum))))			\
		ossl_raise(eBNError, NULL);				\
	if (!(set)) {							\
		if (name) BN_clear_free(name);				\
		ossl_raise(eBNError, "priv_key set failed");		\
	}								\
	return bignum;							\
}

#define OSSL_PKEY_BN3(keytype, type, func_name, a1, a2, a3)		\
	OSSL_PKEY_BN_DEF_FUNC(keytype, type, a1, a1, a2, a3,		\
		type##_get0_##func_name(obj, &a1, &a2, &a3),		\
		type##_set0_##func_name(obj, a1, a2, a3))		\
	OSSL_PKEY_BN_DEF_FUNC(keytype, type, a2, a1, a2, a3,		\
		type##_get0_##func_name(obj, &a1, &a2, &a3),		\
		type##_set0_##func_name(obj, a1, a2, a3))		\
	OSSL_PKEY_BN_DEF_FUNC(keytype, type, a3, a1, a2, a3,		\
		type##_get0_##func_name(obj, &a1, &a2, &a3),		\
		type##_set0_##func_name(obj, a1, a2, a3))

#define OSSL_PKEY_BN2(keytype, type, func_name, a1, a2)			\
	OSSL_PKEY_BN_DEF_FUNC(keytype, type, a1, a1, a2, unused,	\
		type##_get0_##func_name(obj, &a1, &a2),			\
		type##_set0_##func_name(obj, a1, a2))			\
	OSSL_PKEY_BN_DEF_FUNC(keytype, type, a2, a1, a2, unused,	\
		type##_get0_##func_name(obj, &a1, &a2),			\
		type##_set0_##func_name(obj, a1, a2))

#define DEF_OSSL_PKEY_BN(class, keytype, name)				\
do {									\
	rb_define_method((class), #name, ossl_##keytype##_get_##name, 0);	\
	rb_define_method((class), #name "=", ossl_##keytype##_set_##name, 1);\
} while (0)

#endif /* _OSSL_PKEY_H_ */
