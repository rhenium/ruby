/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001 Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#define NewX509Attr(klass) \
    TypedData_Wrap_Struct((klass), &ossl_x509attr_type, 0)
#define SetX509Attr(obj, attr) do { \
    if (!(attr)) { \
	ossl_raise(rb_eRuntimeError, "ATTR wasn't initialized!"); \
    } \
    RTYPEDDATA_DATA(obj) = (attr); \
} while (0)
#define GetX509Attr(obj, attr) do { \
    TypedData_Get_Struct((obj), X509_ATTRIBUTE, &ossl_x509attr_type, (attr)); \
    if (!(attr)) { \
	ossl_raise(rb_eRuntimeError, "ATTR wasn't initialized!"); \
    } \
} while (0)
#define SafeGetX509Attr(obj, attr) do { \
    OSSL_Check_Kind((obj), cX509Attr); \
    GetX509Attr((obj), (attr)); \
} while (0)

/*
 * Classes
 */
VALUE cX509Attr;
VALUE eX509AttrError;

static void
ossl_x509attr_free(void *ptr)
{
    X509_ATTRIBUTE_free(ptr);
}

static const rb_data_type_t ossl_x509attr_type = {
    "OpenSSL/X509/ATTRIBUTE",
    {
	0, ossl_x509attr_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

/*
 * Public
 */
VALUE
ossl_x509attr_new(X509_ATTRIBUTE *attr)
{
    X509_ATTRIBUTE *new;
    VALUE obj;

    obj = NewX509Attr(cX509Attr);
    if (!attr) {
	new = X509_ATTRIBUTE_new();
    } else {
	new = X509_ATTRIBUTE_dup(attr);
    }
    if (!new) {
	ossl_raise(eX509AttrError, NULL);
    }
    SetX509Attr(obj, new);

    return obj;
}

X509_ATTRIBUTE *
DupX509AttrPtr(VALUE obj)
{
    X509_ATTRIBUTE *attr, *new;

    SafeGetX509Attr(obj, attr);
    if (!(new = X509_ATTRIBUTE_dup(attr))) {
	ossl_raise(eX509AttrError, NULL);
    }

    return new;
}

/*
 * Private
 */
static VALUE
ossl_x509attr_alloc(VALUE klass)
{
    X509_ATTRIBUTE *attr;
    VALUE obj;

    obj = NewX509Attr(klass);
    if (!(attr = X509_ATTRIBUTE_new()))
	ossl_raise(eX509AttrError, NULL);
    SetX509Attr(obj, attr);

    return obj;
}

/*
 * call-seq:
 *    Attribute.new(oid [, value]) => attr
 */
static VALUE
ossl_x509attr_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE oid, value;
    X509_ATTRIBUTE *attr, *x;
    const unsigned char *p;

    GetX509Attr(self, attr);
    if(rb_scan_args(argc, argv, "11", &oid, &value) == 1){
	oid = ossl_to_der_if_possible(oid);
	StringValue(oid);
	p = (unsigned char *)RSTRING_PTR(oid);
	x = d2i_X509_ATTRIBUTE(&attr, &p, RSTRING_LEN(oid));
	DATA_PTR(self) = attr;
	if(!x){
	    ossl_raise(eX509AttrError, NULL);
	}
	return self;
    }
    rb_funcall(self, rb_intern("oid="), 1, oid);
    rb_funcall(self, rb_intern("value="), 1, value);

    return self;
}

/*
 * call-seq:
 *    attr.oid = string => string
 */
static VALUE
ossl_x509attr_set_oid(VALUE self, VALUE oid)
{
    X509_ATTRIBUTE *attr;
    ASN1_OBJECT *obj;
    char *s;

    s = StringValuePtr(oid);
    obj = OBJ_txt2obj(s, 0);
    if(!obj) obj = OBJ_txt2obj(s, 1);
    if(!obj) ossl_raise(eX509AttrError, NULL);
    GetX509Attr(self, attr);
    X509_ATTRIBUTE_set1_object(attr, obj);

    return oid;
}

/*
 * call-seq:
 *    attr.oid => string
 */
static VALUE
ossl_x509attr_get_oid(VALUE self)
{
    X509_ATTRIBUTE *attr;
    ASN1_OBJECT *oid;
    BIO *out;
    VALUE ret;
    int nid;

    GetX509Attr(self, attr);
    oid = X509_ATTRIBUTE_get0_object(attr);
    if ((nid = OBJ_obj2nid(oid)) != NID_undef)
	ret = rb_str_new2(OBJ_nid2sn(nid));
    else{
	if (!(out = BIO_new(BIO_s_mem())))
	    ossl_raise(eX509AttrError, NULL);
	i2a_ASN1_OBJECT(out, oid);
	ret = ossl_membio2str(out);
    }

    return ret;
}

/*#if defined(HAVE_ST_X509_ATTRIBUTE_SINGLE)
#  define OSSL_X509ATTR_IS_SINGLE(attr)  ((attr)->single)
#  define OSSL_X509ATTR_SET_SINGLE(attr) ((attr)->single = 1)
#else
#  define OSSL_X509ATTR_IS_SINGLE(attr)  (!(attr)->value.set)
#  define OSSL_X509ATTR_SET_SINGLE(attr) ((attr)->value.set = 0)
#endif*/

/*
 * call-seq:
 *    attr.value = asn1 => asn1
 */
static VALUE
ossl_x509attr_set_value(VALUE self, VALUE value)
{
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *a1type;

    if(!(a1type = ossl_asn1_get_asn1type(value)))
	ossl_raise(eASN1Error, "could not get ASN1_TYPE");
    if(ASN1_TYPE_get(a1type) == V_ASN1_SEQUENCE){
	ASN1_TYPE_free(a1type);
	ossl_raise(eASN1Error, "couldn't set SEQUENCE for attribute value.");
    }

    GetX509Attr(self, attr);
    if (X509_ATTRIBUTE_count(attr)) {
	ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
	/* populated, reset first */
	X509_ATTRIBUTE *new_attr = X509_ATTRIBUTE_new();
	if (!attr) {
	    ASN1_TYPE_free(a1type);
	    ossl_raise(rb_eRuntimeError, "X509_ATTRIBUTE_new() failed");
	}
	SetX509Attr(self, new_attr);
	X509_ATTRIBUTE_set1_object(new_attr, obj);
	X509_ATTRIBUTE_free(attr);
	attr = new_attr;
    }

    if (!X509_ATTRIBUTE_set1_data(attr, ASN1_TYPE_get(a1type), a1type->value.ptr, -1)) {
	ASN1_TYPE_free(a1type);
	ossl_raise(eX509AttrError, "X509_ATTRIBUTE_set1_data() failed");
    }
    ASN1_TYPE_free(a1type);

    return value;
}

/*
 * call-seq:
 *    attr.value => asn1
 */
static VALUE
ossl_x509attr_get_value(VALUE self)
{
    X509_ATTRIBUTE *attr;
    VALUE str, asn1;
    long length;
    unsigned char *p;
    int count;

    GetX509Attr(self, attr);
    count = X509_ATTRIBUTE_count(attr);
    if (!count) return Qnil;
    if (count == 1) {
	ASN1_TYPE *a1type = X509_ATTRIBUTE_get0_type(attr, 0);
	length = i2d_ASN1_TYPE(a1type, NULL);
	str = rb_str_new(0, length);
	p = (unsigned char *)RSTRING_PTR(str);
	i2d_ASN1_TYPE(a1type, &p);
    }
    else{
	/*length = i2d_ASN1_SET_OF_ASN1_TYPE(attr->value.set,
			(unsigned char **) NULL, i2d_ASN1_TYPE,
			V_ASN1_SET, V_ASN1_UNIVERSAL, 0);
	str = rb_str_new(0, length);
	p = (unsigned char *)RSTRING_PTR(str);
	i2d_ASN1_SET_OF_ASN1_TYPE(attr->value.set, &p,
			i2d_ASN1_TYPE, V_ASN1_SET, V_ASN1_UNIVERSAL, 0);*/
	length = i2d_X509_ATTRIBUTE(attr, NULL);
	str = rb_str_new(0, length);
	p = (unsigned char *)RSTRING_PTR(str);
	i2d_X509_ATTRIBUTE(attr, &p);
    }
    ossl_str_adjust(str, p);
    asn1 = rb_funcall(mASN1, rb_intern("decode"), 1, str);

    return asn1;
}

/*
 * call-seq:
 *    attr.to_der => string
 */
static VALUE
ossl_x509attr_to_der(VALUE self)
{
    X509_ATTRIBUTE *attr;
    VALUE str;
    int len;
    unsigned char *p;

    GetX509Attr(self, attr);
    if((len = i2d_X509_ATTRIBUTE(attr, NULL)) <= 0)
	ossl_raise(eX509AttrError, NULL);
    str = rb_str_new(0, len);
    p = (unsigned char *)RSTRING_PTR(str);
    if(i2d_X509_ATTRIBUTE(attr, &p) <= 0)
	ossl_raise(eX509AttrError, NULL);
    rb_str_set_len(str, p - (unsigned char*)RSTRING_PTR(str));

    return str;
}

/*
 * X509_ATTRIBUTE init
 */
void
Init_ossl_x509attr(void)
{
    eX509AttrError = rb_define_class_under(mX509, "AttributeError", eOSSLError);

    cX509Attr = rb_define_class_under(mX509, "Attribute", rb_cObject);
    rb_define_alloc_func(cX509Attr, ossl_x509attr_alloc);
    rb_define_method(cX509Attr, "initialize", ossl_x509attr_initialize, -1);
    rb_define_method(cX509Attr, "oid=", ossl_x509attr_set_oid, 1);
    rb_define_method(cX509Attr, "oid", ossl_x509attr_get_oid, 0);
    rb_define_method(cX509Attr, "value=", ossl_x509attr_set_value, 1);
    rb_define_method(cX509Attr, "value", ossl_x509attr_get_value, 0);
    rb_define_method(cX509Attr, "to_der", ossl_x509attr_to_der, 0);
}
