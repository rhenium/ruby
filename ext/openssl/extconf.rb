# -*- coding: us-ascii -*-
# frozen_string_literal: false
=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'LICENCE'.)
=end

require "mkmf"
require File.expand_path('../deprecation', __FILE__)

dir_config("openssl")
dir_config("kerberos")

Logging::message "=== OpenSSL for Ruby configurator ===\n"

##
# Adds -DOSSL_DEBUG for compilation and some more targets when GCC is used
# To turn it on, use: --with-debug or --enable-debug
#
if with_config("debug") or enable_config("debug")
  $defs.push("-DOSSL_DEBUG") unless $defs.include? "-DOSSL_DEBUG"
end

Logging::message "=== Checking for system dependent stuff... ===\n"
have_library("nsl", "t_open")
have_library("socket", "socket")
have_header("assert.h")

Logging::message "=== Checking for required stuff... ===\n"
if $mingw
  have_library("wsock32")
  have_library("gdi32")
end

result = pkg_config("openssl") && have_header("openssl/ssl.h")

unless result
  result = have_header("openssl/ssl.h")
  result &&= %w[crypto libeay32].any? {|lib| have_library(lib, "OpenSSL_add_all_digests")}
  result &&= %w[ssl ssleay32].any? {|lib| have_library(lib, "SSL_library_init")}
  unless result
    Logging::message "=== Checking for required stuff failed. ===\n"
    Logging::message "Makefile wasn't created. Fix the errors above.\n"
    exit 1
  end
end

unless have_header("openssl/conf_api.h")
  raise "OpenSSL 0.9.6 or later required."
end
unless OpenSSL.check_func("SSL_library_init()", "openssl/ssl.h")
  raise "Ignore OpenSSL broken by Apple.\nPlease use another openssl. (e.g. using `configure --with-openssl-dir=/path/to/openssl')"
end

def have_func_or_macro(name, header)
  have_func(name) ||
    have_macro(name, [header]) && $defs.push("-DHAVE_#{name.upcase}")
end

Logging::message "=== Checking for OpenSSL features... ===\n"
have_func("ERR_peek_last_error")
have_func("ASN1_put_eoc")
have_func("BN_mod_add")
have_func("BN_mod_sqr")
have_func("BN_mod_sub")
have_func("BN_pseudo_rand_range")
have_func("BN_rand_range")
have_func("BN_is_prime_ex") # for 0.9.6
have_func("BN_is_prime_fasttest_ex") # for 0.9.6
have_func("BN_generate_prime_ex") # for 0.9.6
have_func("BN_GENCB_new")
have_func("CONF_get1_default_config_file")
have_func("EVP_CIPHER_CTX_new")
have_func("EVP_CIPHER_CTX_free")
have_func("EVP_CIPHER_CTX_copy")
have_func("EVP_CIPHER_CTX_set_padding")
have_func("EVP_CipherFinal_ex")
have_func("EVP_CipherInit_ex")
have_func("EVP_DigestFinal_ex")
have_func("EVP_DigestInit_ex")
have_func("EVP_MD_CTX_new")
have_func("EVP_MD_CTX_create") # for 0.9.6
have_func("EVP_MD_CTX_free")
have_func("EVP_MD_CTX_destroy") # for 0.9.6
have_func("EVP_MD_CTX_init") # for 0.9.6
have_func("EVP_PKEY_id")
have_func("HMAC_CTX_new")
have_func("HMAC_CTX_init") # for 0.9.6
have_func("HMAC_CTX_free")
have_func("HMAC_CTX_cleanup") # for 0.9.6
have_func("HMAC_CTX_reset")
have_func("HMAC_Init_ex")
have_func("HMAC_CTX_copy")
have_func("PEM_def_callback")
have_func("PKCS5_PBKDF2_HMAC")
have_func("PKCS5_PBKDF2_HMAC_SHA1")
have_func("RAND_egd")
have_func("X509V3_set_nconf")
have_func("X509V3_EXT_nconf_nid")
have_func("X509_CRL_add0_revoked")
have_func("X509_CRL_set_issuer_name")
have_func("X509_CRL_set_version")
have_func("X509_CRL_sort")
have_func("X509_CRL_set_nextUpdate") # for 0.9.6
have_func("X509_CRL_get0_signature")
have_func("X509_REQ_get0_signature")
have_func("X509_get0_tbs_sigalg")
have_func("X509_REVOKED_get0_serialNumber")
have_func("X509_REVOKED_set_serialNumber")
have_func("X509_REVOKED_get0_revocationDate")
have_func("X509_REVOKED_set_nextUpdate")
have_func("X509_NAME_hash_old")
have_func("X509_STORE_get_ex_data")
have_func("X509_STORE_set_ex_data")
have_func("X509_up_ref")
have_func("OBJ_NAME_do_all_sorted")
have_func("SSL_SESSION_get_id")
have_func("SSL_SESSION_cmp")
have_func("OPENSSL_cleanse")
have_func("SSLv2_method")
have_func("SSLv2_server_method")
have_func("SSLv2_client_method")
have_func("SSLv3_method")
have_func("SSLv3_server_method")
have_func("SSLv3_client_method")
have_func("TLSv1_1_method")
have_func("TLSv1_1_server_method")
have_func("TLSv1_1_client_method")
have_func("TLSv1_2_method")
have_func("TLSv1_2_server_method")
have_func("TLSv1_2_client_method")
have_func("SSL_CTX_set_alpn_select_cb")
have_func("SSL_CTX_set_next_proto_select_cb")
have_func("SSL_CTX_set_tmp_ecdh_callback") # workaround: 1.1.0 removed this
have_macro("SSL_get_server_tmp_key", ['openssl/ssl.h']) && $defs.push("-DHAVE_SSL_GET_SERVER_TMP_KEY")
unless have_func("SSL_set_tlsext_host_name", ['openssl/ssl.h'])
  have_macro("SSL_set_tlsext_host_name", ['openssl/ssl.h']) && $defs.push("-DHAVE_SSL_SET_TLSEXT_HOST_NAME")
end
if have_header("openssl/engine.h")
  have_func("ENGINE_add")
  have_func("ENGINE_load_builtin_engines")
  have_func("ENGINE_load_openbsd_dev_crypto")
  have_func("ENGINE_get_digest")
  have_func("ENGINE_get_cipher")
  have_func_or_macro("ENGINE_load_dynamic", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_4758cca", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_aep", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_atalla", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_chil", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_cswift", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_nuron", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_sureware", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_ubsec", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_padlock", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_capi", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_gmp", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_gost", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_cryptodev", "openssl/engine.h")
  have_func_or_macro("ENGINE_load_aesni", "openssl/engine.h")
end
have_func("DH_generate_parameters_ex")
have_func("DSA_generate_parameters_ex")
have_func("RSA_generate_key_ex")
if checking_for('OpenSSL version is 0.9.7 or later') {
    try_static_assert('OPENSSL_VERSION_NUMBER >= 0x00907000L', 'openssl/opensslv.h')
  }
  have_header("openssl/ocsp.h")
  have_func("OCSP_id_get0_info")
  have_func("OCSP_SINGLERESP_delete_ext")
  have_func("OCSP_SINGLERESP_get0_id")
end
have_struct_member("CRYPTO_THREADID", "ptr", "openssl/crypto.h")
have_struct_member("EVP_CIPHER_CTX", "flags", "openssl/evp.h")
have_struct_member("EVP_CIPHER_CTX", "engine", "openssl/evp.h")
have_struct_member("EVP_PKEY", "type", "openssl/evp.h")
have_macro("OPENSSL_FIPS", ['openssl/opensslconf.h']) && $defs.push("-DHAVE_OPENSSL_FIPS")
have_macro("EVP_CTRL_GCM_GET_TAG", ['openssl/evp.h']) && $defs.push("-DHAVE_AUTHENTICATED_ENCRYPTION")
have_func("CRYPTO_lock") # removed in OpenSSL 1.1

Logging::message "=== Checking done. ===\n"

create_header
create_makefile("openssl") {|conf|
  conf << "THREAD_MODEL = #{CONFIG["THREAD_MODEL"]}\n"
}
Logging::message "Done.\n"
