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

unless checking_for("OpenSSL version is 0.9.8 or later") {
    try_static_assert("OPENSSL_VERSION_NUMBER >= 0x00908000L", "openssl/opensslv.h") }
  raise "OpenSSL 0.9.8 or later is required."
end
unless OpenSSL.check_func("SSL_library_init()", "openssl/ssl.h")
  raise "Ignore OpenSSL broken by Apple.\nPlease use another openssl. (e.g. using `configure --with-openssl-dir=/path/to/openssl')"
end

Logging::message "=== Checking for OpenSSL features... ===\n"
have_func("EVP_CIPHER_CTX_copy")
have_func("HMAC_CTX_copy")
have_func("PKCS5_PBKDF2_HMAC")
have_func("RAND_egd")
have_func("X509_NAME_hash_old")
have_func("X509_STORE_get_ex_data")
have_func("X509_STORE_set_ex_data")
have_func("X509_REVOKED_dup")
have_func("CRYPTO_memcmp")
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
have_macro("SSL_CTX_clear_options", ["openssl/ssl.h"]) && $defs.push("-DHAVE_SSL_CTX_CLEAR_OPTIONS")
have_func("SSL_CTX_set_alpn_select_cb")
have_func("SSL_CTX_set_next_proto_select_cb")
have_macro("SSL_get_server_tmp_key", ['openssl/ssl.h']) && $defs.push("-DHAVE_SSL_GET_SERVER_TMP_KEY")
unless have_func("SSL_set_tlsext_host_name", ['openssl/ssl.h'])
  have_macro("SSL_set_tlsext_host_name", ['openssl/ssl.h']) && $defs.push("-DHAVE_SSL_SET_TLSEXT_HOST_NAME")
end

have_func("ENGINE_load_builtin_engines")
have_func("ENGINE_load_openbsd_dev_crypto")
have_func("ENGINE_cleanup")
have_func("ENGINE_load_dynamic")
have_func("ENGINE_load_4758cca")
have_func("ENGINE_load_aep")
have_func("ENGINE_load_atalla")
have_func("ENGINE_load_chil")
have_func("ENGINE_load_cswift")
have_func("ENGINE_load_nuron")
have_func("ENGINE_load_sureware")
have_func("ENGINE_load_ubsec")
have_func("ENGINE_load_padlock")
have_func("ENGINE_load_capi")
have_func("ENGINE_load_gmp")
have_func("ENGINE_load_gost")
have_func("ENGINE_load_cryptodev")
have_func("ENGINE_load_aesni")

have_struct_member("CRYPTO_THREADID", "ptr", "openssl/crypto.h")
have_struct_member("EVP_CIPHER_CTX", "flags", "openssl/evp.h")
have_struct_member("EVP_CIPHER_CTX", "engine", "openssl/evp.h")
have_struct_member("X509_ATTRIBUTE", "single", "openssl/x509.h")
have_macro("OPENSSL_FIPS", ['openssl/opensslconf.h']) && $defs.push("-DHAVE_OPENSSL_FIPS")
have_macro("EVP_CTRL_GCM_GET_TAG", ['openssl/evp.h']) && $defs.push("-DHAVE_AUTHENTICATED_ENCRYPTION")

Logging::message "=== Checking done. ===\n"

create_header
create_makefile("openssl") {|conf|
  conf << "THREAD_MODEL = #{CONFIG["THREAD_MODEL"]}\n"
}
Logging::message "Done.\n"
