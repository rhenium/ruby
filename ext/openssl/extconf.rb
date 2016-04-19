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
# compile options
have_func("SSLv2_method")
have_func("SSLv3_method")
have_func("TLSv1_1_method")
have_func("TLSv1_2_method")
have_macro("OPENSSL_FIPS", ['openssl/opensslconf.h']) && $defs.push("-DHAVE_OPENSSL_FIPS")
have_func("RAND_egd")
# ENGINE_load_xx is deprecated in OpenSSL 1.1.0 and become a macro
engines = %w{builtin_engines openbsd_dev_crypto dynamic 4758cca aep atalla chil
             cswift nuron sureware ubsec padlock capi gmp gost cryptodev aesni}
engines.each { |name|
  have_func("ENGINE_load_#{name}", ["openssl/engine.h"])
}

have_func("SSL_CTX_clear_options", ["openssl/ssl.h"])
have_func("HMAC_CTX_copy")

# added in 1.0.0
have_func("EVP_CIPHER_CTX_copy")
have_func("PKCS5_PBKDF2_HMAC")
have_func("X509_NAME_hash_old")
have_func("SSL_set_tlsext_host_name", ["openssl/ssl.h"])
have_struct_member("CRYPTO_THREADID", "ptr", "openssl/crypto.h")

# added in 1.0.1
have_func("SSL_CTX_set_next_proto_select_cb")
have_macro("EVP_CTRL_GCM_GET_TAG", ['openssl/evp.h']) && $defs.push("-DHAVE_AUTHENTICATED_ENCRYPTION")

# added in 1.0.2
have_func("CRYPTO_memcmp")
have_func("X509_REVOKED_dup")
have_func("SSL_CTX_set_alpn_select_cb")
have_func("SSL_get_server_tmp_key", ["openssl/ssl.h"])

# added in 1.1.0
have_func("X509_STORE_get_ex_data")
have_func("X509_STORE_set_ex_data")

have_struct_member("X509_ATTRIBUTE", "single", "openssl/x509.h")
Logging::message "=== Checking done. ===\n"

create_header
create_makefile("openssl") {|conf|
  conf << "THREAD_MODEL = #{CONFIG["THREAD_MODEL"]}\n"
}
Logging::message "Done.\n"
