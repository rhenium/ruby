# -*- encoding: utf-8 -*-
# stub: openssl 1.1.0 ruby lib
# stub: ext/openssl/extconf.rb

Gem::Specification.new do |s|
  s.name = "openssl".freeze
  s.version = "1.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Martin Bosslet".freeze, "SHIBATA Hiroshi".freeze, "Zachary Scott".freeze]
  s.date = "2016-08-06"
  s.description = "It wraps the OpenSSL library.".freeze
  s.email = ["ruby-core@ruby-lang.org".freeze]
  s.extensions = ["ext/openssl/extconf.rb".freeze]
  s.files = [".gitignore".freeze, ".travis.yml".freeze, "BSDL".freeze, "CONTRIBUTING.md".freeze, "Dockerfile".freeze, "LICENSE.txt".freeze, "NEWS".freeze, "README.md".freeze, "Rakefile".freeze, "docker-compose.yml".freeze, "ext/openssl/deprecation.rb".freeze, "ext/openssl/extconf.rb".freeze, "ext/openssl/openssl_missing.c".freeze, "ext/openssl/openssl_missing.h".freeze, "ext/openssl/ossl.c".freeze, "ext/openssl/ossl.h".freeze, "ext/openssl/ossl_asn1.c".freeze, "ext/openssl/ossl_asn1.h".freeze, "ext/openssl/ossl_bio.c".freeze, "ext/openssl/ossl_bio.h".freeze, "ext/openssl/ossl_bn.c".freeze, "ext/openssl/ossl_bn.h".freeze, "ext/openssl/ossl_cipher.c".freeze, "ext/openssl/ossl_cipher.h".freeze, "ext/openssl/ossl_config.c".freeze, "ext/openssl/ossl_config.h".freeze, "ext/openssl/ossl_digest.c".freeze, "ext/openssl/ossl_digest.h".freeze, "ext/openssl/ossl_engine.c".freeze, "ext/openssl/ossl_engine.h".freeze, "ext/openssl/ossl_hmac.c".freeze, "ext/openssl/ossl_hmac.h".freeze, "ext/openssl/ossl_ns_spki.c".freeze, "ext/openssl/ossl_ns_spki.h".freeze, "ext/openssl/ossl_ocsp.c".freeze, "ext/openssl/ossl_ocsp.h".freeze, "ext/openssl/ossl_pkcs12.c".freeze, "ext/openssl/ossl_pkcs12.h".freeze, "ext/openssl/ossl_pkcs5.c".freeze, "ext/openssl/ossl_pkcs5.h".freeze, "ext/openssl/ossl_pkcs7.c".freeze, "ext/openssl/ossl_pkcs7.h".freeze, "ext/openssl/ossl_pkey.c".freeze, "ext/openssl/ossl_pkey.h".freeze, "ext/openssl/ossl_pkey_dh.c".freeze, "ext/openssl/ossl_pkey_dsa.c".freeze, "ext/openssl/ossl_pkey_ec.c".freeze, "ext/openssl/ossl_pkey_rsa.c".freeze, "ext/openssl/ossl_rand.c".freeze, "ext/openssl/ossl_rand.h".freeze, "ext/openssl/ossl_ssl.c".freeze, "ext/openssl/ossl_ssl.h".freeze, "ext/openssl/ossl_ssl_session.c".freeze, "ext/openssl/ossl_version.h".freeze, "ext/openssl/ossl_x509.c".freeze, "ext/openssl/ossl_x509.h".freeze, "ext/openssl/ossl_x509attr.c".freeze, "ext/openssl/ossl_x509cert.c".freeze, "ext/openssl/ossl_x509crl.c".freeze, "ext/openssl/ossl_x509ext.c".freeze, "ext/openssl/ossl_x509name.c".freeze, "ext/openssl/ossl_x509req.c".freeze, "ext/openssl/ossl_x509revoked.c".freeze, "ext/openssl/ossl_x509store.c".freeze, "ext/openssl/ruby_missing.h".freeze, "lib/openssl.rb".freeze, "lib/openssl/bn.rb".freeze, "lib/openssl/buffering.rb".freeze, "lib/openssl/cipher.rb".freeze, "lib/openssl/config.rb".freeze, "lib/openssl/digest.rb".freeze, "lib/openssl/pkey.rb".freeze, "lib/openssl/ssl.rb".freeze, "lib/openssl/x509.rb".freeze, "openssl.gemspec".freeze, "sample/c_rehash.rb".freeze, "sample/cert2text.rb".freeze, "sample/certstore.rb".freeze, "sample/cipher.rb".freeze, "sample/crlstore.rb".freeze, "sample/echo_cli.rb".freeze, "sample/echo_svr.rb".freeze, "sample/gen_csr.rb".freeze, "sample/smime_read.rb".freeze, "sample/smime_write.rb".freeze, "sample/wget.rb".freeze, "test/envutil.rb".freeze, "test/find_executable.rb".freeze, "test/memory_status.rb".freeze, "test/test_asn1.rb".freeze, "test/test_bn.rb".freeze, "test/test_buffering.rb".freeze, "test/test_cipher.rb".freeze, "test/test_config.rb".freeze, "test/test_digest.rb".freeze, "test/test_engine.rb".freeze, "test/test_fips.rb".freeze, "test/test_hmac.rb".freeze, "test/test_ns_spki.rb".freeze, "test/test_ocsp.rb".freeze, "test/test_pair.rb".freeze, "test/test_partial_record_read.rb".freeze, "test/test_pkcs12.rb".freeze, "test/test_pkcs5.rb".freeze, "test/test_pkcs7.rb".freeze, "test/test_pkey_dh.rb".freeze, "test/test_pkey_dsa.rb".freeze, "test/test_pkey_ec.rb".freeze, "test/test_pkey_rsa.rb".freeze, "test/test_random.rb".freeze, "test/test_ssl.rb".freeze, "test/test_ssl_session.rb".freeze, "test/test_x509attr.rb".freeze, "test/test_x509cert.rb".freeze, "test/test_x509crl.rb".freeze, "test/test_x509ext.rb".freeze, "test/test_x509name.rb".freeze, "test/test_x509req.rb".freeze, "test/test_x509store.rb".freeze, "test/ut_eof.rb".freeze, "test/utils.rb".freeze, "tool/sync-with-trunk".freeze]
  s.homepage = "http://www.ruby-lang.org/".freeze
  s.licenses = ["Ruby".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.3.0".freeze)
  s.rubygems_version = "2.6.6".freeze
  s.summary = "OpenSSL provides SSL, TLS and general purpose cryptography.".freeze
  s.test_files = ["test/envutil.rb".freeze, "test/find_executable.rb".freeze, "test/memory_status.rb".freeze, "test/test_asn1.rb".freeze, "test/test_bn.rb".freeze, "test/test_buffering.rb".freeze, "test/test_cipher.rb".freeze, "test/test_config.rb".freeze, "test/test_digest.rb".freeze, "test/test_engine.rb".freeze, "test/test_fips.rb".freeze, "test/test_hmac.rb".freeze, "test/test_ns_spki.rb".freeze, "test/test_ocsp.rb".freeze, "test/test_pair.rb".freeze, "test/test_partial_record_read.rb".freeze, "test/test_pkcs12.rb".freeze, "test/test_pkcs5.rb".freeze, "test/test_pkcs7.rb".freeze, "test/test_pkey_dh.rb".freeze, "test/test_pkey_dsa.rb".freeze, "test/test_pkey_ec.rb".freeze, "test/test_pkey_rsa.rb".freeze, "test/test_random.rb".freeze, "test/test_ssl.rb".freeze, "test/test_ssl_session.rb".freeze, "test/test_x509attr.rb".freeze, "test/test_x509cert.rb".freeze, "test/test_x509crl.rb".freeze, "test/test_x509ext.rb".freeze, "test/test_x509name.rb".freeze, "test/test_x509req.rb".freeze, "test/test_x509store.rb".freeze, "test/ut_eof.rb".freeze, "test/utils.rb".freeze]

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>.freeze, ["~> 10.3"])
      s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 0.9"])
      s.add_development_dependency(%q<test-unit>.freeze, ["~> 3.0"])
      s.add_development_dependency(%q<rdoc>.freeze, ["~> 4.2"])
    else
      s.add_dependency(%q<rake>.freeze, ["~> 10.3"])
      s.add_dependency(%q<rake-compiler>.freeze, ["~> 0.9"])
      s.add_dependency(%q<test-unit>.freeze, ["~> 3.0"])
      s.add_dependency(%q<rdoc>.freeze, ["~> 4.2"])
    end
  else
    s.add_dependency(%q<rake>.freeze, ["~> 10.3"])
    s.add_dependency(%q<rake-compiler>.freeze, ["~> 0.9"])
    s.add_dependency(%q<test-unit>.freeze, ["~> 3.0"])
    s.add_dependency(%q<rdoc>.freeze, ["~> 4.2"])
  end
end
