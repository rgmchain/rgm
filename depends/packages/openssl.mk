package=openssl
$(package)_version=1.0.2
$(package)_version_suffix=u
$(package)_download_path=https://www.openssl.org/source/old/$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version)$($(package)_version_suffix).tar.gz
$(package)_sha256_hash=ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16
$(package)_patches=secure_getenv.patch

define $(package)_set_vars
$(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)"
$(package)_config_opts=--prefix=$($(package)_staging_prefix_dir) --openssldir=$($(package)_staging_prefix_dir)/etc/openssl
$(package)_config_opts+=no-camellia no-capieng no-cast no-comp no-dso no-dtls1
$(package)_config_opts+=no-ec_nistp_64_gcc_128 no-gost no-gmp no-heartbeats
$(package)_config_opts+=no-idea no-jpake no-krb5 no-libunbound no-md2 no-mdc2
$(package)_config_opts+=no-rc4 no-rc5 no-rdrand no-rfc3779 no-rsax no-sctp
$(package)_config_opts+=no-seed no-sha0 no-static_engine no-whirlpool no-zlib
$(package)_config_opts+=no-shared threads
$(package)_config_opts_x86_64_linux=linux-x86_64
$(package)_config_opts_i686_linux=linux-generic32
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/secure_getenv.patch
endef

define $(package)_config_cmds
  ./Configure $(if $(findstring mingw32,$(host_os)),$(if $(findstring x86_64,$(host_arch)),mingw64,mingw),$(if $(findstring linux,$(host_os)),$(if $(findstring x86_64,$(host_arch)),linux-x86_64,linux-generic32),)) $($(package)_config_opts) && make depend
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS) build_libs
endef

define $(package)_stage_cmds
  $(MAKE) INSTALL_PREFIX=$($(package)_staging_dir) install_sw || true && \
  mkdir -p $($(package)_staging_prefix_dir)/lib $($(package)_staging_prefix_dir)/include/openssl && \
  cp libssl.a libcrypto.a $($(package)_staging_prefix_dir)/lib/ && \
  find . -path "*/include/openssl/*.h" -exec cp -L {} $($(package)_staging_prefix_dir)/include/openssl/ \;
endef
