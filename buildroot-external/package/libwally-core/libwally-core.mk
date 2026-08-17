################################################################################
#
# libwally-core
#
# Bitcoin primitive wallet library. Provides BIP32/BIP39, BIP143/BIP341
# sighashes, RFC6979 deterministic ECDSA and BIP174/BIP370 PSBT support.
#
# Pinned to an exact upstream tag. The bundled secp256k1-zkp submodule is
# fetched at the revision recorded in that tag, so the whole crypto stack is
# byte-for-byte determined by LIBWALLY_CORE_VERSION below. Buildroot caches
# the resulting tarball in $(DL_DIR), which is what an offline/air-gapped
# rebuild replays (see `make signeros-source` in the top-level Makefile).
#
################################################################################

LIBWALLY_CORE_VERSION = release_1.5.6
LIBWALLY_CORE_SITE = https://github.com/ElementsProject/libwally-core.git
LIBWALLY_CORE_SITE_METHOD = git
LIBWALLY_CORE_GIT_SUBMODULES = YES

LIBWALLY_CORE_LICENSE = MIT
LIBWALLY_CORE_LICENSE_FILES = LICENSE

# Static archive linked into btc_signer_gui; nothing is shipped on the image.
LIBWALLY_CORE_INSTALL_STAGING = YES
LIBWALLY_CORE_INSTALL_TARGET = NO

LIBWALLY_CORE_DEPENDENCIES = \
	host-autoconf \
	host-automake \
	host-libtool \
	host-pkgconf

# The tarball is generated from git, so there are no pre-generated autotools
# files. Run upstream's own bootstrap (it also bootstraps src/secp256k1)
# rather than Buildroot's generic AUTORECONF, which does not recurse.
LIBWALLY_CORE_AUTORECONF = NO

define LIBWALLY_CORE_RUN_AUTOGEN
	cd $(@D) && PATH=$(BR_PATH) ./tools/autogen.sh
endef
LIBWALLY_CORE_PRE_CONFIGURE_HOOKS += LIBWALLY_CORE_RUN_AUTOGEN

# --disable-builtin-memset appends -fno-builtin-memset, which stops the
#   compiler eliding the memset() inside wally_bzero()/wally_clear(). That is
#   the difference between a real secret wipe and a no-op at -Os.
# --disable-elements drops all Liquid/confidential-transaction code; SignerOS
#   signs Bitcoin PSBTs only. The elements *ABI* is left at its default (on)
#   so the public struct layouts match upstream exactly.
LIBWALLY_CORE_CONF_OPTS = \
	--enable-static \
	--disable-shared \
	--disable-swig-python \
	--disable-swig-java \
	--disable-tests \
	--disable-secp256k1-tests \
	--disable-clear-tests \
	--disable-elements \
	--disable-builtin-memset \
	--disable-debug \
	--disable-coverage \
	--disable-fuzzing

$(eval $(autotools-package))
