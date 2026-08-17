################################################################################
#
# btc-signer-gui
#
# The SignerOS kiosk application, built from src/btc_signer_gui/ in this
# repository (SITE_METHOD = local, so no download and no network at build
# time for this package).
#
################################################################################

# Buildroot's own notion of the package version, which only names the build
# directory. Deliberately *not* the release version: bumping it every release
# would move output/build/btc-signer-gui-<x>/ and throw away the object files
# with it. The release version is passed in as a -D below.
BTC_SIGNER_GUI_VERSION = 1.0.0
BTC_SIGNER_GUI_SITE = $(BR2_EXTERNAL_SIGNEROS_PATH)/../src/btc_signer_gui
BTC_SIGNER_GUI_SITE_METHOD = local
BTC_SIGNER_GUI_LICENSE = MIT
BTC_SIGNER_GUI_LICENSE_FILES = LICENSE

BTC_SIGNER_GUI_DEPENDENCIES = host-pkgconf libwally-core

ifeq ($(BR2_PACKAGE_BTC_SIGNER_GUI_QT6),y)
BTC_SIGNER_GUI_DEPENDENCIES += qt6base
BTC_SIGNER_GUI_QT_MAJOR = 6
else
BTC_SIGNER_GUI_DEPENDENCIES += qt5base
BTC_SIGNER_GUI_QT_MAJOR = 5
endif

# The release version, from VERSION at the repo root - the same line the image
# file names carry, so the kiosk on screen and the file it was flashed from
# cannot disagree. scripts/build.sh exports SIGNEROS_VERSION (and forces this
# package's configure step when it changes, since a changed -D alone does not
# invalidate a cmake stamp); a bare `make` inside buildroot/ reads the file.
BTC_SIGNER_GUI_SIGNEROS_VERSION = $(strip $(or \
	$(SIGNEROS_VERSION), \
	$(shell cat $(BR2_EXTERNAL_SIGNEROS_PATH)/../VERSION 2>/dev/null), \
	0.0.0-dev))

BTC_SIGNER_GUI_CONF_OPTS = \
	-DSIGNEROS_VERSION=$(BTC_SIGNER_GUI_SIGNEROS_VERSION) \
	-DSIGNEROS_QT_MAJOR=$(BTC_SIGNER_GUI_QT_MAJOR) \
	-DSIGNEROS_NETWORK=$(call qstrip,$(BR2_PACKAGE_BTC_SIGNER_GUI_NETWORK)) \
	-DSIGNEROS_WORD_SUGGESTIONS=$(if $(BR2_PACKAGE_BTC_SIGNER_GUI_WORD_SUGGESTIONS),ON,OFF)

# MinSizeRel (-Os) everywhere: the rootfs is a RAM-resident initramfs, so
# every byte of text is a byte of permanently occupied physical memory.
BTC_SIGNER_GUI_CONF_OPTS += -DCMAKE_BUILD_TYPE=MinSizeRel

$(eval $(cmake-package))
