################################################################################
#
# btc-signer-gui
#
# The SignerOS kiosk application, built from src/btc_signer_gui/ in this
# repository (SITE_METHOD = local, so no download and no network at build
# time for this package).
#
################################################################################

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

BTC_SIGNER_GUI_CONF_OPTS = \
	-DSIGNEROS_QT_MAJOR=$(BTC_SIGNER_GUI_QT_MAJOR) \
	-DSIGNEROS_NETWORK=$(call qstrip,$(BR2_PACKAGE_BTC_SIGNER_GUI_NETWORK)) \
	-DSIGNEROS_WORD_SUGGESTIONS=$(if $(BR2_PACKAGE_BTC_SIGNER_GUI_WORD_SUGGESTIONS),ON,OFF)

# MinSizeRel (-Os) everywhere: the rootfs is a RAM-resident initramfs, so
# every byte of text is a byte of permanently occupied physical memory.
BTC_SIGNER_GUI_CONF_OPTS += -DCMAKE_BUILD_TYPE=MinSizeRel

$(eval $(cmake-package))
