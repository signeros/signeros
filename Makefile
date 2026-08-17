# SignerOS - convenience wrapper around scripts/
#
# Everything here just calls a script; the scripts are the interface and they
# work standalone. `make help` lists what is available.

SHELL := /bin/bash
REPO  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
O     ?= $(REPO)/output
JOBS  ?= $(shell nproc 2>/dev/null || echo 4)

# The release version. One line in VERSION at the repo root is the authority for
# the whole tree - the image file names, the stamp in the initramfs and the
# string the kiosk shows all come from it. Override it for a one-off build with
# `make image SIGNEROS_VERSION=0.2.0-rc1`; the scripts read the same variable.
SIGNEROS_VERSION ?= $(strip $(shell cat $(REPO)/VERSION 2>/dev/null))
export SIGNEROS_VERSION

.DEFAULT_GOAL := help
.PHONY: help all image app keys reconfigure test test-selftest test-gui gui host-test source \
        menuconfig flash clean distclean check-scripts version

help:
	@echo "SignerOS $(SIGNEROS_VERSION)"
	@echo
	@echo "  make image           build the full appliance image (30-90 min first time)"
	@echo "  make app             re-sync and rebuild ONLY the kiosk, then re-make"
	@echo "                       the images - for iterating on src/. Costs a kernel"
	@echo "                       relink now that the rootfs lives inside the kernel."
	@echo "  make keys            generate a Secure Boot signing key in keys/"
	@echo "  make reconfigure     after editing the defconfig or a kernel fragment:"
	@echo "                       regenerate .config, re-run the kernel/busybox"
	@echo "                       kconfig steps, rebuild"
	@echo "  make test            boot it under UEFI and verify signing end to end"
	@echo "  make test-selftest   just the headless signing test"
	@echo "  make test-gui        just the framebuffer rendering test"
	@echo "  make gui             open the kiosk in a QEMU window to look at it"
	@echo "  make host-test       build and exercise the signing core on this machine"
	@echo "                       (add WALLY=build to fetch and build libwally too)"
	@echo "  make source          download every source tarball, for offline builds"
	@echo "  make menuconfig      inspect or adjust the Buildroot configuration"
	@echo "  make flash DEV=/dev/sdX [EXPAND=1]"
	@echo "  make check-scripts   shell and Python syntax checks"
	@echo "  make version         print the version this tree builds as"
	@echo "  make clean           remove $(O)"
	@echo "  make distclean       also remove the Buildroot checkout"
	@echo
	@echo "  Variables: O=$(O)  JOBS=$(JOBS)  FRAGMENTS=\"eglfs gpu-firmware\""
	@echo "  Secure Boot: export SIGNEROS_SB_KEY=... SIGNEROS_SB_CERT=... before"
	@echo "               'make image' to sign the boot payload (see 'make keys')"
	@echo

all: image

image:
	@O=$(O) $(REPO)/scripts/build.sh --jobs $(JOBS) \
		$(foreach f,$(FRAGMENTS),--fragment $(f))

# Fast loop for changes under src/btc_signer_gui.
#
# The package uses SITE_METHOD=local, which Buildroot implements as
# OVERRIDE_SRCDIR; `<pkg>-rebuild` deletes the .stamp_rsynced stamp, so the
# edited sources are re-copied rather than the stale copy in output/build being
# rebuilt. The second step regenerates the rootfs and both images.
#
# This is no longer a seconds-long loop. The rootfs is linked into the kernel
# (BR2_TARGET_ROOTFS_INITRAMFS), so any change to the kiosk relinks and
# recompresses the kernel - twice, because signeros-test.img is a second kernel
# build. Add --no-test-image below if you are only iterating on the UI and do
# not need `make test` in between.
app:
	@$(MAKE) -C $(REPO)/buildroot O=$(O) BR2_EXTERNAL=$(REPO)/buildroot-external \
		btc-signer-gui-rebuild
	@O=$(O) $(REPO)/scripts/build.sh --jobs $(JOBS)

# Buildroot has no way to notice that configs/buildroot_x86_64_defconfig or
# board/signeros/linux_hardening_defconfig changed: the package stamps are still
# valid, so the kernel would be rebuilt from its old .config. These packages have
# to be told to re-run their configuration step explicitly.
#
# Cheaper than `make clean` (the toolchain survives), but for an image you intend
# to flash and trust, prefer a full `make clean && make image`.
reconfigure:
	@$(MAKE) -C $(REPO)/buildroot O=$(O) BR2_EXTERNAL=$(REPO)/buildroot-external \
		buildroot_x86_64_defconfig
	@$(MAKE) -C $(REPO)/buildroot O=$(O) BR2_EXTERNAL=$(REPO)/buildroot-external \
		linux-reconfigure busybox-reconfigure
	@O=$(O) $(REPO)/scripts/build.sh --jobs $(JOBS)

source:
	@O=$(O) $(REPO)/scripts/build.sh --source-only

menuconfig:
	@O=$(O) $(REPO)/scripts/build.sh --menuconfig

test:
	@O=$(O) $(REPO)/scripts/test_in_qemu.sh

test-selftest:
	@O=$(O) $(REPO)/scripts/test_in_qemu.sh --selftest-only

test-gui:
	@O=$(O) $(REPO)/scripts/test_in_qemu.sh --gui-only

# Always the production image. There is no testnet GUI variant any more: the
# command line is compiled into the signed kernel, so signeros-test.img can only
# run the headless self-test. The fixture is generated on mainnet instead, which
# is why its addresses match what the production build renders.
gui:
	@O=$(O) $(REPO)/scripts/test_in_qemu.sh --interactive

keys:
	@$(REPO)/scripts/make_sb_keys.sh

host-test:
	@O=$(O) $(REPO)/scripts/host_selftest.sh \
		$(if $(filter build,$(WALLY)),--build-wally,)

flash:
	@test -n "$(DEV)" || { echo "usage: make flash DEV=/dev/sdX [EXPAND=1]"; exit 2; }
	@sudo IMAGE=$(O)/images/signeros.img $(REPO)/scripts/flash_usb.sh $(DEV) \
		$(if $(EXPAND),--expand-data,)

# Cheap gate worth running before every commit: it catches the class of mistake
# that only shows up 40 minutes into a build or 3 minutes into a QEMU boot.
check-scripts:
	@set -e; \
	for f in $(REPO)/scripts/*.sh \
	         $(REPO)/buildroot-external/board/signeros/post-*.sh; do \
		bash -n "$$f" && echo "  ok   $${f#$(REPO)/}"; \
	done; \
	for f in $(REPO)/buildroot-external/board/signeros/rootfs-overlay/etc/init.d/S* \
	         $(REPO)/buildroot-external/board/signeros/rootfs-overlay/usr/bin/* \
	         $(REPO)/buildroot-external/board/signeros/rootfs-overlay/usr/sbin/* \
	         $(REPO)/buildroot-external/board/signeros/rootfs-overlay/usr/lib/signeros/*.sh; do \
		sh -n "$$f" && echo "  ok   $${f#$(REPO)/}"; \
	done; \
	python3 -m py_compile $(REPO)/scripts/*.py && echo "  ok   scripts/*.py"; \
	python3 $(REPO)/scripts/make_test_data.py self-check > /dev/null \
		&& echo "  ok   fixture crypto matches published test vectors"; \
	printf '%s' "$(SIGNEROS_VERSION)" \
		| grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$$' \
		|| { echo "  FAIL VERSION is '$(SIGNEROS_VERSION)', which is not a version"; exit 1; }; \
	echo "  ok   VERSION is $(SIGNEROS_VERSION)"

# The images come out as signeros-$(SIGNEROS_VERSION)-x86_64.img, with
# signeros.img left as a symlink to the newest one. Edit VERSION and rebuild;
# nothing else in the tree needs touching.
version:
	@echo "$(SIGNEROS_VERSION)"

clean:
	@O=$(O) $(REPO)/scripts/build.sh --clean

distclean: clean
	@rm -rf $(REPO)/buildroot
	@echo "removed the Buildroot checkout"
