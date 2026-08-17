################################################################################
# SignerOS Buildroot external tree
#
# Sorted wildcard keeps the include order deterministic, which matters for
# reproducible builds (BR2_REPRODUCIBLE=y).
################################################################################

include $(sort $(wildcard $(BR2_EXTERNAL_SIGNEROS_PATH)/package/*/*.mk))

SIGNEROS_BOARD_DIR = $(BR2_EXTERNAL_SIGNEROS_PATH)/board/signeros

################################################################################
# signeros-test-image - build signeros-test.img
#
# WHY THIS IS A SEPARATE TARGET AND A SECOND KERNEL BUILD
#
# SignerOS boots a unified kernel image: the initramfs is linked into the kernel
# and the command line is compiled into it with CONFIG_CMDLINE_OVERRIDE=y, so
# the signed PE binary is the complete, unforgeable boot payload. The price is
# that the command line cannot be varied at boot by anybody - including
# scripts/test_in_qemu.sh, which needs a serial console and
# signeros.selftest=1 to verify the build headlessly.
#
# So the self-test image is a second kernel build. Same kernel source, same
# kernel configuration, the same images/rootfs.cpio linked in; the only
# difference between the two bzImages is the CONFIG_CMDLINE string, which comes
# from board/signeros/cmdline-selftest. That keeps `make test` evidence about
# the artefact you ship rather than about a differently-built one, and it keeps
# the production command line genuinely locked.
#
# It is a separate target, run by scripts/build.sh after the main build, so that
# `make all` stays a single kernel build for anyone who does not want the test
# image.
#
# Comment and blank lines in cmdline-selftest are stripped and the remaining
# lines joined; every real option starts with a lowercase letter, which is what
# the /^[a-z]/ match relies on (and why it needs no '#' that GNU make would
# treat as a comment here).
#
# Two things about the recipe below that are easy to get wrong:
#
#   $(EXTRA_ENV) on the post-image.sh line is how Buildroot itself invokes a
#   post-image script, and it is not optional: it puts $(HOST_DIR)/bin on PATH,
#   which is where genimage, mkfs.vfat and mcopy live. Without it the script runs
#   all the way to the last step and dies with "genimage: command not found".
#
#   Keep comments out of the recipe itself. GNU make passes a '#' line inside a
#   recipe to the shell and echoes it first, so an explanation there ends up
#   printed in the middle of the build output.
#
# THE RESTORE IS NOT OPTIONAL, AND NEITHER IS THE touch
#
# This target must leave the tree exactly as it found it, because the next
# ordinary build installs $(LINUX_IMAGE_PATH) into images/bzImage and signs it as
# the appliance. Getting that wrong once already shipped a self-test kernel
# inside signeros.img: it booted, ran the headless signer against whatever it
# found on the data partition, and powered off with no GUI.
#
# The subtle part is the touch. kbuild decides whether to re-run syncconfig - and
# therefore whether to regenerate include/config/auto.conf and invalidate
# setup.o - from the MTIME of .config, not from its contents. Restoring the
# backup with mv puts back the backup's older timestamp, so .config ends up older
# than the auto.conf written during the self-test build. kbuild then sees nothing
# to do, keeps the self-test CONFIG_CMDLINE in auto.conf, considers the self-test
# bzImage current, and the next build happily copies it out as production.
#
# touch fixes exactly that, and the explicit rebuild + reinstall below means the
# invariant does not depend on anyone else's build ordering. post-image.sh greps
# the finished binary for signeros.selftest=1 as the backstop.
################################################################################

SIGNEROS_SELFTEST_CMDLINE := $(shell sed -n 's/[[:space:]]*$$//; /^[a-z]/p' \
	$(SIGNEROS_BOARD_DIR)/cmdline-selftest | tr '\n' ' ' | sed -e 's/[[:space:]]*$$//')

.PHONY: signeros-test-image
signeros-test-image:
	$(Q)test -f $(LINUX_DIR)/.config || { \
		echo "signeros-test-image: no kernel configuration in $(LINUX_DIR)."; \
		echo "Build the appliance first: ./scripts/build.sh"; \
		exit 1; \
	}
	$(Q)test -n '$(SIGNEROS_SELFTEST_CMDLINE)' || { \
		echo "signeros-test-image: extracted an empty command line from"; \
		echo "$(SIGNEROS_BOARD_DIR)/cmdline-selftest - every option line must"; \
		echo "start with a lowercase letter."; \
		exit 1; \
	}
	@$(call MESSAGE,"Rebuilding the kernel with the self-test command line")
	$(Q)cp -a $(LINUX_DIR)/.config $(LINUX_DIR)/.config.signeros-production
	$(Q)$(LINUX_DIR)/scripts/config --file $(LINUX_DIR)/.config \
		--set-str CMDLINE '$(SIGNEROS_SELFTEST_CMDLINE)'
	$(Q)$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(LINUX_DIR) olddefconfig
	$(Q)grep -qxF 'CONFIG_CMDLINE="$(SIGNEROS_SELFTEST_CMDLINE)"' $(LINUX_DIR)/.config || { \
		echo "signeros-test-image: kconfig did not keep the self-test command line."; \
		echo "Got: $$(grep -m1 '^CONFIG_CMDLINE=' $(LINUX_DIR)/.config)"; \
		mv -f $(LINUX_DIR)/.config.signeros-production $(LINUX_DIR)/.config; \
		exit 1; \
	}
	$(Q)$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(LINUX_DIR) $(LINUX_TARGET_NAME)
	$(Q)$(INSTALL) -m 0644 -D $(LINUX_IMAGE_PATH) $(BINARIES_DIR)/bzImage-selftest
	@$(call MESSAGE,"Rebuilding the production kernel")
	$(Q)mv -f $(LINUX_DIR)/.config.signeros-production $(LINUX_DIR)/.config
	$(Q)touch $(LINUX_DIR)/.config
	$(Q)$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(LINUX_DIR) olddefconfig
	$(Q)$(LINUX_MAKE_ENV) $(BR2_MAKE) $(LINUX_MAKE_FLAGS) -C $(LINUX_DIR) $(LINUX_TARGET_NAME)
	$(Q)$(INSTALL) -m 0644 -D $(LINUX_IMAGE_PATH) $(BINARIES_DIR)/bzImage
	$(Q)if grep -aqF 'signeros.selftest=1' $(BINARIES_DIR)/bzImage; then \
		echo "signeros-test-image: images/bzImage is STILL the self-test kernel"; \
		echo "after the restore. Refusing to leave that in place - a later build"; \
		echo "would sign it as the appliance."; \
		exit 1; \
	fi
	@$(call MESSAGE,"Assembling signeros-test.img")
	$(Q)$(EXTRA_ENV) SIGNEROS_SELFTEST_BZIMAGE=$(BINARIES_DIR)/bzImage-selftest \
		$(SIGNEROS_BOARD_DIR)/post-image.sh $(BINARIES_DIR)
