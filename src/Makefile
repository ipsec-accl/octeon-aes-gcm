# SPDX-License-Identifier: GPL-2.0
#
# Makefile — Octeon III AES-GCM COP2 Hardware Offload Module
#
# Build Targets:
#   make                  — Build module (requires KDIR and CROSS_COMPILE)
#   make clean            — Clean build artifacts
#   make install          — Install to module staging area
#   make test-load        — Syntax check: verify module metadata
#
# Prerequisites:
#   - Cavium Octeon MIPS64 cross-compiler toolchain
#   - EdgeOS 2.x kernel source (GPL tarball from Ubiquiti)
#
# Example invocation:
#   make KDIR=/path/to/edgeos-kernel \
#        CROSS_COMPILE=mips64-octeon-linux-gnu- \
#        ARCH=mips

# Module object
obj-m := octeon_aes_gcm.o

# Kernel source directory
# Override with: make KDIR=/path/to/kernel/source
KDIR ?= /lib/modules/$(shell uname -r)/build

# Cross-compilation settings for Octeon MIPS64
# Override with: make CROSS_COMPILE=mips64-octeon-linux-gnu-
ARCH ?= mips
CROSS_COMPILE ?= mips64-octeon-linux-gnu-

# Package metadata for 'make deb'
# Override if targeting a different platform or kernel:
#   make deb PLATFORM=e300 KERNEL_VER=4.9.79-UBNT
PLATFORM    ?= e300
KERNEL_VER  ?= 4.9.79-UBNT
PKG_NAME    := octeon-aes-gcm
PKG_VERSION := 1.0.0-$(PLATFORM)-$(KERNEL_VER)
PKG_ARCH    := mips
DEB_FILE    := ../$(PKG_NAME)_$(PKG_VERSION)_$(PKG_ARCH).deb
LOAD_SCRIPT := ../load-octeon-gcm.sh

# Extra compiler flags
ccflags-y += -DCONFIG_CAVIUM_OCTEON_CRYPTO
ccflags-y += -Wno-unused-function
ccflags-y += -I$(srctree)/arch/mips/cavium-octeon/crypto

# Primary target: build the kernel module
all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) modules

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) clean
	rm -f Module.symvers modules.order

# Install to INSTALL_MOD_PATH (default: /)
install:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) modules_install

# Quick metadata check (run on target device after scp)
test-load:
	@echo "=== Module Info ==="
	modinfo octeon_aes_gcm.ko 2>/dev/null || echo "(run on target device)"
	@echo ""
	@echo "=== Verify octeon-crypto dependency ==="
	@echo "Ensure 'octeon-crypto' module is loaded before insmod."

# Build Debian package: octeon-aes-gcm_<version>_mips.deb
# Contains the .ko and boot script; installs to /config/ so it survives firmware upgrades.
# Requires dpkg-deb on the build machine (available on Raspbian).
# Place the resulting .deb in /config/data/firstboot/install-packages/ on the router
# so it is automatically reinstalled after a firmware upgrade.
deb: octeon_aes_gcm.ko
	@which dpkg-deb >/dev/null 2>&1 || \
		{ echo "ERROR: dpkg-deb not found — run: sudo apt-get install dpkg-dev"; exit 1; }
	@[ -f "$(LOAD_SCRIPT)" ] || \
		{ echo "ERROR: $(LOAD_SCRIPT) not found"; exit 1; }
	$(SHELL) -ec '\
		WORK=$$(mktemp -d); trap "rm -rf $$WORK" EXIT; \
		install -d -m 0755 $$WORK/config/modules; \
		install -d -m 0755 $$WORK/config/scripts/pre-config.d; \
		install -m 0644 octeon_aes_gcm.ko $$WORK/config/modules/octeon_aes_gcm.ko; \
		install -m 0755 $(LOAD_SCRIPT) $$WORK/config/scripts/pre-config.d/load-octeon-gcm.sh; \
		mkdir -p $$WORK/DEBIAN; \
		{ printf "Package: $(PKG_NAME)\n"; \
		  printf "Version: $(PKG_VERSION)\n"; \
		  printf "Architecture: $(PKG_ARCH)\n"; \
		  printf "Maintainer: ipsec-accl\n"; \
		  printf "Description: Octeon AES-GCM COP2 hardware offload for EdgeRouter 6P\n"; \
		  printf " Registers rfc4106(gcm(aes)) and gcm(aes) at priority 500.\n"; \
		  printf " Built for platform $(PLATFORM), kernel $(KERNEL_VER).\n"; \
		} > $$WORK/DEBIAN/control; \
		{ printf "#!/bin/sh\nset -e\n"; \
		  printf "mkdir -p /config/modules\n"; \
		  printf "mkdir -p /config/scripts/pre-config.d\n"; \
		  printf "chmod 0755 /config/scripts/pre-config.d/load-octeon-gcm.sh\n"; \
		  printf "if lsmod | grep -q octeon_aes_gcm; then\n"; \
		  printf "    logger -t octeon-aes-gcm postinst: module already loaded\n"; \
		  printf "elif [ \"\$$(uname -r)\" != \"$(KERNEL_VER)\" ]; then\n"; \
		  printf "    logger -t octeon-aes-gcm postinst: WARNING: kernel mismatch -- skipping load\n"; \
		  printf "else\n"; \
		  printf "    insmod /config/modules/octeon_aes_gcm.ko \\\\\n"; \
		  printf "        && logger -t octeon-aes-gcm postinst: module loaded \\\\\n"; \
		  printf "        || logger -t octeon-aes-gcm postinst: insmod failed\n"; \
		  printf "fi\n"; \
		} > $$WORK/DEBIAN/postinst; \
		chmod 0755 $$WORK/DEBIAN/postinst; \
		dpkg-deb --root-owner-group --build $$WORK $(DEB_FILE); \
	'
	@echo "Built: $(DEB_FILE)"

.PHONY: all clean install test-load deb
