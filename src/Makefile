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

.PHONY: all clean install test-load
