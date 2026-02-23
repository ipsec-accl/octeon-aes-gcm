#!/bin/bash
# Load Octeon AES-GCM COP2 hardware offload module at boot.
#
# Place in /config/scripts/pre-config.d/
# Runs as root BEFORE EdgeOS configuration is applied, so the module is
# registered in the Linux Crypto API before IPsec (charon) starts.
# No ipsec restart needed — hardware GCM is available from the first SA.
#
# After a firmware upgrade the kernel version may change, making the
# pre-built .ko incompatible.  In that case this script logs a warning
# and skips loading — rebuild the module against the new kernel and
# copy the new .ko to /config/tmp/octeon_aes_gcm.ko to restore offload.

KO="/config/tmp/octeon_aes_gcm.ko"
EXPECTED_KERNEL="4.9.79-UBNT"
RUNNING_KERNEL=$(uname -r)
TAG="octeon-aes-gcm"

if [ ! -f "$KO" ]; then
    logger -t "$TAG" "Module not found at $KO — skipping"
    exit 0
fi

if lsmod | grep -q octeon_aes_gcm; then
    logger -t "$TAG" "Module already loaded"
    exit 0
fi

if [ "$RUNNING_KERNEL" != "$EXPECTED_KERNEL" ]; then
    logger -t "$TAG" "WARNING: kernel mismatch — module built for $EXPECTED_KERNEL, running $RUNNING_KERNEL"
    logger -t "$TAG" "Rebuild octeon_aes_gcm.ko against the new kernel and copy to $KO"
    exit 0
fi

insmod "$KO"
if [ $? -ne 0 ]; then
    logger -t "$TAG" "insmod failed — check kernel compatibility"
    exit 1
fi

logger -t "$TAG" "Module loaded — hardware AES-GCM available for IPsec"
