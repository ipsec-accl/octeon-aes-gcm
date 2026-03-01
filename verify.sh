#!/bin/bash
# verify.sh — Post-install verification for octeon-aes-gcm module
# Run on EdgeRouter 6P after installing octeon-aes-gcm .deb or insmod

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "      $1"; }

echo "========================================"
echo " Octeon AES-GCM Module Verification"
echo "========================================"
echo ""

# 1. Check CPU
echo "--- CPU Info ---"
model=$(grep "cpu model" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
echo "CPU: $model"
if echo "$model" | grep -qi "octeon"; then
    pass "Running on Octeon processor"
else
    warn "Not detected as Octeon — COP2 may not be available"
fi
echo ""

# 2. Check octeon-crypto dependency
echo "--- Dependencies ---"
if lsmod | grep -q "octeon_crypto"; then
    pass "octeon-crypto module loaded"
else
    fail "octeon-crypto module NOT loaded"
    info "Run: sudo modprobe octeon-crypto"
fi
echo ""

# 3. Check our module
echo "--- Module Status ---"
if lsmod | grep -q "octeon_aes_gcm"; then
    pass "octeon_aes_gcm module loaded"
    size=$(lsmod | grep octeon_aes_gcm | awk '{print $2}')
    info "Module size: ${size} bytes"
else
    fail "octeon_aes_gcm module NOT loaded"
    info "Run: sudo dpkg -i octeon-aes-gcm_*.deb"
    info "  or: sudo insmod /config/modules/octeon_aes_gcm.ko"
    info "Check: dmesg | tail -20"
    exit 1
fi
echo ""

# 4. Check dmesg for initialization
echo "--- Kernel Messages ---"
if dmesg | grep -q "octeon-aes-gcm.*Registered rfc4106"; then
    pass "rfc4106(gcm(aes)) registered successfully"
else
    fail "rfc4106(gcm(aes)) registration not found in dmesg"
    dmesg | grep "octeon-aes-gcm" | tail -5
fi

if dmesg | grep -q "octeon-aes-gcm.*Registered gcm(aes)"; then
    pass "gcm(aes) registered successfully"
else
    warn "gcm(aes) not registered (non-fatal)"
fi
echo ""

# 5. Check /proc/crypto
echo "--- Crypto API Registration ---"
if grep -q "octeon-rfc4106-gcm-aes" /proc/crypto; then
    pass "Driver found in /proc/crypto"

    # Extract priority
    priority=$(grep -A10 "octeon-rfc4106-gcm-aes" /proc/crypto | \
               grep "priority" | head -1 | awk '{print $3}')
    if [ -n "$priority" ]; then
        info "Priority: $priority"
        if [ "$priority" -ge 500 ]; then
            pass "Priority >= 500 (will override software implementation)"
        else
            warn "Priority < 500 — software implementation may take precedence"
        fi
    fi
else
    fail "Driver NOT found in /proc/crypto"
fi

# Check if it's the default for rfc4106
echo ""
echo "--- Active rfc4106 implementations ---"
grep -B1 -A10 "rfc4106(gcm(aes))" /proc/crypto | \
    grep -E "name|driver|priority" | head -12
echo ""

# 6. Check for IPsec SAs using GCM
echo "--- IPsec Status ---"
sa_count=$(ip xfrm state 2>/dev/null | grep -c "aes" || true)
if [ "$sa_count" -gt 0 ]; then
    info "Found $sa_count IPsec SA(s) with AES"
    ip xfrm state 2>/dev/null | grep -E "proto|algo" | head -10
else
    info "No active IPsec SAs (normal if tunnel not yet established)"
fi
echo ""

# 7. Quick functional test via /proc/crypto
echo "--- Functional Check ---"
info "To run a crypto self-test (if tcrypt is available):"
info "  sudo modprobe tcrypt mode=211"
info ""
info "To verify with live IPsec traffic:"
info "  watch -n1 'cat /proc/net/xfrm_stat'"
echo ""

echo "========================================"
echo " Verification complete"
echo "========================================"
