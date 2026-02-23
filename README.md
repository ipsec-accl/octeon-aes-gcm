# octeon-aes-gcm

AES-128-GCM hardware offload kernel module for the **Ubiquiti EdgeRouter 6P and EdgeRouter 4** (Cavium CN7130).

Enables IPsec ESP with `aes128gcm128` to use the router's built-in COP2 cryptographic
coprocessor instead of falling back to software. Verified working on EdgeOS 2.0.9
(Linux 4.9.79-UBNT) with StrongSwan 5.6.3.

## Background

The EdgeRouter 6P and EdgeRouter 4 are powered by the Cavium CN7130 SoC, which contains
a **COP2 cryptographic coprocessor** capable of hardware-accelerated AES and Galois Field
Multiply (GFM/GHASH) — the two operations needed for AES-GCM.

Ubiquiti's closed-source `cvm_ipsec_kame` driver uses this hardware for **AES-CBC** only.
When you configure `aes128gcm128` in IPsec, EdgeOS silently falls back to a software
implementation — even though the hardware fully supports it.

This was confirmed via **NIST CAVP certificate AES #3301**, which covers the CN7130's AES
engine including GCM/GHASH, proving the hardware capability exists.

This module fills that gap.

## How it differs from Ubiquiti's AES-CBC offload

Both use the **same COP2 hardware**. The difference is the software path:

```
AES-CBC (Ubiquiti's cvm_ipsec_kame):
  StrongSwan → XFRM → netfilter/KLIPS hook (cvm_ipsec_kame) → COP2 AES registers

AES-GCM (this module):
  StrongSwan → XFRM → Linux Crypto API → octeon_aes_gcm.ko → COP2 AES + GFM registers
```

Ubiquiti's driver intercepts at the netfilter level and handles complete ESP packet
processing, but only for the algorithms they chose to implement (AES-CBC, 3DES).

This module instead registers `rfc4106(gcm(aes))` in the **Linux Crypto API** at
priority 500 (above the software fallback). When StrongSwan negotiates AES-GCM for
a CHILD_SA, the kernel's native XFRM/ESP stack naturally picks our hardware
implementation for all encrypt/decrypt operations.

The COP2 hardware provides:
- **AES block cipher** (`dmtc2`/`dmfc2` to AES engine registers) — used for CTR
  keystream generation and the J0 block for the authentication tag
- **GFM (Galois Field Multiply-Accumulate)** — used for GHASH, computing the
  authentication tag over AAD + ciphertext

## Supported hardware

| Device | SoC | Status |
|--------|-----|--------|
| EdgeRouter 6P | CN7130 | ✅ Confirmed working |
| EdgeRouter 4 | CN7130 | ✅ Same SoC — should work |
| Other Octeon III (CN7xxx) devices | CN7xxx | Likely works — same COP2 |

**Kernel**: EdgeOS 2.0.9 / Linux 4.9.79-UBNT

Other Cavium Octeon III based devices running a 4.9 kernel should work. COP2
register addresses are sourced from
[MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14](https://github.com/MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14)
(`arch/mips/include/asm/octeon/cvmx-asm.h`).

## Installing the pre-built binary (no compilation needed)

If you are running **EdgeOS 2.0.9**, you can use the pre-built kernel module (`octeon_aes_gcm.ko`) at the root of this repo.
No cross-compiler or kernel source needed.

If you are running a different EdgeOS version, see [Building from source](#building-from-source).

### Step 1 — Get the files

Clone this repo on any machine with internet access, or download the two files
you need:
- `octeon_aes_gcm.ko` — the kernel module
- `load-octeon-gcm.sh` — the boot script

### Step 2 — Copy the module to the router

Upload the kernel module to `/config/tmp/` on the router. The `/config` partition
persists across reboots and firmware upgrades — unlike `/tmp` which is cleared on
every boot — making it the right place to store the module permanently.

```bash
# Run on your local machine.
# Replace 192.168.1.1 with your router's IP, and admin with your username.
scp octeon_aes_gcm.ko admin@192.168.1.1:/config/tmp/octeon_aes_gcm.ko
```

### Step 3 — Load the module

SSH into the router, then run:

```bash
sudo insmod /config/tmp/octeon_aes_gcm.ko
```

Verify it loaded:
```bash
dmesg | grep octeon-aes-gcm
```

Expected output:
```
octeon-aes-gcm: Octeon III AES-GCM hardware offload v1.0.0
octeon-aes-gcm: COP2 AES + GFM engine, priority 500
octeon-aes-gcm: Registered rfc4106(gcm(aes)) [octeon-rfc4106-gcm-aes]
octeon-aes-gcm: Registered gcm(aes) [octeon-gcm-aes]
```

> **Note:** If you already have an IPsec tunnel running, restart IPsec now so it
> picks up the hardware implementation for new SAs:
> ```bash
> sudo ipsec restart
> ```

### Step 4 — Set up automatic loading at boot

EdgeOS runs scripts in `/config/scripts/pre-config.d/` **before** IPsec (charon)
starts. Placing our script there means hardware GCM is available from the very
first IPsec SA — no `ipsec restart` needed after boot.

First, create the directory and upload the boot script from your local machine:

```bash
# Run on your local machine:
scp load-octeon-gcm.sh admin@192.168.1.1:/config/tmp/load-octeon-gcm.sh
```

Then SSH into the router and install it:

```bash
sudo mkdir -p /config/scripts/pre-config.d
sudo cp /config/tmp/load-octeon-gcm.sh /config/scripts/pre-config.d/load-octeon-gcm.sh
sudo chmod +x /config/scripts/pre-config.d/load-octeon-gcm.sh
```

The script checks the running kernel version before loading. If the kernel changed
after a firmware upgrade, it logs a warning and skips loading safely — you'll need
to rebuild the module for the new kernel.

After the next reboot, confirm the module loaded automatically:
```bash
ssh admin@192.168.1.1 "grep octeon-aes-gcm /var/log/messages"
# → octeon-aes-gcm: Module loaded — hardware AES-GCM available for IPsec
```

### Step 5 — Configure IPsec to use AES-GCM

If you already have an IPsec tunnel configured, you just need to update (or add) the
ESP proposal to use AES-GCM. If you are starting from scratch, configure your tunnel
as usual and set the ESP encryption to one of the AES-GCM variants below.

Via the EdgeOS CLI:

```
configure
set vpn ipsec esp-group ESP_GCM proposal 1 encryption aes128gcm128
set vpn ipsec esp-group ESP_GCM proposal 1 hash null
commit
save
```

Or in `/etc/ipsec.conf` / swanctl:
```
esp=aes128gcm128!
```

GCM is an AEAD cipher — it provides both encryption and authentication, so `hash null`
is correct (there is no separate HMAC).

**AES-192 and AES-256 are also supported** by this module. Replace `aes128gcm128` with:

| Variant | EdgeOS CLI | swanctl |
|---------|-----------|---------|
| AES-128-GCM (default) | `aes128gcm128` | `esp=aes128gcm128!` |
| AES-192-GCM | `aes192gcm128` | `esp=aes192gcm128!` |
| AES-256-GCM | `aes256gcm128` | `esp=aes256gcm128!` |

### Step 6 — Verify hardware is being used

**Check 1 — Confirm the driver registered in the kernel crypto API:**

```bash
grep -A 2 "octeon-rfc4106-gcm-aes" /proc/crypto
```

Expected output:
```
name         : rfc4106(gcm(aes))
driver       : octeon-rfc4106-gcm-aes
```

If `driver` shows `generic-gcm-aes` or similar instead, the hardware module did not
load — check `dmesg | grep octeon-aes-gcm` for errors.

**Check 2 — Confirm the active IPsec SA is using the hardware algorithm:**

After establishing the tunnel, SSH into the router and run:

```bash
sudo ip xfrm state | grep -E "proto|aead"
```

Expected output includes:
```
proto esp ...
    aead rfc4106(gcm(aes)) ...
```

**Check 3 — Live traffic test (no decryption errors):**

```bash
# On the receiving router — note the baseline count:
grep InStateProtoError /proc/net/xfrm_stat

# On the sending router — send some traffic:
ping6 -c 10 -I <SRC_ADDR> <DST_ADDR>

# On the receiving router — should not have increased:
grep InStateProtoError /proc/net/xfrm_stat
```

`XfrmInStateProtoError` increments when the kernel receives an ESP packet but fails
to decrypt/authenticate it. Zero increment confirms the hardware is producing correct
ciphertext and authentication tags.

You can also run `verify.sh` on the router:

```bash
scp verify.sh admin@192.168.1.1:/tmp/
ssh admin@192.168.1.1 "bash /tmp/verify.sh"
```

### IKE collision note (same-subnet peers)

If both IPsec peers are on the **same ISP /64 IPv6 subnet** (common when the
EdgeRouter 6P is your primary router and a second ER-6P is a backup on the same
line), you may encounter a persistent IKE collision loop after one router reboots.

**Root cause**: IPv6 Neighbor Discovery (NDP) traffic between the two routers' WAN
addresses matches the XFRM transport-mode policy, creating a larval `ESP/SPI=0`
state that continuously triggers ACQUIRE events on both sides — causing both charons
to initiate IKE simultaneously and collide.

**Fix**: Set the always-on router to respond-only for the peer connection:

```
# On the primary/always-on router:
configure
set vpn ipsec site-to-site peer <BACKUP_IPV6_ADDR> connection-type respond
commit
save
```

This eliminates the ACQUIRE loop on the primary router. The backup router remains
the sole initiator; the primary only responds. Tunnel re-establishes cleanly after
the backup reboots.

## Building from source

You need a Linux machine with a MIPS64 cross-compiler. I and Claude Code used a **Raspberry Pi 4**
(Debian aarch64) — the instructions below are specific to that setup, but any
Debian/Ubuntu machine (aarch64 or x86_64) works the same way.

### Step 1 — Install the cross-compiler

```bash
sudo apt update
sudo apt install crossbuild-essential-mips64
```

Verify:
```bash
mips64-linux-gnuabi64-gcc --version
# mips64-linux-gnuabi64-gcc (Debian 14.2.0-8cross1) 14.2.0
```

### Step 2 — Get the EdgeOS kernel source

The EdgeOS 2.0.9 kernel source is maintained by the community at
[Lochnair/kernel_e300](https://github.com/Lochnair/kernel_e300).

```bash
git clone https://github.com/Lochnair/kernel_e300.git
cd kernel_e300
git checkout v2.0.9-hotfix.2
```

### Step 3 — Prepare the kernel for out-of-tree module builds

This configures the kernel for MIPS and generates the headers needed to build modules.
Takes a few minutes.

```bash
make ARCH=mips CROSS_COMPILE=mips64-linux-gnuabi64- cavium_octeon_defconfig
make ARCH=mips CROSS_COMPILE=mips64-linux-gnuabi64- prepare modules_prepare
```

### Step 4 — Build the module

```bash
cd /path/to/octeon-aes-gcm/src
make KDIR=/path/to/kernel_e300 \
     CROSS_COMPILE=mips64-linux-gnuabi64- \
     ARCH=mips
```

Output: `src/octeon_aes_gcm.ko`

Then follow the [install steps above](#installing-the-pre-built-binary-no-compilation-needed)
using your freshly built `.ko` instead of the pre-built one.

## References

- **[MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14](https://github.com/MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14)**
  — Marvell's official Octeon Linux 4.14 kernel tree. The primary reference for all
  COP2 register addresses used in this driver, via
  `arch/mips/include/asm/octeon/cvmx-asm.h`. This file contains the authoritative
  inline assembly macros (`CVMX_MT_AES_ENC*`, `CVMX_MT_GFM_*`, `CVMX_MF_GFM_*`) and
  was the source for discovering: (1) the correct non-reflected GFM register addresses
  (`0x025x`), (2) the `0x4000` execute trigger bit, (3) the `=d` constraint bug in the
  reflected GFM macros, and (4) the GFM polynomial value `0xe100`.
  See implementation notes 1, 3, 5, 6, and 7 below.
- **[Lochnair/kernel_e300](https://github.com/Lochnair/kernel_e300)** — Community-maintained
  EdgeOS 4.9 kernel source, used as the build target (`KDIR`). Does not include
  `cvmx-asm.h`; used for kernel headers and the `octeon-crypto` module API only.
- **[NIST CAVP AES Certificate #3301](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=11151)**
  — Confirms CN7130 COP2 supports GCM/GHASH in hardware
- **[RFC 4106](https://www.rfc-editor.org/rfc/rfc4106)** — The Use of Galois/Counter Mode (GCM) in IPsec Encapsulating Security Payload
- **[NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)** — Recommendation for Block Cipher Modes of Operation: GCM and GMAC
- **[Linux Kernel Crypto API](https://www.kernel.org/doc/html/latest/crypto/index.html)** — `include/crypto/aead.h`, `include/crypto/internal/aead.h`

## Key implementation notes

The following bugs were discovered and fixed during development — documented here
for anyone working on similar Cavium COP2 drivers:

1. **GFM trigger bit**: `CVMX_MT_GFM_XORMUL1` maps to register `0x425D` (not `0x025D`).
   The `0x4000` bit is the execute trigger for GFM operations.
   *(Source: Marvell 4.14 `cvmx-asm.h` — `CVMX_MT_GFM_XORMUL1` → `dmtc2 val, 0x425d`)*

2. **AAD scope for rfc4106**: XFRM passes `assoclen = 16` (SPI + SeqNum + explicit IV).
   Only the first 8 bytes (SPI + SeqNum) are authenticated per RFC 4106 — the explicit
   IV is excluded from GHASH.
   *(Source: RFC 4106)*

3. **AES ECB encrypt registers**: ECB encrypt is `0x010A`/`0x310B` (not `0x010E`/`0x010F`
   which are ECB *decrypt*). The `0x3000` bit is the execute trigger for AES operations.
   *(Source: Marvell 4.14 `cvmx-asm.h` — `CVMX_MT_AES_ENC0` → `0x010a`, `CVMX_MT_AES_ENC1` → `0x310b`)*

4. **Key length encoding**: The `AES_KEYLENGTH` register (`0x0110`) expects `keybytes/8 - 1`:
   AES-128 → 1, AES-192 → 2, AES-256 → 3. Not the raw byte count.
   *(Source: Marvell 4.14 `cvmx-asm.h` — `CVMX_MT_AES_KEY_LENGTH`)*

5. **Bug in Marvell SDK's reflected GFM macro**: The `CVMX_MT_GFM_MUL_REFLECT` macro in
   Marvell 4.14 `cvmx-asm.h` has a bug — it uses `"=d"` (output/write-only constraint)
   for what should be an input operand. Because `"=d"` tells the compiler this register
   is *written* rather than *read*, the compiler may overwrite the input data before the
   `dmtc2` instruction reads it, corrupting the value passed to hardware. The
   non-reflected variant (`CVMX_MT_GFM_MUL`, `0x025x` registers) does not have this bug.
   I and Claude Code use the non-reflected mode throughout.
   *(Source: Marvell 4.14 `cvmx-asm.h` — side-by-side comparison of reflected vs non-reflected macros)*

6. **GFM non-reflected mode**: Use `0x025x` registers (non-reflected). The `0x005x`
   reflected variant is avoided due to the SDK macro bug described above.
   *(Source: Marvell 4.14 `cvmx-asm.h`)*

7. **GFM polynomial**: Register `0x025E` expects `0xe100` — not `0xE100000000000000`.
   This is `0xe1` in bits `[15:8]`, encoding the GCM reduction polynomial
   `1 + x + x^2 + x^7` with `x^0` at the MSB.
   *(Source: Marvell 4.14 `cvmx-asm.h` — `CVMX_MT_GFM_POLY` → `dmtc2 val, 0x025e`)*

## License

GPL-2.0 — required for Linux kernel modules.
