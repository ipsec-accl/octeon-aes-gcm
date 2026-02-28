# Octeon AES-GCM COP2 Driver — Development Notes

Complete technical reference covering the design, all bugs found and fixed, the full
optimization journey, and operational lessons from building and running this driver.

---

## 1. Project Overview

The EdgeRouter 6P (and ER-4) contain a Cavium CN7130 SoC with a **COP2 cryptographic
coprocessor** that handles AES and GFM (Galois Field Multiply/GHASH) in hardware.
Ubiquiti's closed-source `cvm_ipsec_kame` driver uses COP2 for AES-CBC and 3DES but
**ignores it for AES-GCM**, silently falling back to software despite the hardware
supporting it (confirmed via NIST CAVP AES certificate #3301).

This module (`octeon_aes_gcm.ko`) fills that gap by registering `rfc4106(gcm(aes))`
and `gcm(aes)` in the Linux Crypto API at priority 500. XFRM picks it up automatically
for IPsec ESP with any AES-GCM variant (AES-128/192/256).

**Key reference repos:**
- [`MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14`](https://github.com/MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14)
  — authoritative COP2 register definitions (`arch/mips/include/asm/octeon/cvmx-asm.h`)
- [`Lochnair/kernel_e300`](https://github.com/Lochnair/kernel_e300)
  — EdgeOS 4.9 kernel source, used as `KDIR` for cross-compilation
- **`cvm_ipsec_kame`** — fully closed source, ships as binary blob with EdgeOS, no public source anywhere

---

## 2. Architecture

### Software path comparison

```
cvm_ipsec_kame (Ubiquiti, AES-CBC):
  StrongSwan → XFRM → netfilter hook (cvm_ipsec_kame) → COP2 AES registers

This module (AES-GCM):
  StrongSwan → XFRM → Linux Crypto API → octeon_aes_gcm.ko → COP2 AES + GFM registers
```

Ubiquiti's driver intercepts at the netfilter level and handles complete ESP packet
processing in a single contiguous-buffer pass. Our module goes through the standard
Linux Crypto API, which adds per-packet overhead from:
- Scatterlist linearization (`scatterwalk_map_and_copy`) on every packet
- AEAD vtable dispatch through the crypto subsystem
- Crypto API request setup/teardown

This overhead cannot be eliminated without bypassing the Crypto API entirely. Reaching
~90% of native CBC performance is realistic; 100% parity with `cvm_ipsec_kame`'s exact
internal implementation is not, but that level of detail is irrelevant to the goal.

### COP2 hardware operation

The module uses two independent COP2 engine blocks:

1. **AES ECB engine** — generates CTR keystream blocks. Triggered by writing plaintext
   to `COP2_AES_ENC0/ENC1` (`dmtc2`). The trigger is **non-blocking**; result is read
   from `COP2_AES_RESULT0/RESULT1` (`dmfc2`), which stalls until completion.

2. **GFM engine** — performs GHASH (GF(2^128) multiply-accumulate). Triggered by
   writing data to `COP2_GFM_XORMUL0/XORMUL1`. Also non-blocking. Computes:
   `accumulator = (accumulator XOR input) × H  mod poly`

Because both engines are fully independent, AES and GFM operations can overlap in
time. This is the basis of the single-pass pipeline optimization (see §6).

### `octeon_crypto_enable/disable` behavior

Confirmed from `arch/mips/cavium-octeon/crypto/octeon-crypto.c` (Marvell 4.14):

- `octeon_crypto_enable()` **only** sets the ST0_CU2 bit — it does NOT reload AES key,
  GFM H, polynomial, or accumulator into hardware registers.
- `octeon_crypto_disable()` (when `crypto_flags == 0`) just clears ST0_CU2 — no save.
- Hardware registers retain their values across `disable`/`enable` unless another task
  uses COP2 on the same CPU in between.
- The scheduler saves/restores `octeon_cop2_state` on context switch **only** when the
  task has ST0_CU2 set in its saved status register.

Implication: a per-CPU `last_ctx` pointer can detect whether our key/H/poly are still
live in hardware, skipping the reload for consecutive packets from the same SA.

---

## 3. COP2 Register Reference

All addresses verified against Marvell 4.14 `cvmx-asm.h`.

### AES engine

| Register | Address | Notes |
|----------|---------|-------|
| AES_KEY0–3 | 0x0104–0x0107 | 128-bit or 256-bit key |
| AES_KEYLENGTH | 0x0110 | `keybytes/8 - 1`: AES-128→1, AES-192→2, AES-256→3 |
| AES_ENC0 | 0x010A | ECB encrypt input [127:64] |
| AES_ENC1 | 0x310B | ECB encrypt input [63:0] → **triggers** (0x3000 = execute) |
| AES_DEC0 | 0x010E | ECB decrypt input [127:64] |
| AES_DEC1 | 0x310F | ECB decrypt input [63:0] → triggers |
| AES_ENC_CBC0/1 | 0x0108/0x3109 | CBC encrypt |
| AES_DEC_CBC0/1 | 0x010C/0x310D | CBC decrypt |
| AES_RESULT0/1 | 0x0100/0x0101 | Result (read stalls until done) |

### GFM engine (non-reflected, 0x025x — what we use)

| Register | Address | Notes |
|----------|---------|-------|
| GFM_MUL0/1 | 0x0258/0x0259 | Hash subkey H = AES_K(0^128) |
| GFM_RESINP0/1 | 0x025A/0x025B | Accumulator (read/write to clear) |
| GFM_XOR0 | 0x025C | XOR input [127:64] |
| GFM_XORMUL1 | **0x425D** | XOR input [63:0] → **triggers** (0x4000 = execute) |
| GFM_POLY0 | 0x025E | Reduction polynomial — write **0xe100** |

### GFM reflected registers (0x005x — NOT used)

| Register | Address | Notes |
|----------|---------|-------|
| GFM_MUL_REFLECT0/1 | 0x0058/0x0059 | Has `=d` constraint bug in SDK macro |
| GFM_RESULT_REFLECT0/1 | 0x005A/0x005B | — |
| GFM_XORMUL1_REFLECT | 0x405D | trigger bit is 0x4000 |

The reflected variant is avoided: `CVMX_MT_GFM_MUL_REFLECT` in Marvell's SDK uses
`[rt] "=d" (val)` (output/write constraint) on a `dmtc2` instruction — this is an
input operand. The compiler may overwrite the register before the instruction reads it.
The non-reflected `CVMX_MT_GFM_MUL` correctly uses `[rt] "d" (val)`.

---

## 4. Bugs Found and Fixed During Development

All bugs were found by comparing working Cavium SDK code against the initial driver
implementation. Most were discovered in sessions 1–3, with the last (§4.7) found
during the single-pass pipeline implementation.

### 4.1 GFM trigger bit wrong (Session 1)

**Bug:** `GHASH` never triggered. The code wrote to `0x025D` for `XORMUL1`, but
the execute trigger bit (`0x4000`) was missing.

**Fix:** `0x025D` → `0x425D` (= `0x4000 | 0x025D`). Every GFM block computation was
silently a no-op before this fix.

**Source:** Marvell 4.14 `cvmx-asm.h`: `CVMX_MT_GFM_XORMUL1 → dmtc2 val, 0x425d`

### 4.2 AAD GHASH scope wrong for rfc4106 (Session 1)

**Bug:** XFRM passes `assoclen = 16` for rfc4106 (8-byte ESP header + 8-byte explicit
IV). The driver was feeding all 16 bytes to GHASH. RFC 4106 specifies that only the
8-byte ESP header (SPI + SeqNum) is authenticated; the explicit IV is excluded.

**Fix:** `octeon_gcm_ghash_aad(aad, assoclen - 8)` — GHASH only the first 8 bytes.

### 4.3 AES ECB encrypt registers wrong (Session 1)

**Bug:** The driver used `0x010E`/`0x010F` for AES ECB encrypt. Those are the ECB
**decrypt** registers. The correct ECB encrypt registers are `0x010A`/`0x310B`.

**Fix:** `0x010E/0x010F` → `0x010A/0x310B`.

**Source:** Marvell 4.14: `CVMX_MT_AES_ENC0 → 0x010a`, `CVMX_MT_AES_ENC1 → 0x310b`

### 4.4 AES key length encoding wrong (Session 3)

**Bug:** The `AES_KEYLENGTH` register was written with the raw byte count (16, 24, or
32). The hardware expects `keybytes/8 - 1`: AES-128 → 1, AES-192 → 2, AES-256 → 3.

**Fix:** Changed to `ctx->key_length / 8 - 1` for all key sizes.

**Source:** Confirmed in wolfSSL, FreeBSD Octeon driver, and Cavium CPRI docs.

### 4.5 GFM mode wrong — reflected vs non-reflected (Session 3)

**Bug:** The driver was using the reflected interface (`0x005x` registers). Cavium's
reference implementation uses non-reflected (`0x025x`). These are different
representations of the GF(2^128) elements and produce different GHASH outputs.

**Fix:** Switched all GFM operations to non-reflected registers (`0x025x`). H and
polynomial are loaded in the format expected by the non-reflected engine.

### 4.6 GFM polynomial value wrong (Session 3)

**Bug:** The polynomial register `0x025E` was being written with
`0xE100000000000000`. The Cavium reference writes `0xe100` (the polynomial in
bits [15:8] only).

**Fix:** `0xE100000000000000` → `0xe100ULL`. The value `0xe1` encodes
`1 + x + x^2 + x^7` with `x^0` at the MSB.

**Source:** Marvell 4.14: `CVMX_MT_GFM_POLY → dmtc2 val, 0x025e`

### 4.7 Decrypt pipeline off-by-one AES counter (Single-pass implementation)

**Bug:** In `octeon_gcm_ghash_ctr_decrypt`, `AES_trigger(i+1)` fired **before**
`AES_read(i)`. The subsequent read returned `AES(i+1)`'s keystream instead of
`AES(i)`'s.

```c
// BUGGY order:
GFM_trigger(ct[i]);
AES_trigger(i+1);    // ← fires before reading AES(i)!
AES_read();          // ← gets AES(i+1), NOT AES(i)
pt[i] = ct[i] ^ AES_result;  // ← wrong keystream
```

**Diagnosis was subtle:** GHASH was computed over the ciphertext (already in memory,
unaffected by the bug), so the authentication tag **passed** despite wrong plaintext.
The decrypted bytes were wrong → ICMPv6 checksum failure → silent drop at the network
layer. Symptoms: 100% ping loss, but `XfrmInStateProtoError = 0` on both sides and
sequence counters incrementing correctly. If you see `InStateProtoError=0` with complete
packet loss, suspect upper-layer checksum (wrong plaintext), not auth tag.

**Fix:** Move `AES_trigger(i+1)` to after `AES_read(i)` and the XOR/memcpy:

```c
// CORRECT order:
GFM_trigger(ct[i]);          // overlaps with AES(i) running
AES_read(i);                 // stalls until AES(i) done
pt[i] = ct[i] ^ AES_result;
if (i < n_full - 1 || remainder > 0)
    AES_trigger(i+1);        // AFTER read — head start for next iteration
```

---

## 5. Optimization Analysis

Two independent analysis passes identified all significant opportunities before
implementation began.

### 5.1 First analysis (Gemini, ~2026-02-20)

Three opportunities identified:

**G-1: Per-packet kmalloc (high impact).** Every packet triggered 2–4 `GFP_ATOMIC`
allocations in the hot path. Fix: embed scratch buffers in `octeon_gcm_reqctx`
(allocated once per request), eliminating heap allocation for standard-MTU packets.

**G-2: Two-pass CTR + GHASH (medium impact).** Encrypt wrote full ciphertext to buffer,
then re-read it entirely for GHASH — double traversal of packet data. Fix: single-pass
interleaving of AES-CTR and GFM block by block (also hides AES pipeline stall; see G-3).

**G-3: AES pipeline stall (lower impact, synergistic with G-2).** AES result read
immediately followed the trigger, serializing AES and GFM. Since both engines are
independent, issuing GFM for block N−1 between AES trigger and AES read for block N
hides AES latency. G-2 and G-3 are the same fix.

### 5.2 Second analysis (Claude, 2026-02-23)

Eleven findings after detailed code review:

| # | Finding | Type |
|---|---------|------|
| 1 | rfc4106 AAD never needs kmalloc — 16/20-byte stack buf suffices | Perf |
| 2 | **Decrypt writes plaintext before tag verify** — unauthenticated plaintext visible | **Security** |
| 3 | kmalloc calls inside IRQ-disabled COP2 section | Perf |
| 4 | AES pipeline stall (same as G-3, see pipeline implementation) | Perf |
| 5 | Per-CPU last_ctx: skip key+H+poly reload on consecutive same-SA packets | Perf |
| 6 | Tag XOR byte loop should use `crypto_xor()` (stack alignment UB with u64 cast) | Correctness |
| 7 | Dead `ivsize` parameter in `octeon_gcm_build_j0` | Code quality |
| 8 | AAD dst-copy inside `ct_len > 0` guard — missed when `ct_len == 0` | Correctness |
| 9 | `j0`/`counter` stored as `u8[16]`, used as `u64[2]` — unnecessary memcpy per block | Perf |
| 10 | `octeon_crypto_enable()` doesn't reload hw registers — per-CPU caching is correct | Architecture |
| 11 | `cvm_ipsec_kame` is completely closed source — zero public source anywhere | Architecture |

**Security finding (item 2) detail:** The decrypt path wrote decrypted plaintext to
`req->dst` before comparing the auth tag. On tag failure, it tried `kzalloc` to zero
`req->dst`, but that allocation can fail under memory pressure, leaving unauthenticated
plaintext visible in the output buffer. Fix: keep `pt_buf` alive, only write to `req->dst`
after `crypto_memneq` confirms the tag is valid.

**Tag XOR alignment note:** `tag_bytes` and `tag_computed` are stack `u8[16]` arrays.
MIPS64 stack frames are 16-byte aligned but individual `u8` locals are not guaranteed
8-byte-aligned within the frame. A `u64 *` cast on them is undefined behavior. Using
`crypto_xor()` (the kernel's own XOR helper) avoids this. `rctx->tag_enc` IS safely
castable because `cra_alignmask = 7` guarantees 8-byte alignment for reqctx fields.

### 5.3 What was not implemented

**Single-entry scatterlist fast path:** If `req->src` is a single contiguous `sg` entry
(common for XFRM-built scatterlists), `sg_virt()` can be used directly instead of
linearizing. Would eliminate the two largest per-packet copies even without inline
buffers. Not implemented — inline buffers solve the same problem with less complexity.

**XFRM offload flag:** `XFRM_OFFLOAD` in `include/net/xfrm.h` allows early offload
decisions within the XFRM stack, reducing Crypto API indirection cost. Would close
the performance gap vs. `cvm_ipsec_kame` further. Not implemented — significant kernel
integration work.

---

## 6. Implemented Optimizations (Commit History)

All changes tested on backup (10.0.11.1) ↔ Yokohama (10.0.52.1) IPsec tunnel.
Pass criteria: 5+ pings both directions, `XfrmInStateProtoError` unchanged.

### be7caa4 — Security + correctness fixes in decrypt paths

- Deferred plaintext write to after auth tag verification (security fix)
- Moved AAD dst-copy outside `ct_len > 0` guard (correctness fix)
- Added `assoclen` input validation for rfc4106 (16 or 20 only)

### e5c1921 — Replace rfc4106 AAD kmalloc with 20-byte stack buffer

`assoclen` for rfc4106 is always 16 or 20 (validated). Replaced two `kmalloc` calls
(one for GHASH, one for src→dst copy) with a single 20-byte stack buffer. Eliminates
heap allocation from inside the IRQ-disabled COP2 section.

### 58c24f0 — Trivial cleanups

- `gcm_counter_inc()`: replaced 8 manual byte-shift operations with
  `put_unaligned_be32(get_unaligned_be32(ptr+12)+1, ptr+12)` (compiles to a single
  native 32-bit load/store on big-endian MIPS)
- Tag XOR: replaced 4 byte loops with `crypto_xor()` at all 4 encrypt/decrypt sites
- Removed dead `ivsize` parameter from `octeon_gcm_build_j0()`

### 637fbd5 — Refactor: extract ctr_crypt helper, native u64 reqctx fields

- Extracted `octeon_gcm_ctr_crypt()` to deduplicate 4 identical CTR while-loops
- Changed `j0` and `counter` in `octeon_gcm_reqctx` from `u8[16]` to `u64[2]`,
  eliminating memcpy on every AES counter operation
- Updated `gcm_counter_inc()` to accept `u64 *` (casts to `u8 *` for the BE counter
  in the last 4 bytes)

### fbdeb48 — Embed inline scratch buffers in reqctx to eliminate per-packet kmalloc

Added `OCTEON_GCM_INLINE_BUF_SIZE = 1600` and two inline scratch halves to
`octeon_gcm_reqctx` (total +3200 bytes, allocated once per request). Added
`gcm_buf_get()` / `gcm_buf_put()` helpers. All 4 encrypt/decrypt paths use inline
buffers for standard-MTU packets; `kmalloc` fallback retained for jumbo frames.
Total `reqctx` size: ~3264 bytes.

### c69267c — Single-pass AES+GFM pipeline, per-CPU key cache, gcm(aes) AAD stack buf

Three improvements in one commit:

**Single-pass encrypt (`octeon_gcm_ctr_encrypt_ghash`):** AES trigger for block N
fires first, then GFM for block N−1 runs while AES N is computing, then AES result
is read. Both engines run concurrently:
```
Iteration N:  AES_trigger(N), GFM_trigger(ct[N-1]), AES_read(N), XOR → ct[N]
```

**Single-pass decrypt (`octeon_gcm_ghash_ctr_decrypt`):** Ciphertext is already
in memory, so GFM can start immediately without waiting for AES:
```
Prolog:       AES_trigger(0)
Iteration i:  GFM_trigger(ct[i]), AES_read(i), XOR → pt[i], AES_trigger(i+1)
```

Note: `AES_trigger(i+1)` must fire **after** `AES_read(i)` — see Bug 4.7.

**Per-CPU key cache:** `DEFINE_PER_CPU(const struct octeon_gcm_ctx *, octeon_gcm_last_ctx)`.
On a cache hit, skips 8 `dmtc2` calls (5 for AES key, 3 for GFM poly+H). Always safe:
cache is cleared on CPU migration (octeon_crypto_disable clears ST0_CU2, so the
scheduler won't save our state, and the next enable will detect a mismatch).
Accumulator is always cleared regardless of cache state.

**gcm(aes) AAD stack buffer:** Added `GCM_SMALL_AAD_SIZE = 64` threshold. AAD ≤ 64
bytes uses a stack buffer; larger uses `kmalloc`. The `octeon_gcm_decrypt` path keeps
`aad_p` alive through the tag verify so it can be used for the dst-copy on success.

Also fixed the off-by-one bug in `octeon_gcm_ghash_ctr_decrypt` (Bug 4.7).

### b555d7e — Micro-optimizations across encrypt/decrypt pipelines

Six additional micro-optimizations, all tested 5/5 pings both directions:

1. **Encrypt: peel first loop iteration.** Iteration 0 has no prior ciphertext to GFM.
   Peeling it removes the `has_prev_ct` branch from the hot path; iterations 1..N run
   completely branch-free.

2. **Encrypt: direct u64 cast on plaintext pointer.** Eliminates intermediate `pt_blk[]`
   copy. Buffers are 8-byte aligned via `cra_alignmask = 7`, making the cast safe.

3. **Encrypt/decrypt: `n_full > 0` replaces `has_prev_ct` bool.** Same semantics, no
   dedicated flag variable.

4. **Decrypt: pre-trigger AES for partial block.** Extended loop guard from
   `i < n_full - 1` to `i < n_full - 1 || remainder > 0`. Last full-block iteration
   now pre-triggers the counter for the partial block, giving it a head start equivalent
   to the overlap that full blocks get.

5. **Decrypt: single-buffer remainder handling.** Replaced `u8 partial[16] = {0}` +
   `u64 partial_u64[2]` + two `memcpy` calls with a single `u64 partial_u64[2] = {0,0}`
   + one `memcpy`. Eliminates a staging copy.

6. **All 4 entry points: fused AES(J0) + accumulator clear.** Previously called
   `octeon_gcm_encrypt_counter()` (non-blocking AES trigger → stall → read) followed by
   `octeon_gfm_clear_accum()` (2 dmtc2). Now: trigger AES(J0), immediately issue the 2
   accumulator-clear dmtc2 writes, then read the AES result. The accumulator clear runs
   while AES(J0) computes, hiding ~8 serial cycles per packet. Removed the now-unused
   `octeon_gcm_encrypt_counter()` helper.

---

## 7. Performance Measurements

Real-world iperf3 benchmarks over backup (CA) ↔ Yokohama IPsec tunnel (110 ms RTT,
1 Gbps ISPs on both sides). 8 parallel streams, no `-w` flag (EdgeOS has low socket
buffer limits). All numbers are approximate and vary with ISP conditions.

| Configuration | Encrypt (CA→YOK) | Decrypt (CA←YOK) |
|--------------|-----------------|-----------------|
| Software (no module, kernel gcm-generic) | ~65.5 Mbps | ~31.4 Mbps |
| Hardware c69267c (pipeline + key cache) | ~70.8 Mbps | ~64.5 Mbps |
| Old hardware fbdeb48 (pre-pipeline) | ~63.3 Mbps | ~61.7 Mbps |

Observations:
- Decrypt improvement from c69267c is large (~2×) because the old code serialized GHASH
  and CTR — the single-pass pipeline eliminates the second traversal entirely.
- Encrypt improvement is smaller because the old code also did a single pass (GHASH was
  over ciphertext which required CTR to finish first), but the pipeline still reduces
  AES stall time.
- Software decrypt was slower than software encrypt, likely due to GHASH overhead
  (software GF multiply is expensive; hardware does it "for free" in a dmtc2).
- b555d7e micro-optimizations were not separately benchmarked; expected improvement
  is in the single-digit percent range.

---

## 8. Operational Notes

### Boot script

Script at `gcm/load-octeon-gcm.sh`, deployed to
`/config/scripts/pre-config.d/load-octeon-gcm.sh` on all three routers.
Runs before charon starts (pre-config.d), so hardware GCM is registered from the
first IPsec SA. The script checks the running kernel version before loading; if
the kernel changed after a firmware upgrade, it skips loading and logs a warning.

Verify after reboot:
```bash
grep octeon-aes-gcm /var/log/messages
# → octeon-aes-gcm: Module loaded — hardware AES-GCM available for IPsec
```

### Module hot-swap limitation

After loading, the module **cannot be hot-swapped** (rmmod while IPsec is running or
has ever run) without a reboot. Even after `ipsec stop` + `ip xfrm state flush` +
`ip xfrm policy flush`, `lsmod` shows `octeon_aes_gcm 3` references.

These are held by `seqiv(octeon-rfc4106-gcm-aes)` and other composed algorithm
instances that the kernel crypto subsystem creates automatically. The `seqiv` module
wraps our algorithm with a sequence-number IV generator; each wrapper holds a module
reference via `crypto_spawn`. These wrappers don't auto-GC while the module is loaded:
removing them requires deregistering our algorithms (which requires rmmod), but rmmod
requires zero references — circular.

**Workaround:** reboot. The pre-config.d boot script handles loading the new module
automatically. The new `.ko` only needs to be staged at `/config/tmp/octeon_aes_gcm.ko`
before reboot.

Hot-swap **does** work on a fresh boot before any IPsec SA has ever been negotiated
(before charon loads the composed algorithm instances for the first time).

### IKE collision fix (same-ISP /64 peers)

If two ER-6P routers are on the same ISP IPv6 /64 subnet, NDP (ipv6-icmp) traffic
between their WAN addresses matches the XFRM policy, creating larval `SPI=0` states
that trigger ACQUIRE events on both sides simultaneously. Both charons initiate
IKE_SA_INIT at the same time and collide repeatedly.

Fix: set the always-on router to respond-only for the backup peer:
```
set vpn ipsec site-to-site peer <BACKUP_IPV6> connection-type respond
```

The backup becomes the sole initiator; the primary never generates ACQUIRE events
for that peer. Tunnel establishes cleanly in <1 second after backup sends IKE_SA_INIT.

Applied to all three routers (2026-02-22).

### Active test tunnel

- Backup (10.0.11.1) ↔ Yokohama (10.0.52.1)
- Connection name: `peer-240d:1a:166:6700::1:2-tunnel-1`
- Backup is sole initiator
- Yokohama IPv6 tunnel address: `240d:1a:166:6700::1:2`
- Backup CA IPv6 tunnel address: `2600:1700:3ece:e817:dab3:70ff:fe34:f3a2`

Bring up manually after a flush:
```bash
ssh osa@10.0.11.1 "sudo ipsec restart && sleep 8 && \
  sudo ipsec up peer-240d:1a:166:6700::1:2-tunnel-1"
```

---

## 9. Source Files

| File | Description |
|------|-------------|
| `src/octeon_aes_gcm.c` | Main driver — AEAD registration, all encrypt/decrypt paths |
| `src/octeon_cop2.h` | COP2 register map, inline asm macros, AES/GFM helpers |
| `src/Makefile` | Out-of-tree kernel module build |
| `load-octeon-gcm.sh` | Pre-config.d boot script, deployed to all 3 routers |
| `docs/development-notes.md` | This file |
| `docs/plans/2026-02-24-cop2-gcm-optimization.md` | Original optimization plan (verified task list) |
| `OPTIMIZATION_NOTES.md` | First-pass analysis by Gemini |
| `OPTIMIZATION_NOTES_2.md` | Second-pass analysis by Claude (11 findings) |
| `STORY.md` | Narrative development log |
