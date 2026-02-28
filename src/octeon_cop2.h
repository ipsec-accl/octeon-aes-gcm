/* SPDX-License-Identifier: GPL-2.0 */
/*
 * octeon_cop2.h - Cavium Octeon III (CN7xxx) COP2 Crypto Engine Definitions
 *
 * COP2 register map and inline assembly macros for AES and GFM (GHASH)
 * hardware acceleration on MIPS64 Octeon III processors.
 *
 * Target: EdgeRouter 6P (CN7130) / EdgeOS 2.x (kernel 4.9)
 *
 * Register addresses verified against:
 *   MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14
 *   arch/mips/include/asm/octeon/cvmx-asm.h
 *
 * This is Marvell's officially maintained kernel tree and the authoritative
 * source for COP2 inline assembly macros (CVMX_MT_AES_ENC*, CVMX_MT_GFM_*,
 * CVMX_MF_GFM_*). It also documents the =d constraint bug in the reflected
 * GFM macros. Lochnair/kernel_e300 (used for building) does not include
 * cvmx-asm.h.
 */

#ifndef _OCTEON_COP2_H
#define _OCTEON_COP2_H

#include <linux/types.h>
#include <asm/unaligned.h>

/* =========================================================================
 * COP2 Register Map - AES Engine
 * =========================================================================
 *
 * The AES engine operates on 128-bit blocks using two 64-bit COP2 registers
 * per logical AES register. Registers are numbered [high_word, low_word].
 *
 * Data flow for AES-ECB encrypt:
 *   1. Load key into AES_KEY registers
 *   2. Set AES_KEYLENGTH
 *   3. Write plaintext block to AES_ENC0/ENC1 (triggers encrypt)
 *   4. Read ciphertext from AES_RESULT0/RESULT1
 */

/* AES Result (128-bit output: ciphertext or intermediate) */
#define COP2_AES_RESULT0        0x0100  /* Result bits [127:64] */
#define COP2_AES_RESULT1        0x0101  /* Result bits [63:0]   */

/* AES IV (128-bit, used for CBC/CTR modes) */
#define COP2_AES_IV0            0x0102  /* IV bits [127:64] */
#define COP2_AES_IV1            0x0103  /* IV bits [63:0]   */

/* AES Key (up to 256-bit) */
#define COP2_AES_KEY0           0x0104  /* Key bits [127:64]  (AES-128: high) */
#define COP2_AES_KEY1           0x0105  /* Key bits [63:0]    (AES-128: low)  */
#define COP2_AES_KEY2           0x0106  /* Key bits [255:192] (AES-256 only)  */
#define COP2_AES_KEY3           0x0107  /* Key bits [191:128] (AES-256 only)  */

/* AES-CBC Encrypt (write triggers CBC encrypt using IV) */
#define COP2_AES_ENC_CBC0       0x0108  /* CBC encrypt input [127:64] */
#define COP2_AES_ENC_CBC1       0x3109  /* CBC encrypt input [63:0] → triggers (0x3000 = execute) */

/* AES-CBC Decrypt */
#define COP2_AES_DEC_CBC0       0x010C  /* CBC decrypt input [127:64] */
#define COP2_AES_DEC_CBC1       0x310D  /* CBC decrypt input [63:0] → triggers (0x3000 = execute) */

/* AES-ECB Encrypt (write triggers ECB encrypt, no IV/chaining) */
#define COP2_AES_ENC0           0x010A  /* ECB encrypt input [127:64]                              */
#define COP2_AES_ENC1           0x310B  /* ECB encrypt input [63:0] → triggers (0x3000 = execute) */

/* AES Key Length */
#define COP2_AES_KEYLENGTH      0x0110  /* 1=AES-128 (keybytes/8-1), 2=AES-192, 3=AES-256 */

/* AES-ECB Decrypt */
#define COP2_AES_DEC0           0x010E  /* ECB decrypt input [127:64]                              */
#define COP2_AES_DEC1           0x310F  /* ECB decrypt input [63:0] → triggers (0x3000 = execute) */

/* =========================================================================
 * COP2 Register Map - GFM (Galois Field Multiply) Engine
 * =========================================================================
 *
 * The GFM engine performs multiplication in GF(2^128) used for GHASH
 * in AES-GCM. It supports multiply-accumulate operations:
 *
 *   GFM_RESULT = (GFM_RESULT XOR input) * GFM_MUL  mod GFM_POLY
 *
 * This exactly matches the GHASH recurrence:
 *   Y_i = (Y_{i-1} XOR X_i) * H
 *
 * Data flow:
 *   1. Set GFM_POLY to GCM reduction polynomial
 *   2. Set GFM_MUL to H (= AES_K(0^128))
 *   3. Clear GFM_RESULT to zero
 *   4. For each 128-bit block X_i:
 *      Write X_i to GFM_XORMUL0/XORMUL1 (triggers XOR + multiply)
 *   5. Read GHASH output from GFM_RESULT
 */

/*
 * GFM Register Map — TWO variants exist in the Octeon III SDK (cvmx-asm.h):
 *
 *   Non-reflected (0x025x): used by the Cavium reference aes_gcm.c implementation.
 *   Reflected     (0x005x): alternate interface; the CVMX_MT_GFM_MUL_REFLECT macro
 *                           has a known constraint bug in the SDK (wrong "=d" vs "d").
 *
 * We use non-reflected (0x025x), matching the Cavium reference.  The polynomial
 * and H key are loaded in the format expected by the non-reflected engine.
 * Data bytes are fed from memory without any bit-reversal (same as reference code).
 *
 * From MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14 cvmx-asm.h:
 *   CVMX_MT_GFM_MUL(val,pos)    → dmtc2 val, 0x0258+pos
 *   CVMX_MT_GFM_XOR0(val)       → dmtc2 val, 0x025c
 *   CVMX_MT_GFM_XORMUL1(val)    → dmtc2 val, 0x425d  (0x4000 = execute)
 *   CVMX_MF_GFM_RESINP(val,pos) → dmfc2 val, 0x025a+pos
 *   CVMX_MT_GFM_RESINP(val,pos) → dmtc2 val, 0x025a+pos  (clear/init)
 */

/* GFM Multiplier (H value for GHASH) — non-reflected */
#define COP2_GFM_MUL0           0x0258  /* H bits [127:64] */
#define COP2_GFM_MUL1           0x0259  /* H bits [63:0]   */

/* GFM Result / Accumulator — non-reflected read/write */
#define COP2_GFM_RESULT0        0x025A  /* Result bits [127:64] */
#define COP2_GFM_RESULT1        0x025B  /* Result bits [63:0]   */

/* GFM XOR-Multiply Trigger — non-reflected */
#define COP2_GFM_XORMUL0        0x025C  /* XOR input high word [127:64]           */
#define COP2_GFM_XORMUL1        0x425D  /* XOR input low word  [63:0]  → triggers */

/* GFM Reduction Polynomial */
#define COP2_GFM_POLY0          0x025E  /* Polynomial [127:64] */
#define COP2_GFM_POLY1          0x025F  /* Polynomial [63:0]   */

/*
 * GCM uses the polynomial: x^128 + x^7 + x^2 + x + 1
 *
 * The Cavium non-reflected GFM polynomial register (0x025E) expects 0xe100.
 * Verified via CVMX_MT_GFM_POLY in Marvell 4.14 cvmx-asm.h:
 *   CVMX_MT_GFM_POLY(val) → dmtc2 val, 0x025e
 *
 * 0xe100 = 0x000000000000e100: byte pattern 0xe1,0x00 in low 16 bits.
 * 0xe1 = 1110_0001b encodes (1+x+x^2+x^7) with x^0 at MSB of the byte.
 */
#define GCM_POLY_HI             0xe100ULL


/* =========================================================================
 * Inline Assembly Macros
 * =========================================================================
 *
 * MIPS COP2 data movement instructions:
 *   dmtc2 rt, impl   — Move doubleword To COP2 register
 *   dmfc2 rt, impl   — Move doubleword From COP2 register
 *
 * These are privileged instructions requiring kernel mode.
 * COP2 access must be bracketed by octeon_crypto_enable/disable
 * to properly save/restore COP2 state across context switches.
 */

/* --- Write to COP2 register --- */

#define OCTEON_MT_COP2(val, reg)                        \
	asm volatile("dmtc2 %[v], " __stringify(reg)    \
		     : : [v] "r" (val) : "memory")

/* --- Read from COP2 register --- */

#define OCTEON_MF_COP2(val, reg)                        \
	asm volatile("dmfc2 %[v], " __stringify(reg)    \
		     : [v] "=r" (val) : : "memory")


/* =========================================================================
 * AES Helper Macros
 * ========================================================================= */

/* Load AES-128 key (128 bits = 2 x 64-bit words, big-endian) */
static inline void octeon_aes_set_key128(const u64 *key)
{
	OCTEON_MT_COP2(key[0], 0x0104);  /* KEY0: bits [127:64] */
	OCTEON_MT_COP2(key[1], 0x0105);  /* KEY1: bits [63:0]   */
	OCTEON_MT_COP2(1ULL,   0x0110);  /* KEYLENGTH = 1 (= 16/8 - 1) */
}

/* Load AES-256 key (256 bits = 4 x 64-bit words, big-endian) */
static inline void octeon_aes_set_key256(const u64 *key)
{
	OCTEON_MT_COP2(key[0], 0x0104);
	OCTEON_MT_COP2(key[1], 0x0105);
	OCTEON_MT_COP2(key[2], 0x0106);
	OCTEON_MT_COP2(key[3], 0x0107);
	OCTEON_MT_COP2(3ULL,   0x0110);  /* KEYLENGTH = 3 (= 32/8 - 1) */
}

/*
 * AES-ECB encrypt one 128-bit block in-place.
 *
 * Input:  block[0] = bits [127:64], block[1] = bits [63:0]
 * Output: block[0] = encrypted [127:64], block[1] = encrypted [63:0]
 *
 * Key must already be loaded via octeon_aes_set_key*().
 */
static inline void octeon_aes_encrypt_block(u64 *block)
{
	/* Write input to ENC0/ENC1 — writing ENC1 (0x310B) triggers the encrypt.
	 * 0x3000 bit is the execute flag for AES operations.
	 * From MarvellEmbeddedProcessors/Octeon-Linux-kernel-4.14 cvmx-asm.h:
	 *   CVMX_MT_AES_ENC0  → dmtc2 val, 0x010a
	 *   CVMX_MT_AES_ENC1  → dmtc2 val, 0x310b  ← 0x3000 = execute trigger */
	OCTEON_MT_COP2(block[0], 0x010A);  /* AES_ENC0: input [127:64]          */
	OCTEON_MT_COP2(block[1], 0x310B);  /* AES_ENC1: input [63:0] → triggers */

	/* Read result */
	OCTEON_MF_COP2(block[0], 0x0100);  /* AES_RESULT0: result [127:64] */
	OCTEON_MF_COP2(block[1], 0x0101);  /* AES_RESULT1: result [63:0]   */
}


/* =========================================================================
 * GFM (GHASH) Helper Macros
 * ========================================================================= */

/*
 * Load the GFM reduction polynomial and hash subkey H into hardware.
 *
 * Only needed on a per-CPU cache miss (transform change). Kept separate
 * from accumulator clearing to enable per-CPU key caching.
 *
 * @h: pointer to 128-bit hash subkey H = AES_K(0^128)
 *     h[0] = bits [127:64], h[1] = bits [63:0]
 */
static inline void octeon_gfm_load_key(const u64 *h)
{
	/* Set reduction polynomial for GCM */
	OCTEON_MT_COP2(GCM_POLY_HI, 0x025E);  /* GFM_POLY = 0xe100 */

	/* Set multiplier H — non-reflected interface, H loaded directly from AES result */
	OCTEON_MT_COP2(h[0], 0x0258);  /* GFM_MUL0: H[127:64] */
	OCTEON_MT_COP2(h[1], 0x0259);  /* GFM_MUL1: H[63:0]   */
}

/*
 * Clear the GFM accumulator to zero.
 *
 * Must be called before each new GHASH computation, even on a per-CPU
 * cache hit, since the accumulator holds state from the previous packet.
 */
static inline void octeon_gfm_clear_accum(void)
{
	OCTEON_MT_COP2(0ULL, 0x025A);  /* GFM_RESINP0 = 0 */
	OCTEON_MT_COP2(0ULL, 0x025B);  /* GFM_RESINP1 = 0 */
}

/*
 * Process one 128-bit block through GHASH:
 *   accumulator = (accumulator XOR block) * H  mod polynomial
 *
 * @block: pointer to 128-bit data block
 *         block[0] = bits [127:64], block[1] = bits [63:0]
 */
static inline void octeon_gfm_xormul(const u64 *block)
{
	/* Non-reflected interface: data in big-endian byte order, as-is.
	 * 0x425D = 0x4000 (execute) | 0x025D (XORMUL1 base).
	 * From SDK: CVMX_MT_GFM_XOR0 → 0x025c, CVMX_MT_GFM_XORMUL1 → 0x425d */
	OCTEON_MT_COP2(block[0], 0x025C);  /* GFM_XOR0:    data[127:64] */
	OCTEON_MT_COP2(block[1], 0x425D);  /* GFM_XORMUL1: data[63:0]  → triggers */
}

/*
 * Read the current GHASH accumulator value.
 *
 * @result: pointer to 128-bit output buffer
 *          result[0] = bits [127:64], result[1] = bits [63:0]
 */
static inline void octeon_gfm_read_result(u64 *result)
{
	/* Read via non-reflected addresses.
	 * From SDK: CVMX_MF_GFM_RESINP → dmfc2 val, 0x025a/0x025b */
	OCTEON_MF_COP2(result[0], 0x025A);  /* GFM_RESINP0: result[127:64] */
	OCTEON_MF_COP2(result[1], 0x025B);  /* GFM_RESINP1: result[63:0]   */
}


/* =========================================================================
 * Utility
 * ========================================================================= */

/*
 * Increment the 32-bit big-endian counter in the last 4 bytes of
 * a 16-byte counter block (GCM J0 format: Nonce[12] || Counter[4]).
 */
static inline void gcm_counter_inc(u64 *ctr_block)
{
	put_unaligned_be32(get_unaligned_be32((u8 *)ctr_block + 12) + 1,
			   (u8 *)ctr_block + 12);
}

#endif /* _OCTEON_COP2_H */
