// SPDX-License-Identifier: GPL-2.0
/*
 * octeon_aes_gcm.c - AES-GCM Hardware Offload for Cavium Octeon III
 *
 * Implements rfc4106(gcm(aes)) using the Octeon III COP2 cryptographic
 * engine for AES-ECB and GFM (GHASH) hardware acceleration.
 *
 * Target: EdgeRouter 6P (CN7130) / EdgeOS 2.x (Linux 4.9)
 *
 * This module registers an AEAD algorithm with the Linux Crypto API
 * at priority 500 (above the software implementation at ~100-300),
 * enabling automatic IPsec offload via XFRM when AES-GCM is selected.
 *
 * Architecture:
 *   - AES-ECB encrypt via COP2 AES engine (for CTR keystream + tag)
 *   - GHASH via COP2 GFM engine (Galois Field Multiply-Accumulate)
 *   - Scatterlist walking for IPsec packet processing
 *   - COP2 state save/restore via octeon-crypto module
 *
 * Usage with StrongSwan / IPsec:
 *   esp=aes128gcm128  →  rfc4106(gcm(aes)) with 128-bit key, 128-bit ICV
 *
 * Copyright (C) 2025
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <asm/octeon/octeon.h>

/* COP2 state management from octeon-crypto module */
#include "octeon-crypto.h"

/* Our COP2 register definitions and helpers */
#include "octeon_cop2.h"

#define DRIVER_NAME     "octeon-aes-gcm"
#define DRIVER_VERSION  "1.0.0"

/* GCM constants */
#define GCM_RFC4106_IV_SIZE 8       /* IV size in ESP header              */
#define GCM_BLOCK_SIZE      16      /* AES block size                     */
#define GCM_NONCE_SIZE      4       /* Salt / nonce prepended to IV       */
#define GCM_FULL_IV_SIZE    12      /* nonce(4) + IV(8) = 12 bytes        */
#define GCM_MAX_AUTH_SIZE   16      /* Maximum authentication tag size    */

/* Algorithm priority — higher than software (~100-300) */
#define OCTEON_GCM_PRIORITY 500

/* Stack buffer threshold for generic gcm(aes) AAD.
 * Covers TLS 1.2 (13 B), TLS 1.3 (5 B), QUIC, and similar callers.
 * Larger AAD falls back to kmalloc. */
#define GCM_SMALL_AAD_SIZE  64

/* Inline scratch buffer size — covers standard 1500-byte MTU plus ESP overhead.
 * Packets at or below this size need no heap allocation for pt_buf/ct_buf. */
#define OCTEON_GCM_INLINE_BUF_SIZE 1600

/*
 * Per-transform context (allocated once per setkey).
 * Stored in crypto_aead_ctx(tfm).
 */
struct octeon_gcm_ctx {
	/* AES key in 64-bit words for COP2 loading (big-endian) */
	u64 key[4];            /* Up to AES-256: key[0..3]        */
	unsigned int keylen;   /* AES key length in bytes (16/24/32) */

	/* RFC 4106 nonce (4 bytes, from the last 4 bytes of setkey) */
	u8 nonce[GCM_NONCE_SIZE];

	/* GHASH subkey H = AES_K(0^128), precomputed at setkey time */
	u64 hash_subkey[2];    /* H[0] = bits[127:64], H[1] = bits[63:0] */

	/* Authentication tag size (set by setauthsize) */
	unsigned int authsize;
};

/*
 * Per-request scratch space.
 * Allocated via aead_request_ctx(req).
 */
struct octeon_gcm_reqctx {
	u64 j0[2];                        /* Initial counter block (u64 for COP2 AES input)  */
	u64 counter[2];                   /* Running CTR counter (u64 for COP2 AES input)    */
	u8 tag_enc[GCM_BLOCK_SIZE];       /* AES_K(J0) for final tag XOR */
	/*
	 * Inline scratch space for ct_buf and pt_buf.
	 * [0 .. OCTEON_GCM_INLINE_BUF_SIZE-1]      → ct_buf
	 * [OCTEON_GCM_INLINE_BUF_SIZE .. *2-1]     → pt_buf
	 * Covers standard MTU packets without heap allocation.
	 */
	u8 inline_buf[OCTEON_GCM_INLINE_BUF_SIZE * 2];
};


/*
 * Per-CPU transform cache.
 *
 * Tracks which octeon_gcm_ctx was last loaded into this CPU's COP2 registers.
 * On a cache hit (last_ctx == ctx), the AES key, GFM polynomial, and GHASH
 * subkey H are already in hardware — skip the 8 dmtc2 reload writes.
 * The GFM accumulator is always cleared regardless (it holds per-packet state).
 *
 * Hardware retains COP2 register state between enable/disable cycles as long
 * as no other COP2 user runs on this CPU (verified: octeon_crypto_enable only
 * sets ST0_CU2; it does not restore registers).
 */
static DEFINE_PER_CPU(const struct octeon_gcm_ctx *, octeon_gcm_last_ctx);

/* =========================================================================
 * Low-Level GCM Operations (COP2-backed)
 * =========================================================================
 *
 * All functions in this section assume COP2 is already enabled via
 * octeon_crypto_enable() and the AES key is loaded.
 */

/*
 * Compute GHASH subkey H = AES_K(0^128)
 *
 * Must be called with COP2 enabled and key loaded.
 */
static void octeon_gcm_derive_h(u64 *h)
{
	h[0] = 0;
	h[1] = 0;
	octeon_aes_encrypt_block(h);
}

/*
 * Load the AES key into COP2 registers from the transform context.
 */
static inline void octeon_gcm_load_key(const struct octeon_gcm_ctx *ctx)
{
	switch (ctx->keylen) {
	case 16:
		octeon_aes_set_key128(ctx->key);
		break;
	case 32:
		octeon_aes_set_key256(ctx->key);
		break;
	default:
		/* AES-192: load 3 words + set keylength = 2 (= 24/8 - 1) */
		OCTEON_MT_COP2(ctx->key[0], 0x0104);
		OCTEON_MT_COP2(ctx->key[1], 0x0105);
		OCTEON_MT_COP2(ctx->key[2], 0x0106);
		OCTEON_MT_COP2(2ULL, 0x0110);
		break;
	}
}

/*
 * Build J0 for rfc4106: nonce(4) || IV(8) || 0x00000001
 */
static void octeon_rfc4106_build_j0(const struct octeon_gcm_ctx *ctx,
				    const u8 *iv, u64 *j0)
{
	u8 *p = (u8 *)j0;

	memcpy(p, ctx->nonce, GCM_NONCE_SIZE);
	memcpy(p + GCM_NONCE_SIZE, iv, GCM_RFC4106_IV_SIZE);
	p[12] = 0x00;
	p[13] = 0x00;
	p[14] = 0x00;
	p[15] = 0x01;
}

/*
 * Build J0 for generic gcm(aes): IV(12) || 0x00000001
 * (96-bit IV case per NIST SP 800-38D)
 */
static void octeon_gcm_build_j0(const u8 *iv, u64 *j0)
{
	u8 *p = (u8 *)j0;

	memcpy(p, iv, GCM_FULL_IV_SIZE);
	p[12] = 0x00;
	p[13] = 0x00;
	p[14] = 0x00;
	p[15] = 0x01;
}

/*
 * Process AAD (Associated Authenticated Data) through GHASH.
 *
 * Handles padding to 16-byte boundary as required by GCM.
 * COP2 GFM engine must be initialized before calling.
 */
static void octeon_gcm_ghash_aad(const u8 *aad, unsigned int aad_len)
{
	u64 block[2];
	unsigned int i;
	unsigned int full_blocks = aad_len / GCM_BLOCK_SIZE;
	unsigned int remainder = aad_len % GCM_BLOCK_SIZE;

	/* Process full 16-byte blocks */
	for (i = 0; i < full_blocks; i++) {
		memcpy(block, aad + i * GCM_BLOCK_SIZE, GCM_BLOCK_SIZE);
		octeon_gfm_xormul(block);
	}

	/* Process final partial block (zero-padded) */
	if (remainder) {
		memset(block, 0, GCM_BLOCK_SIZE);
		memcpy(block, aad + full_blocks * GCM_BLOCK_SIZE, remainder);
		octeon_gfm_xormul(block);
	}
}

/*
 * Single-pass AES-CTR encrypt + GHASH ciphertext.
 *
 * Interleaves GFM for ciphertext block N-1 with AES keystream generation
 * for block N, hiding AES ECB latency behind GFM computation.
 * Both engines are independent COP2 hardware blocks that run concurrently.
 *
 *   Iteration N:  AES_trigger(N), GFM_trigger(ct[N-1]), AES_read(N), XOR → ct[N]
 *
 * On return, the GHASH accumulator includes all ct bytes (full blocks
 * plus a zero-padded partial block if len % 16 != 0).
 * Caller finalizes GHASH with octeon_gcm_ghash_final().
 *
 * COP2 must be enabled with key loaded, H loaded, accumulator cleared.
 */
static void octeon_gcm_ctr_encrypt_ghash(struct octeon_gcm_reqctx *rctx,
					 const u8 *pt, u8 *ct,
					 unsigned int len)
{
	unsigned int n_full = len / GCM_BLOCK_SIZE;
	unsigned int remainder = len % GCM_BLOCK_SIZE;
	unsigned int i;
	u64 ks[2];
	u64 ct_blk[2];

	if (n_full > 0) {
		/*
		 * Iteration 0: peeled — no prior ciphertext block to GFM.
		 * Direct u64 cast avoids an intermediate pt_blk[] copy.
		 */
		gcm_counter_inc(rctx->counter);
		OCTEON_MT_COP2(rctx->counter[0], 0x010A);
		OCTEON_MT_COP2(rctx->counter[1], 0x310B);

		OCTEON_MF_COP2(ks[0], 0x0100);
		OCTEON_MF_COP2(ks[1], 0x0101);

		ct_blk[0] = ((const u64 *)pt)[0] ^ ks[0];
		ct_blk[1] = ((const u64 *)pt)[1] ^ ks[1];
		memcpy(ct, ct_blk, GCM_BLOCK_SIZE);

		/* Iterations 1..n_full-1: branch-free hot path */
		for (i = 1; i < n_full; i++) {
			gcm_counter_inc(rctx->counter);
			OCTEON_MT_COP2(rctx->counter[0], 0x010A);
			OCTEON_MT_COP2(rctx->counter[1], 0x310B);

			/*
			 * GFM ct[i-1] while AES(i) computes.
			 * Both engines are independent and run in parallel.
			 */
			OCTEON_MT_COP2(ct_blk[0], 0x025C);
			OCTEON_MT_COP2(ct_blk[1], 0x425D);

			OCTEON_MF_COP2(ks[0], 0x0100);
			OCTEON_MF_COP2(ks[1], 0x0101);

			ct_blk[0] = ((const u64 *)(pt + i * GCM_BLOCK_SIZE))[0] ^ ks[0];
			ct_blk[1] = ((const u64 *)(pt + i * GCM_BLOCK_SIZE))[1] ^ ks[1];
			memcpy(ct + i * GCM_BLOCK_SIZE, ct_blk, GCM_BLOCK_SIZE);
		}
	}

	if (remainder) {
		u8 partial[GCM_BLOCK_SIZE] = { 0 };
		unsigned int j;

		/* Issue AES for partial counter block (non-blocking) */
		gcm_counter_inc(rctx->counter);
		OCTEON_MT_COP2(rctx->counter[0], 0x010A);
		OCTEON_MT_COP2(rctx->counter[1], 0x310B);

		/* GFM last full block while AES partial is computing */
		if (n_full > 0) {
			OCTEON_MT_COP2(ct_blk[0], 0x025C);
			OCTEON_MT_COP2(ct_blk[1], 0x425D);
		}

		OCTEON_MF_COP2(ks[0], 0x0100);
		OCTEON_MF_COP2(ks[1], 0x0101);

		/* XOR keystream; keep tail bytes zero for GCM padding */
		memcpy(partial, pt + n_full * GCM_BLOCK_SIZE, remainder);
		for (j = 0; j < remainder; j++)
			partial[j] ^= ((u8 *)ks)[j];
		memcpy(ct + n_full * GCM_BLOCK_SIZE, partial, remainder);

		/* GHASH the zero-padded partial ciphertext block */
		memcpy(ct_blk, partial, GCM_BLOCK_SIZE);
		OCTEON_MT_COP2(ct_blk[0], 0x025C);
		OCTEON_MT_COP2(ct_blk[1], 0x425D);
	} else if (n_full > 0) {
		/* No partial block: GFM the last full ciphertext block */
		OCTEON_MT_COP2(ct_blk[0], 0x025C);
		OCTEON_MT_COP2(ct_blk[1], 0x425D);
	}
}

/*
 * Single-pass GHASH ciphertext + AES-CTR decrypt.
 *
 * Interleaves GFM for ciphertext block N with AES keystream generation for
 * block N+1. For decrypt, the ciphertext is already in memory, so GFM can
 * start immediately — we don't need the AES result to feed GFM.
 *
 *   Prolog:       AES_trigger(0)
 *   Iteration i:  GFM_trigger(ct[i]),  AES_read(i),  XOR → pt[i],  AES_trigger(i+1)
 *
 * AES_trigger(i+1) fires after AES_read(i), overlapping with the XOR,
 * memcpy, and the next iteration's GFM_trigger.  By the time AES_read(i+1)
 * is reached, AES(i+1) has had a significant head start.
 *
 * COP2 must be enabled with key loaded, H loaded, accumulator cleared.
 */
static void octeon_gcm_ghash_ctr_decrypt(struct octeon_gcm_reqctx *rctx,
					 const u8 *ct, u8 *pt,
					 unsigned int len)
{
	unsigned int n_full = len / GCM_BLOCK_SIZE;
	unsigned int remainder = len % GCM_BLOCK_SIZE;
	unsigned int i;
	u64 ks[2];
	u64 ct_blk[2], pt_blk[2];

	if (n_full > 0) {
		/* Prolog: issue AES for block 0 before the loop */
		gcm_counter_inc(rctx->counter);
		OCTEON_MT_COP2(rctx->counter[0], 0x010A);
		OCTEON_MT_COP2(rctx->counter[1], 0x310B);

		for (i = 0; i < n_full; i++) {
			/*
			 * Issue GFM for ct[i] while AES(i) computes.
			 * ct is already in memory — no AES result needed.
			 */
			memcpy(ct_blk, ct + i * GCM_BLOCK_SIZE, GCM_BLOCK_SIZE);
			OCTEON_MT_COP2(ct_blk[0], 0x025C);
			OCTEON_MT_COP2(ct_blk[1], 0x425D);

			/* Read AES block i result — stalls until done */
			OCTEON_MF_COP2(ks[0], 0x0100);
			OCTEON_MF_COP2(ks[1], 0x0101);

			pt_blk[0] = ct_blk[0] ^ ks[0];
			pt_blk[1] = ct_blk[1] ^ ks[1];
			memcpy(pt + i * GCM_BLOCK_SIZE, pt_blk, GCM_BLOCK_SIZE);

			/*
			 * Pre-trigger AES for next block (full or partial) after
			 * the read — overlaps with next iteration's GFM trigger
			 * and the memcpy above.
			 */
			if (i < n_full - 1 || remainder > 0) {
				gcm_counter_inc(rctx->counter);
				OCTEON_MT_COP2(rctx->counter[0], 0x010A);
				OCTEON_MT_COP2(rctx->counter[1], 0x310B);
			}
		}
	}

	if (remainder) {
		u64 partial_u64[2] = { 0, 0 };
		unsigned int j;

		/* Single copy into zero-initialized u64 buffer (no staging via u8[]) */
		memcpy(partial_u64, ct + n_full * GCM_BLOCK_SIZE, remainder);

		/*
		 * AES pre-triggered at end of last full-block iteration when
		 * n_full > 0; trigger here only if there were no full blocks.
		 */
		if (n_full == 0) {
			gcm_counter_inc(rctx->counter);
			OCTEON_MT_COP2(rctx->counter[0], 0x010A);
			OCTEON_MT_COP2(rctx->counter[1], 0x310B);
		}

		/* GFM the zero-padded partial ciphertext while AES computes */
		OCTEON_MT_COP2(partial_u64[0], 0x025C);
		OCTEON_MT_COP2(partial_u64[1], 0x425D);

		OCTEON_MF_COP2(ks[0], 0x0100);
		OCTEON_MF_COP2(ks[1], 0x0101);

		for (j = 0; j < remainder; j++)
			((u8 *)partial_u64)[j] ^= ((u8 *)ks)[j];
		memcpy(pt + n_full * GCM_BLOCK_SIZE, partial_u64, remainder);
	}
}

/*
 * Finalize GHASH by appending the length block:
 *   [len(A) in bits as u64_be] || [len(C) in bits as u64_be]
 *
 * Then read the GHASH output.
 */
static void octeon_gcm_ghash_final(unsigned int aad_len,
				   unsigned int ct_len,
				   u64 *tag_out)
{
	u64 len_block[2];

	/* Length block: bit lengths in big-endian */
	len_block[0] = cpu_to_be64((u64)aad_len * 8);
	len_block[1] = cpu_to_be64((u64)ct_len * 8);
	octeon_gfm_xormul(len_block);

	/* Read final GHASH value */
	octeon_gfm_read_result(tag_out);
}



/*
 * Scratch buffer helpers for pt_buf / ct_buf.
 *
 * For packets ≤ OCTEON_GCM_INLINE_BUF_SIZE, return a pointer into the
 * per-request inline_buf (no heap allocation).  For larger packets (jumbo
 * frames), fall back to kmalloc(GFP_ATOMIC).
 *
 * Callers pass:
 *   offset  — 0 for ct_buf, OCTEON_GCM_INLINE_BUF_SIZE for pt_buf
 *   heap    — set to true when the returned buffer is heap-allocated
 */
static u8 *gcm_buf_get(struct octeon_gcm_reqctx *rctx,
			unsigned int offset, unsigned int size, bool *heap)
{
	if (size <= OCTEON_GCM_INLINE_BUF_SIZE) {
		*heap = false;
		return rctx->inline_buf + offset;
	}
	*heap = true;
	return kmalloc(size, GFP_ATOMIC);
}

static void gcm_buf_put(u8 *buf, bool heap)
{
	if (heap)
		kfree(buf);
}


/* =========================================================================
 * Crypto API Callbacks
 * ========================================================================= */

/*
 * Common key setup: load key into context and precompute GHASH subkey H.
 */
static int octeon_gcm_setkey_common(struct octeon_gcm_ctx *ctx,
				    const u8 *key, unsigned int aes_keylen)
{
	struct octeon_cop2_state cop2_state;
	unsigned long cop2_flags;

	ctx->keylen = aes_keylen;

	/* Copy AES key into 64-bit aligned buffer (big-endian on Octeon) */
	memset(ctx->key, 0, sizeof(ctx->key));
	memcpy(ctx->key, key, aes_keylen);

	/*
	 * Precompute GHASH subkey H = AES_K(0^128)
	 * This requires COP2 access.
	 */
	cop2_flags = octeon_crypto_enable(&cop2_state);
	octeon_gcm_load_key(ctx);
	octeon_gcm_derive_h(ctx->hash_subkey);
	octeon_crypto_disable(&cop2_state, cop2_flags);

	return 0;
}

/*
 * setkey for rfc4106(gcm(aes)) — IPsec variant.
 *
 * Key material layout:
 *   [AES key (16/24/32 bytes)] [nonce (4 bytes)]
 *
 * Total keylen = AES keylen + 4
 */
static int octeon_rfc4106_setkey(struct crypto_aead *tfm,
				 const u8 *key, unsigned int keylen)
{
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	unsigned int aes_keylen;

	/* Subtract the 4-byte nonce to get the actual AES key length */
	if (keylen < GCM_NONCE_SIZE)
		return -EINVAL;

	aes_keylen = keylen - GCM_NONCE_SIZE;

	if (aes_keylen != 16 && aes_keylen != 24 && aes_keylen != 32) {
		crypto_aead_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	/* Copy nonce (last 4 bytes) */
	memcpy(ctx->nonce, key + aes_keylen, GCM_NONCE_SIZE);

	return octeon_gcm_setkey_common(ctx, key, aes_keylen);
}

/*
 * setkey for generic gcm(aes) — raw AES key, no nonce.
 */
static int octeon_gcm_setkey(struct crypto_aead *tfm,
			     const u8 *key, unsigned int keylen)
{
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);

	if (keylen != 16 && keylen != 24 && keylen != 32) {
		crypto_aead_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	/* Generic GCM: no nonce at setkey time; IV is the full 12-byte nonce */
	memset(ctx->nonce, 0, GCM_NONCE_SIZE);

	return octeon_gcm_setkey_common(ctx, key, keylen);
}

/*
 * setauthsize — Set the authentication tag size.
 *
 * RFC 4106 allows 8, 12, or 16 bytes. IPsec typically uses 16 (128 bits).
 */
static int octeon_gcm_setauthsize(struct crypto_aead *tfm,
				  unsigned int authsize)
{
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);

	switch (authsize) {
	case 8:
	case 12:
	case 16:
		ctx->authsize = authsize;
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * encrypt — Encrypt plaintext and generate authentication tag.
 *
 * Input scatterlist layout (rfc4106):
 *   [AAD (assoclen bytes)] [plaintext (cryptlen bytes)]
 *
 * Output scatterlist layout:
 *   [AAD (assoclen bytes)] [ciphertext (cryptlen bytes)] [tag (authsize bytes)]
 */
static int octeon_rfc4106_encrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	struct octeon_gcm_reqctx *rctx = aead_request_ctx(req);
	struct octeon_cop2_state cop2_state;
	unsigned long cop2_flags;
	unsigned int assoclen = req->assoclen;
	unsigned int cryptlen = req->cryptlen;
	u64 tag[2];
	u8 tag_bytes[GCM_MAX_AUTH_SIZE];
	/* Stack buffer for rfc4106 AAD: assoclen is 16 or 20 (validated below) */
	u8 aad[20];

	/* Validate assoclen: must be 16 (standard) or 20 (ESN). Per rfc4106,
	 * assoclen = ESP_header(8) + explicit_IV(8), or + ESN(4) = 20.
	 * Matches kernel rfc4106 wrapper check (crypto/gcm.c:867). */
	if (assoclen != 16 && assoclen != 20)
		return -EINVAL;

	/* Build J0: nonce(4) || IV(8) || 0x00000001 */
	octeon_rfc4106_build_j0(ctx, req->iv, rctx->j0);

	/* Counter for CTR mode starts at J0 + 1 (J0 is reserved for tag) */
	rctx->counter[0] = rctx->j0[0];
	rctx->counter[1] = rctx->j0[1];

	/* --- Begin COP2 critical section --- */
	cop2_flags = octeon_crypto_enable(&cop2_state);

	/* Skip key+H reload if hardware still holds this transform's state */
	if (__this_cpu_read(octeon_gcm_last_ctx) != ctx) {
		octeon_gcm_load_key(ctx);
		octeon_gfm_load_key(ctx->hash_subkey);
		__this_cpu_write(octeon_gcm_last_ctx, ctx);
	}

	/*
	 * Trigger AES(J0) and clear the GFM accumulator in parallel.
	 * Both are required before processing data; doing them together
	 * hides the AES(J0) latency inside the two GFM accumulator writes.
	 */
	OCTEON_MT_COP2(rctx->j0[0], 0x010A);
	OCTEON_MT_COP2(rctx->j0[1], 0x310B);          /* triggers AES(J0) */
	octeon_gfm_clear_accum();                      /* runs while AES computes */
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[0], 0x0100);
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[1], 0x0101);

	/*
	 * GHASH: Process AAD (ESP header only, not the explicit IV).
	 *
	 * Read the full assoclen bytes from src into a stack buffer.
	 * GHASH only the first (assoclen - 8) bytes (SPI + SeqNum).
	 * Copy all assoclen bytes to dst if src != dst.
	 * No heap allocation needed — assoclen is at most 20 bytes.
	 */
	scatterwalk_map_and_copy(aad, req->src, 0, assoclen, 0);
	octeon_gcm_ghash_aad(aad, assoclen - GCM_RFC4106_IV_SIZE);
	if (req->src != req->dst)
		scatterwalk_map_and_copy(aad, req->dst, 0, assoclen, 1);

	/*
	 * Process plaintext → ciphertext via CTR mode.
	 * Simultaneously accumulate ciphertext into GHASH.
	 *
	 * For simplicity and correctness with complex scatterlists,
	 * we linearize the data. For most IPsec packets this is
	 * efficient since they fit in 1-2 scatterlist entries.
	 */
	if (cryptlen > 0) {
		u8 *pt_buf, *ct_buf;
		bool pt_heap, ct_heap;

		pt_buf = gcm_buf_get(rctx, 0, cryptlen, &pt_heap);
		ct_buf = gcm_buf_get(rctx, OCTEON_GCM_INLINE_BUF_SIZE,
				     cryptlen, &ct_heap);
		if (!pt_buf || !ct_buf) {
			gcm_buf_put(pt_buf, pt_heap);
			gcm_buf_put(ct_buf, ct_heap);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		/* Read plaintext from src (skip AAD) */
		scatterwalk_map_and_copy(pt_buf, req->src, assoclen,
					 cryptlen, 0);

		/* AES-CTR encrypt + GHASH ciphertext (single-pass pipelined) */
		octeon_gcm_ctr_encrypt_ghash(rctx, pt_buf, ct_buf, cryptlen);

		/* Write ciphertext to dst (skip AAD) */
		scatterwalk_map_and_copy(ct_buf, req->dst, assoclen,
					 cryptlen, 1);

		gcm_buf_put(pt_buf, pt_heap);
		gcm_buf_put(ct_buf, ct_heap);
	}

	/* Finalize GHASH: length block uses actual AAD bytes (not incl. IV) */
	octeon_gcm_ghash_final(assoclen - GCM_RFC4106_IV_SIZE, cryptlen, tag);

	/* --- End COP2 critical section --- */
	octeon_crypto_disable(&cop2_state, cop2_flags);

	/* Compute final tag: GHASH_result XOR AES_K(J0) */
	memcpy(tag_bytes, tag, GCM_BLOCK_SIZE);
	crypto_xor(tag_bytes, rctx->tag_enc, GCM_BLOCK_SIZE);

	/* Append authentication tag to output */
	scatterwalk_map_and_copy(tag_bytes, req->dst,
				 assoclen + cryptlen, ctx->authsize, 1);

	return 0;
}

/*
 * decrypt — Verify authentication tag and decrypt ciphertext.
 *
 * Input scatterlist layout (rfc4106):
 *   [AAD (assoclen bytes)] [ciphertext (cryptlen - authsize bytes)] [tag (authsize bytes)]
 *
 * Output scatterlist layout:
 *   [AAD (assoclen bytes)] [plaintext (cryptlen - authsize bytes)]
 *
 * Returns 0 on success, -EBADMSG if tag verification fails.
 */
static int octeon_rfc4106_decrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	struct octeon_gcm_reqctx *rctx = aead_request_ctx(req);
	struct octeon_cop2_state cop2_state;
	unsigned long cop2_flags;
	unsigned int assoclen = req->assoclen;
	unsigned int cryptlen = req->cryptlen;
	unsigned int ct_len;
	u64 tag_calc[2];
	u8 tag_computed[GCM_MAX_AUTH_SIZE];
	u8 tag_received[GCM_MAX_AUTH_SIZE];
	/* Stack buffer for rfc4106 AAD: assoclen is 16 or 20 (validated below).
	 * Kept alive past the COP2 section for the post-verify dst copy. */
	u8 aad[20];
	u8 *ct_buf = NULL, *pt_buf = NULL;
	bool ct_heap = false, pt_heap = false;
	int ret;

	/* Validate assoclen per rfc4106 contract (crypto/gcm.c:867) */
	if (assoclen != 16 && assoclen != 20)
		return -EINVAL;

	/* cryptlen includes the auth tag for decrypt */
	if (cryptlen < ctx->authsize)
		return -EINVAL;

	ct_len = cryptlen - ctx->authsize;

	/* Extract received authentication tag */
	scatterwalk_map_and_copy(tag_received, req->src,
				 assoclen + ct_len, ctx->authsize, 0);

	/* Build J0: nonce(4) || IV(8) || 0x00000001 */
	octeon_rfc4106_build_j0(ctx, req->iv, rctx->j0);
	rctx->counter[0] = rctx->j0[0];
	rctx->counter[1] = rctx->j0[1];

	/* --- Begin COP2 critical section --- */
	cop2_flags = octeon_crypto_enable(&cop2_state);

	/* Skip key+H reload if hardware still holds this transform's state */
	if (__this_cpu_read(octeon_gcm_last_ctx) != ctx) {
		octeon_gcm_load_key(ctx);
		octeon_gfm_load_key(ctx->hash_subkey);
		__this_cpu_write(octeon_gcm_last_ctx, ctx);
	}

	/* Trigger AES(J0) and clear GFM accumulator in parallel */
	OCTEON_MT_COP2(rctx->j0[0], 0x010A);
	OCTEON_MT_COP2(rctx->j0[1], 0x310B);          /* triggers AES(J0) */
	octeon_gfm_clear_accum();                      /* runs while AES computes */
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[0], 0x0100);
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[1], 0x0101);

	/*
	 * GHASH: Process AAD (ESP header only, not the explicit IV).
	 * Read once into stack buffer; reuse for dst copy after tag verify.
	 */
	scatterwalk_map_and_copy(aad, req->src, 0, assoclen, 0);
	octeon_gcm_ghash_aad(aad, assoclen - GCM_RFC4106_IV_SIZE);

	/*
	 * GHASH ciphertext, then CTR-decrypt into pt_buf.
	 * Do NOT write pt_buf to dst yet — wait until tag is verified.
	 */
	if (ct_len > 0) {
		ct_buf = gcm_buf_get(rctx, 0, ct_len, &ct_heap);
		pt_buf = gcm_buf_get(rctx, OCTEON_GCM_INLINE_BUF_SIZE,
				     ct_len, &pt_heap);
		if (!ct_buf || !pt_buf) {
			gcm_buf_put(ct_buf, ct_heap);
			gcm_buf_put(pt_buf, pt_heap);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		/* Read ciphertext (skip AAD) */
		scatterwalk_map_and_copy(ct_buf, req->src, assoclen,
					 ct_len, 0);

		/* GHASH ciphertext + AES-CTR decrypt (single-pass pipelined) */
		octeon_gcm_ghash_ctr_decrypt(rctx, ct_buf, pt_buf, ct_len);
	}

	/* Finalize GHASH: length block uses actual AAD bytes (not incl. IV) */
	octeon_gcm_ghash_final(assoclen - GCM_RFC4106_IV_SIZE, ct_len, tag_calc);

	/* --- End COP2 critical section --- */
	octeon_crypto_disable(&cop2_state, cop2_flags);

	/* Compute expected tag */
	memcpy(tag_computed, tag_calc, GCM_BLOCK_SIZE);
	crypto_xor(tag_computed, rctx->tag_enc, GCM_BLOCK_SIZE);

	/* Constant-time tag comparison */
	ret = crypto_memneq(tag_computed, tag_received, ctx->authsize);
	if (ret) {
		/*
		 * Authentication failed. dst was never written — no
		 * unauthenticated plaintext is visible to the caller.
		 */
		gcm_buf_put(ct_buf, ct_heap);
		gcm_buf_put(pt_buf, pt_heap);
		return -EBADMSG;
	}

	/*
	 * Tag verified. Now safe to write output to dst.
	 * AAD copy is outside the ct_len guard so it always runs
	 * when src != dst, regardless of payload length.
	 * Reuse the aad[] stack buffer read earlier — no extra allocation.
	 */
	if (req->src != req->dst)
		scatterwalk_map_and_copy(aad, req->dst, 0, assoclen, 1);

	if (ct_len > 0) {
		scatterwalk_map_and_copy(pt_buf, req->dst, assoclen,
					 ct_len, 1);
	}

	gcm_buf_put(ct_buf, ct_heap);
	gcm_buf_put(pt_buf, pt_heap);
	return 0;
}


/*
 * Generic gcm(aes) encrypt — uses full 12-byte IV directly.
 */
static int octeon_gcm_encrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	struct octeon_gcm_reqctx *rctx = aead_request_ctx(req);
	struct octeon_cop2_state cop2_state;
	unsigned long cop2_flags;
	unsigned int assoclen = req->assoclen;
	unsigned int cryptlen = req->cryptlen;
	u64 tag[2];
	u8 tag_bytes[GCM_MAX_AUTH_SIZE];

	/* Build J0: IV(12) || 0x00000001 */
	octeon_gcm_build_j0(req->iv, rctx->j0);
	rctx->counter[0] = rctx->j0[0];
	rctx->counter[1] = rctx->j0[1];

	cop2_flags = octeon_crypto_enable(&cop2_state);

	/* Skip key+H reload if hardware still holds this transform's state */
	if (__this_cpu_read(octeon_gcm_last_ctx) != ctx) {
		octeon_gcm_load_key(ctx);
		octeon_gfm_load_key(ctx->hash_subkey);
		__this_cpu_write(octeon_gcm_last_ctx, ctx);
	}

	/* Trigger AES(J0) and clear GFM accumulator in parallel */
	OCTEON_MT_COP2(rctx->j0[0], 0x010A);
	OCTEON_MT_COP2(rctx->j0[1], 0x310B);          /* triggers AES(J0) */
	octeon_gfm_clear_accum();                      /* runs while AES computes */
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[0], 0x0100);
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[1], 0x0101);

	if (assoclen > 0) {
		u8 aad_local[GCM_SMALL_AAD_SIZE];
		u8 *aad_p;
		bool aad_heap = false;

		if (assoclen <= GCM_SMALL_AAD_SIZE) {
			aad_p = aad_local;
		} else {
			aad_p = kmalloc(assoclen, GFP_ATOMIC);
			if (!aad_p) {
				octeon_crypto_disable(&cop2_state, cop2_flags);
				return -ENOMEM;
			}
			aad_heap = true;
		}
		scatterwalk_map_and_copy(aad_p, req->src, 0, assoclen, 0);
		octeon_gcm_ghash_aad(aad_p, assoclen);
		if (req->src != req->dst)
			scatterwalk_map_and_copy(aad_p, req->dst, 0, assoclen, 1);
		if (aad_heap)
			kfree(aad_p);
	}

	if (cryptlen > 0) {
		u8 *pt_buf, *ct_buf;
		bool pt_heap, ct_heap;

		pt_buf = gcm_buf_get(rctx, 0, cryptlen, &pt_heap);
		ct_buf = gcm_buf_get(rctx, OCTEON_GCM_INLINE_BUF_SIZE,
				     cryptlen, &ct_heap);
		if (!pt_buf || !ct_buf) {
			gcm_buf_put(pt_buf, pt_heap);
			gcm_buf_put(ct_buf, ct_heap);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		scatterwalk_map_and_copy(pt_buf, req->src, assoclen,
					 cryptlen, 0);
		octeon_gcm_ctr_encrypt_ghash(rctx, pt_buf, ct_buf, cryptlen);
		scatterwalk_map_and_copy(ct_buf, req->dst, assoclen,
					 cryptlen, 1);

		gcm_buf_put(pt_buf, pt_heap);
		gcm_buf_put(ct_buf, ct_heap);
	}

	octeon_gcm_ghash_final(assoclen, cryptlen, tag);
	octeon_crypto_disable(&cop2_state, cop2_flags);

	memcpy(tag_bytes, tag, GCM_BLOCK_SIZE);
	crypto_xor(tag_bytes, rctx->tag_enc, GCM_BLOCK_SIZE);

	scatterwalk_map_and_copy(tag_bytes, req->dst,
				 assoclen + cryptlen, ctx->authsize, 1);

	return 0;
}

/*
 * Generic gcm(aes) decrypt — uses full 12-byte IV directly.
 */
static int octeon_gcm_decrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct octeon_gcm_ctx *ctx = crypto_aead_ctx(tfm);
	struct octeon_gcm_reqctx *rctx = aead_request_ctx(req);
	struct octeon_cop2_state cop2_state;
	unsigned long cop2_flags;
	unsigned int assoclen = req->assoclen;
	unsigned int cryptlen = req->cryptlen;
	unsigned int ct_len;
	u64 tag_calc[2];
	u8 tag_computed[GCM_MAX_AUTH_SIZE];
	u8 tag_received[GCM_MAX_AUTH_SIZE];
	u8 aad_local[GCM_SMALL_AAD_SIZE];
	u8 *aad_p = NULL;
	bool aad_heap = false;
	u8 *ct_buf = NULL, *pt_buf = NULL;
	bool ct_heap = false, pt_heap = false;
	int ret;

	if (cryptlen < ctx->authsize)
		return -EINVAL;

	ct_len = cryptlen - ctx->authsize;

	scatterwalk_map_and_copy(tag_received, req->src,
				 assoclen + ct_len, ctx->authsize, 0);

	/* Build J0: IV(12) || 0x00000001 */
	octeon_gcm_build_j0(req->iv, rctx->j0);
	rctx->counter[0] = rctx->j0[0];
	rctx->counter[1] = rctx->j0[1];

	cop2_flags = octeon_crypto_enable(&cop2_state);

	/* Skip key+H reload if hardware still holds this transform's state */
	if (__this_cpu_read(octeon_gcm_last_ctx) != ctx) {
		octeon_gcm_load_key(ctx);
		octeon_gfm_load_key(ctx->hash_subkey);
		__this_cpu_write(octeon_gcm_last_ctx, ctx);
	}

	/* Trigger AES(J0) and clear GFM accumulator in parallel */
	OCTEON_MT_COP2(rctx->j0[0], 0x010A);
	OCTEON_MT_COP2(rctx->j0[1], 0x310B);          /* triggers AES(J0) */
	octeon_gfm_clear_accum();                      /* runs while AES computes */
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[0], 0x0100);
	OCTEON_MF_COP2(((u64 *)rctx->tag_enc)[1], 0x0101);

	if (assoclen > 0) {
		if (assoclen <= GCM_SMALL_AAD_SIZE) {
			aad_p = aad_local;
		} else {
			aad_p = kmalloc(assoclen, GFP_ATOMIC);
			if (!aad_p) {
				octeon_crypto_disable(&cop2_state, cop2_flags);
				return -ENOMEM;
			}
			aad_heap = true;
		}
		scatterwalk_map_and_copy(aad_p, req->src, 0, assoclen, 0);
		octeon_gcm_ghash_aad(aad_p, assoclen);
		/* Keep aad_p alive — reused for dst copy after tag verify. */
	}

	/*
	 * GHASH ciphertext, then CTR-decrypt into pt_buf.
	 * Do NOT write pt_buf to dst yet — wait until tag is verified.
	 */
	if (ct_len > 0) {
		ct_buf = gcm_buf_get(rctx, 0, ct_len, &ct_heap);
		pt_buf = gcm_buf_get(rctx, OCTEON_GCM_INLINE_BUF_SIZE,
				     ct_len, &pt_heap);
		if (!ct_buf || !pt_buf) {
			gcm_buf_put(ct_buf, ct_heap);
			gcm_buf_put(pt_buf, pt_heap);
			if (aad_heap)
				kfree(aad_p);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		scatterwalk_map_and_copy(ct_buf, req->src, assoclen,
					 ct_len, 0);
		octeon_gcm_ghash_ctr_decrypt(rctx, ct_buf, pt_buf, ct_len);
	}

	octeon_gcm_ghash_final(assoclen, ct_len, tag_calc);
	octeon_crypto_disable(&cop2_state, cop2_flags);

	memcpy(tag_computed, tag_calc, GCM_BLOCK_SIZE);
	crypto_xor(tag_computed, rctx->tag_enc, GCM_BLOCK_SIZE);

	ret = crypto_memneq(tag_computed, tag_received, ctx->authsize);
	if (ret) {
		/*
		 * Authentication failed. dst was never written — no
		 * unauthenticated plaintext is visible to the caller.
		 */
		if (aad_heap)
			kfree(aad_p);
		gcm_buf_put(ct_buf, ct_heap);
		gcm_buf_put(pt_buf, pt_heap);
		return -EBADMSG;
	}

	/*
	 * Tag verified. Now safe to write output to dst.
	 * AAD copy is outside the ct_len guard so it always runs
	 * when src != dst, regardless of payload length.
	 * Reuse aad_p (read earlier for GHASH) — no second src read needed.
	 */
	if (req->src != req->dst && aad_p)
		scatterwalk_map_and_copy(aad_p, req->dst, 0, assoclen, 1);

	if (aad_heap)
		kfree(aad_p);

	if (ct_len > 0) {
		scatterwalk_map_and_copy(pt_buf, req->dst, assoclen,
					 ct_len, 1);
	}

	gcm_buf_put(ct_buf, ct_heap);
	gcm_buf_put(pt_buf, pt_heap);
	return 0;
}


/* =========================================================================
 * Algorithm Registration
 * ========================================================================= */

static int octeon_gcm_init_tfm(struct crypto_aead *tfm)
{
	crypto_aead_set_reqsize(tfm, sizeof(struct octeon_gcm_reqctx));
	return 0;
}

static struct aead_alg octeon_gcm_alg = {
	.init           = octeon_gcm_init_tfm,
	.setkey         = octeon_rfc4106_setkey,
	.setauthsize    = octeon_gcm_setauthsize,
	.encrypt        = octeon_rfc4106_encrypt,
	.decrypt        = octeon_rfc4106_decrypt,

	.ivsize         = GCM_RFC4106_IV_SIZE,
	.maxauthsize    = GCM_MAX_AUTH_SIZE,

	.base = {
		.cra_name        = "rfc4106(gcm(aes))",
		.cra_driver_name = "octeon-rfc4106-gcm-aes",
		.cra_priority    = OCTEON_GCM_PRIORITY,
		.cra_flags       = 0,
		.cra_blocksize   = 1,
		.cra_ctxsize     = sizeof(struct octeon_gcm_ctx),
		.cra_alignmask   = 7,  /* 8-byte alignment for u64 access */
		.cra_module      = THIS_MODULE,
	},
};

/*
 * Also register generic gcm(aes) for non-IPsec use cases.
 * Note: gcm(aes) uses a full 12-byte IV directly, no nonce.
 */
static struct aead_alg octeon_gcm_generic_alg = {
	.init           = octeon_gcm_init_tfm,
	.setkey         = octeon_gcm_setkey,
	.setauthsize    = octeon_gcm_setauthsize,
	.encrypt        = octeon_gcm_encrypt,
	.decrypt        = octeon_gcm_decrypt,

	.ivsize         = GCM_FULL_IV_SIZE,
	.maxauthsize    = GCM_MAX_AUTH_SIZE,

	.base = {
		.cra_name        = "gcm(aes)",
		.cra_driver_name = "octeon-gcm-aes",
		.cra_priority    = OCTEON_GCM_PRIORITY,
		.cra_flags       = 0,
		.cra_blocksize   = 1,
		.cra_ctxsize     = sizeof(struct octeon_gcm_ctx),
		.cra_alignmask   = 7,
		.cra_module      = THIS_MODULE,
	},
};


/* =========================================================================
 * Module Init / Exit
 * ========================================================================= */

static bool gcm_generic_registered;

static int __init octeon_gcm_mod_init(void)
{
	int ret;

	pr_info("%s: Octeon III AES-GCM hardware offload v%s\n",
		DRIVER_NAME, DRIVER_VERSION);
	pr_info("%s: COP2 AES + GFM engine, priority %d\n",
		DRIVER_NAME, OCTEON_GCM_PRIORITY);

	/* Register rfc4106(gcm(aes)) — primary, for IPsec */
	ret = crypto_register_aead(&octeon_gcm_alg);
	if (ret) {
		pr_err("%s: Failed to register rfc4106(gcm(aes)): %d\n",
		       DRIVER_NAME, ret);
		return ret;
	}

	pr_info("%s: Registered rfc4106(gcm(aes)) [octeon-rfc4106-gcm-aes]\n",
		DRIVER_NAME);

	/* Register generic gcm(aes) — optional, for TLS etc. */
	ret = crypto_register_aead(&octeon_gcm_generic_alg);
	if (ret) {
		pr_warn("%s: Failed to register gcm(aes): %d (non-fatal)\n",
			DRIVER_NAME, ret);
	} else {
		gcm_generic_registered = true;
		pr_info("%s: Registered gcm(aes) [octeon-gcm-aes]\n",
			DRIVER_NAME);
	}

	return 0;
}

static void octeon_gcm_invalidate_cpu_cache(void *unused)
{
	__this_cpu_write(octeon_gcm_last_ctx, NULL);
}

static void __exit octeon_gcm_mod_exit(void)
{
	/*
	 * Null out per-CPU last_ctx on all cores before unregistering.
	 * Prevents a dangling pointer to freed ctx memory if a concurrent
	 * packet were to arrive between unregister and module teardown.
	 */
	on_each_cpu(octeon_gcm_invalidate_cpu_cache, NULL, 1);
	if (gcm_generic_registered)
		crypto_unregister_aead(&octeon_gcm_generic_alg);
	crypto_unregister_aead(&octeon_gcm_alg);
	pr_info("%s: Unloaded\n", DRIVER_NAME);
}

module_init(octeon_gcm_mod_init);
module_exit(octeon_gcm_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Octeon AES-GCM Offload");
MODULE_DESCRIPTION("AES-GCM hardware offload using Octeon III COP2 engine");
MODULE_ALIAS_CRYPTO("rfc4106(gcm(aes))");
MODULE_ALIAS_CRYPTO("gcm(aes)");
MODULE_VERSION(DRIVER_VERSION);
