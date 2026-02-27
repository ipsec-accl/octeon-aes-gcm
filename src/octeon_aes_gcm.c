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
	/* Working buffers — avoid stack allocation for large blocks */
	u8 j0[GCM_BLOCK_SIZE];           /* Initial counter block       */
	u8 counter[GCM_BLOCK_SIZE];      /* Running CTR counter         */
	u8 tag_enc[GCM_BLOCK_SIZE];      /* AES_K(J0) for final tag XOR */
	u8 keystream[GCM_BLOCK_SIZE];    /* CTR keystream block         */
};


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
				    const u8 *iv, u8 *j0)
{
	memcpy(j0, ctx->nonce, GCM_NONCE_SIZE);
	memcpy(j0 + GCM_NONCE_SIZE, iv, GCM_RFC4106_IV_SIZE);
	j0[12] = 0x00;
	j0[13] = 0x00;
	j0[14] = 0x00;
	j0[15] = 0x01;
}

/*
 * Build J0 for generic gcm(aes): IV(12) || 0x00000001
 * (96-bit IV case per NIST SP 800-38D)
 */
static void octeon_gcm_build_j0(const u8 *iv, u8 *j0)
{
	memcpy(j0, iv, GCM_FULL_IV_SIZE);
	j0[12] = 0x00;
	j0[13] = 0x00;
	j0[14] = 0x00;
	j0[15] = 0x01;
}

/*
 * Encrypt a single counter block to produce keystream.
 *
 * @counter: 16-byte counter block (not modified)
 * @out:     16-byte keystream output
 *
 * COP2 must be enabled with key loaded.
 */
static void octeon_gcm_encrypt_counter(const u8 *counter, u8 *out)
{
	u64 block[2];

	memcpy(block, counter, GCM_BLOCK_SIZE);
	octeon_aes_encrypt_block(block);
	memcpy(out, block, GCM_BLOCK_SIZE);
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
 * Process ciphertext through GHASH, one block at a time.
 *
 * Called incrementally as ciphertext is produced (encrypt) or
 * before decryption (decrypt). Handles the final partial block.
 */
static void octeon_gcm_ghash_ct_block(const u8 *data, unsigned int len)
{
	u64 block[2];
	unsigned int i;
	unsigned int full_blocks = len / GCM_BLOCK_SIZE;
	unsigned int remainder = len % GCM_BLOCK_SIZE;

	for (i = 0; i < full_blocks; i++) {
		memcpy(block, data + i * GCM_BLOCK_SIZE, GCM_BLOCK_SIZE);
		octeon_gfm_xormul(block);
	}

	if (remainder) {
		memset(block, 0, GCM_BLOCK_SIZE);
		memcpy(block, data + full_blocks * GCM_BLOCK_SIZE, remainder);
		octeon_gfm_xormul(block);
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
	unsigned int i;

	/* Validate assoclen: must be 16 (standard) or 20 (ESN). Per rfc4106,
	 * assoclen = ESP_header(8) + explicit_IV(8), or + ESN(4) = 20.
	 * Matches kernel rfc4106 wrapper check (crypto/gcm.c:867). */
	if (assoclen != 16 && assoclen != 20)
		return -EINVAL;

	/* Build J0: nonce(4) || IV(8) || 0x00000001 */
	octeon_rfc4106_build_j0(ctx, req->iv, rctx->j0);

	/* Counter for CTR mode starts at J0 + 1 (J0 is reserved for tag) */
	memcpy(rctx->counter, rctx->j0, GCM_BLOCK_SIZE);

	/* --- Begin COP2 critical section --- */
	cop2_flags = octeon_crypto_enable(&cop2_state);

	/* Load AES key into COP2 */
	octeon_gcm_load_key(ctx);

	/* Encrypt J0 for final tag computation: tag_enc = AES_K(J0) */
	octeon_gcm_encrypt_counter(rctx->j0, rctx->tag_enc);

	/* Initialize GHASH engine with precomputed H */
	octeon_gfm_init(ctx->hash_subkey);

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

		pt_buf = kmalloc(cryptlen, GFP_ATOMIC);
		ct_buf = kmalloc(cryptlen, GFP_ATOMIC);
		if (!pt_buf || !ct_buf) {
			kfree(pt_buf);
			kfree(ct_buf);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		/* Read plaintext from src (skip AAD) */
		scatterwalk_map_and_copy(pt_buf, req->src, assoclen,
					 cryptlen, 0);

		/* AES-CTR encrypt */
		{
			unsigned int pos = 0;
			unsigned int block_len;

			while (pos < cryptlen) {
				gcm_counter_inc(rctx->counter);
				octeon_gcm_encrypt_counter(rctx->counter,
							   rctx->keystream);
				block_len = min_t(unsigned int,
						  GCM_BLOCK_SIZE,
						  cryptlen - pos);
				for (i = 0; i < block_len; i++)
					ct_buf[pos + i] = pt_buf[pos + i] ^
							  rctx->keystream[i];
				pos += block_len;
			}
		}

		/* GHASH the ciphertext */
		octeon_gcm_ghash_ct_block(ct_buf, cryptlen);

		/* Write ciphertext to dst (skip AAD) */
		scatterwalk_map_and_copy(ct_buf, req->dst, assoclen,
					 cryptlen, 1);

		kfree(pt_buf);
		kfree(ct_buf);
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
	unsigned int i;
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
	memcpy(rctx->counter, rctx->j0, GCM_BLOCK_SIZE);

	/* --- Begin COP2 critical section --- */
	cop2_flags = octeon_crypto_enable(&cop2_state);

	octeon_gcm_load_key(ctx);

	/* Encrypt J0 for tag computation */
	octeon_gcm_encrypt_counter(rctx->j0, rctx->tag_enc);

	/* Initialize GHASH */
	octeon_gfm_init(ctx->hash_subkey);

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
		ct_buf = kmalloc(ct_len, GFP_ATOMIC);
		pt_buf = kmalloc(ct_len, GFP_ATOMIC);
		if (!ct_buf || !pt_buf) {
			kfree(ct_buf);
			kfree(pt_buf);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		/* Read ciphertext (skip AAD) */
		scatterwalk_map_and_copy(ct_buf, req->src, assoclen,
					 ct_len, 0);

		/* GHASH the ciphertext */
		octeon_gcm_ghash_ct_block(ct_buf, ct_len);

		/* AES-CTR decrypt */
		{
			unsigned int pos = 0;
			unsigned int block_len;

			while (pos < ct_len) {
				gcm_counter_inc(rctx->counter);
				octeon_gcm_encrypt_counter(rctx->counter,
							   rctx->keystream);
				block_len = min_t(unsigned int,
						  GCM_BLOCK_SIZE,
						  ct_len - pos);
				for (i = 0; i < block_len; i++)
					pt_buf[pos + i] = ct_buf[pos + i] ^
							  rctx->keystream[i];
				pos += block_len;
			}
		}
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
		kfree(ct_buf);
		kfree(pt_buf);
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

	kfree(ct_buf);
	kfree(pt_buf);
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
	u8 *aad_buf = NULL;
	unsigned int i;

	/* Build J0: IV(12) || 0x00000001 */
	octeon_gcm_build_j0(req->iv, rctx->j0);
	memcpy(rctx->counter, rctx->j0, GCM_BLOCK_SIZE);

	cop2_flags = octeon_crypto_enable(&cop2_state);
	octeon_gcm_load_key(ctx);
	octeon_gcm_encrypt_counter(rctx->j0, rctx->tag_enc);
	octeon_gfm_init(ctx->hash_subkey);

	if (assoclen > 0) {
		aad_buf = kmalloc(assoclen, GFP_ATOMIC);
		if (!aad_buf) {
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}
		scatterwalk_map_and_copy(aad_buf, req->src, 0, assoclen, 0);
		octeon_gcm_ghash_aad(aad_buf, assoclen);
		kfree(aad_buf);
	}

	if (req->src != req->dst && assoclen > 0) {
		u8 *tmp = kmalloc(assoclen, GFP_ATOMIC);
		if (!tmp) {
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}
		scatterwalk_map_and_copy(tmp, req->src, 0, assoclen, 0);
		scatterwalk_map_and_copy(tmp, req->dst, 0, assoclen, 1);
		kfree(tmp);
	}

	if (cryptlen > 0) {
		u8 *pt_buf, *ct_buf;

		pt_buf = kmalloc(cryptlen, GFP_ATOMIC);
		ct_buf = kmalloc(cryptlen, GFP_ATOMIC);
		if (!pt_buf || !ct_buf) {
			kfree(pt_buf);
			kfree(ct_buf);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		scatterwalk_map_and_copy(pt_buf, req->src, assoclen,
					 cryptlen, 0);

		{
			unsigned int pos = 0;
			unsigned int block_len;

			while (pos < cryptlen) {
				gcm_counter_inc(rctx->counter);
				octeon_gcm_encrypt_counter(rctx->counter,
							   rctx->keystream);
				block_len = min_t(unsigned int,
						  GCM_BLOCK_SIZE,
						  cryptlen - pos);
				for (i = 0; i < block_len; i++)
					ct_buf[pos + i] = pt_buf[pos + i] ^
							  rctx->keystream[i];
				pos += block_len;
			}
		}

		octeon_gcm_ghash_ct_block(ct_buf, cryptlen);
		scatterwalk_map_and_copy(ct_buf, req->dst, assoclen,
					 cryptlen, 1);

		kfree(pt_buf);
		kfree(ct_buf);
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
	u8 *aad_buf = NULL;
	u8 *ct_buf = NULL, *pt_buf = NULL;
	unsigned int i;
	int ret;

	if (cryptlen < ctx->authsize)
		return -EINVAL;

	ct_len = cryptlen - ctx->authsize;

	scatterwalk_map_and_copy(tag_received, req->src,
				 assoclen + ct_len, ctx->authsize, 0);

	/* Build J0: IV(12) || 0x00000001 */
	octeon_gcm_build_j0(req->iv, rctx->j0);
	memcpy(rctx->counter, rctx->j0, GCM_BLOCK_SIZE);

	cop2_flags = octeon_crypto_enable(&cop2_state);
	octeon_gcm_load_key(ctx);
	octeon_gcm_encrypt_counter(rctx->j0, rctx->tag_enc);
	octeon_gfm_init(ctx->hash_subkey);

	if (assoclen > 0) {
		aad_buf = kmalloc(assoclen, GFP_ATOMIC);
		if (!aad_buf) {
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}
		scatterwalk_map_and_copy(aad_buf, req->src, 0, assoclen, 0);
		octeon_gcm_ghash_aad(aad_buf, assoclen);
		kfree(aad_buf);
	}

	/*
	 * GHASH ciphertext, then CTR-decrypt into pt_buf.
	 * Do NOT write pt_buf to dst yet — wait until tag is verified.
	 */
	if (ct_len > 0) {
		ct_buf = kmalloc(ct_len, GFP_ATOMIC);
		pt_buf = kmalloc(ct_len, GFP_ATOMIC);
		if (!ct_buf || !pt_buf) {
			kfree(ct_buf);
			kfree(pt_buf);
			octeon_crypto_disable(&cop2_state, cop2_flags);
			return -ENOMEM;
		}

		scatterwalk_map_and_copy(ct_buf, req->src, assoclen,
					 ct_len, 0);
		octeon_gcm_ghash_ct_block(ct_buf, ct_len);

		{
			unsigned int pos = 0;
			unsigned int block_len;

			while (pos < ct_len) {
				gcm_counter_inc(rctx->counter);
				octeon_gcm_encrypt_counter(rctx->counter,
							   rctx->keystream);
				block_len = min_t(unsigned int,
						  GCM_BLOCK_SIZE,
						  ct_len - pos);
				for (i = 0; i < block_len; i++)
					pt_buf[pos + i] = ct_buf[pos + i] ^
							  rctx->keystream[i];
				pos += block_len;
			}
		}
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
		kfree(ct_buf);
		kfree(pt_buf);
		return -EBADMSG;
	}

	/*
	 * Tag verified. Now safe to write output to dst.
	 * AAD copy is outside the ct_len guard so it always runs
	 * when src != dst, regardless of payload length.
	 */
	if (req->src != req->dst && assoclen > 0) {
		u8 *tmp = kmalloc(assoclen, GFP_ATOMIC);
		if (!tmp) {
			kfree(ct_buf);
			kfree(pt_buf);
			return -ENOMEM;
		}
		scatterwalk_map_and_copy(tmp, req->src, 0, assoclen, 0);
		scatterwalk_map_and_copy(tmp, req->dst, 0, assoclen, 1);
		kfree(tmp);
	}

	if (ct_len > 0) {
		scatterwalk_map_and_copy(pt_buf, req->dst, assoclen,
					 ct_len, 1);
	}

	kfree(ct_buf);
	kfree(pt_buf);
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

static void __exit octeon_gcm_mod_exit(void)
{
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
