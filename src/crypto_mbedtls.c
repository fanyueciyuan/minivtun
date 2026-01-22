/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * MbedTLS crypto backend
 * Modified: 2026-01-19 - Added HMAC authentication support
 */

#include <stdlib.h>
#include <string.h>
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <assert.h>

#include "crypto_wrapper.h"
#include "log.h"

struct crypto_context {
	const mbedtls_cipher_info_t *cipher_info;
	unsigned char enc_key[CRYPTO_MAX_KEY_SIZE];      // Encryption key
	size_t enc_key_len;
	unsigned char hmac_key[CRYPTO_HMAC_KEY_SIZE];    // HMAC key (32 bytes)
};

struct name_cipher_pair {
	const char *name;
	mbedtls_cipher_type_t type;
};

static struct name_cipher_pair cipher_pairs[] = {
	{ "aes-128", MBEDTLS_CIPHER_AES_128_CBC },
	{ "aes-256", MBEDTLS_CIPHER_AES_256_CBC },
	{ "des", MBEDTLS_CIPHER_DES_CBC },
	{ "desx", MBEDTLS_CIPHER_DES_EDE3_CBC },
	{ NULL, 0 },
};

const void * crypto_get_type(const char *name)
{
	for (int i = 0; cipher_pairs[i].name; i++) {
		if (strcasecmp(cipher_pairs[i].name, name) == 0) {
			const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(cipher_pairs[i].type);
			if (cipher_info) {
				assert(mbedtls_cipher_info_get_key_bitlen(cipher_info) / 8 <= CRYPTO_MAX_KEY_SIZE);
				assert(mbedtls_cipher_info_get_iv_size(cipher_info) <= CRYPTO_MAX_BLOCK_SIZE);
				return cipher_info;
			}
		}
	}
	LOG("Unsupported crypto type for MbedTLS backend: %s", name);
	return NULL;
}

struct crypto_context* crypto_init(const void *cptype, const char* password)
{
	if (!cptype || !password || !password[0]) {
		return NULL;
	}

	struct crypto_context* ctx = malloc(sizeof(struct crypto_context));
	if (!ctx) {
		PLOG("malloc failed for crypto context");
		return NULL;
	}
	memset(ctx, 0, sizeof(struct crypto_context));

	ctx->cipher_info = cptype;
	ctx->enc_key_len = mbedtls_cipher_info_get_key_bitlen(ctx->cipher_info) / 8;

	/* PBKDF2-SHA256 key derivation (100,000 iterations) */
	const unsigned char salt[] = "minivtun-v2-salt-2026";
	unsigned char key_material[64];  /* Enough for max encryption key (32) + HMAC key (32) */

	mbedtls_md_context_t md_ctx;
	mbedtls_md_init(&md_ctx);

	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md_info) {
		LOG("mbedtls_md_info_from_type failed for SHA256");
		free(ctx);
		return NULL;
	}

	if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0) {
		LOG("mbedtls_md_setup failed");
		mbedtls_md_free(&md_ctx);
		free(ctx);
		return NULL;
	}

	if (mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
	                               (const unsigned char*)password, strlen(password),
	                               salt, sizeof(salt) - 1,
	                               100000,  // 100,000 iterations
	                               64,      // Output: 32 enc + 32 hmac
	                               key_material) != 0) {
		LOG("mbedtls_pkcs5_pbkdf2_hmac failed");
		mbedtls_md_free(&md_ctx);
		free(ctx);
		return NULL;
	}

	mbedtls_md_free(&md_ctx);

	/* Split derived key material into encryption key and HMAC key */
	memcpy(ctx->enc_key, key_material, ctx->enc_key_len);
	memcpy(ctx->hmac_key, key_material + ctx->enc_key_len, CRYPTO_HMAC_KEY_SIZE);

	/* Securely clear temporary key material */
	memset(key_material, 0, sizeof(key_material));

	LOG("Crypto context initialized for MbedTLS with HMAC support");
	return ctx;
}

void crypto_free(struct crypto_context* ctx)
{
	if (ctx) {
		/* Securely clear sensitive key material before freeing */
		memset(ctx, 0, sizeof(*ctx));
		free(ctx);
	}
}

static const char crypto_ivec_initdata[CRYPTO_MAX_BLOCK_SIZE] = {
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
};

#define CRYPTO_DATA_PADDING(data, dlen, bs) \
	do { \
		size_t last_len = *(dlen) % (bs); \
		if (last_len) { \
			size_t padding_len = bs - last_len; \
			memset((char *)data + *(dlen), 0x0, padding_len); \
			*(dlen) += padding_len; \
		} \
	} while(0)

int crypto_encrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
	if (!c_ctx) { // Encryption disabled
		memmove(out, in, *dlen);
		return 0;
	}

	/* New approach: Only encrypt payload, skip 20-byte header
	 * Header contains: opcode, rsv, seq, auth_key - keep in plaintext
	 * This avoids the ciphertext-loss problem when HMAC overwrites auth_key */
	const size_t HEADER_SIZE = 20;  // MINIVTUN_MSG_BASIC_HLEN

	if (*dlen < HEADER_SIZE) {
		// Message too small, just copy
		memmove(out, in, *dlen);
		return 0;
	}

	// Copy header as-is (plaintext)
	memcpy(out, in, HEADER_SIZE);

	// Encrypt only the payload part
	size_t payload_len = *dlen - HEADER_SIZE;
	if (payload_len == 0) {
		// No payload, nothing to encrypt
		return 0;
	}

	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_init(&cipher_ctx);

	if (mbedtls_cipher_setup(&cipher_ctx, c_ctx->cipher_info) != 0) {
		mbedtls_cipher_free(&cipher_ctx);
		return -1;
	}
	if (mbedtls_cipher_setkey(&cipher_ctx, c_ctx->enc_key, mbedtls_cipher_info_get_key_bitlen(c_ctx->cipher_info), MBEDTLS_ENCRYPT) != 0) {
		mbedtls_cipher_free(&cipher_ctx);
		return -1;
	}

	unsigned char iv[CRYPTO_MAX_BLOCK_SIZE];
	size_t iv_len = mbedtls_cipher_info_get_iv_size(c_ctx->cipher_info);
	if (iv_len == 0) iv_len = 16;
	memcpy(iv, crypto_ivec_initdata, iv_len);

	// Pad payload to block size
	void* payload_in = (unsigned char*)in + HEADER_SIZE;
	void* payload_out = (unsigned char*)out + HEADER_SIZE;
	CRYPTO_DATA_PADDING(payload_in, &payload_len, mbedtls_cipher_get_block_size(&cipher_ctx));

	size_t output_len = 0;
	if (mbedtls_cipher_crypt(&cipher_ctx, iv, iv_len, payload_in, payload_len, payload_out, &output_len) != 0) {
		mbedtls_cipher_free(&cipher_ctx);
		return -1;
	}
	*dlen = HEADER_SIZE + output_len;

	mbedtls_cipher_free(&cipher_ctx);
	return 0; // Success
}

int crypto_decrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
	if (!c_ctx) { // Decryption disabled
		memmove(out, in, *dlen);
		return 0;
	}

	/* New approach: Only decrypt payload, skip 20-byte header
	 * Header was sent in plaintext */
	const size_t HEADER_SIZE = 20;  // MINIVTUN_MSG_BASIC_HLEN

	if (*dlen < HEADER_SIZE) {
		// Message too small, just copy
		memmove(out, in, *dlen);
		return 0;
	}

	// Copy header as-is (it was never encrypted)
	memcpy(out, in, HEADER_SIZE);

	// Decrypt only the payload part
	size_t payload_len = *dlen - HEADER_SIZE;
	if (payload_len == 0) {
		// No payload, nothing to decrypt
		*dlen = HEADER_SIZE;
		return 0;
	}

	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_init(&cipher_ctx);

	if (mbedtls_cipher_setup(&cipher_ctx, c_ctx->cipher_info) != 0) {
		mbedtls_cipher_free(&cipher_ctx);
		return -1;
	}
	if (mbedtls_cipher_setkey(&cipher_ctx, c_ctx->enc_key, mbedtls_cipher_info_get_key_bitlen(c_ctx->cipher_info), MBEDTLS_DECRYPT) != 0) {
		mbedtls_cipher_free(&cipher_ctx);
		return -1;
	}

	unsigned char iv[CRYPTO_MAX_BLOCK_SIZE];
	size_t iv_len = mbedtls_cipher_info_get_iv_size(c_ctx->cipher_info);
	if (iv_len == 0) iv_len = 16;
	memcpy(iv, crypto_ivec_initdata, iv_len);

	// Pad payload to block size (for in-place decryption)
	void* payload_in = (unsigned char*)in + HEADER_SIZE;
	void* payload_out = (unsigned char*)out + HEADER_SIZE;
	CRYPTO_DATA_PADDING(payload_in, &payload_len, mbedtls_cipher_get_block_size(&cipher_ctx));

	size_t output_len = 0;
	if (mbedtls_cipher_crypt(&cipher_ctx, iv, iv_len, payload_in, payload_len, payload_out, &output_len) != 0) {
		mbedtls_cipher_free(&cipher_ctx);
		return -1;
	}
	*dlen = HEADER_SIZE + output_len;

	mbedtls_cipher_free(&cipher_ctx);
	return 0; // Success
}

/* Compute HMAC-SHA256 authentication tag */
void crypto_compute_hmac(struct crypto_context* ctx,
                         const void* msg, size_t msg_len,
                         void* tag, size_t tag_len)
{
	if (!ctx || !msg || !tag) {
		return;
	}

	unsigned char hmac_output[32];  // SHA256 produces 32 bytes

	mbedtls_md_context_t md_ctx;
	mbedtls_md_init(&md_ctx);

	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md_info) {
		LOG("crypto_compute_hmac: mbedtls_md_info_from_type failed");
		mbedtls_md_free(&md_ctx);
		return;
	}

	if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0) {  // 1 = enable HMAC
		LOG("crypto_compute_hmac: mbedtls_md_setup failed");
		mbedtls_md_free(&md_ctx);
		return;
	}

	if (mbedtls_md_hmac_starts(&md_ctx, ctx->hmac_key, CRYPTO_HMAC_KEY_SIZE) != 0) {
		LOG("crypto_compute_hmac: mbedtls_md_hmac_starts failed");
		mbedtls_md_free(&md_ctx);
		return;
	}

	if (mbedtls_md_hmac_update(&md_ctx, (const unsigned char*)msg, msg_len) != 0) {
		LOG("crypto_compute_hmac: mbedtls_md_hmac_update failed");
		mbedtls_md_free(&md_ctx);
		return;
	}

	if (mbedtls_md_hmac_finish(&md_ctx, hmac_output) != 0) {
		LOG("crypto_compute_hmac: mbedtls_md_hmac_finish failed");
		mbedtls_md_free(&md_ctx);
		return;
	}

	mbedtls_md_free(&md_ctx);

	/* Copy first tag_len bytes (typically 16) to output tag */
	memcpy(tag, hmac_output, tag_len);
}

/* Verify HMAC-SHA256 authentication tag (timing-safe) */
bool crypto_verify_hmac(struct crypto_context* ctx, void* msg, size_t msg_len)
{
	if (!ctx || !msg || msg_len < MINIVTUN_MSG_BASIC_HLEN) {
		return false;
	}

	/* Message format: header(plaintext) + encrypted_payload
	 * auth_key is at offset 4-19 in the plaintext header
	 * We compute HMAC over entire message with auth_key zeroed */
	struct minivtun_msg *nmsg = (struct minivtun_msg *)msg;
	unsigned char received_tag[CRYPTO_AUTH_TAG_SIZE];
	memcpy(received_tag, nmsg->hdr.auth_key, CRYPTO_AUTH_TAG_SIZE);

	/* Zero out auth_key field before computing HMAC */
	memset(nmsg->hdr.auth_key, 0, sizeof(nmsg->hdr.auth_key));

	/* Compute expected HMAC over entire message */
	unsigned char computed_tag[CRYPTO_AUTH_TAG_SIZE];
	crypto_compute_hmac(ctx, msg, msg_len, computed_tag, CRYPTO_AUTH_TAG_SIZE);

	/* Restore received HMAC to message (not needed for decryption anymore,
	 * but good for consistency if message is reprocessed) */
	memcpy(nmsg->hdr.auth_key, received_tag, CRYPTO_AUTH_TAG_SIZE);

	/* Constant-time comparison to prevent timing attacks */
	int result = 0;
	for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
		result |= (received_tag[i] ^ computed_tag[i]);
	}

	return (result == 0);
}
