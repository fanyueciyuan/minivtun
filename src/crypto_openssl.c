/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * OpenSSL crypto backend
 */

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>  // For fprintf (debug logging)

#include "crypto_wrapper.h"
#include "log.h"
#include "minivtun.h"  // For struct minivtun_msg and MINIVTUN_MSG_BASIC_HLEN


struct name_cipher_pair {
	const char *name;
	const EVP_CIPHER *(*cipher)(void);
};

static struct name_cipher_pair cipher_pairs[] = {
	{ "aes-128", EVP_aes_128_cbc, },
	{ "aes-256", EVP_aes_256_cbc, },
	{ "des", EVP_des_cbc, },
	{ "desx", EVP_desx_cbc, },
	{ "rc4", EVP_rc4, },
	{ NULL, NULL, },
};


struct crypto_context {
    const EVP_CIPHER *cptype;
    unsigned char enc_key[CRYPTO_MAX_KEY_SIZE];
    size_t enc_key_len;
    unsigned char hmac_key[CRYPTO_HMAC_KEY_SIZE];
};


const void * crypto_get_type(const char *name)
{
	const EVP_CIPHER *cipher = NULL;
	int i;

	for (i = 0; cipher_pairs[i].name; i++) {
		if (strcasecmp(cipher_pairs[i].name, name) == 0) {
			cipher = cipher_pairs[i].cipher();
			break;
		}
	}

	if (cipher) {
		assert(EVP_CIPHER_key_length(cipher) <= CRYPTO_MAX_KEY_SIZE);
		assert(EVP_CIPHER_iv_length(cipher) <= CRYPTO_MAX_BLOCK_SIZE);
		return cipher;
	} else {
		return NULL;
	}
}


static void fill_with_string_md5sum(const char *in, void *out, size_t outlen)
{
	char *outp = out, *oute = outp + outlen;
	unsigned char md5_buf[16];
    MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, in, strlen(in));
	MD5_Final(md5_buf, &ctx);

    memcpy(out, md5_buf, (outlen > 16) ? 16 : outlen);

	/* Fill in remaining buffer with repeated data. */
	for (outp = out + 16; outp < oute; outp += 16) {
		size_t bs = (oute - outp >= 16) ? 16 : (oute - outp);
		memcpy(outp, out, bs);
	}
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

    ctx->cptype = cptype;
    ctx->enc_key_len = EVP_CIPHER_key_length(ctx->cptype);

    /* Use PBKDF2 to derive key material */
    const unsigned char salt[] = "minivtun-v2-salt-2026";
    const int iterations = 100000;
    unsigned char key_material[64]; /* Enough for max encryption key (32) + HMAC key (32) */

    int ret = PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        salt, sizeof(salt) - 1,
        iterations,
        EVP_sha256(),
        sizeof(key_material),
        key_material
    );

    if (ret != 1) {
        LOG("PBKDF2 key derivation failed");
        free(ctx);
        return NULL;
    }

    /* Split key material: first part for encryption, second for HMAC */
    memcpy(ctx->enc_key, key_material, ctx->enc_key_len);
    memcpy(ctx->hmac_key, key_material + ctx->enc_key_len, CRYPTO_HMAC_KEY_SIZE);

    /* Debug: Print derived keys */
    fprintf(stderr, "\n=== Crypto Init ===\n");
    fprintf(stderr, "Password: '%s'\n", password);
    fprintf(stderr, "Encryption key (%zu bytes): ", ctx->enc_key_len);
    for (size_t i = 0; i < ctx->enc_key_len; i++) {
        fprintf(stderr, "%02x", ctx->enc_key[i]);
    }
    fprintf(stderr, "\nHMAC key (32 bytes): ");
    for (int i = 0; i < CRYPTO_HMAC_KEY_SIZE; i++) {
        fprintf(stderr, "%02x", ctx->hmac_key[i]);
    }
    fprintf(stderr, "\n===================\n\n");

    /* Clear sensitive data */
    memset(key_material, 0, sizeof(key_material));

    return ctx;
}


void crypto_free(struct crypto_context* ctx)
{
    if (ctx) {
        /* Clear sensitive key material before freeing */
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

	size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;
    int ret = -1;
    size_t orig_payload_len = payload_len;

	if (iv_len == 0) iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);

	// Pad payload to block size
	void* payload_in = (unsigned char*)in + HEADER_SIZE;
	void* payload_out = (unsigned char*)out + HEADER_SIZE;
	CRYPTO_DATA_PADDING(payload_in, &payload_len, iv_len);

	fprintf(stderr, "[ENCRYPT] Header: %zu bytes (plaintext), Payload: %zu bytes → padded to %zu bytes\n",
	        HEADER_SIZE, orig_payload_len, payload_len);

	EVP_CIPHER_CTX_init(ctx);
	if(!EVP_EncryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->enc_key, iv)) goto out;
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if(!EVP_EncryptUpdate(ctx, payload_out, &outl, payload_in, payload_len)) goto out;
	if(!EVP_EncryptFinal_ex(ctx, (unsigned char *)payload_out + outl, &outl2)) goto out;

	payload_len = (size_t)(outl + outl2);
	*dlen = HEADER_SIZE + payload_len;
	fprintf(stderr, "[ENCRYPT] Total output: %zu bytes (header %zu + encrypted payload %zu)\n",
	        *dlen, HEADER_SIZE, payload_len);
    ret = 0;

out:
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int crypto_decrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
    if (!c_ctx) { // Encryption disabled
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

	size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;
    int ret = -1;
    size_t orig_payload_len = payload_len;

	if (iv_len == 0) iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);

	// Pad payload to block size (for in-place decryption)
	void* payload_in = (unsigned char*)in + HEADER_SIZE;
	void* payload_out = (unsigned char*)out + HEADER_SIZE;
	CRYPTO_DATA_PADDING(payload_in, &payload_len, iv_len);

	fprintf(stderr, "[DECRYPT] Header: %zu bytes (plaintext), Payload: %zu bytes → padded to %zu bytes\n",
	        HEADER_SIZE, orig_payload_len, payload_len);

	EVP_CIPHER_CTX_init(ctx);
	if(!EVP_DecryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->enc_key, iv)) goto out;
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if(!EVP_DecryptUpdate(ctx, payload_out, &outl, payload_in, payload_len)) goto out;
	if(!EVP_DecryptFinal_ex(ctx, (unsigned char *)payload_out + outl, &outl2)) goto out;

	payload_len = (size_t)(outl + outl2);
	*dlen = HEADER_SIZE + payload_len;
	fprintf(stderr, "[DECRYPT] Total output: %zu bytes (header %zu + decrypted payload %zu)\n",
	        *dlen, HEADER_SIZE, payload_len);
    ret = 0;

out:
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
    return ret;
}


/* New HMAC-based authentication functions */

void crypto_compute_hmac(struct crypto_context* ctx,
                         const void* msg, size_t msg_len,
                         void* tag, size_t tag_len)
{
    if (!ctx || !msg || !tag) return;

    unsigned char hmac_output[32]; /* SHA-256 output */
    unsigned int hmac_len;

    HMAC(EVP_sha256(),
         ctx->hmac_key, CRYPTO_HMAC_KEY_SIZE,
         msg, msg_len,
         hmac_output, &hmac_len);

    /* Copy first tag_len bytes */
    size_t copy_len = (tag_len < hmac_len) ? tag_len : hmac_len;
    memcpy(tag, hmac_output, copy_len);
}

bool crypto_verify_hmac(struct crypto_context* ctx, void* msg, size_t msg_len)
{
    if (!ctx || !msg) return false;

    /* Message format: header(plaintext) + encrypted_payload
     * auth_key is at offset 4-19 in the plaintext header
     * We compute HMAC over entire message with auth_key zeroed */
    unsigned char *msg_bytes = (unsigned char*)msg;
    unsigned char received_tag[CRYPTO_AUTH_TAG_SIZE];
    unsigned char computed_tag[CRYPTO_AUTH_TAG_SIZE];

    fprintf(stderr, "\n=== HMAC Verify ===\n");
    fprintf(stderr, "Message length: %zu\n", msg_len);

    /* 1. Extract received HMAC from auth_key field (offset 4) */
    memcpy(received_tag, msg_bytes + 4, CRYPTO_AUTH_TAG_SIZE);

    fprintf(stderr, "Received HMAC: ");
    for (int i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        fprintf(stderr, "%02x", received_tag[i]);
    }
    fprintf(stderr, "\n");

    /* 2. Zero auth_key field for HMAC computation */
    memset(msg_bytes + 4, 0, CRYPTO_AUTH_TAG_SIZE);

    /* 3. Compute HMAC over message with auth_key=0 */
    crypto_compute_hmac(ctx, msg, msg_len, computed_tag, CRYPTO_AUTH_TAG_SIZE);

    fprintf(stderr, "Computed HMAC: ");
    for (int i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        fprintf(stderr, "%02x", computed_tag[i]);
    }
    fprintf(stderr, "\n");

    /* 4. Restore HMAC to auth_key field (not needed for decryption anymore,
     *    but good for consistency if message is reprocessed) */
    memcpy(msg_bytes + 4, received_tag, CRYPTO_AUTH_TAG_SIZE);

    /* 5. Constant-time comparison (prevent timing attack) */
    int result = 0;
    for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        result |= (received_tag[i] ^ computed_tag[i]);
    }

    bool match = (result == 0);
    fprintf(stderr, "HMAC match: %s\n", match ? "YES" : "NO");
    fprintf(stderr, "===================\n\n");

    return match;
}
