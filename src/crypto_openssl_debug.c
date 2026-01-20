/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * OpenSSL crypto backend - DEBUG VERSION
 *
 * This is a debug version with extensive logging to diagnose HMAC issues.
 * Replace src/crypto_openssl.c with this file temporarily for debugging.
 */

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>  // Added for debug output

#include "crypto_wrapper.h"
#include "log.h"


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
    unsigned char key_material[64]; /* 32 bytes for encryption + 32 bytes for HMAC */

    fprintf(stderr, "\n=== DEBUG: crypto_init() ===\n");
    fprintf(stderr, "Password: '%s'\n", password);
    fprintf(stderr, "Salt: '%s'\n", salt);
    fprintf(stderr, "Iterations: %d\n", iterations);

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
    memcpy(ctx->hmac_key, key_material + 32, CRYPTO_HMAC_KEY_SIZE);

    /* DEBUG: Print derived keys */
    fprintf(stderr, "Encryption key (%zu bytes): ", ctx->enc_key_len);
    for (size_t i = 0; i < ctx->enc_key_len; i++) {
        fprintf(stderr, "%02x", ctx->enc_key[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "HMAC key (32 bytes): ");
    for (int i = 0; i < CRYPTO_HMAC_KEY_SIZE; i++) {
        fprintf(stderr, "%02x", ctx->hmac_key[i]);
    }
    fprintf(stderr, "\n=== END crypto_init() ===\n\n");

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
	size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;
    int ret = -1;

	if (iv_len == 0) iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);

	EVP_CIPHER_CTX_init(ctx);
	if(!EVP_EncryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->enc_key, iv)) goto out;
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if(!EVP_EncryptUpdate(ctx, out, &outl, in, *dlen)) goto out;
	if(!EVP_EncryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2)) goto out;

	*dlen = (size_t)(outl + outl2);
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

	size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;
    int ret = -1;

	if (iv_len == 0) iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);

	EVP_CIPHER_CTX_init(ctx);
	if(!EVP_DecryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->enc_key, iv)) goto out;
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if(!EVP_DecryptUpdate(ctx, out, &outl, in, *dlen)) goto out;
	if(!EVP_DecryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2)) goto out;

	*dlen = (size_t)(outl + outl2);
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

    fprintf(stderr, "\n=== DEBUG: crypto_compute_hmac() ===\n");
    fprintf(stderr, "Message length: %zu\n", msg_len);

    fprintf(stderr, "First 40 bytes of message: ");
    for (size_t i = 0; i < 40 && i < msg_len; i++) {
        fprintf(stderr, "%02x", ((unsigned char*)msg)[i]);
    }
    fprintf(stderr, "\n");

    HMAC(EVP_sha256(),
         ctx->hmac_key, CRYPTO_HMAC_KEY_SIZE,
         msg, msg_len,
         hmac_output, &hmac_len);

    fprintf(stderr, "Full HMAC output (32 bytes): ");
    for (unsigned int i = 0; i < hmac_len; i++) {
        fprintf(stderr, "%02x", hmac_output[i]);
    }
    fprintf(stderr, "\n");

    /* Copy first tag_len bytes */
    size_t copy_len = (tag_len < hmac_len) ? tag_len : hmac_len;
    memcpy(tag, hmac_output, copy_len);

    fprintf(stderr, "Truncated HMAC (%zu bytes): ", copy_len);
    for (size_t i = 0; i < copy_len; i++) {
        fprintf(stderr, "%02x", ((unsigned char*)tag)[i]);
    }
    fprintf(stderr, "\n=== END crypto_compute_hmac() ===\n\n");
}

bool crypto_verify_hmac(struct crypto_context* ctx, void* msg, size_t msg_len)
{
    if (!ctx || !msg) return false;

    /* Message is struct minivtun_msg* */
    /* auth_key is at offset 4 (after opcode+rsv+seq), length 16 */
    unsigned char *msg_bytes = (unsigned char*)msg;
    unsigned char received_tag[CRYPTO_AUTH_TAG_SIZE];
    unsigned char computed_tag[CRYPTO_AUTH_TAG_SIZE];

    fprintf(stderr, "\n=== DEBUG: crypto_verify_hmac() ===\n");
    fprintf(stderr, "Message length: %zu\n", msg_len);

    /* 1. Extract received HMAC (offset 4 = sizeof(opcode+rsv+seq)) */
    memcpy(received_tag, msg_bytes + 4, CRYPTO_AUTH_TAG_SIZE);

    fprintf(stderr, "Received HMAC (16 bytes): ");
    for (int i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        fprintf(stderr, "%02x", received_tag[i]);
    }
    fprintf(stderr, "\n");

    /* 2. Clear auth_key field to zero */
    memset(msg_bytes + 4, 0, CRYPTO_AUTH_TAG_SIZE);

    /* 3. Compute HMAC */
    crypto_compute_hmac(ctx, msg, msg_len, computed_tag, CRYPTO_AUTH_TAG_SIZE);

    fprintf(stderr, "Computed HMAC (16 bytes): ");
    for (int i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        fprintf(stderr, "%02x", computed_tag[i]);
    }
    fprintf(stderr, "\n");

    /* 4. Restore original auth_key (for subsequent processing) */
    memcpy(msg_bytes + 4, received_tag, CRYPTO_AUTH_TAG_SIZE);

    /* 5. Constant-time comparison (prevent timing attack) */
    int result = 0;
    for (size_t i = 0; i < CRYPTO_AUTH_TAG_SIZE; i++) {
        result |= (received_tag[i] ^ computed_tag[i]);
    }

    bool match = (result == 0);
    fprintf(stderr, "HMAC match: %s\n", match ? "YES ✓" : "NO ✗");
    fprintf(stderr, "=== END crypto_verify_hmac() ===\n\n");

    return match;
}
