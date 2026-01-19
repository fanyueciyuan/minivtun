/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * MbedTLS crypto backend
 */

#include <stdlib.h>
#include <string.h>
#include <mbedtls/cipher.h>
#include <mbedtls/md5.h>
#include <assert.h>

#include "crypto_wrapper.h"
#include "log.h"

struct crypto_context {
    const mbedtls_cipher_info_t *cipher_info;
    unsigned char key[CRYPTO_MAX_KEY_SIZE];
    size_t key_len;
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

static void fill_with_string_md5sum(const char *in, void *out, size_t outlen)
{
	char *outp = out;
    char *oute = outp + outlen;
	unsigned char md5_buf[16];
    mbedtls_md5_context ctx;

	mbedtls_md5_init(&ctx);
	mbedtls_md5_starts(&ctx);
	mbedtls_md5_update(&ctx, (const unsigned char *)in, strlen(in));
	mbedtls_md5_finish(&ctx, md5_buf);
    mbedtls_md5_free(&ctx);

    memcpy(out, md5_buf, (outlen > 16) ? 16 : outlen);

	/* Fill in remaining buffer with repeated data. */
	for (outp = (char*)out + 16; outp < oute; outp += 16) {
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
    memset(ctx, 0, sizeof(struct crypto_context));

    ctx->cipher_info = cptype;
    ctx->key_len = mbedtls_cipher_info_get_key_bitlen(ctx->cipher_info) / 8;

    fill_with_string_md5sum(password, ctx->key, ctx->key_len);

    LOG("Crypto context initialized for MbedTLS");
    return ctx;
}

void crypto_free(struct crypto_context* ctx)
{
    if (ctx) {
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
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_cipher_init(&cipher_ctx);
    
    if (mbedtls_cipher_setup(&cipher_ctx, c_ctx->cipher_info) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        return -1;
    }
    if (mbedtls_cipher_setkey(&cipher_ctx, c_ctx->key, mbedtls_cipher_info_get_key_bitlen(c_ctx->cipher_info), MBEDTLS_ENCRYPT) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        return -1;
    }

    unsigned char iv[CRYPTO_MAX_BLOCK_SIZE];
    size_t iv_len = mbedtls_cipher_info_get_iv_size(c_ctx->cipher_info);
    if (iv_len == 0) iv_len = 16;
    memcpy(iv, crypto_ivec_initdata, iv_len);

    CRYPTO_DATA_PADDING(in, dlen, mbedtls_cipher_get_block_size(&cipher_ctx));

    size_t output_len = 0;
    if (mbedtls_cipher_crypt(&cipher_ctx, iv, iv_len, in, *dlen, out, &output_len) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        return -1;
    }
    *dlen = output_len;

    mbedtls_cipher_free(&cipher_ctx);
    return 0; // Success
}

int crypto_decrypt(struct crypto_context* c_ctx, void* in, void* out, size_t* dlen)
{
    if (!c_ctx) { // Decryption disabled
        memmove(out, in, *dlen);
        return 0;
    }

    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_cipher_init(&cipher_ctx);

    if (mbedtls_cipher_setup(&cipher_ctx, c_ctx->cipher_info) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        return -1;
    }
    if (mbedtls_cipher_setkey(&cipher_ctx, c_ctx->key, mbedtls_cipher_info_get_key_bitlen(c_ctx->cipher_info), MBEDTLS_DECRYPT) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        return -1;
    }
    
    unsigned char iv[CRYPTO_MAX_BLOCK_SIZE];
    size_t iv_len = mbedtls_cipher_info_get_iv_size(c_ctx->cipher_info);
    if (iv_len == 0) iv_len = 16;
    memcpy(iv, crypto_ivec_initdata, iv_len);

    CRYPTO_DATA_PADDING(in, dlen, mbedtls_cipher_get_block_size(&cipher_ctx));

    size_t output_len = 0;
    if (mbedtls_cipher_crypt(&cipher_ctx, iv, iv_len, in, *dlen, out, &output_len) != 0) {
        mbedtls_cipher_free(&cipher_ctx);
        return -1;
    }
    *dlen = output_len;

    mbedtls_cipher_free(&cipher_ctx);
    return 0; // Success
}