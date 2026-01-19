/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * OpenSSL crypto backend
 */

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <string.h>
#include <assert.h>

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
    unsigned char key[CRYPTO_MAX_KEY_SIZE];
    size_t key_len;
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
    ctx->key_len = EVP_CIPHER_key_length(ctx->cptype);
    fill_with_string_md5sum(password, ctx->key, ctx->key_len);

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
	size_t iv_len = EVP_CIPHER_iv_length(c_ctx->cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;
    int ret = -1;

	if (iv_len == 0) iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);

	EVP_CIPHER_CTX_init(ctx);
	if(!EVP_EncryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->key, iv)) goto out;
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
	if(!EVP_DecryptInit_ex(ctx, c_ctx->cptype, NULL, c_ctx->key, iv)) goto out;
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
