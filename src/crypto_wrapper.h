/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 *
 * Crypto wrapper interface
 */
#ifndef __CRYPTO_WRAPPER_H
#define __CRYPTO_WRAPPER_H

#include <stddef.h>

#define CRYPTO_MAX_KEY_SIZE  32
#define CRYPTO_MAX_BLOCK_SIZE  32

struct crypto_context;

const void * crypto_get_type(const char *name);

struct crypto_context* crypto_init(const void *cptype, const char* password);

void crypto_free(struct crypto_context* ctx);

int crypto_encrypt(struct crypto_context* ctx, void* in, void* out, size_t* len);

int crypto_decrypt(struct crypto_context* ctx, void* in, void* out, size_t* len);


#endif /* __CRYPTO_WRAPPER_H */
