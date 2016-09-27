/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include <openssl/lhash.h>
#include "internal/bn_int.h"
#include <openssl/rand.h>
#include <openssl/engine.h>
#include "rsa_locl.h"

static const RSA_METHOD *default_RSA_meth = NULL;

RSA *RSA_new(void)
{
    RSA *r = RSA_new_method(NULL);

    return r;
}

void RSA_set_default_method(const RSA_METHOD *meth)
{
    default_RSA_meth = meth;
}

const RSA_METHOD *RSA_get_default_method(void)
{
    if (default_RSA_meth == NULL) {
#ifdef RSA_NULL
        default_RSA_meth = RSA_null_method();
#else
        default_RSA_meth = RSA_PKCS1_OpenSSL();
#endif
    }

    return default_RSA_meth;
}

const RSA_METHOD *RSA_get_method(const RSA *rsa)
{
    return rsa->meth;
}

int RSA_set_method(RSA *rsa, const RSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const RSA_METHOD *mtmp;
    mtmp = rsa->meth;
    if (mtmp->finish)
        mtmp->finish(rsa);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(rsa->engine);
    rsa->engine = NULL;
#endif
    rsa->meth = meth;
    if (meth->init)
        meth->init(rsa);
    return 1;
}

RSA *RSA_new_method(ENGINE *engine)
{
    RSA *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_RSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_RSA(ret->engine);
        if (ret->meth == NULL) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->references = 1;
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(ret->engine);
#endif
        OPENSSL_free(ret);
        return NULL;
    }

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
        OPENSSL_free(ret);
        return NULL;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        RSA_free(ret);
        ret = NULL;
    }

    return ret;
}

void RSA_free(RSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_atomic_add(&r->references, -1, &i, r->lock);
    REF_PRINT_COUNT("RSA", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    BN_clear_free(r->n);
    BN_clear_free(r->e);
    BN_clear_free(r->d);
    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->dmp1);
    BN_clear_free(r->dmq1);
    BN_clear_free(r->iqmp);
    BN_BLINDING_free(r->blinding);
    BN_BLINDING_free(r->mt_blinding);
    OPENSSL_free(r->bignum_data);
    OPENSSL_free(r);
}

int RSA_up_ref(RSA *r)
{
    int i;

    if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("RSA", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int RSA_set_ex_data(RSA *r, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&r->ex_data, idx, arg));
}

void *RSA_get_ex_data(const RSA *r, int idx)
{
    return (CRYPTO_get_ex_data(&r->ex_data, idx));
}

int RSA_memory_lock(RSA *r)
{
    int i, j, k, off;
    char *p;
    BIGNUM *bn, **t[6], *b;
    BN_ULONG *ul;

    if (r->d == NULL)
        return (1);
    t[0] = &r->d;
    t[1] = &r->p;
    t[2] = &r->q;
    t[3] = &r->dmp1;
    t[4] = &r->dmq1;
    t[5] = &r->iqmp;
    k = bn_sizeof_BIGNUM() * 6;
    off = k / sizeof(BN_ULONG) + 1;
    j = 1;
    for (i = 0; i < 6; i++)
        j += bn_get_top(*t[i]);
    if ((p = OPENSSL_malloc((off + j) * sizeof(*p))) == NULL) {
        RSAerr(RSA_F_RSA_MEMORY_LOCK, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    memset(p, 0, sizeof(*p) * (off + j));
    bn = (BIGNUM *)p;
    ul = (BN_ULONG *)&(p[off]);
    for (i = 0; i < 6; i++) {
        b = *(t[i]);
        *(t[i]) = bn_array_el(bn, i);
        memcpy(bn_array_el(bn, i), b, bn_sizeof_BIGNUM());
        memcpy(ul, bn_get_words(b), sizeof(*ul) * bn_get_top(b));
        bn_set_static_words(bn_array_el(bn, i), ul, bn_get_top(b));
        ul += bn_get_top(b);
        BN_clear_free(b);
    }

    /* I should fix this so it can still be done */
    r->flags &= ~(RSA_FLAG_CACHE_PRIVATE | RSA_FLAG_CACHE_PUBLIC);

    r->bignum_data = p;
    return (1);
}

int RSA_security_bits(const RSA *rsa)
{
    return BN_security_bits(BN_num_bits(rsa->n), -1);
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* d is the private component and may be NULL */
    if (n == NULL || e == NULL)
        return 0;

    BN_free(r->n);
    BN_free(r->e);
    BN_free(r->d);
    r->n = n;
    r->e = e;
    r->d = d;

    return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    if (p == NULL || q == NULL)
        return 0;

    BN_free(r->p);
    BN_free(r->q);
    r->p = p;
    r->q = q;

    return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    if (dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
        return 0;

    BN_free(r->dmp1);
    BN_free(r->dmq1);
    BN_free(r->iqmp);
    r->dmp1 = dmp1;
    r->dmq1 = dmq1;
    r->iqmp = iqmp;

    return 1;
}

void RSA_get0_key(const RSA *r, BIGNUM **n, BIGNUM **e, BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, BIGNUM **p, BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

void RSA_clear_flags(RSA *r, int flags)
{
    r->flags &= ~flags;
}

int RSA_test_flags(const RSA *r, int flags)
{
    return r->flags & flags;
}

void RSA_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}

ENGINE *RSA_get0_engine(RSA *r)
{
    return r->engine;
}
