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

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "dsa_locl.h"
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include <openssl/dh.h>

static const DSA_METHOD *default_DSA_method = NULL;

void DSA_set_default_method(const DSA_METHOD *meth)
{
    default_DSA_method = meth;
}

const DSA_METHOD *DSA_get_default_method(void)
{
    if (!default_DSA_method)
        default_DSA_method = DSA_OpenSSL();
    return default_DSA_method;
}

DSA *DSA_new(void)
{
    return DSA_new_method(NULL);
}

int DSA_set_method(DSA *dsa, const DSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DSA_METHOD *mtmp;
    mtmp = dsa->meth;
    if (mtmp->finish)
        mtmp->finish(dsa);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(dsa->engine);
    dsa->engine = NULL;
#endif
    dsa->meth = meth;
    if (meth->init)
        meth->init(dsa);
    return 1;
}

const DSA_METHOD *DSA_get_method(DSA *d)
{
    return d->meth;
}

DSA *DSA_new_method(ENGINE *engine)
{
    DSA *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ret->meth = DSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    if (engine) {
        if (!ENGINE_init(engine)) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_DSA(ret->engine);
        if (ret->meth == NULL) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            ENGINE_finish(ret->engine);
            OPENSSL_free(ret);
            return NULL;
        }
    }
#endif

    ret->references = 1;
    ret->flags = ret->meth->flags & ~DSA_FLAG_NON_FIPS_ALLOW;

    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data);

    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
#ifndef OPENSSL_NO_ENGINE
        ENGINE_finish(ret->engine);
#endif
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data);
        OPENSSL_free(ret);
        return NULL;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DSA_free(ret);
        ret = NULL;
    }

    return ret;
}

void DSA_free(DSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_atomic_add(&r->references, -1, &i, r->lock);
    REF_PRINT_COUNT("DSA", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth->finish)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    BN_clear_free(r->p);
    BN_clear_free(r->q);
    BN_clear_free(r->g);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r);
}

int DSA_up_ref(DSA *r)
{
    int i;

    if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DSA", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int DSA_size(const DSA *r)
{
    int ret, i;
    ASN1_INTEGER bs;
    unsigned char buf[4];       /* 4 bytes looks really small. However,
                                 * i2d_ASN1_INTEGER() will not look beyond
                                 * the first byte, as long as the second
                                 * parameter is NULL. */

    i = BN_num_bits(r->q);
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_ASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_ASN1_INTEGER(&bs, NULL);
    i += i;                     /* r and s */
    ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
    return (ret);
}

int DSA_set_ex_data(DSA *d, int idx, void *arg)
{
    return (CRYPTO_set_ex_data(&d->ex_data, idx, arg));
}

void *DSA_get_ex_data(DSA *d, int idx)
{
    return (CRYPTO_get_ex_data(&d->ex_data, idx));
}

int DSA_security_bits(const DSA *d)
{
    if (d->p && d->q)
        return BN_security_bits(BN_num_bits(d->p), BN_num_bits(d->q));
    return -1;
}

#ifndef OPENSSL_NO_DH
DH *DSA_dup_DH(const DSA *r)
{
    /*
     * DSA has p, q, g, optional pub_key, optional priv_key. DH has p,
     * optional length, g, optional pub_key, optional priv_key, optional q.
     */

    DH *ret = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub_key = NULL, *priv_key = NULL;

    if (r == NULL)
        goto err;
    ret = DH_new();
    if (ret == NULL)
        goto err;
    if (r->p != NULL || r->g != NULL || r->q != NULL) {
        if (r->p == NULL || r->g == NULL || r->q == NULL) {
            /* Shouldn't happen */
            goto err;
        }
        p = BN_dup(r->p);
        g = BN_dup(r->g);
        q = BN_dup(r->q);
        if (p == NULL || g == NULL || q == NULL || !DH_set0_pqg(ret, p, q, g))
            goto err;
        p = g = q = NULL;
    }

    if (r->pub_key != NULL) {
        pub_key = BN_dup(r->pub_key);
        if (pub_key == NULL)
            goto err;
        if (r->priv_key != NULL) {
            priv_key = BN_dup(r->priv_key);
            if (priv_key == NULL)
                goto err;
        }
        if (!DH_set0_key(ret, pub_key, priv_key))
            goto err;
    } else if (r->priv_key != NULL) {
        /* Shouldn't happen */
        goto err;
    }

    return ret;

 err:
    BN_free(p);
    BN_free(g);
    BN_free(q);
    BN_free(pub_key);
    BN_free(priv_key);
    DH_free(ret);
    return NULL;
}
#endif

void DSA_get0_pqg(const DSA *d, BIGNUM **p, BIGNUM **q, BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (p == NULL || q == NULL || g == NULL)
        return 0;
    BN_free(d->p);
    BN_free(d->q);
    BN_free(d->g);
    d->p = p;
    d->q = q;
    d->g = g;

    return 1;
}

void DSA_get0_key(const DSA *d, BIGNUM **pub_key, BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* Note that it is valid for priv_key to be NULL */
    if (pub_key == NULL)
        return 0;

    BN_free(d->pub_key);
    BN_free(d->priv_key);
    d->pub_key = pub_key;
    d->priv_key = priv_key;

    return 1;
}

void DSA_clear_flags(DSA *d, int flags)
{
    d->flags &= ~flags;
}

int DSA_test_flags(const DSA *d, int flags)
{
    return d->flags & flags;
}

void DSA_set_flags(DSA *d, int flags)
{
    d->flags |= flags;
}

ENGINE *DSA_get0_engine(DSA *d)
{
    return d->engine;
}
