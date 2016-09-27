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
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "internal/evp_int.h"
#include "evp_locl.h"

int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->set_asn1_parameters != NULL)
        ret = c->cipher->set_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {
        case EVP_CIPH_WRAP_MODE:
            if (EVP_CIPHER_CTX_nid(c) == NID_id_smime_alg_CMS3DESwrap)
                ASN1_TYPE_set(type, V_ASN1_NULL, NULL);
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
        case EVP_CIPH_OCB_MODE:
            ret = -1;
            break;

        default:
            ret = EVP_CIPHER_set_asn1_iv(c, type);
        }
    } else
        ret = -1;
    return (ret);
}

int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int ret;

    if (c->cipher->get_asn1_parameters != NULL)
        ret = c->cipher->get_asn1_parameters(c, type);
    else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1) {
        switch (EVP_CIPHER_CTX_mode(c)) {

        case EVP_CIPH_WRAP_MODE:
            ret = 1;
            break;

        case EVP_CIPH_GCM_MODE:
        case EVP_CIPH_CCM_MODE:
        case EVP_CIPH_XTS_MODE:
        case EVP_CIPH_OCB_MODE:
            ret = -1;
            break;

        default:
            ret = EVP_CIPHER_get_asn1_iv(c, type);
            break;
        }
    } else
        ret = -1;
    return (ret);
}

int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int l;

    if (type != NULL) {
        l = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(l <= sizeof(c->iv));
        i = ASN1_TYPE_get_octetstring(type, c->oiv, l);
        if (i != (int)l)
            return (-1);
        else if (i > 0)
            memcpy(c->iv, c->oiv, l);
    }
    return (i);
}

int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
{
    int i = 0;
    unsigned int j;

    if (type != NULL) {
        j = EVP_CIPHER_CTX_iv_length(c);
        OPENSSL_assert(j <= sizeof(c->iv));
        i = ASN1_TYPE_set_octetstring(type, c->oiv, j);
    }
    return (i);
}

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int EVP_CIPHER_type(const EVP_CIPHER *ctx)
{
    int nid;
    ASN1_OBJECT *otmp;
    nid = EVP_CIPHER_nid(ctx);

    switch (nid) {

    case NID_rc2_cbc:
    case NID_rc2_64_cbc:
    case NID_rc2_40_cbc:

        return NID_rc2_cbc;

    case NID_rc4:
    case NID_rc4_40:

        return NID_rc4;

    case NID_aes_128_cfb128:
    case NID_aes_128_cfb8:
    case NID_aes_128_cfb1:

        return NID_aes_128_cfb128;

    case NID_aes_192_cfb128:
    case NID_aes_192_cfb8:
    case NID_aes_192_cfb1:

        return NID_aes_192_cfb128;

    case NID_aes_256_cfb128:
    case NID_aes_256_cfb8:
    case NID_aes_256_cfb1:

        return NID_aes_256_cfb128;

    case NID_des_cfb64:
    case NID_des_cfb8:
    case NID_des_cfb1:

        return NID_des_cfb64;

    case NID_des_ede3_cfb64:
    case NID_des_ede3_cfb8:
    case NID_des_ede3_cfb1:

        return NID_des_cfb64;

    default:
        /* Check it has an OID and it is valid */
        otmp = OBJ_nid2obj(nid);
        if (OBJ_get0_data(otmp) == NULL)
            nid = NID_undef;
        ASN1_OBJECT_free(otmp);
        return nid;
    }
}

int EVP_CIPHER_block_size(const EVP_CIPHER *e)
{
    return e->block_size;
}

int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->block_size;
}

int EVP_CIPHER_impl_ctx_size(const EVP_CIPHER *e)
{
    return e->ctx_size;
}

int EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
               const unsigned char *in, unsigned int inl)
{
    return ctx->cipher->do_cipher(ctx, out, in, inl);
}

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher;
}

int EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx)
{
    return ctx->encrypt;
}

unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher)
{
    return cipher->flags;
}

void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->app_data;
}

void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *EVP_CIPHER_CTX_get_cipher_data(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher_data;
}

void *EVP_CIPHER_CTX_set_cipher_data(EVP_CIPHER_CTX *ctx, void *cipher_data)
{
    void *old_cipher_data;

    old_cipher_data = ctx->cipher_data;
    ctx->cipher_data = cipher_data;

    return old_cipher_data;
}

int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
{
    return cipher->iv_len;
}

int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->iv_len;
}

const unsigned char *EVP_CIPHER_CTX_original_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->oiv;
}

const unsigned char *EVP_CIPHER_CTX_iv(const EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char *EVP_CIPHER_CTX_iv_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->iv;
}

unsigned char *EVP_CIPHER_CTX_buf_noconst(EVP_CIPHER_CTX *ctx)
{
    return ctx->buf;
}

int EVP_CIPHER_CTX_num(const EVP_CIPHER_CTX *ctx)
{
    return ctx->num;
}

void EVP_CIPHER_CTX_set_num(EVP_CIPHER_CTX *ctx, int num)
{
    ctx->num = num;
}

int EVP_CIPHER_key_length(const EVP_CIPHER *cipher)
{
    return cipher->key_len;
}

int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
{
    return ctx->key_len;
}

int EVP_CIPHER_nid(const EVP_CIPHER *cipher)
{
    return cipher->nid;
}

int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx)
{
    return ctx->cipher->nid;
}

int EVP_MD_block_size(const EVP_MD *md)
{
    return md->block_size;
}

int EVP_MD_type(const EVP_MD *md)
{
    return md->type;
}

int EVP_MD_pkey_type(const EVP_MD *md)
{
    return md->pkey_type;
}

int EVP_MD_size(const EVP_MD *md)
{
    if (!md) {
        EVPerr(EVP_F_EVP_MD_SIZE, EVP_R_MESSAGE_DIGEST_IS_NULL);
        return -1;
    }
    return md->md_size;
}

unsigned long EVP_MD_flags(const EVP_MD *md)
{
    return md->flags;
}

EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type)
{
    EVP_MD *md = OPENSSL_zalloc(sizeof(*md));

    if (md != NULL) {
        md->type = md_type;
        md->pkey_type = pkey_type;
    }
    return md;
}
EVP_MD *EVP_MD_meth_dup(const EVP_MD *md)
{
    EVP_MD *to = EVP_MD_meth_new(md->type, md->pkey_type);

    if (to != NULL)
        memcpy(to, md, sizeof(*to));
    return to;
}
void EVP_MD_meth_free(EVP_MD *md)
{
    OPENSSL_free(md);
}
int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize)
{
    md->block_size = blocksize;
    return 1;
}
int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
{
    md->md_size = resultsize;
    return 1;
}
int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
{
    md->ctx_size = datasize;
    return 1;
}
int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags)
{
    md->flags = flags;
    return 1;
}
int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx))
{
    md->init = init;
    return 1;
}
int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count))
{
    md->update = update;
    return 1;
}
int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md))
{
    md->final = final;
    return 1;
}
int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from))
{
    md->copy = copy;
    return 1;
}
int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx))
{
    md->cleanup = cleanup;
    return 1;
}
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2))
{
    md->md_ctrl = ctrl;
    return 1;
}

int EVP_MD_meth_get_input_blocksize(const EVP_MD *md)
{
    return md->block_size;
}
int EVP_MD_meth_get_result_size(const EVP_MD *md)
{
    return md->md_size;
}
int EVP_MD_meth_get_app_datasize(const EVP_MD *md)
{
    return md->ctx_size;
}
unsigned long EVP_MD_meth_get_flags(const EVP_MD *md)
{
    return md->block_size;
}
int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->init;
}
int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count)
{
    return md->update;
}
int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md)
{
    return md->final;
}
int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from)
{
    return md->copy;
}
int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->cleanup;
}
int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2)
{
    return md->md_ctrl;
}

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
{
    if (!ctx)
        return NULL;
    return ctx->digest;
}

EVP_PKEY_CTX *EVP_MD_CTX_pkey_ctx(const EVP_MD_CTX *ctx)
{
    return ctx->pctx;
}

void *EVP_MD_CTX_md_data(const EVP_MD_CTX *ctx)
{
    return ctx->md_data;
}

int (*EVP_MD_CTX_update_fn(EVP_MD_CTX *ctx))(EVP_MD_CTX *ctx,
                                             const void *data, size_t count)
{
    return ctx->update;
}

void EVP_MD_CTX_set_update_fn(EVP_MD_CTX *ctx,
                              int (*update) (EVP_MD_CTX *ctx,
                                             const void *data, size_t count))
{
    ctx->update = update;
}

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags |= flags;
}

void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)
{
    ctx->flags &= ~flags;
}

int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
{
    return (ctx->flags & flags);
}
