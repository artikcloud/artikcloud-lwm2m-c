/* Author: Adam Eijdenberg <adam.eijdenberg@gmail.com>. */
/* ====================================================================
 * Copyright (c) 1998-2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/ct.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/safestack.h>

#include "internal/cryptlib.h"

/*
 * Information about a CT log server.
 */
struct ctlog_st {
    char *name;
    uint8_t log_id[CT_V1_HASHLEN];
    EVP_PKEY *public_key;
};

/*
 * A store for multiple CTLOG instances.
 * It takes ownership of any CTLOG instances added to it.
 */
struct ctlog_store_st {
    STACK_OF(CTLOG) *logs;
};

/* The context when loading a CT log list from a CONF file. */
typedef struct ctlog_store_load_ctx_st {
    CTLOG_STORE *log_store;
    CONF *conf;
    size_t invalid_log_entries;
} CTLOG_STORE_LOAD_CTX;

/*
 * Creates an empty context for loading a CT log store.
 * It should be populated before use.
 */
static CTLOG_STORE_LOAD_CTX *ctlog_store_load_ctx_new();

/*
 * Deletes a CT log store load context.
 * Does not delete any of the fields.
 */
static void ctlog_store_load_ctx_free(CTLOG_STORE_LOAD_CTX* ctx);

static CTLOG_STORE_LOAD_CTX *ctlog_store_load_ctx_new()
{
    CTLOG_STORE_LOAD_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL) {
        CTerr(CT_F_CTLOG_STORE_LOAD_CTX_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return ctx;
err:
    ctlog_store_load_ctx_free(ctx);
    return NULL;
}

static void ctlog_store_load_ctx_free(CTLOG_STORE_LOAD_CTX* ctx)
{
    OPENSSL_free(ctx);
}

/* Converts a log's public key into a SHA256 log ID */
static int ct_v1_log_id_from_pkey(EVP_PKEY *pkey,
                                  unsigned char log_id[CT_V1_HASHLEN])
{
    int ret = 0;
    unsigned char *pkey_der = NULL;
    int pkey_der_len = i2d_PUBKEY(pkey, &pkey_der);

    if (pkey_der_len <= 0) {
        CTerr(CT_F_CT_V1_LOG_ID_FROM_PKEY, CT_R_LOG_KEY_INVALID);
        goto err;
    }

    SHA256(pkey_der, pkey_der_len, log_id);
    ret = 1;
err:
    OPENSSL_free(pkey_der);
    return ret;
}

CTLOG_STORE *CTLOG_STORE_new(void)
{
    CTLOG_STORE *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        goto err;

    ret->logs = sk_CTLOG_new_null();
    if (ret->logs == NULL)
        goto err;

    return ret;
err:
    CTLOG_STORE_free(ret);
    return NULL;
}

void CTLOG_STORE_free(CTLOG_STORE *store)
{
    if (store != NULL) {
        sk_CTLOG_pop_free(store->logs, CTLOG_free);
        OPENSSL_free(store);
    }
}

static CTLOG *ctlog_new_from_conf(const CONF *conf, const char *section)
{
    CTLOG *ret = NULL;
    char *description = NCONF_get_string(conf, section, "description");
    char *pkey_base64;

    if (description == NULL) {
        CTerr(CT_F_CTLOG_NEW_FROM_CONF, CT_R_LOG_CONF_MISSING_DESCRIPTION);
        goto end;
    }

    pkey_base64 = NCONF_get_string(conf, section, "key");
    if (pkey_base64 == NULL) {
        CTerr(CT_F_CTLOG_NEW_FROM_CONF, CT_R_LOG_CONF_MISSING_KEY);
        goto end;
    }

    ret = CTLOG_new_from_base64(pkey_base64, description);
    if (ret == NULL) {
        CTerr(CT_F_CTLOG_NEW_FROM_CONF, CT_R_LOG_CONF_INVALID);
        goto end;
    }

end:
    return ret;
}

int CTLOG_STORE_load_default_file(CTLOG_STORE *store)
{
    const char *fpath = getenv(CTLOG_FILE_EVP);

    if (fpath == NULL)
      fpath = CTLOG_FILE;

    return CTLOG_STORE_load_file(store, fpath);
}

/*
 * Called by CONF_parse_list, which stops if this returns <= 0, so don't unless
 * something very bad happens. Otherwise, one bad log entry would stop loading
 * of any of the following log entries.
 */
static int ctlog_store_load_log(const char *log_name, int log_name_len,
                                void *arg)
{
    CTLOG_STORE_LOAD_CTX *load_ctx = arg;
    CTLOG *ct_log;
    /* log_name may not be null-terminated, so fix that before using it */
    char *tmp;

    /* log_name will be NULL for empty list entries */
    if (log_name == NULL)
        return 1;

    tmp = OPENSSL_strndup(log_name, log_name_len);
    ct_log = ctlog_new_from_conf(load_ctx->conf, tmp);
    OPENSSL_free(tmp);
    if (ct_log == NULL) {
        /* If we can't load this log, record that fact and skip it */
        ++load_ctx->invalid_log_entries;
        return 1;
    }

    sk_CTLOG_push(load_ctx->log_store->logs, ct_log);
    return 1;
}

int CTLOG_STORE_load_file(CTLOG_STORE *store, const char *file)
{
    int ret = 0;
    char *enabled_logs;
    CTLOG_STORE_LOAD_CTX* load_ctx = ctlog_store_load_ctx_new();

    load_ctx->log_store = store;
    load_ctx->conf = NCONF_new(NULL);
    if (load_ctx->conf == NULL)
        goto end;

    if (NCONF_load(load_ctx->conf, file, NULL) <= 0) {
        CTerr(CT_F_CTLOG_STORE_LOAD_FILE, CT_R_LOG_CONF_INVALID);
        goto end;
    }

    enabled_logs = NCONF_get_string(load_ctx->conf, NULL, "enabled_logs");
    if (enabled_logs == NULL) {
        CTerr(CT_F_CTLOG_STORE_LOAD_FILE, CT_R_LOG_CONF_INVALID);
        goto end;
    }

    if (!CONF_parse_list(enabled_logs, ',', 1, ctlog_store_load_log, load_ctx) ||
        load_ctx->invalid_log_entries > 0) {
        CTerr(CT_F_CTLOG_STORE_LOAD_FILE, CT_R_LOG_CONF_INVALID);
        goto end;
    }

    ret = 1;
end:
    NCONF_free(load_ctx->conf);
    ctlog_store_load_ctx_free(load_ctx);
    return ret;
}

/*
 * Initialize a new CTLOG object.
 * Takes ownership of the public key.
 * Copies the name.
 */
CTLOG *CTLOG_new(EVP_PKEY *public_key, const char *name)
{
    CTLOG *ret = CTLOG_new_null();

    if (ret == NULL)
        goto err;

    ret->name = OPENSSL_strdup(name);
    if (ret->name == NULL)
        goto err;

    ret->public_key = public_key;
    if (ct_v1_log_id_from_pkey(public_key, ret->log_id) != 1)
        goto err;

    return ret;
err:
    CTLOG_free(ret);
    return NULL;
}

CTLOG *CTLOG_new_null(void)
{
    CTLOG *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        CTerr(CT_F_CTLOG_NEW_NULL, ERR_R_MALLOC_FAILURE);

    return ret;
}

/* Frees CT log and associated structures */
void CTLOG_free(CTLOG *log)
{
    if (log != NULL) {
        OPENSSL_free(log->name);
        EVP_PKEY_free(log->public_key);
        OPENSSL_free(log);
    }
}

const char *CTLOG_get0_name(const CTLOG *log)
{
    return log->name;
}

void CTLOG_get0_log_id(const CTLOG *log, const uint8_t **log_id,
                       size_t *log_id_len)
{
    *log_id = log->log_id;
    *log_id_len = CT_V1_HASHLEN;
}

EVP_PKEY *CTLOG_get0_public_key(const CTLOG *log)
{
    return log->public_key;
}

/*
 * Given a log ID, finds the matching log.
 * Returns NULL if no match found.
 */
const CTLOG *CTLOG_STORE_get0_log_by_id(const CTLOG_STORE *store,
                                        const uint8_t *log_id,
                                        size_t log_id_len)
{
    int i;

    for (i = 0; i < sk_CTLOG_num(store->logs); ++i) {
        const CTLOG *log = sk_CTLOG_value(store->logs, i);
        if (memcmp(log->log_id, log_id, log_id_len) == 0)
            return log;
    }

    return NULL;
}
