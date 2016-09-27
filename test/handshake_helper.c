/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "handshake_helper.h"

/*
 * Since there appears to be no way to extract the sent/received alert
 * from the SSL object directly, we use the info callback and stash
 * the result in ex_data.
 */
typedef struct handshake_ex_data {
    int alert_sent;
    int alert_received;
} HANDSHAKE_EX_DATA;

static int ex_data_idx;

static void info_callback(const SSL *s, int where, int ret)
{
    if (where & SSL_CB_ALERT) {
        HANDSHAKE_EX_DATA *ex_data =
            (HANDSHAKE_EX_DATA*)(SSL_get_ex_data(s, ex_data_idx));
        if (where & SSL_CB_WRITE) {
            ex_data->alert_sent = ret;
        } else {
            ex_data->alert_received = ret;
        }
    }
}

typedef enum {
    PEER_SUCCESS,
    PEER_RETRY,
    PEER_ERROR
} peer_status_t;

static peer_status_t do_handshake_step(SSL *ssl)
{
    int ret;

    ret = SSL_do_handshake(ssl);

    if (ret == 1) {
        return PEER_SUCCESS;
    } else if (ret == 0) {
        return PEER_ERROR;
    } else {
        int error = SSL_get_error(ssl, ret);
        /* Memory bios should never block with SSL_ERROR_WANT_WRITE. */
        if (error == SSL_ERROR_WANT_READ)
            return PEER_RETRY;
        else
            return PEER_ERROR;
    }
}

typedef enum {
    /* Both parties succeeded. */
    HANDSHAKE_SUCCESS,
    /* Client errored. */
    CLIENT_ERROR,
    /* Server errored. */
    SERVER_ERROR,
    /* Peers are in inconsistent state. */
    INTERNAL_ERROR,
    /* One or both peers not done. */
    HANDSHAKE_RETRY
} handshake_status_t;

/*
 * Determine the handshake outcome.
 * last_status: the status of the peer to have acted last.
 * previous_status: the status of the peer that didn't act last.
 * client_spoke_last: 1 if the client went last.
 */
static handshake_status_t handshake_status(peer_status_t last_status,
                                           peer_status_t previous_status,
                                           int client_spoke_last)
{
    switch (last_status) {
    case PEER_SUCCESS:
        switch (previous_status) {
        case PEER_SUCCESS:
            /* Both succeeded. */
            return HANDSHAKE_SUCCESS;
        case PEER_RETRY:
            /* Let the first peer finish. */
            return HANDSHAKE_RETRY;
        case PEER_ERROR:
            /*
             * Second peer succeeded despite the fact that the first peer
             * already errored. This shouldn't happen.
             */
            return INTERNAL_ERROR;
        }

    case PEER_RETRY:
        if (previous_status == PEER_RETRY) {
            /* Neither peer is done. */
            return HANDSHAKE_RETRY;
        } else {
            /*
             * Deadlock: second peer is waiting for more input while first
             * peer thinks they're done (no more input is coming).
             */
            return INTERNAL_ERROR;
        }
    case PEER_ERROR:
        switch (previous_status) {
        case PEER_SUCCESS:
            /*
             * First peer succeeded but second peer errored.
             * TODO(emilia): we should be able to continue here (with some
             * application data?) to ensure the first peer receives the
             * alert / close_notify.
             */
            return client_spoke_last ? CLIENT_ERROR : SERVER_ERROR;
        case PEER_RETRY:
            /* We errored; let the peer finish. */
            return HANDSHAKE_RETRY;
        case PEER_ERROR:
            /* Both peers errored. Return the one that errored first. */
            return client_spoke_last ? SERVER_ERROR : CLIENT_ERROR;
        }
    }
    /* Control should never reach here. */
    return INTERNAL_ERROR;
}

HANDSHAKE_RESULT do_handshake(SSL_CTX *server_ctx, SSL_CTX *client_ctx)
{
    SSL *server, *client;
    BIO *client_to_server, *server_to_client;
    HANDSHAKE_EX_DATA server_ex_data, client_ex_data;
    HANDSHAKE_RESULT ret;
    int client_turn = 1;
    peer_status_t client_status = PEER_RETRY, server_status = PEER_RETRY;
    handshake_status_t status = HANDSHAKE_RETRY;

    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    OPENSSL_assert(server != NULL && client != NULL);

    memset(&server_ex_data, 0, sizeof(server_ex_data));
    memset(&client_ex_data, 0, sizeof(client_ex_data));
    memset(&ret, 0, sizeof(ret));
    ret.result = SSL_TEST_INTERNAL_ERROR;

    client_to_server = BIO_new(BIO_s_mem());
    server_to_client = BIO_new(BIO_s_mem());

    OPENSSL_assert(client_to_server != NULL && server_to_client != NULL);

    /* Non-blocking bio. */
    BIO_set_nbio(client_to_server, 1);
    BIO_set_nbio(server_to_client, 1);

    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    /* The bios are now owned by the SSL object. */
    SSL_set_bio(client, server_to_client, client_to_server);
    OPENSSL_assert(BIO_up_ref(server_to_client) > 0);
    OPENSSL_assert(BIO_up_ref(client_to_server) > 0);
    SSL_set_bio(server, client_to_server, server_to_client);

    ex_data_idx = SSL_get_ex_new_index(0, "ex data", NULL, NULL, NULL);
    OPENSSL_assert(ex_data_idx >= 0);

    OPENSSL_assert(SSL_set_ex_data(server, ex_data_idx,
                                   &server_ex_data) == 1);
    OPENSSL_assert(SSL_set_ex_data(client, ex_data_idx,
                                   &client_ex_data) == 1);

    SSL_set_info_callback(server, &info_callback);
    SSL_set_info_callback(client, &info_callback);

    /*
     * Half-duplex handshake loop.
     * Client and server speak to each other synchronously in the same process.
     * We use non-blocking BIOs, so whenever one peer blocks for read, it
     * returns PEER_RETRY to indicate that it's the other peer's turn to write.
     * The handshake succeeds once both peers have succeeded. If one peer
     * errors out, we also let the other peer retry (and presumably fail).
     */
    for(;;) {
        if (client_turn) {
            client_status = do_handshake_step(client);
            status = handshake_status(client_status, server_status,
                                      1 /* client went last */);
        } else {
            server_status = do_handshake_step(server);
            status = handshake_status(server_status, client_status,
                                      0 /* server went last */);
        }

        switch (status) {
        case HANDSHAKE_SUCCESS:
            ret.result = SSL_TEST_SUCCESS;
            goto err;
        case CLIENT_ERROR:
            ret.result = SSL_TEST_CLIENT_FAIL;
            goto err;
        case SERVER_ERROR:
            ret.result = SSL_TEST_SERVER_FAIL;
            goto err;
        case INTERNAL_ERROR:
            ret.result = SSL_TEST_INTERNAL_ERROR;
            goto err;
        case HANDSHAKE_RETRY:
            /* Continue. */
            client_turn ^= 1;
            break;
        }
    }
 err:
    ret.server_alert_sent = server_ex_data.alert_sent;
    ret.server_alert_received = client_ex_data.alert_received;
    ret.client_alert_sent = client_ex_data.alert_sent;
    ret.client_alert_received = server_ex_data.alert_received;
    ret.server_protocol = SSL_version(server);
    ret.client_protocol = SSL_version(client);

    SSL_free(server);
    SSL_free(client);
    return ret;
}
