/*******************************************************************************
 *
 * Copyright (c) 2013, 2014 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Gregory Lemercier, Samsung Semiconductor - support for TCP/TLS
 *    David Navarro, Intel Corporation - initial API and implementation
 *    Pascal Rieux - Please refer to git log
 *    
 *******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "connection.h"

/* Needed for Mac OS X */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

static lwm2m_dtls_info_t *dtlsinfo_list = NULL;

// from commandline.c
void output_buffer(FILE * stream, uint8_t * buffer, int length, int indent);
static char *security_get_public_id(lwm2m_object_t * obj, int instanceId, int * length);
static char *security_get_secret_key(lwm2m_object_t * obj, int instanceId, int * length);

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    int keyLen = 0;
    lwm2m_dtls_info_t *dtls = dtlsinfo_list;
    char *id = NULL, *key = NULL;

    // Look up DTLS info based on SSL pointer
    while (dtls != NULL)
    {
        if (ssl == dtls->connection->ssl)
        {
            id = dtls->identity;
            key = dtls->key;
            keyLen = dtls->key_length;
            break;
        }

        dtls = dtls->next;
    }

    if(!id || !key)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Could not find DTLS credentials\n");
#endif
        return 0;
    }

    if (strlen(id) > max_identity_len)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "PSK identity is too long\n");
#endif
        return 0;
    }

    strncpy(identity, id, max_identity_len);

    if (keyLen > max_psk_len)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "PSK key is too long\n");
#endif
        return 0;
    }

    memcpy(psk, key, keyLen);

#ifdef WITH_LOGS
    {
        int i = 0;
        fprintf(stdout, "id: %s\n", identity);
        fprintf(stdout, "Key:");
        for (i=0; i<keyLen; i++)
            fprintf(stdout, "%02x", psk[i]);
        fprintf(stdout, "\n");
    }
#endif

    return keyLen;
}

static int security_get_security_mode(lwm2m_object_t * obj, int instanceId)
{
    int size = 1;
    lwm2m_data_t * dataP = lwm2m_data_new(size);
    dataP->id = 2; // security mode

    obj->readFunc(instanceId, &size, &dataP, obj);
    if (dataP != NULL &&
            dataP->type == LWM2M_TYPE_INTEGER)
    {
        int val = dataP->value.asInteger;
        lwm2m_free(dataP);
        return val;
    }
    else
    {
        lwm2m_free(dataP);
        return -1;
    }
}

static char *security_get_server_public(lwm2m_object_t * obj, int instanceId, int * length)
{
    int size = 1;
    lwm2m_data_t * dataP = lwm2m_data_new(size);
    dataP->id = 4; // server public key or id

    obj->readFunc(instanceId, &size, &dataP, obj);
    if (dataP != NULL &&
            dataP->type == LWM2M_TYPE_OPAQUE)
    {
        char *val = (char*)dataP->value.asBuffer.buffer;
        *length = dataP->value.asBuffer.length;
        lwm2m_free(dataP);
        return val;
    }
    else
    {
        lwm2m_free(dataP);
        return NULL;
    }
}

static bool ssl_add_client_cert(SSL_CTX *ctx, lwm2m_object_t *sec_obj, int sec_inst)
{
    int len = 0;
    X509* cert;
    char *public_cert = NULL, *secret_key = NULL;

    public_cert = security_get_public_id(sec_obj, sec_inst, &len);
    if (!public_cert) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to get client certificate from security object.\r\n");
#endif
        return false;
    }

    cert = d2i_X509(NULL, (const unsigned char **)&public_cert, len);
    if (!cert) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to parse client certificate.\r\n");
#endif
        return false;
    }

    SSL_CTX_use_certificate(ctx, cert);
    X509_free(cert);

    secret_key = security_get_secret_key(sec_obj, sec_inst, &len);
    if (!secret_key) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to get secret private key from security object.\r\n");
#endif
       return false;
    }

    if (!SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, ctx,
            (const unsigned char *)secret_key, len)) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to parse private key. (len %d)\r\n", len);
#endif
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to check private key.\r\n");
#endif
        return false;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return true;
}
static bool ssl_store_add_cert(SSL_CTX *ctx, const char *root_ca)
{
    X509 *x509_cert = NULL;
    X509_STORE *keystore;
    bool ret = false;
    BIO* bio;

    bio = BIO_new_mem_buf(root_ca, -1);
    if (!bio) {
        goto exit;
    }

    x509_cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!x509_cert) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to parse root CA.\r\n");
#endif
        goto exit;
    }

    keystore = SSL_CTX_get_cert_store(ctx);
    if (!keystore) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to load keystore.\r\n");
#endif
        goto exit;
    }

    /* Set CA certificate to context */
    if (!X509_STORE_add_cert(keystore, x509_cert)) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to add certificate to the keystore");
#endif
        goto exit;
    }

    ret = true;
exit:
    if (bio)
        BIO_free(bio);

    if (x509_cert)
        X509_free(x509_cert);

    return ret;
}

static SSL_CTX* ssl_configure_certificate_mode(connection_t *conn)
{
    SSL_CTX *ctx = NULL;

    if (conn->protocol == COAP_UDP_DTLS) {
        ctx = SSL_CTX_new(DTLS_client_method());
    } else {
#if (OPENSSL_VERSION_NUMBER >= 0x10100005L)
        ctx = SSL_CTX_new(TLS_client_method());
#else
        ctx = SSL_CTX_new(SSLv23_client_method());
#endif
    }

    if (!ctx) {
        return NULL;
    }

    if (!ssl_add_client_cert(ctx, conn->sec_obj, conn->sec_inst)) {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to add client certificate to SSL context.\r\n");
#endif
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (conn->protocol == COAP_TCP_TLS) {
        SSL_CTX_set_verify(ctx, conn->verify_cert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
        if (conn->root_ca) {
            if (!ssl_store_add_cert(ctx, conn->root_ca))
            {
                SSL_CTX_free(ctx);
                return NULL;
            }
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

static SSL_CTX* ssl_configure_pre_shared_key(connection_t *conn)
{
    SSL_CTX *ctx = NULL;

    if ((conn->protocol == COAP_UDP_DTLS) && conn->sec_obj)
    {
        char *id = NULL, *psk = NULL;
        int len = 0;
        lwm2m_dtls_info_t *dtls = NULL;

        if (!conn->sec_obj)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "No security object provided\n");
#endif
            return NULL;
        }
        // Retrieve ID/PSK from security object for DTLS handshake
        dtls = malloc(sizeof(lwm2m_dtls_info_t));

        if (!dtls)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "Failed to allocate memory for DTLS security info\n");
#endif
            free(dtls);
            return NULL;
        }

        memset(dtls, 0, sizeof(lwm2m_dtls_info_t));

        id = security_get_public_id(conn->sec_obj, conn->sec_inst, &len);
        if (len > MAX_DTLS_INFO_LEN)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "Public ID is too long\n");
#endif
            free(dtls);
            return NULL;
        }

        memcpy(dtls->identity, id, len);

        psk = security_get_secret_key(conn->sec_obj, conn->sec_inst, &len);
        if (len > MAX_DTLS_INFO_LEN)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "Secret key is too long\n");
#endif
            free(dtls);
            return NULL;
        }

        memcpy(dtls->key, psk, len);
        dtls->key_length = len;
        dtls->connection = conn;
        dtls->id = lwm2m_list_newId((lwm2m_list_t*)dtlsinfo_list);
        dtlsinfo_list = (lwm2m_dtls_info_t*)LWM2M_LIST_ADD((lwm2m_list_t*)dtlsinfo_list, (lwm2m_list_t*)dtls);

        ctx = SSL_CTX_new(DTLS_client_method());
        SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
        SSL_CTX_set_cipher_list(ctx, "PSK-AES128-CCM8:PSK-AES128-CBC-SHA");
    }
    else
    {
#if (OPENSSL_VERSION_NUMBER >= 0x10100005L)
        ctx = SSL_CTX_new(TLS_client_method());
#else
        ctx = SSL_CTX_new(SSLv23_client_method());
#endif
        if (conn->root_ca) {
            if (!ssl_store_add_cert(ctx, conn->root_ca))
            {
                SSL_CTX_free(ctx);
                return NULL;
            }
        }

        SSL_CTX_set_cipher_list(ctx, "ALL");
        printf("SSL verify ? %d\n", conn->verify_cert);
        SSL_CTX_set_verify(ctx, conn->verify_cert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);
#if (OPENSSL_VERSION_NUMBER >= 0x10100005L)
        SSL_CTX_set_default_verify_dir(ctx);
#endif

        /* Ignore SIGPIPE to avoid the program from exiting on closed socket */
        signal(SIGPIPE, SIG_IGN);
    }

    return ctx;
}

static bool ssl_init(connection_t * conn)
{
    BIO *sbio = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int flags = 0;
    int ret = 0;

    OpenSSL_add_all_algorithms();
    ERR_clear_error();
    ERR_load_BIO_strings();
    SSL_load_error_strings();

    if(SSL_library_init() < 0)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to initialize OpenSSL\n");
#endif
        goto error;
    }

    uint8_t securityMode = security_get_security_mode(conn->sec_obj, conn->sec_inst);
    if (securityMode == 0) { /* Pre shared key mode */
        ctx = ssl_configure_pre_shared_key(conn);
    } else if (securityMode == 2) { /* Certificate mode */
        ctx =  ssl_configure_certificate_mode(conn);
    } else {
        return NULL;
    }

    if (!ctx)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to create SSL context\n");
#endif
        goto error;
    }

    ssl = SSL_new(ctx);
    if (!ssl)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to allocate SSL connection\n");
#endif
        goto error;
    }

    if (conn->protocol == COAP_UDP_DTLS)
    {
        X509* peer_cert = NULL;
        X509* server_cert = NULL;
        struct sockaddr peer;
        int peerlen = sizeof (struct sockaddr);
        struct timeval timeout;
        int ret;
        int handshake_timeout = 50;
        char *cert = NULL;
        int len;
        int oldflags = fcntl (conn->sock, F_GETFL, 0);

        oldflags |= O_NONBLOCK;
        fcntl(conn->sock, F_SETFL, oldflags);

        sbio = BIO_new_dgram (conn->sock, BIO_NOCLOSE);
        if (getsockname (conn->sock, &peer, (socklen_t *)&peerlen) < 0)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "getsockname failed (%s)\n", strerror (errno));
#endif
        }
        if (securityMode == 2) { /* Certificate mode */
            cert = security_get_server_public(conn->sec_obj, conn->sec_inst, &len);
            if (len < 0) {
#ifdef WITH_LOGS
                fprintf(stderr, "Failed to get server certificate\n");
#endif
                goto error;
            }

            server_cert = d2i_X509(NULL, (const unsigned char **)&cert, len);
            if (!server_cert) {
#ifdef WITH_LOGS
                fprintf(stderr, "Failed to parse server certificate\n");
#endif
                goto error;
            }
        }

#if (OPENSSL_VERSION_NUMBER >= 0x10100005L)
        BIO_ctrl_set_connected (sbio, &peer);
#else
        BIO_ctrl_set_connected (sbio, 0, &peer);
#endif

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);
        SSL_set_bio (ssl, sbio, sbio);
        SSL_set_connect_state (ssl);

        conn->ssl = ssl;
        conn->ssl_ctx = ctx;

        do {
            ret = SSL_do_handshake(ssl);
            if (ret < 1)
            {
                switch (SSL_get_error(ssl, ret))
                {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    break;
                default:
#ifdef WITH_LOGS
                    fprintf(stderr, "%s: SSL error: %s\n", __func__,
                            ERR_error_string(SSL_get_error(ssl, ret), NULL));
#endif
                    goto error;
                }

                usleep(100*1000);
                if (handshake_timeout-- <= 0) {
#ifdef WITH_LOGS
                    fprintf(stderr, "%s: SSL handshake timed out\n", __func__);
#endif
                    goto error;
                }
            }
        } while(ret != 1);

        oldflags &= O_NONBLOCK;
        fcntl(conn->sock, F_SETFL, oldflags);

        if (securityMode == 2) { /* Certificate mode */
            peer_cert = SSL_get_peer_certificate(ssl);
            if (X509_cmp(peer_cert, server_cert)) {
#ifdef WITH_LOGS
                fprintf(stderr, "%s: server.serverCertificate does not match peer certificate.\n", __func__);
#endif
                X509_free(server_cert);
                goto error;
            }
            X509_free(server_cert);
        }
    }
    else
    {
        sbio = BIO_new_socket(conn->sock, BIO_NOCLOSE);
        if (!sbio)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "%s: failed to create socket BIO\n", __func__);
#endif
            goto error;
        }

        SSL_set_bio (ssl, sbio, sbio);
        ret = SSL_connect(ssl);
        if (ret < 1)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "%s: SSL handshake failed\n", __func__);
#endif
            ERR_print_errors_fp(stderr);
            goto error;
        }

        conn->ssl = ssl;
        conn->ssl_ctx = ctx;
    }

    return true;

error:
    if (ssl)
        SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);

    return false;
}

static char *security_get_public_id(lwm2m_object_t * obj, int instanceId, int * length)
{
    int size = 1;
    lwm2m_data_t * dataP = lwm2m_data_new(size);
    dataP->id = 3; // public key or id

    obj->readFunc(instanceId, &size, &dataP, obj);
    if (dataP != NULL &&
            dataP->type == LWM2M_TYPE_OPAQUE)
    {
        char *val = (char*)dataP->value.asBuffer.buffer;
        *length = dataP->value.asBuffer.length;
        lwm2m_free(dataP);
        return val;
    }
    else
    {
        lwm2m_free(dataP);
        return NULL;
    }
}

static char *security_get_secret_key(lwm2m_object_t * obj, int instanceId, int * length)
{
    int size = 1;
    lwm2m_data_t * dataP = lwm2m_data_new(size);
    dataP->id = 5; // secret key

    obj->readFunc(instanceId, &size, &dataP, obj);
    if (dataP != NULL &&
            dataP->type == LWM2M_TYPE_OPAQUE)
    {
        char *val = (char*)dataP->value.asBuffer.buffer;
        *length = dataP->value.asBuffer.length;
        lwm2m_free(dataP);
        return val;
    }
    else
    {
        lwm2m_free(dataP);
        return NULL;
    }
}

int connection_restart(connection_t *conn)
{
    int sock;
    connection_t *newConn = NULL;

    conn->connected = false;

    /* Close previous connection */
    close(conn->sock);

    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }

    /* Increase port in case of TCP connections to avoid TIME_WAIT issue */
    if ((conn->protocol == COAP_TCP) || (conn->protocol == COAP_TCP_TLS))
    {
        char portStr[16];
        snprintf(portStr, 16, "%d", atoi(conn->local_port) + 1);
        strncpy(conn->local_port, portStr, 16);
    }

    sock = create_socket(conn->protocol, conn->local_port, conn->address_family);
    if (sock <= 0)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to create new socket\n");
#endif
        return -1;
    }

    newConn = connection_create(conn->protocol,
                                conn->root_ca,
                                conn->verify_cert,
                                conn->use_se,
                                sock,
                                conn->host,
                                conn->local_port,
                                conn->remote_port,
                                conn->address_family,
                                conn->sec_obj,
                                conn->sec_inst,
                                conn->timeout);

    if (!newConn)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to create new connection\n");
#endif
        close(sock);
        return -1;
    }

    if (conn->protocol == COAP_UDP_DTLS)
    {
        lwm2m_dtls_info_t *dtls = dtlsinfo_list;

        /* Delete old connection's DTLS info */
        while (dtls != NULL)
        {
            if (conn == dtls->connection)
            {
                lwm2m_dtls_info_t *node;
                dtlsinfo_list = (lwm2m_dtls_info_t *)LWM2M_LIST_RM(dtlsinfo_list, dtls->id, &node);
                free(node);
                break;
            }
            dtls = dtls->next;
        }

        /* Replace connection pointer in new DTLS info */
        dtls = dtlsinfo_list;
        while (dtls != NULL)
        {
            if (newConn == dtls->connection)
            {
                dtls->connection = newConn;
                break;
            }
            dtls = dtls->next;
        }
    }

    /*
     * Copy new connection on top of the old one to keep same pointer,
     * then dispose of the newly allocated memory
     */
    free(conn->host);
    memcpy(conn, newConn, sizeof(connection_t));
    free(newConn);

    return 0;
}

int create_socket(coap_protocol_t protocol, const char * portStr, int addressFamily)
{
    int s = -1;
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = addressFamily;
    switch(protocol)
    {
    case COAP_TCP:
    case COAP_TCP_TLS:
        hints.ai_socktype = SOCK_STREAM;
        break;
    case COAP_UDP:
    case COAP_UDP_DTLS:
        hints.ai_socktype = SOCK_DGRAM;
        break;
    default:
        break;
    }

    hints.ai_flags = AI_PASSIVE;

    if (0 != getaddrinfo(NULL, portStr, &hints, &res))
    {
        return -1;
    }

    for(p = res ; p != NULL && s == -1 ; p = p->ai_next)
    {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s >= 0)
        {
            if (-1 == bind(s, p->ai_addr, p->ai_addrlen))
            {
                close(s);
                s = -1;
            }
        }
    }

    freeaddrinfo(res);

    return s;
}

connection_t * connection_find(connection_t * connList,
                               struct sockaddr_storage * addr,
                               size_t addrLen)
{
    connection_t * connP;

    connP = connList;
    while (connP != NULL)
    {
        if ((connP->addrLen == addrLen)
         && (memcmp(&(connP->addr), addr, addrLen) == 0))
        {
            return connP;
        }
        connP = connP->next;
    }

    return connP;
}

connection_t * connection_create(coap_protocol_t protocol,
                                 char *root_ca,
                                 bool verify_cert,
                                 bool use_se,
                                 int sock,
                                 char *host,
                                 char *local_port,
                                 char *remote_port,
                                 int addressFamily,
                                 lwm2m_object_t * sec_obj,
                                 int sec_inst,
                                 int timeout)
{
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    struct addrinfo *p;
    int s, ret;
    struct sockaddr *sa;
    socklen_t sl;
    connection_t * connP = NULL;
    long arg = 0;
    int flags = 0;
    fd_set rset, wset;
    struct timeval  ts;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = addressFamily;

    switch(protocol)
    {
    case COAP_TCP:
    case COAP_TCP_TLS:
        hints.ai_socktype = SOCK_STREAM;
        break;
    case COAP_UDP:
    case COAP_UDP_DTLS:
        hints.ai_socktype = SOCK_DGRAM;
        break;
    default:
        break;
    }

    if (0 != getaddrinfo(host, remote_port, &hints, &servinfo) || servinfo == NULL)
    {
        return NULL;
    }

    // we test the various addresses
    s = -1;
    for(p = servinfo ; p != NULL && s == -1 ; p = p->ai_next)
    {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s >= 0)
        {
            sa = p->ai_addr;
            sl = p->ai_addrlen;

            /* We go non-blocking mode to set timeout on connect */
            flags = fcntl(s, F_GETFL, 0);
            fcntl(s, F_SETFL, flags | O_NONBLOCK);

#ifdef WITH_LOGS
            fprintf(stderr, "Try to connect to server with timeout %d ms\n", timeout);
#endif
            ret = connect(s, p->ai_addr, p->ai_addrlen);
            if (ret < 0)
            {
                if (errno != EINPROGRESS)
                {
#ifdef WITH_LOGS
                    fprintf(stderr, "Connect to socket failed (err=%d)\n", errno);
#endif
                    goto fail;
                }

                FD_ZERO(&rset);
                FD_ZERO(&wset);
                FD_SET(s, &rset);
                FD_SET(s, &wset);
                ts.tv_sec = timeout / 1000;
                ts.tv_usec = (timeout - (ts.tv_sec * 1000)) * 1000;
                ret = select(s + 1, &rset, &wset, NULL, (timeout) ? &ts : NULL);
                if (ret <= 0)
                {
#ifdef WITH_LOGS
                    fprintf(stderr, "Waiting for socket failed (err=%d)\n", ret);
#endif
                    goto fail;
                }

                if (!FD_ISSET(s, &rset) && !FD_ISSET(s, &wset))
                {
#ifdef WITH_LOGS
                    fprintf(stderr, "No fd was set\n");
#endif
                    goto fail;
                }
            }

            continue;
fail:
            close(s);
            s = -1;
        }
    }

    if (s >= 0)
    {
        if (protocol != COAP_UDP)
        {
            if (connect(sock, sa, sl) < 0)
            {
#ifdef WITH_LOGS
                fprintf(stderr, "Failed to connect to socket: %s\n", strerror(errno));
#endif
                close(sock);
                return NULL;
            }
        }

        /* Allocate and fill up connection structure */
        connP = (connection_t *)malloc(sizeof(connection_t));
        if (connP == NULL)
        {
#ifdef WITH_LOGS
            fprintf(stderr, "Failed to allocate memory for connection\n");
#endif
            return NULL;
        }

        memset(connP, 0, sizeof(connection_t));
        connP->sock = sock;
        connP->protocol = protocol;
        connP->verify_cert = verify_cert;

        if (root_ca)
            connP->root_ca = strdup(root_ca);

        memcpy(&(connP->addr), sa, sl);
        connP->host = strndup(host, strlen(host));
        connP->addrLen = sl;
        strncpy(connP->local_port, local_port, 16);
        strncpy(connP->remote_port, remote_port, 16);
        connP->address_family = addressFamily;
        connP->sec_obj = sec_obj;
        connP->sec_inst = sec_inst;
        connP->use_se = use_se;
        connP->timeout = timeout;

        if ((protocol == COAP_TCP_TLS) ||
            (protocol == COAP_UDP_DTLS))
        {
            if (!ssl_init(connP))
            {
#ifdef WITH_LOGS
                fprintf(stderr, "Failed to initialize SSL session\n");
#endif
                goto error;
            }
        }
        close(s);
    }
    else
    {
#ifdef WITH_LOGS
        fprintf(stderr, "Failed to find responsive server\n");
#endif
        goto error;
    }

    if (NULL != servinfo)
        free(servinfo);

    connP->connected = true;

    return connP;

error:
    if (NULL != servinfo)
        free(servinfo);

    if (connP)
    {
        free(connP->host);
        free(connP);
        connP = NULL;
    }

    return NULL;
}

void connection_free(connection_t * connList)
{
    while (connList != NULL)
    {
        connection_t * nextP;
        lwm2m_dtls_info_t *dtls = dtlsinfo_list;

        // Free DTLS info if any
        while (dtls != NULL)
        {
            if (connList == dtls->connection)
            {
                lwm2m_dtls_info_t *node;
                dtlsinfo_list = (lwm2m_dtls_info_t *)LWM2M_LIST_RM(dtlsinfo_list, dtls->id, &node);
                free(node);
                break;
            }

            dtls = dtls->next;
        }

        nextP = connList->next;
        if (connList->host)
            free(connList->host);
        if (connList->root_ca)
            free(connList->root_ca);
        if (connList->ssl)
            SSL_free(connList->ssl);
        if (connList->ssl_ctx)
            SSL_CTX_free(connList->ssl_ctx);
        free(connList);

        connList = nextP;
    }
}

int connection_send(connection_t *connP,
                    uint8_t * buffer,
                    size_t length)
{
    int nbSent;
    size_t offset;

    if (!connP->connected)
        return -1;

#ifdef WITH_LOGS
    char s[INET6_ADDRSTRLEN];
    in_port_t port;

    s[0] = 0;

    if (AF_INET == connP->addr.sin6_family)
    {
        struct sockaddr_in *saddr = (struct sockaddr_in *)&connP->addr;
        inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin_port;
    }
    else if (AF_INET6 == connP->addr.sin6_family)
    {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&connP->addr;
        inet_ntop(saddr->sin6_family, &saddr->sin6_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin6_port;
    }

    fprintf(stdout, "Sending %lu bytes to [%s]:%hu\r\n", length, s, ntohs(port));

    output_buffer(stderr, buffer, length, 0);
#endif

    offset = 0;
    while (offset != length)
    {
        switch(connP->protocol)
        {
        case COAP_UDP_DTLS:
        case COAP_TCP_TLS:
            nbSent = SSL_write(connP->ssl, buffer + offset, length - offset);
            if (nbSent < 1) {
#ifdef WITH_LOGS
                fprintf(stderr, "SSL Send error: %s\n", ERR_error_string(SSL_get_error(connP->ssl, nbSent), NULL));
#endif
                return -1;
            }
            break;
        case COAP_TCP:
            nbSent = send(connP->sock, buffer + offset, length - offset, 0);
            if (nbSent == -1) {
#ifdef WITH_LOGS
                fprintf(stderr, "Send error: %s\n", strerror(errno));
#endif
                return -1;
            }
            break;
        case COAP_UDP:
            nbSent = sendto(connP->sock, buffer + offset, length - offset, 0, (struct sockaddr *)&(connP->addr), connP->addrLen);
            if (nbSent == -1) {
#ifdef WITH_LOGS
                fprintf(stderr, "Send error: %s\n", strerror(errno));
#endif
                return -1;
            }
            break;
        default:
            break;
        }

        offset += nbSent;
    }
    return 0;
}

uint8_t lwm2m_buffer_send(void * sessionH,
                          uint8_t * buffer,
                          size_t length,
                          void * userdata)
{
    connection_t * connP = (connection_t*) sessionH;

    if (connP == NULL)
    {
#ifdef WITH_LOGS
        fprintf(stderr, "#> failed sending %lu bytes, missing connection\r\n", length);
#endif
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    if (-1 == connection_send(connP, buffer, length))
    {
#ifdef WITH_LOGS
        fprintf(stderr, "#> failed sending %lu bytes, try reconnecting\r\n", length);
#endif
        connP->connected = false;
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void * session1,
                            void * session2,
                            void * userData)
{
    return (session1 == session2);
}

int connection_read(connection_t *connP, uint8_t * buffer, size_t size) {
    int numBytes;

    switch(connP->protocol)
    {
        case COAP_UDP:
            numBytes = recvfrom(connP->sock, buffer, size, 0, NULL, NULL);
            if (numBytes < 0)
            {
#ifdef WITH_LOGS
                fprintf(stderr, "Error in recvfrom(): %d %s\r\n", errno, strerror(errno));
#endif
                return 0;
            }
            break;
        case COAP_TCP:
            numBytes = recv(connP->sock, buffer, size, 0);
            if (numBytes < 0)
            {
#ifdef WITH_LOGS
                fprintf(stderr, "Error in recv(): %d %s\r\n", errno, strerror(errno));
#endif
                return 0;
            }
            break;
        case COAP_UDP_DTLS:
        case COAP_TCP_TLS:
            numBytes = SSL_read(connP->ssl, buffer, size);
            if (numBytes < 1)
            {
                return 0;
            }
            break;
        default:
#ifdef WITH_LOGS
            fprintf(stderr, "Error protocol = %d is not supported.\r\n", connP->protocol);
#endif
            return 0;
    }

    return numBytes;
}
