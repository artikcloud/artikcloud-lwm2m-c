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
 *    Gregory Lemercier, Samsung - Please refer to git log
 *    David Navarro, Intel Corporation - initial API and implementation
 *    Benjamin Cabé - Please refer to git log
 *    Fabien Fleutot - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Julien Vermillard - Please refer to git log
 *    Axel Lorente - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
 *    Pascal Rieux - Please refer to git log
 *    Christian Renz - Please refer to git log
 *    Ricky Liu - Please refer to git log
 *
 *******************************************************************************/

/*
 Copyright (c) 2013, 2014 Intel Corporation

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 THE POSSIBILITY OF SUCH DAMAGE.

 David Navarro <david.navarro@intel.com>
 Bosch Software Innovations GmbH - Please refer to git log

*/

#include "lwm2mclient.h"
#include "liblwm2m.h"
#include "commandline.h"
#include "connection.h"
#include "internals.h"
#include "er-coap-13/er-coap-13.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>

#define CLIENT_PORT_RANGE_START    64900
#define CLIENT_PORT_RANGE_END      64999

#define MAX_PACKET_SIZE            1024

typedef struct {
    coap_protocol_t proto;
    char            uri_prefix[16];
    char            friendly_name[16];
} coap_uri_protocol;

typedef struct
{
    lwm2m_object_t * securityObjP;
    lwm2m_object_t * serverObject;
    int sock;
    connection_t * connList;
    lwm2m_context_t * lwm2mH;
    struct sockaddr_storage server_addr;
    size_t server_addrlen;
    SSL *ssl;
    int addressFamily;
    lwm2m_object_t * objArray[LWM2M_OBJ_COUNT];
    coap_protocol_t proto;
    pthread_t rx_thread;
    bool rx_thread_exit;
} client_data_t;

static coap_uri_protocol protocols[] = {
    { COAP_UDP, "coap://", "UDP" },
    { COAP_UDP_DTLS, "coaps://", "UDP/DTLS" },
    { COAP_TCP, "coap+tcp://", "TCP" },
    { COAP_TCP_TLS, "coaps+tcp://", "TCP/TLS" }
};

extern lwm2m_object_t *get_server_object(int serverId, const char *binding, int lifetime, bool storing);
extern lwm2m_object_t *get_security_object(int serverId, const char *serverUri, char *bsPskId, char *psk, uint16_t pskLen,
        bool isBootstrap);
extern lwm2m_object_t *get_object_device(object_device_t *default_value);
extern lwm2m_object_t *get_object_firmware(object_firmware_t *default_value);
extern lwm2m_object_t *get_object_location(object_location_t *default_value);
extern lwm2m_object_t *get_object_conn_m(object_conn_monitoring_t *default_value);
extern lwm2m_object_t *get_object_conn_s(void);
extern void clean_security_object(lwm2m_object_t *object);
extern void clean_server_object(lwm2m_object_t *object);
extern void free_object_device(lwm2m_object_t *object);
extern void free_object_firmware(lwm2m_object_t *object);
extern void free_object_location(lwm2m_object_t *object);
extern void free_object_conn_s(lwm2m_object_t *object);
extern void free_object_conn_m(lwm2m_object_t *object);
extern void acl_ctrl_free_object(lwm2m_object_t *object);
extern char *get_server_uri(lwm2m_object_t *object, uint16_t secObjInstID);
extern lwm2m_object_t *acc_ctrl_create_object(void);
extern bool acc_ctrl_obj_add_inst(lwm2m_object_t *accCtrlObjP, uint16_t instId, uint16_t acObjectId, uint16_t acObjInstId,
        uint16_t acOwner);
extern bool acc_ctrl_oi_add_ac_val(lwm2m_object_t *accCtrlObjP, uint16_t instId, uint16_t aclResId, uint16_t acValue);
extern void conn_s_updateRxStatistic(lwm2m_object_t * objectP, uint16_t rxDataByte, bool smsBased);
extern void prv_firmware_register_callback(lwm2m_object_t * objectP, enum lwm2m_execute_callback_type type,
        lwm2m_exe_callback callback, void *param);
extern void prv_device_register_callback(lwm2m_object_t * objectP, enum lwm2m_execute_callback_type type,
        lwm2m_exe_callback callback, void *param);
extern uint8_t device_change_object(lwm2m_data_t * dataArray, lwm2m_object_t *object);
extern uint8_t firmware_change_object(lwm2m_data_t *dataArray, lwm2m_object_t *object);
extern uint8_t location_change_object(lwm2m_data_t *dataArray, lwm2m_object_t *object);
extern uint8_t connectivity_moni_change(lwm2m_data_t *dataArray, lwm2m_object_t *object);

void * lwm2m_connect_server(uint16_t secObjInstID, void * userData)
{
    client_data_t * dataP = NULL;
    char * uri = NULL;
    char * host = NULL;
    char * port = NULL;
    void * newConnP = NULL;
    lwm2m_list_t * instance = NULL;
    int i = 0;
    coap_protocol_t protocol = -1;
    lwm2m_object_t  *securityObj = NULL;

    dataP = (client_data_t *)userData;
    securityObj = dataP->securityObjP;

    uri = get_server_uri(dataP->securityObjP, secObjInstID);

    if (uri == NULL) return NULL;

    // parse uri in the form "coaps://[host]:[port]"
    for (i=0; i<sizeof(protocols)/sizeof(coap_uri_protocol); i++)
    {
        if (0 == strncmp(uri, protocols[i].uri_prefix, strlen(protocols[i].uri_prefix)))
        {
            host = uri + strlen(protocols[i].uri_prefix);
            protocol = protocols[i].proto;
            break;
        }
    }

    port = strrchr(host, ':');
    if (port == NULL) goto exit;
    // remove brackets
    if (host[0] == '[')
    {
        host++;
        if (*(port - 1) == ']')
        {
            *(port - 1) = 0;
        }
        else goto exit;
    }
    // split strings
    *port = 0;
    port++;

#ifdef WITH_LOGS
    fprintf(stdout, "\r\nOpening connection to server at %s:%s\r\n", host, port);
#endif

    // If secure connection, make sure we have a security object
    instance = LWM2M_LIST_FIND(dataP->securityObjP->instanceList, secObjInstID);
    if (instance == NULL) goto exit;

    connection_t *conn = connection_create((connection_t *)dataP->connList, protocol, dataP->sock, host, port,
                            dataP->addressFamily, securityObj, instance->id);
    if (!conn)
    {
        fprintf(stderr, "Connection creation failed.\r\n");
        goto exit;
    }

    memcpy(&dataP->server_addr, &conn->addr, conn->addrLen);
    dataP->server_addrlen = conn->addrLen;
    dataP->ssl = conn->ssl;
    newConnP = (void*)conn;

    dataP->connList = (void*)newConnP;

exit:
    lwm2m_free(uri);
    return (void *)newConnP;
}

void lwm2m_close_connection(void * sessionH,
                            void * userData)
{
    client_data_t *app_data = (client_data_t *)userData;
    connection_t *targetP = (connection_t *)sessionH;

    if (targetP == app_data->connList)
    {
        app_data->connList = targetP->next;
        lwm2m_free(targetP);
    }
    else
    {
        connection_t *parentP = app_data->connList;
        while ((parentP != NULL) && (parentP->next != targetP))
        {
            parentP = parentP->next;
        }
        if (parentP != NULL)
        {
            parentP->next = targetP->next;
            lwm2m_free(targetP);
        }
    }
}

static void *rx_thread_func(void *param)
{
    client_data_t *data = (client_data_t *)param;
    struct pollfd pfd;
    int ret = 0;
    int numBytes;
    uint8_t buffer[MAX_PACKET_SIZE];
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);

    pfd.fd = data->sock;
    pfd.events = POLLIN;

    while(true)
    {
        ret = poll(&pfd, 1, 250);
        if (ret < 0)
        {
            fprintf(stderr, "Error in select(): %d %s\r\n", errno, strerror(errno));
            continue;
        }

        if (data->rx_thread_exit)
        {
            /* Exiting */
            break;
        }

        if (!ret)
        {
            /* time out */
            continue;
        }

        /* Handling incoming data */
        switch(data->proto)
        {
        case COAP_UDP:
             numBytes = recvfrom(data->sock, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrLen);
             if (numBytes < 0)
             {
                 fprintf(stderr, "Error in recvfrom(): %d %s\r\n", errno, strerror(errno));
                 continue;
             }
             break;
        case COAP_TCP:
             numBytes = recv(data->sock, buffer, MAX_PACKET_SIZE, 0);
             if (numBytes < 0)
             {
                 fprintf(stderr, "Error in recv(): %d %s\r\n", errno, strerror(errno));
                 continue;
             }
             break;
        case COAP_UDP_DTLS:
        case COAP_TCP_TLS:
            numBytes = SSL_read(data->ssl, buffer, MAX_PACKET_SIZE);
            if (numBytes < 1)
            {
                fprintf(stderr, "SSL Read error: %s\n", ERR_error_string(SSL_get_error(data->ssl, numBytes), NULL));
                continue;
            }
            break;
        default:
            break;
        }

        memcpy(&addr, &data->server_addr, data->server_addrlen);
        addrLen = data->server_addrlen;

        if (numBytes > 0)
        {
             char s[INET6_ADDRSTRLEN];
             in_port_t port;

            if (AF_INET == addr.ss_family)
            {
                 struct sockaddr_in *saddr = (struct sockaddr_in *)&addr;
                 inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET6_ADDRSTRLEN);
                 port = saddr->sin_port;
            }
            else if (AF_INET6 == addr.ss_family)
            {
                struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&addr;
                inet_ntop(saddr->sin6_family, &saddr->sin6_addr, s, INET6_ADDRSTRLEN);
                port = saddr->sin6_port;
            }
#ifdef WITH_LOGS
            fprintf(stdout, "%d bytes received from [%s]:%hu\r\n", numBytes, s, ntohs(port));
            output_buffer(stdout, buffer, numBytes, 0);
#endif

            connection_t *conn = connection_find((connection_t *)data->connList, &addr, addrLen);
            if (conn)
            {
                lwm2m_handle_packet(data->lwm2mH, data->proto, buffer, numBytes, conn);
                conn_s_updateRxStatistic(data->objArray[LWM2M_OBJ_CONN_STAT], numBytes, false);
            }
        }
        else
        {
            fprintf(stderr, "server has closed the connection\r\n");
            break;
        }
    }

    return NULL;
}

client_handle_t lwm2m_client_start(object_container_t *init_val)
{
    int result;
    int i;
    int opt;
    bool bootstrapRequested = false;
    coap_protocol_t protocol = -1;
    char local_port[16];
    client_data_t* data;
    lwm2m_context_t *ctx = NULL;
    uint16_t pskLen = -1;
    char * pskBuffer = NULL;
    char * psk = init_val->server->psk;
    char * uri = init_val->server->serverUri;
    int serverId = init_val->server->serverId;

    data = malloc(sizeof(client_data_t));
    if (!data) {
        fprintf(stderr, "Failed to allocate memory for client data\r\n");
        return NULL;
    }

    memset(data, 0, sizeof(client_data_t));

    /* Figure out protocol from the URI prefix */
    for (i=0; i<sizeof(protocols)/sizeof(coap_uri_protocol); i++)
    {
        if (0 == strncmp(uri, protocols[i].uri_prefix, strlen(protocols[i].uri_prefix)))
        {
            fprintf(stdout, "Connecting to server over %s\r\n", protocols[i].friendly_name);
            protocol = protocols[i].proto;
            break;
        }
    }

    if (protocol == (coap_protocol_t)-1)
    {
        fprintf(stderr, "Unknown protocol, should be one of: ");
        for (i=0; i<sizeof(protocols)/sizeof(coap_uri_protocol); i++)
        {
            fprintf(stderr, "%s, ", protocols[i].uri_prefix);
        }
        fprintf(stderr, "\r\n");
        return NULL;
    }

    data->proto = protocol;

    /* Default to IPV4, should add parameter to allow IPV6 */
    data->addressFamily = AF_INET;

    /*
     * Randomize local port based on predefined range
     * Depending on the range it should be enough to avoid reusing
     * twice the same port across the TIME_WAIT period after
     * closing the socket
     */
    snprintf(local_port, 16, "%d", (rand() % (CLIENT_PORT_RANGE_END - CLIENT_PORT_RANGE_START)) + CLIENT_PORT_RANGE_START);

    fprintf(stdout, "Trying to bind LWM2M Client to port %s\r\n", local_port);

    data->sock = create_socket(data->proto, local_port, data->addressFamily);
    if (data->sock < 0)
    {
        fprintf(stderr, "Failed to open socket: %d %s\r\n", errno, strerror(errno));
        return NULL;
    }

    /*
     * Now the main function fill an array with each object, this list will be later passed to liblwm2m.
     * Those functions are located in their respective object file.
     */
    if (psk != NULL)
    {
        pskLen = strlen(psk) / 2;
        pskBuffer = malloc(pskLen);

        if (NULL == pskBuffer)
        {
            fprintf(stderr, "Failed to create PSK binary buffer\r\n");
            return NULL;
        }
        // Hex string to binary
        char *h = psk;
        char *b = pskBuffer;
        char xlate[] = "0123456789ABCDEF";

        for ( ; *h; h += 2, ++b)
        {
            char *l = strchr(xlate, toupper(*h));
            char *r = strchr(xlate, toupper(*(h+1)));

            if (!r || !l)
            {
                fprintf(stderr, "Failed to parse Pre-Shared-Key HEXSTRING\r\n");
                return NULL;
            }

            *b = ((l - xlate) << 4) + (r - xlate);
        }
    }

    fprintf(stdout, " Server Uri =  %s\n", uri);

    data->objArray[LWM2M_OBJ_SECURITY] = get_security_object(serverId, uri, init_val->server->bsPskId, pskBuffer, pskLen, false);
    if (NULL == data->objArray[LWM2M_OBJ_SECURITY])
    {
        fprintf(stderr, "Failed to create security object\r\n");
        return NULL;
    }
    data->securityObjP = data->objArray[LWM2M_OBJ_SECURITY];

    switch(data->proto)
    {
    case COAP_UDP:
    case COAP_UDP_DTLS:
        data->objArray[LWM2M_OBJ_SERVER] = get_server_object(serverId, "U", init_val->server->lifetime, false);
        strncpy(init_val->device->binding_mode, "U", LWM2M_MAX_STR_LEN);
        break;
    case COAP_TCP:
        data->objArray[LWM2M_OBJ_SERVER] = get_server_object(serverId, "C", init_val->server->lifetime, false);
        strncpy(init_val->device->binding_mode, "C", LWM2M_MAX_STR_LEN);
        break;
    case COAP_TCP_TLS:
        data->objArray[LWM2M_OBJ_SERVER] = get_server_object(serverId, "T", init_val->server->lifetime, false);
        strncpy(init_val->device->binding_mode, "T", LWM2M_MAX_STR_LEN);
        break;
    default:
        break;
    }

    if (NULL == data->objArray[LWM2M_OBJ_SERVER])
    {
        fprintf(stderr, "Failed to create server object\r\n");
        return NULL;
    }

    data->objArray[LWM2M_OBJ_DEVICE] = get_object_device(init_val->device);
    if (NULL == data->objArray[LWM2M_OBJ_DEVICE])
    {
        fprintf(stderr, "Failed to create Device object\r\n");
        return NULL;
    }

    data->objArray[LWM2M_OBJ_FIRMWARE] = get_object_firmware(init_val->firmware);
    if (NULL == data->objArray[LWM2M_OBJ_FIRMWARE])
    {
        fprintf(stderr, "Failed to create Firmware object\r\n");
        return NULL;
    }

    data->objArray[LWM2M_OBJ_LOCATION] = get_object_location(init_val->location);
    if (NULL == data->objArray[LWM2M_OBJ_LOCATION])
    {
        fprintf(stderr, "Failed to create location object\r\n");
        return NULL;
    }

    data->objArray[LWM2M_OBJ_CONN_MON] = get_object_conn_m(init_val->monitoring);
    if (NULL == data->objArray[LWM2M_OBJ_CONN_MON])
    {
        fprintf(stderr, "Failed to create connectivity monitoring object\r\n");
        return NULL;
    }

    data->objArray[LWM2M_OBJ_CONN_STAT] = get_object_conn_s();
    if (NULL == data->objArray[LWM2M_OBJ_CONN_STAT])
    {
        fprintf(stderr, "Failed to create connectivity statistics object\r\n");
        return NULL;
    }

    int instId = 0;
    data->objArray[LWM2M_OBJ_ACL] = acc_ctrl_create_object();
    if (NULL == data->objArray[LWM2M_OBJ_ACL])
    {
        fprintf(stderr, "Failed to create Access Control object\r\n");
        return NULL;
    }
    else if (acc_ctrl_obj_add_inst(data->objArray[LWM2M_OBJ_ACL], instId, 3, 0, serverId)==false)
    {
        fprintf(stderr, "Failed to create Access Control object instance\r\n");
        return NULL;
    }
    else if (acc_ctrl_oi_add_ac_val(data->objArray[LWM2M_OBJ_ACL], instId, 0, 0b000000000001111)==false)
    {
        fprintf(stderr, "Failed to create Access Control ACL default resource\r\n");
        return NULL;
    }
    else if (acc_ctrl_oi_add_ac_val(data->objArray[LWM2M_OBJ_ACL], instId, 999, 0b000000000000001)==false)
    {
        fprintf(stderr, "Failed to create Access Control ACL resource for serverId: 999\r\n");
        return NULL;
    }

    /*
     * The liblwm2m library is now initialized with the functions that will be in
     * charge of communication
     */
    ctx = lwm2m_init(data);
    if (!ctx)
    {
        fprintf(stderr, "lwm2m_init() failed\r\n");
        return NULL;
    }

    data->lwm2mH = ctx;

    /*
     * We configure the liblwm2m library with the name of the client - which shall be unique for each client -
     * the number of objects we will be passing through and the objects array
     */
    result = lwm2m_configure(data->lwm2mH, init_val->server->client_name, NULL, NULL, LWM2M_OBJ_COUNT, data->objArray);
    if (result != 0)
    {
        fprintf(stderr, "lwm2m_configure() failed: 0x%X\r\n", result);
        return NULL;
    }

    /* Service once to initialize the first steps */
    lwm2m_client_service(data);

    /* Start rx thread */
    data->rx_thread_exit = false;
    if (pthread_create(&data->rx_thread, NULL, rx_thread_func, (void *)data))
    {
        fprintf(stderr, "Failed to create rx thread\r\n");
        return NULL;
    }

    return (client_handle_t)data;
}

void lwm2m_client_stop(client_handle_t handle)
{
    client_data_t *data =  (client_data_t *)handle;

    /* gracefully exit RX thread */
    data->rx_thread_exit = true;
    pthread_join(data->rx_thread, NULL);

    if (data) {
        if (data->lwm2mH)
            lwm2m_close(data->lwm2mH);
        close(data->sock);
        connection_free(data->connList);
        clean_security_object(data->objArray[LWM2M_OBJ_SECURITY]);
        lwm2m_free(data->objArray[LWM2M_OBJ_SECURITY]);
        clean_server_object(data->objArray[LWM2M_OBJ_SERVER]);
        lwm2m_free(data->objArray[LWM2M_OBJ_SERVER]);
        free_object_device(data->objArray[LWM2M_OBJ_DEVICE]);
        free_object_firmware(data->objArray[LWM2M_OBJ_FIRMWARE]);
        free_object_location(data->objArray[LWM2M_OBJ_LOCATION]);
        free_object_conn_m(data->objArray[LWM2M_OBJ_CONN_MON]);
        free_object_conn_s(data->objArray[LWM2M_OBJ_CONN_STAT]);
        acl_ctrl_free_object(data->objArray[LWM2M_OBJ_ACL]);
        free(data);
    }
}

int lwm2m_client_service(client_handle_t handle)
{
    client_data_t *data =  (client_data_t *)handle;
    int result;
    int numBytes;
    uint8_t buffer[MAX_PACKET_SIZE];
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);
    time_t timeout = 60;
    time_t reboot_time = 0;

    result = lwm2m_step(data->lwm2mH, &timeout);
    if (result != 0)
    {
        fprintf(stderr, "lwm2m_step() failed: 0x%X\r\n", result);
        return LWM2M_CLIENT_ERROR;
    }

    return timeout;
}

void lwm2m_register_callback(client_handle_t handle, enum lwm2m_execute_callback_type type,
        lwm2m_exe_callback callback, void *param)
{
    client_data_t *data =  (client_data_t *)handle;

    if (!handle || !callback || (type >= LWM2M_EXE_COUNT))
    {
        fprintf(stderr, "lwm2m_register_callback: wrong parameters\r\n");
        return;
    }

    switch(type)
    {
    case LWM2M_EXE_FIRMWARE_UPDATE:
        prv_firmware_register_callback(data->objArray[LWM2M_OBJ_FIRMWARE], type,
                callback, param);
        break;
    case LWM2M_EXE_FACTORY_RESET:
    case LWM2M_EXE_DEVICE_REBOOT:
        prv_device_register_callback(data->objArray[LWM2M_OBJ_DEVICE], type,
                callback, param);
        break;
    case LWM2M_NOTIFY_RESOURCE_CHANGED:
        prv_device_register_callback(data->objArray[LWM2M_OBJ_DEVICE], type,
                callback, param);
        prv_firmware_register_callback(data->objArray[LWM2M_OBJ_FIRMWARE], type,
                callback, param);
        break;
    default:
        fprintf(stderr, "lwm2m_register_callback: unsupported callback\r\n");
        break;
    }
}

void lwm2m_unregister_callback(client_handle_t handle, enum lwm2m_execute_callback_type type)
{
    client_data_t *data =  (client_data_t *)handle;

    if (!handle || (type >= LWM2M_EXE_COUNT))
    {
        fprintf(stderr, "lwm2m_unregister_callback: wrong parameters\r\n");
        return;
    }

    switch(type)
    {
    case LWM2M_EXE_FIRMWARE_UPDATE:
        prv_firmware_register_callback(data->objArray[LWM2M_OBJ_FIRMWARE], type, NULL, NULL);
        break;
    case LWM2M_EXE_FACTORY_RESET:
    case LWM2M_EXE_DEVICE_REBOOT:
        prv_device_register_callback(data->objArray[LWM2M_OBJ_DEVICE], type, NULL, NULL);
        break;
    case LWM2M_NOTIFY_RESOURCE_CHANGED:
        prv_device_register_callback(data->objArray[LWM2M_OBJ_DEVICE], type, NULL, NULL);
        prv_firmware_register_callback(data->objArray[LWM2M_OBJ_FIRMWARE], type, NULL, NULL);
        break;
    default:
        fprintf(stderr, "lwm2m_register_callback: unsupported callback\r\n");
        break;
    }
}

int lwm2m_write_resource(client_handle_t handle, lwm2m_resource_t *res)
{
    int ret;
    client_data_t *client =  (client_data_t *)handle;
    lwm2m_uri_t uri_t;

    if (!res)
    {
        fprintf(stderr, "lwm2m_write_resource: wrong parameters\r\n");
        return LWM2M_CLIENT_ERROR;
    }

    ret = lwm2m_stringToUri(res->uri, strlen(res->uri), &uri_t);
    if (ret == 0)
    {
        fprintf(stderr, "lwm2m_stringToUri() failed: 0x%X", ret);
        return LWM2M_CLIENT_ERROR;
    }

    if (res->buffer && res->length)
    {
        /* Change the value */
        lwm2m_object_t *object = (lwm2m_object_t *)lwm2m_list_find(
                (lwm2m_list_t *)client->lwm2mH->objectList, uri_t.objectId);

        if (object)
        {
            int result = COAP_405_METHOD_NOT_ALLOWED;
            lwm2m_data_t data;

            data.id = uri_t.resourceId;
            lwm2m_data_encode_nstring((const char*)res->buffer, res->length, &data);

            if (object->writeFunc)
            {
                result = object->writeFunc(uri_t.instanceId, 1, &data, object);
            }

            /*
             * If property is not writable, we can still try to change it
             * locally for objects that support it
             */
            if (result == COAP_405_METHOD_NOT_ALLOWED)
            {
                switch(uri_t.objectId)
                {
                case LWM2M_DEVICE_OBJECT_ID:
                    result = device_change_object(&data, object);
                    break;
                case LWM2M_CONN_MONITOR_OBJECT_ID:
                    result = connectivity_moni_change(&data, object);
                    break;
                case LWM2M_FIRMWARE_UPDATE_OBJECT_ID:
                    result = firmware_change_object(&data, object);
                    break;
                case LWM2M_LOCATION_OBJECT_ID:
                    result = location_change_object(&data, object);
                    break;
                default:
                    break;
                }
            }

            if (result != COAP_204_CHANGED)
            {
                fprintf(stderr, "lwm2m_write_resource: failed (%d)\r\n", result);
                return LWM2M_CLIENT_ERROR;
            }
        }
        else
        {
            fprintf(stderr, "lwm2m_write_resource: object not found\r\n");
            return LWM2M_CLIENT_ERROR;
        }
    }

    lwm2m_resource_value_changed(client->lwm2mH, &uri_t);

    return LWM2M_CLIENT_OK;
}

static int encode_data(lwm2m_data_t *data, uint8_t **buffer)
{
    int size = 0;

    switch (data->type)
    {
    case LWM2M_TYPE_STRING:
        size = data[0].value.asBuffer.length;
        *buffer = (uint8_t *)lwm2m_malloc(size);
        if (!buffer)
        {
            fprintf(stderr, "encode_data: failed to allocate memory\r\n");
            return LWM2M_CLIENT_ERROR;
        }
        memcpy(*buffer, data[0].value.asBuffer.buffer, size);
        break;

    case LWM2M_TYPE_INTEGER:
        size = utils_int64ToPlainText(data[0].value.asInteger, buffer);
        break;

    case LWM2M_TYPE_FLOAT:
        size = utils_float64ToPlainText(data[0].value.asFloat, buffer);
        break;

    case LWM2M_TYPE_BOOLEAN:
        size = utils_boolToPlainText(data[0].value.asBoolean, buffer);
        break;

    case LWM2M_TYPE_OBJECT_LINK:
    case LWM2M_TYPE_OPAQUE:
    case LWM2M_TYPE_UNDEFINED:
    default:
        fprintf(stderr, "encode_data: unsupported type (%d)\r\n", data[0].type);
        size = LWM2M_CLIENT_ERROR;
        break;
    }

    return size;
}

int lwm2m_read_resource(client_handle_t handle, lwm2m_resource_t *res)
{
    int ret;
    client_data_t *client =  (client_data_t *)handle;
    lwm2m_uri_t uri_t;
    lwm2m_object_t *object;

    if (!res)
    {
        fprintf(stderr, "lwm2m_read_resource: wrong parameters\r\n");
        return LWM2M_CLIENT_ERROR;
    }

    ret = lwm2m_stringToUri(res->uri, strlen(res->uri), &uri_t);
    if (ret == 0)
    {
        fprintf(stderr, "lwm2m_stringToUri() failed: 0x%X", ret);
        return LWM2M_CLIENT_ERROR;
    }

    object = (lwm2m_object_t *)lwm2m_list_find(
            (lwm2m_list_t *)client->lwm2mH->objectList, uri_t.objectId);

    if (object)
    {
        if (object->readFunc)
        {
            int result = COAP_405_METHOD_NOT_ALLOWED;
            lwm2m_data_t *data;
            int num = 1;

            data = malloc(num * sizeof(lwm2m_data_t));
            if (!data)
            {
                fprintf(stderr, "lwm2m_read_resource: failed to allocate memory\r\n");
                return LWM2M_CLIENT_ERROR;
            }
            data[0].id = uri_t.resourceId;
            result = object->readFunc(uri_t.instanceId, &num, &data, object);
            if (result != COAP_205_CONTENT)
            {
                fprintf(stderr, "lwm2m_read_resource: failed (%d)\r\n", result);
                free(data);
                return LWM2M_CLIENT_ERROR;
            }
            else
            {
                if (data[0].type == LWM2M_TYPE_MULTIPLE_RESOURCE)
                {
                    int i = 0, idx = 0;
                    int num = data[0].value.asChildren.count;
                    lwm2m_data_t *array = data[0].value.asChildren.array;
                    lwm2m_resource_t *resarray = NULL;

                    resarray = lwm2m_malloc(num * sizeof(*resarray));
                    if (!resarray)
                    {
                        fprintf(stderr, "lwm2m_read_resource: failed to allocate memory\r\n");
                        return LWM2M_CLIENT_ERROR;
                    }

                    /* Retrieve the buffers from all children and compute total size */
                    res->length = 0;
                    for (i=0; i<num; i++)
                    {
                        resarray[i].length = encode_data(&array[i], &resarray[i].buffer);
                        res->length += resarray[i].length + 3;
                    }

                    /* Generate a single buffer out of the parsed ones */
                    res->buffer = lwm2m_malloc(res->length);
                    if (!res->length)
                    {
                        fprintf(stderr, "lwm2m_read_resource: failed to allocate memory\r\n");
                        return LWM2M_CLIENT_ERROR;
                    }

                    memset(res->buffer, 0, res->length);
                    for (i=0; i<num; i++)
                    {
                        char prefix[5];
                        char suffix[] = ",";
                        snprintf(prefix, 5, "%d=", i);
                        memcpy(res->buffer + idx, prefix, strlen(prefix));
                        idx += strlen(prefix);
                        memcpy(res->buffer + idx, resarray[i].buffer, resarray[i].length);
                        idx += resarray[i].length;
                        if (i < (num-1))
                        {
                            memcpy(res->buffer + idx, (uint8_t*)suffix, 1);
                            idx++;
                        }
                    }

                    lwm2m_free(resarray);
                }
                else
                {
                    res->length = encode_data(&data[0], &res->buffer);
                    if (res->length < 0)
                    {
                        fprintf(stderr, "lwm2m_read_resource: failed to encode data\r\n");
                        return LWM2M_CLIENT_ERROR;
                        free(data);
                    }
                }
                free(data);
            }
        }
        else
        {
            fprintf(stderr, "lwm2m_read_resource: object not readable\r\n");
            return LWM2M_CLIENT_ERROR;
        }
    }
    else
    {
        fprintf(stderr, "lwm2m_read_resource: object not found\r\n");
        return LWM2M_CLIENT_ERROR;
    }

    return LWM2M_CLIENT_OK;
}

int lwm2m_serialize_tlv_string(int num, char **strs, lwm2m_resource_t* res)
{
    lwm2m_data_t *array = NULL;
    int i = 0;

    array = lwm2m_malloc(num * sizeof(*array));
    if (!array)
    {
        fprintf(stderr, "lwm2m_tlv_string: failed to allocate memory\r\n");
        return LWM2M_CLIENT_ERROR;
    }

    for (i=0; i<num; i++)
    {
        array[i].type = LWM2M_TYPE_STRING;
        array[i].value.asBuffer.length = strlen(strs[i]);
        array[i].value.asBuffer.buffer = (uint8_t*)strs[i];
    }

    res->length = tlv_serialize(true, num, array, &res->buffer);
    if (!res->length)
    {
        fprintf(stderr, "lwm2m_tlv_string: failed to serialize TLV\r\n");
        return LWM2M_CLIENT_ERROR;
    }

    return LWM2M_CLIENT_OK;
}
