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
 *    David Navarro, Intel Corporation - initial API and implementation
 *    domedambrosio - Please refer to git log
 *    Fabien Fleutot - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Manuel Sangoi - Please refer to git log
 *    Julien Vermillard - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
 *    Pascal Rieux - Please refer to git log
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

*/

#include "internals.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_LOCATION_LENGTH 10      // strlen("/rd/65534") + 1

#ifdef LWM2M_CLIENT_MODE

static int prv_getRegistrationQuery(lwm2m_context_t * contextP, lwm2m_server_t * server,
                                    char * buffer, size_t length)
{
    int index;
    int res;

    index = snprintf(buffer, length, "?ep=%s", contextP->endpointName);
    if (index <= 1) return 0;

    if (NULL != contextP->msisdn)
    {
        res = snprintf(buffer + index, length - index, QUERY_DELIMITER QUERY_SMS "%s", contextP->msisdn);
        if (res <= 1) return 0;

        index += res;
    }

    switch (server->binding)
    {
#if defined(COAP_TCP)
	case BINDING_T:
		res = snprintf(buffer + index, length - index, "&b=T");
		break;
#else
    case BINDING_U:
        res = snprintf(buffer + index, length - index, "&b=U");
        break;
    case BINDING_UQ:
        res = snprintf(buffer + index, length - index, "&b=UQ");
        break;
    case BINDING_S:
        res = snprintf(buffer + index, length - index, "&b=S");
        break;
    case BINDING_SQ:
        res = snprintf(buffer + index, length - index, "&b=SQ");
        break;
    case BINDING_US:
        res = snprintf(buffer + index, length - index, "&b=US");
        break;
    case BINDING_UQS:
        res = snprintf(buffer + index, length - index, "&b=UQS");
        break;
#endif
    default:
        res = 0;
    }
    if (res <= 1) return 0;

    return index + res;
}

static void prv_handleRegistrationReply(lwm2m_transaction_t * transacP,
                                        void * message)
{
    coap_packet_t * packet = (coap_packet_t *)message;
    lwm2m_server_t * targetP = (lwm2m_server_t *)(transacP->peerP);

    switch(targetP->status)
    {
    case STATE_REG_PENDING:
    {
        time_t tv_sec = lwm2m_gettime();
        if (tv_sec >= 0)
        {
            targetP->registration = tv_sec;
        }
        if (packet != NULL && packet->code == CREATED_2_01)
        {
            targetP->status = STATE_REGISTERED;
            if (NULL != targetP->location)
            {
                lwm2m_free(targetP->location);
            }
            targetP->location = coap_get_multi_option_as_string(packet->location_path);

            LOG("    => REGISTERED\r\n");
        }
        else
        {
            targetP->status = STATE_REG_FAILED;
            LOG("    => Registration FAILED\r\n");
        }
    }
    break;
    default:
        break;
    }
}

#define PRV_QUERY_BUFFER_LENGTH 200

// send the registration for a single server
static void prv_register(lwm2m_context_t * contextP,
                         lwm2m_server_t * server)
{
    char query[200];
    int query_length;
    uint8_t payload[512];
    int payload_length;

    lwm2m_transaction_t * transaction;

    payload_length = prv_getRegisterPayload(contextP, payload, sizeof(payload));
    if (payload_length == 0) return;

    query_length = prv_getRegistrationQuery(contextP, server, query, sizeof(query));

    if (query_length == 0) return;

#if !defined(COAP_TCP)
    if (0 != server->lifetime)
    {
        if (snprintf(query + query_length,
                        PRV_QUERY_BUFFER_LENGTH - query_length,
                        QUERY_DELIMITER QUERY_LIFETIME "%d",
                        (int)server->lifetime) <= 0)
        {
            return;
        }
    }
#endif

    if (server->sessionH == NULL)
    {
        server->sessionH = contextP->connectCallback(server->secObjInstID, contextP->userData);
    }

    if (NULL != server->sessionH)
    {
        transaction = transaction_new(COAP_TYPE_CON, COAP_POST, NULL, NULL, contextP->nextMID++, 4, NULL, ENDPOINT_SERVER, (void *)server);

        if (transaction == NULL) return;

        coap_set_header_uri_path(transaction->message, "/"URI_REGISTRATION_SEGMENT);
        coap_set_header_uri_query(transaction->message, query);
        coap_set_header_content_type(transaction->message, LWM2M_CONTENT_LINK);
        coap_set_payload(transaction->message, payload, payload_length);

        transaction->callback = prv_handleRegistrationReply;
        transaction->userData = (void *) server;

        contextP->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(contextP->transactionList, transaction);
        if (transaction_send(contextP, transaction) == 0)
        {
            server->status = STATE_REG_PENDING;
        }
    }
}

static void prv_handleRegistrationUpdateReply(lwm2m_transaction_t * transacP,
                                              void * message)
{
    coap_packet_t * packet = (coap_packet_t *)message;
    lwm2m_server_t * targetP = (lwm2m_server_t *)(transacP->peerP);

    switch(targetP->status)
    {
    case STATE_REG_UPDATE_PENDING:
    {
        time_t tv_sec = lwm2m_gettime();
        if (tv_sec >= 0)
        {
            targetP->registration = tv_sec;
        }
        if (packet != NULL && packet->code == CHANGED_2_04)
        {
            targetP->status = STATE_REGISTERED;
            LOG("    => REGISTERED\r\n");
        }
        else
        {
            targetP->status = STATE_REG_FAILED;
            LOG("    => Registration update FAILED\r\n");
        }
    }
    break;
    default:
        break;
    }
}

static int prv_update_registration(lwm2m_context_t * contextP,
                                   lwm2m_server_t * server)
{
    lwm2m_transaction_t * transaction;

    transaction = transaction_new(COAP_TYPE_CON, COAP_POST, NULL, NULL, contextP->nextMID++, 4, NULL, ENDPOINT_SERVER, (void *)server);

	if (transaction == NULL) return INTERNAL_SERVER_ERROR_5_00;

    coap_set_header_uri_path(transaction->message, server->location);

    transaction->callback = prv_handleRegistrationUpdateReply;
    transaction->userData = (void *) server;

    contextP->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(contextP->transactionList, transaction);

    if (transaction_send(contextP, transaction) == 0)
    {
        server->status = STATE_REG_UPDATE_PENDING;
    }

    return 0;
}

// update the registration of a given server
int lwm2m_update_registration(lwm2m_context_t * contextP,
                              uint16_t shortServerID)
{
    lwm2m_server_t * targetP;

    targetP = contextP->serverList;
    if (targetP == NULL)
    {
        if (object_getServers(contextP) == -1)
        {
            return NOT_FOUND_4_04;
        }
    }
    while (targetP != NULL)
    {
        if (targetP->shortID == shortServerID)
        {
            // found the server, trigger the update transaction
            return prv_update_registration(contextP, targetP);
        }
        else
        {
            // try next server
            targetP = targetP->next;
        }
    }

    // no server found
    return NOT_FOUND_4_04;
}

// for each server update the registration if needed
void registration_update(lwm2m_context_t * contextP,
                         time_t currentTime,
                         time_t * timeoutP)
{
    time_t nextUpdate;
    time_t interval;
    lwm2m_server_t * targetP = contextP->serverList;
#ifdef LWM2M_BOOTSTRAP
    bool allServerFailed = true;
    bool serverRegistered = false;

    while (targetP != NULL)
    {
        if (STATE_REGISTERED == targetP->status)
        {
            serverRegistered = true;
            allServerFailed = false;
            break;
        }
        else if (STATE_REG_FAILED != targetP->status) allServerFailed = false;
        targetP = targetP->next;
    }
#endif

    targetP = contextP->serverList;
    while (targetP != NULL)
    {
        switch (targetP->status)
        {
            case STATE_REGISTERED:
                nextUpdate = targetP->lifetime;
                if (30 < nextUpdate)
                {
                    nextUpdate -= 15; // update 15s earlier to have a chance to resend
                }

                interval = targetP->registration + nextUpdate - currentTime;
                if (0 >= interval)
                {
                    LOG("Updating registration...\r\n");
                    prv_update_registration(contextP, targetP);
                }
                else if (interval < *timeoutP)
                {
                    *timeoutP = interval;
                }
                break;

            case STATE_DEREGISTERED:
                // TODO: is it disabled?
                prv_register(contextP, targetP);
                break;

            case STATE_REG_UPDATE_PENDING:
                // TODO: check for timeout and retry?
                break;

            case STATE_DEREG_PENDING:
                break;

            case STATE_REG_FAILED:
#ifdef LWM2M_BOOTSTRAP
                if (serverRegistered || NULL == contextP->bootstrapServerList)
                {
#endif
                    interval = targetP->registration + targetP->lifetime - currentTime;
                    if (0 >= interval)
                    {
                        LOG("Retry registration...\r\n");
                        prv_register(contextP, targetP);
                    }
                    else if (interval < *timeoutP)
                    {
                        *timeoutP = interval;
                    }
#ifdef LWM2M_BOOTSTRAP
                }
#endif
                break;

            default:
                break;
        }
        targetP = targetP->next;
    }
#ifdef LWM2M_BOOTSTRAP
    if (allServerFailed && NULL != contextP->bootstrapServerList)
    {
        if (BOOTSTRAPPED == contextP->bsState || NOT_BOOTSTRAPPED == contextP->bsState)
        {
            contextP->bsState = BOOTSTRAP_REQUESTED;
        }
    }
#endif
}

static void prv_handleDeregistrationReply(lwm2m_transaction_t * transacP,
                                        void * message)
{
    lwm2m_server_t * targetP;

    targetP = (lwm2m_server_t *)(transacP->peerP);
    if (NULL != targetP)
    {
        switch(targetP->status)
        {
        case STATE_DEREG_PENDING:
            targetP->status = STATE_DEREGISTERED;
            break;
        default:
            break;
        }
    }
}

void registration_deregister(lwm2m_context_t * contextP,
                             lwm2m_server_t * serverP)
{
    if (serverP->status == STATE_DEREGISTERED
     || serverP->status == STATE_REG_PENDING
     || serverP->status == STATE_DEREG_PENDING
     || serverP->status == STATE_REG_FAILED
     || serverP->location == NULL)
        {
            return;
        }

    lwm2m_transaction_t * transaction;
    transaction = transaction_new(COAP_TYPE_CON, COAP_DELETE, NULL, NULL, contextP->nextMID++, 4, NULL, ENDPOINT_SERVER, (void *)serverP);

    if (transaction == NULL) return;

    coap_set_header_uri_path(transaction->message, serverP->location);

    transaction->callback = prv_handleDeregistrationReply;
    transaction->userData = (void *) contextP;

    contextP->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(contextP->transactionList, transaction);
    if (transaction_send(contextP, transaction) == 0)
    {
        serverP->status = STATE_DEREG_PENDING;
    }
}
#endif

#ifdef LWM2M_SERVER_MODE
static int prv_getParameters(multi_option_t * query,
                             char ** nameP,
                             uint32_t * lifetimeP,
                             char ** msisdnP,
                             lwm2m_binding_t * bindingP)
{
    *nameP = NULL;
    *lifetimeP = 0;
    *msisdnP = NULL;
    *bindingP = BINDING_UNKNOWN;

    while (query != NULL)
    {
        if (lwm2m_strncmp((char *)query->data, QUERY_TEMPLATE, QUERY_LENGTH) == 0)
        {
            if (*nameP != NULL) goto error;
            if (query->len == QUERY_LENGTH) goto error;

            *nameP = (char *)lwm2m_malloc(query->len - QUERY_LENGTH + 1);
            if (*nameP != NULL)
            {
                memcpy(*nameP, query->data + QUERY_LENGTH, query->len - QUERY_LENGTH);
                (*nameP)[query->len - QUERY_LENGTH] = 0;
            }
        }
        else if (lwm2m_strncmp((char *)query->data, QUERY_SMS, QUERY_SMS_LEN) == 0)
        {
            if (*msisdnP != NULL) goto error;
            if (query->len == QUERY_SMS_LEN) goto error;

            *msisdnP = (char *)lwm2m_malloc(query->len - QUERY_SMS_LEN + 1);
            if (*msisdnP != NULL)
            {
                memcpy(*msisdnP, query->data + QUERY_SMS_LEN, query->len - QUERY_SMS_LEN);
                (*msisdnP)[query->len - QUERY_SMS_LEN] = 0;
            }
        }
        else if (lwm2m_strncmp((char *)query->data, QUERY_LIFETIME, QUERY_LIFETIME_LEN) == 0)
        {
            int i;

            if (*lifetimeP != 0) goto error;
            if (query->len == QUERY_LIFETIME_LEN) goto error;

            for (i = QUERY_LIFETIME_LEN ; i < query->len ; i++)
            {
                if (query->data[i] < '0' || query->data[i] > '9') goto error;
                *lifetimeP = (*lifetimeP * 10) + (query->data[i] - '0');
            }
        }
        else if (lwm2m_strncmp((char *)query->data, QUERY_VERSION, QUERY_VERSION_LEN) == 0)
        {
            if ((query->len != QUERY_VERSION_FULL_LEN)
             || (lwm2m_strncmp((char *)query->data, QUERY_VERSION_FULL, QUERY_VERSION_FULL_LEN) != 0))
            {
                goto error;
            }
        }
        else if (lwm2m_strncmp((char *)query->data, QUERY_BINDING, QUERY_BINDING_LEN) == 0)
        {
            if (*bindingP != BINDING_UNKNOWN) goto error;
            if (query->len == QUERY_BINDING_LEN) goto error;

            *bindingP = lwm2m_stringToBinding(query->data + QUERY_BINDING_LEN, query->len - QUERY_BINDING_LEN);
        }
        query = query->next;
    }

    return 0;

error:
    if (*nameP != NULL) lwm2m_free(*nameP);
    if (*msisdnP != NULL) lwm2m_free(*msisdnP);

    return -1;
}

static int prv_getId(uint8_t * data,
                     uint16_t length,
                     char * altPath,
                     uint16_t altPathLen,
                     uint16_t * objId,
                     uint16_t * instanceId)
{
    int value;
    uint16_t limit;
    uint16_t end;

    // Expecting application/link-format (RFC6690)
    // strip open and close tags
    if (length >= 1 && data[0] == '<' && data[length-1] == '>')
    {
        data++;
        length-=2;
    } 
    else
    {
        return 0;
    }

    if (altPath != NULL)
    {
        if (length <= altPathLen) return 0;
        if (0 != lwm2m_strncmp((char *)data, altPath, altPathLen)) return 0;
        data += altPathLen;
        length -= altPathLen;
    }

    // If there is a preceding /, remove it
    if (length >= 1 && data[0] == '/')
    {
        data++;
        length-=1;
    }

    limit = 0;
    while (limit < length && data[limit] != '/' && data[limit] != ' ') limit++;
    value = prv_get_number(data, limit);
    if (value < 0 || value >= LWM2M_MAX_ID) return 0;
    *objId = value;

    if (limit != length)
    {
        limit += 1;
        end = limit;
        while (end < length && data[end] != ' ') end++;
        if (end != limit)
        {
            value = prv_get_number(data + limit, end - limit);
            if (value >= 0 && value < LWM2M_MAX_ID)
            {
                *instanceId = value;
                return 2;
            }
        }
    }

    return 1;
}

static lwm2m_client_object_t * prv_decodeRegisterPayload(uint8_t * payload,
                                                         uint16_t payloadLength,
                                                         char ** altPath)
{
    lwm2m_client_object_t * objList;
    uint16_t id;
    uint16_t instance;
    uint16_t start;
    uint16_t end;
    int result;
    uint16_t altPathStart;
    uint16_t altPathEnd;
    uint16_t altPathLen;

    objList = NULL;
    start = 0;
    altPathStart = 0;
    altPathEnd = 0;
    altPathLen = 0;
    *altPath = NULL;

    // Does the registration payload begin with an alternative path ?
    while (start < payloadLength && payload[start] == ' ') start++;
    if (start != payloadLength)
    {
        if (payload[start] == '<')
        {
            altPathStart = start + 1;
        }
        while (start < payloadLength - 1 && payload[start] != '>') start++;
        if (start != payloadLength - 1)
        {
            altPathEnd = start - 1;
            if ((payloadLength > altPathEnd + REG_LWM2M_RESOURCE_TYPE_LEN)
             && (0 == lwm2m_strncmp(REG_LWM2M_RESOURCE_TYPE, (char *) payload + altPathEnd + 1, REG_LWM2M_RESOURCE_TYPE_LEN)))
            {
                payload[altPathEnd + 1] = 0;
                *altPath = lwm2m_strdup((char *)payload + altPathStart);
                if (*altPath == NULL) return NULL;
                if (0 == prv_isAltPathValid(*altPath))
                {
                    return NULL;
                }
                altPathLen = altPathEnd - altPathStart + 1;
            }
        }
    }

    if (altPathLen != 0)
    {
        start = altPathEnd + 1 + REG_LWM2M_RESOURCE_TYPE_LEN;
        // If declared alternative path is "/", use NULL instead
        if (altPathLen == 1)
        {
            lwm2m_free(*altPath);
            *altPath = NULL;
        }
    }
    else
    {
        start = 0;
    }

    while (start < payloadLength)
    {
        while (start < payloadLength && payload[start] == ' ') start++;
        if (start == payloadLength) return objList;
        end = start;
        while (end < payloadLength && payload[end] != ',') end++;
        result = prv_getId(payload + start, end - start, *altPath, altPathLen, &id, &instance);
        if (result != 0)
        {
            lwm2m_client_object_t * objectP;

            objectP = (lwm2m_client_object_t *)lwm2m_list_find((lwm2m_list_t *)objList, id);
            if (objectP == NULL)
            {
                objectP = (lwm2m_client_object_t *)lwm2m_malloc(sizeof(lwm2m_client_object_t));
                memset(objectP, 0, sizeof(lwm2m_client_object_t));
                if (objectP == NULL) return objList;
                objectP->id = id;
                objList = (lwm2m_client_object_t *)LWM2M_LIST_ADD(objList, objectP);
            }
            if (result == 2)
            {
                lwm2m_list_t * instanceP;

                instanceP = lwm2m_list_find(objectP->instanceList, instance);
                if (instanceP == NULL)
                {
                    instanceP = (lwm2m_list_t *)lwm2m_malloc(sizeof(lwm2m_list_t));
                    memset(instanceP, 0, sizeof(lwm2m_list_t));
                    instanceP->id = instance;
                    objectP->instanceList = LWM2M_LIST_ADD(objectP->instanceList, instanceP);
                }
            }
        }
        start = end + 1;
    }

    return objList;
}

static lwm2m_client_t * prv_getClientByName(lwm2m_context_t * contextP,
                                            char * name)
{
    lwm2m_client_t * targetP;

    targetP = contextP->clientList;
    while (targetP != NULL && strcmp(name, targetP->name) != 0)
    {
        targetP = targetP->next;
    }

    return targetP;
}

static void prv_freeClientObjectList(lwm2m_client_object_t * objects)
{
    while (objects != NULL)
    {
        lwm2m_client_object_t * objP;

        while (objects->instanceList != NULL)
        {
            lwm2m_list_t * target;

            target = objects->instanceList;
            objects->instanceList = objects->instanceList->next;
            lwm2m_free(target);
        }

        objP = objects;
        objects = objects->next;
        lwm2m_free(objP);
    }
}

void prv_freeClient(lwm2m_client_t * clientP)
{
    if (clientP->name != NULL) lwm2m_free(clientP->name);
    if (clientP->msisdn != NULL) lwm2m_free(clientP->msisdn);
    if (clientP->altPath != NULL) lwm2m_free(clientP->altPath);
    prv_freeClientObjectList(clientP->objectList);
    while(clientP->observationList != NULL)
    {
        lwm2m_observation_t * targetP;

        targetP = clientP->observationList;
        clientP->observationList = clientP->observationList->next;
        lwm2m_free(targetP);
    }
    lwm2m_free(clientP);
}

static int prv_getLocationString(uint16_t id,
                                 char location[MAX_LOCATION_LENGTH])
{
    int result;

    memset(location, 0, MAX_LOCATION_LENGTH);

    result = snprintf(location, MAX_LOCATION_LENGTH, "/"URI_REGISTRATION_SEGMENT"/%hu", id);
    if (result <= 0 || result > MAX_LOCATION_LENGTH)
    {
        return 0;
    }

    return result;
}

coap_status_t handle_registration_request(lwm2m_context_t * contextP,
                                          lwm2m_uri_t * uriP,
                                          void * fromSessionH,
                                          coap_packet_t * message,
                                          coap_packet_t * response)
{
    coap_status_t result;
    time_t tv_sec;

    tv_sec = lwm2m_gettime();
    if (tv_sec < 0) return COAP_500_INTERNAL_SERVER_ERROR;

    switch(message->code)
    {
    case COAP_POST:
    {
        char * name = NULL;
        uint32_t lifetime;
        char * msisdn;
        char * altPath;
        lwm2m_binding_t binding;
        lwm2m_client_object_t * objects;
        lwm2m_client_t * clientP;
        char location[MAX_LOCATION_LENGTH];

        if (0 != prv_getParameters(message->uri_query, &name, &lifetime, &msisdn, &binding))
        {
            return COAP_400_BAD_REQUEST;
        }
        if (message->content_type != LWM2M_CONTENT_LINK
         && message->content_type != LWM2M_CONTENT_TEXT)
        {
            return COAP_400_BAD_REQUEST;
        }

        objects = prv_decodeRegisterPayload(message->payload, message->payload_len, &altPath);

        switch (uriP->flag & LWM2M_URI_MASK_ID)
        {
        case 0:
            // Register operation

            if (objects == NULL)
            {
                lwm2m_free(name);
                if (msisdn != NULL) lwm2m_free(msisdn);
                return COAP_400_BAD_REQUEST;
            }
            // Endpoint client name is mandatory
            if (name == NULL)
            {
                if (msisdn != NULL) lwm2m_free(msisdn);
                return COAP_400_BAD_REQUEST;
            }
            if (lifetime == 0)
            {
                lifetime = LWM2M_DEFAULT_LIFETIME;
            }

            clientP = prv_getClientByName(contextP, name);
            if (clientP != NULL)
            {
                // we reset this registration
                lwm2m_free(clientP->name);
                if (clientP->msisdn != NULL) lwm2m_free(clientP->msisdn);
                if (clientP->altPath != NULL) lwm2m_free(clientP->altPath);
                prv_freeClientObjectList(clientP->objectList);
                clientP->objectList = NULL;
            }
            else
            {
                clientP = (lwm2m_client_t *)lwm2m_malloc(sizeof(lwm2m_client_t));
                if (clientP == NULL)
                {
                    lwm2m_free(name);
                    lwm2m_free(altPath);
                    if (msisdn != NULL) lwm2m_free(msisdn);
                    prv_freeClientObjectList(objects);
                    return COAP_500_INTERNAL_SERVER_ERROR;
                }
                memset(clientP, 0, sizeof(lwm2m_client_t));
                clientP->internalID = lwm2m_list_newId((lwm2m_list_t *)contextP->clientList);
                contextP->clientList = (lwm2m_client_t *)LWM2M_LIST_ADD(contextP->clientList, clientP);
            }
            clientP->name = name;
            clientP->binding = binding;
            clientP->msisdn = msisdn;
            clientP->altPath = altPath;
            clientP->lifetime = lifetime;
            clientP->endOfLife = tv_sec + lifetime;
            clientP->objectList = objects;
            clientP->sessionH = fromSessionH;

            if (prv_getLocationString(clientP->internalID, location) == 0)
            {
                prv_freeClient(clientP);
                return COAP_500_INTERNAL_SERVER_ERROR;
            }
            if (coap_set_header_location_path(response, location) == 0)
            {
                prv_freeClient(clientP);
                return COAP_500_INTERNAL_SERVER_ERROR;
            }

            if (contextP->monitorCallback != NULL)
            {
                contextP->monitorCallback(clientP->internalID, NULL, CREATED_2_01, LWM2M_CONTENT_TEXT, NULL, 0, contextP->monitorUserData);
            }
            result = COAP_201_CREATED;
            break;

        case LWM2M_URI_FLAG_OBJECT_ID:
            clientP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)contextP->clientList, uriP->objectId);
            if (clientP == NULL) return COAP_404_NOT_FOUND;

            // Endpoint client name MUST NOT be present
            if (name != NULL)
            {
                lwm2m_free(name);
                if (msisdn != NULL) lwm2m_free(msisdn);
                return COAP_400_BAD_REQUEST;
            }

            if (binding != BINDING_UNKNOWN)
            {
                clientP->binding = binding;
            }
            if (msisdn != NULL)
            {
                if (clientP->msisdn != NULL) lwm2m_free(clientP->msisdn);
                clientP->msisdn = msisdn;
            }
            if (lifetime != 0)
            {
                clientP->lifetime = lifetime;
            }
            // client IP address, port or MSISDN may have changed
            clientP->sessionH = fromSessionH;

            if (objects != NULL)
            {
                lwm2m_observation_t * observationP;

                // remove observations on object/instance no longer existing
                observationP = clientP->observationList;
                while (observationP != NULL)
                {
                    lwm2m_client_object_t * objP;
                    lwm2m_observation_t * nextP;

                    nextP = observationP->next;

                    objP = (lwm2m_client_object_t *)lwm2m_list_find((lwm2m_list_t *)objects, observationP->uri.objectId);
                    if (objP == NULL)
                    {
                        observationP->callback(clientP->internalID,
                                               &observationP->uri,
                                               COAP_202_DELETED,
                                               LWM2M_CONTENT_TEXT, NULL, 0,
                                               observationP->userData);
                        observation_remove(clientP, observationP);
                    }
                    else
                    {
                        if ((observationP->uri.flag & LWM2M_URI_FLAG_INSTANCE_ID) != 0)
                        {
                            if (lwm2m_list_find((lwm2m_list_t *)objP->instanceList, observationP->uri.instanceId) == NULL)
                            {
                                observationP->callback(clientP->internalID,
                                                       &observationP->uri,
                                                       COAP_202_DELETED,
                                                       LWM2M_CONTENT_TEXT, NULL, 0,
                                                       observationP->userData);
                                observation_remove(clientP, observationP);
                            }
                        }
                    }

                    observationP = nextP;
                }

                prv_freeClientObjectList(clientP->objectList);
                clientP->objectList = objects;
            }

            clientP->endOfLife = tv_sec + clientP->lifetime;

            if (contextP->monitorCallback != NULL)
            {
                contextP->monitorCallback(clientP->internalID, NULL, COAP_204_CHANGED, LWM2M_CONTENT_TEXT, NULL, 0, contextP->monitorUserData);
            }
            result = COAP_204_CHANGED;
            break;

            default:
                return COAP_400_BAD_REQUEST;
        }
    }
    break;

    case COAP_DELETE:
    {
        lwm2m_client_t * clientP;

        if ((uriP->flag & LWM2M_URI_MASK_ID) != LWM2M_URI_FLAG_OBJECT_ID) return COAP_400_BAD_REQUEST;

        contextP->clientList = (lwm2m_client_t *)LWM2M_LIST_RM(contextP->clientList, uriP->objectId, &clientP);
        if (clientP == NULL) return COAP_400_BAD_REQUEST;
        if (contextP->monitorCallback != NULL)
        {
            contextP->monitorCallback(clientP->internalID, NULL, DELETED_2_02, LWM2M_CONTENT_TEXT, NULL, 0, contextP->monitorUserData);
        }
        prv_freeClient(clientP);
        result = COAP_202_DELETED;
    }
    break;

    default:
        return COAP_400_BAD_REQUEST;
    }

    return result;
}

void lwm2m_set_monitoring_callback(lwm2m_context_t * contextP,
                                   lwm2m_result_callback_t callback,
                                   void * userData)
{
    contextP->monitorCallback = callback;
    contextP->monitorUserData = userData;
}


#endif
