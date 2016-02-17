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
 *    Toby Jaffey - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
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
#include <stdio.h>


#ifdef LWM2M_CLIENT_MODE
static lwm2m_observed_t * prv_findObserved(lwm2m_context_t * contextP,
                                           lwm2m_uri_t * uriP)
{
    lwm2m_observed_t * targetP;

    targetP = contextP->observedList;
    while (targetP != NULL
        && (targetP->uri.objectId != uriP->objectId
         || targetP->uri.flag != uriP->flag
         || (LWM2M_URI_IS_SET_INSTANCE(uriP) && targetP->uri.instanceId != uriP->instanceId)
         || (LWM2M_URI_IS_SET_RESOURCE(uriP) && targetP->uri.resourceId != uriP->resourceId)))
    {
        targetP = targetP->next;
    }

    return targetP;
}

static obs_list_t * prv_getObservedList(lwm2m_context_t * contextP,
                                        lwm2m_uri_t * uriP)
{
    obs_list_t * resultP;
    lwm2m_observed_t * targetP;

    resultP = NULL;

    targetP = contextP->observedList;
    while (targetP != NULL)
    {
        if (targetP->uri.objectId == uriP->objectId)
        {
            if (!LWM2M_URI_IS_SET_INSTANCE(uriP)
             || (targetP->uri.flag & LWM2M_URI_FLAG_INSTANCE_ID) == 0
             || uriP->instanceId == targetP->uri.instanceId)
            {
                if (!LWM2M_URI_IS_SET_RESOURCE(uriP)
                 || (targetP->uri.flag & LWM2M_URI_FLAG_RESOURCE_ID) == 0
                 || uriP->resourceId == targetP->uri.resourceId)
                {
                    obs_list_t * newP;

                    newP = (obs_list_t *)lwm2m_malloc(sizeof(obs_list_t));
                    if (newP != NULL)
                    {
                        newP->item = targetP;
                        newP->next = resultP;
                        resultP = newP;
                    }
                }
            }
        }
        targetP = targetP->next;
    }

    return resultP;
}

static void prv_unlinkObserved(lwm2m_context_t * contextP,
                               lwm2m_observed_t * observedP)
{
    if (contextP->observedList == observedP)
    {
        contextP->observedList = contextP->observedList->next;
    }
    else
    {
        lwm2m_observed_t * parentP;

        parentP = contextP->observedList;
        while (parentP->next != NULL
            && parentP->next != observedP)
        {
            parentP = parentP->next;
        }
        if (parentP->next != NULL)
        {
            parentP->next = parentP->next->next;
        }
    }
}

static lwm2m_watcher_t * prv_findWatcher(lwm2m_observed_t * observedP,
                                         lwm2m_server_t * serverP)
{
    lwm2m_watcher_t * targetP;

    targetP = observedP->watcherList;
    while (targetP != NULL
        && targetP->server != serverP)
    {
        targetP = targetP->next;
    }

    return targetP;
}

coap_status_t handle_observe_request(lwm2m_context_t * contextP,
                                     lwm2m_uri_t * uriP,
                                     lwm2m_server_t * serverP,
                                     coap_packet_t * message,
                                     coap_packet_t * response)
{
    lwm2m_observed_t * observedP;
    lwm2m_watcher_t * watcherP;

    LOG("handle_observe_request()\r\n");

    if (!LWM2M_URI_IS_SET_INSTANCE(uriP) && LWM2M_URI_IS_SET_RESOURCE(uriP)) return COAP_400_BAD_REQUEST;
    if (message->token_len == 0) return COAP_400_BAD_REQUEST;

    observedP = prv_findObserved(contextP, uriP);
    if (observedP == NULL)
    {
        observedP = (lwm2m_observed_t *)lwm2m_malloc(sizeof(lwm2m_observed_t));
        if (observedP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
        memset(observedP, 0, sizeof(lwm2m_observed_t));
        memcpy(&(observedP->uri), uriP, sizeof(lwm2m_uri_t));
        observedP->next = contextP->observedList;
        contextP->observedList = observedP;
    }

    watcherP = prv_findWatcher(observedP, serverP);
    if (watcherP == NULL)
    {
        watcherP = (lwm2m_watcher_t *)lwm2m_malloc(sizeof(lwm2m_watcher_t));
        if (watcherP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
        memset(watcherP, 0, sizeof(lwm2m_watcher_t));
        watcherP->server = serverP;
        watcherP->next = observedP->watcherList;
        observedP->watcherList = watcherP;
    }

    watcherP->tokenLen = message->token_len;
    memcpy(watcherP->token, message->token, message->token_len);

    coap_set_header_observe(response, watcherP->counter++);

    return COAP_205_CONTENT;
}

static int prv_extractAttribute(uint8_t* buffer, uint16_t *attributes)
{
    int retValue = 0; // all is happy

    *attributes = 0;
    while (NULL != buffer)
    {
        if (('0' <= *buffer) && ('9' >= *buffer))
        {
            *attributes *= 10;
            *attributes += *buffer - '0';
            buffer++;
        }

        else
            break;
    }

    return retValue;
}

coap_status_t write_observe_attributes(lwm2m_context_t * contextP,
                                     lwm2m_uri_t * uriP,
                                     lwm2m_server_t * serverP,
                                     coap_packet_t * message,
                                     coap_packet_t * response)
{
    if (!LWM2M_URI_IS_SET_INSTANCE(uriP) && LWM2M_URI_IS_SET_RESOURCE(uriP)) return COAP_400_BAD_REQUEST;

    /**
     * OMA-TS-LightweightM2M-V1_0-20141126-C  Section 8.2.4, Page 56:
     * If the URI is not observed, the LWM2M Client MUST ignore the request and respond �2.04 Changed� to the LWM2M Server.
     */
    lwm2m_observed_t *observedP = prv_findObserved(contextP, uriP);
    if (NULL == observedP) return COAP_204_CHANGED;

    coap_status_t retValue = COAP_204_CHANGED;
    multi_option_t *query = message->uri_query;

    lwm2m_attributes_t newAttributes = { 0 };
    if (observedP->attrib != NULL)
    {
        memcpy(&newAttributes, observedP->attrib, sizeof(lwm2m_attributes_t));
    }

    while (NULL != query)
    {
        if (0 == strncmp(query->data, "cancel", 6))
        {
            if (observedP != NULL)
            {
                prv_unlinkObserved(contextP, observedP);
                lwm2m_free(observedP->attrib);
                lwm2m_free(observedP);
            }

            return COAP_204_CHANGED;
        }

        else if (0 == strncmp(query->data, "st=", 3))
        {
            /* Greater Than, Less Than, and Step MUST be specified only when Resource ID is indicated.  */
            if (LWM2M_URI_IS_SET_RESOURCE(uriP) == false)
            {
                newAttributes.flag = 0;
                break;
            }

            prv_extractAttribute(query->data + 3, &(newAttributes.step));
            newAttributes.flag |= LWM2M_ATTRIB_FLAG_STEP_ID;
        }

        else if (0 == strncmp(query->data, "gt=", 3))
        {
            /* Greater Than, Less Than, and Step MUST be specified only when Resource ID is indicated.  */
            if (LWM2M_URI_IS_SET_RESOURCE(uriP) == false)
            {
                newAttributes.flag = 0;
                break;
            }

            prv_extractAttribute(query->data + 3, &(newAttributes.greater_then));
            newAttributes.flag |= LWM2M_ATTRIB_FLAG_GT_ID;
        }

        else if (0 == strncmp(query->data, "lt=", 3))
        {
            /* Greater Than, Less Than, and Step MUST be specified only when Resource ID is indicated.  */
            if (LWM2M_URI_IS_SET_RESOURCE(uriP) == false)
            {
                newAttributes.flag = 0;
                break;
            }

            prv_extractAttribute(query->data + 3, &(newAttributes.less_then));
            newAttributes.flag |= LWM2M_ATTRIB_FLAG_LT_ID;
        }

        else if (0 == strncmp(query->data, "pmax=", 5))
        {
            if ((newAttributes.flag & LWM2M_ATTRIB_FLAG_PMIN_ID) == 0)
            {
                newAttributes.flag = 0;
                break;
            }

            prv_extractAttribute(query->data + 5, &(newAttributes.pmax));
            if (newAttributes.pmax < newAttributes.pmin)
            {
                newAttributes.flag = 0;
                break;
            }

            newAttributes.flag |= LWM2M_ATTRIB_FLAG_PMAX_ID;
        }

        else if (0 == strncmp(query->data, "pmin=", 5))
        {
            prv_extractAttribute(query->data + 5, &(newAttributes.pmin));
            if (((newAttributes.flag & LWM2M_ATTRIB_FLAG_PMAX_ID) == LWM2M_ATTRIB_FLAG_PMAX_ID) && (newAttributes.pmax < newAttributes.pmin))
            {
                newAttributes.flag = 0;
                break;
            }

            newAttributes.flag |= LWM2M_ATTRIB_FLAG_PMIN_ID;
        }

        query = query->next;
    }

    if (newAttributes.flag == 0)
    {
        retValue = COAP_400_BAD_REQUEST;
    }

    else
    {
        lwm2m_object_t *pGlobalObject = contextP->objectList[2];
        pGlobalObject->objID = uriP->objectId;
        if (pGlobalObject->writeAttributesFunc(uriP, &newAttributes) != COAP_204_CHANGED)
            return COAP_400_BAD_REQUEST;

        if (NULL == observedP->attrib)
        {
            observedP->attrib = (lwm2m_attributes_t *)lwm2m_malloc(sizeof(lwm2m_attributes_t));
            if (NULL == observedP->attrib) return COAP_500_INTERNAL_SERVER_ERROR;
            memset(observedP->attrib, 0, sizeof(lwm2m_attributes_t));
        }

        /*
        * In this implementation, multiple 'write attributes' requests are cumulative.
        * QUESTION: Does the OMA-TS-LightweightM2M-V1_0-20141126-C say anything about this?
        */
        observedP->attrib->flag |= newAttributes.flag;
        if ((newAttributes.flag & LWM2M_ATTRIB_FLAG_GT_ID) == LWM2M_ATTRIB_FLAG_GT_ID)
        {
            observedP->attrib->greater_then = newAttributes.greater_then;
        }

        if ((newAttributes.flag & LWM2M_ATTRIB_FLAG_LT_ID) == LWM2M_ATTRIB_FLAG_LT_ID)
        {
            observedP->attrib->less_then = newAttributes.less_then;
        }

        if ((newAttributes.flag & LWM2M_ATTRIB_FLAG_STEP_ID) == LWM2M_ATTRIB_FLAG_STEP_ID)
        {
            observedP->attrib->step = newAttributes.step;
        }

        if ((newAttributes.flag & LWM2M_ATTRIB_FLAG_PMAX_ID) == LWM2M_ATTRIB_FLAG_PMAX_ID)
        {
            observedP->attrib->pmax = newAttributes.pmax;
        }

        if ((newAttributes.flag & LWM2M_ATTRIB_FLAG_PMIN_ID) == LWM2M_ATTRIB_FLAG_PMIN_ID)
        {
            observedP->attrib->pmin = newAttributes.pmin;
        }
    }

    return retValue;
}

#if defined(COAP_TCP)

void cancel_observe(lwm2m_context_t * contextP, void * fromSessionH)
{
    // NO OP. The request should have failed up stream.
    //
}

#else

void cancel_observe(lwm2m_context_t * contextP,
                    uint16_t mid,
                    void * fromSessionH)
{
    lwm2m_observed_t * observedP;

    LOG("cancel_observe()\r\n");

    for (observedP = contextP->observedList;
         observedP != NULL;
         observedP = observedP->next)
    {
        lwm2m_watcher_t * targetP = NULL;

        if (
			observedP->watcherList->lastMid == mid &&
			observedP->watcherList->server->sessionH == fromSessionH)
        {
            targetP = observedP->watcherList;
            observedP->watcherList = observedP->watcherList->next;
        }
        else
        {
            lwm2m_watcher_t * parentP;

            parentP = observedP->watcherList;
            while (parentP->next != NULL && 
				(parentP->next->lastMid != mid || parentP->next->server->sessionH != fromSessionH))
			{
                parentP = parentP->next;
            }
            if (parentP->next != NULL)
            {
                targetP = parentP->next;
                parentP->next = parentP->next->next;
            }
        }
        if (targetP != NULL)
        {
            lwm2m_free(targetP);
            if (observedP->watcherList == NULL)
            {
                prv_unlinkObserved(contextP, observedP);
                if (NULL != observedP->attrib)
                {
                    lwm2m_free(observedP->attrib);
                    observedP->attrib = NULL;
                }
                lwm2m_free(observedP);
            }
            return;
        }
    }
}
#endif

void lwm2m_resource_value_changed(lwm2m_context_t * contextP,
                                  lwm2m_uri_t * uriP)
{
    int result;
    obs_list_t * listP;
    lwm2m_watcher_t * watcherP;

    listP = prv_getObservedList(contextP, uriP);
    while (listP != NULL)
    {
        obs_list_t * targetP;
        uint8_t * buffer = NULL;
        size_t length = 0;
        lwm2m_media_type_t format;

        format = LWM2M_CONTENT_TEXT;
        result = object_read(contextP, &listP->item->uri, &format, &buffer, &length);
        if (result == COAP_205_CONTENT)
        {
            coap_packet_t message[1];

            coap_init_message(message, COAP_TYPE_NON, COAP_205_CONTENT
#if !defined(COAP_TCP)
				, 0
#endif
				);
            coap_set_header_content_type(message, format);
            coap_set_payload(message, buffer, length);

            for (watcherP = listP->item->watcherList ; watcherP != NULL ; watcherP = watcherP->next)
            {
#if !defined(COAP_TCP)
				watcherP->lastMid = contextP->nextMID++;
                message->mid = watcherP->lastMid;
#endif
				coap_set_header_token(message, watcherP->token, watcherP->tokenLen);
                coap_set_header_observe(message, watcherP->counter++);
                (void)message_send(contextP, message, watcherP->server->sessionH);
            }
        }

        targetP = listP;
        listP = listP->next;
        lwm2m_free(targetP);
    }

}
#endif

#ifdef LWM2M_SERVER_MODE
static lwm2m_observation_t * prv_findObservationByURI(lwm2m_client_t * clientP,
                                                      lwm2m_uri_t * uriP)
{
    lwm2m_observation_t * targetP;

    targetP = clientP->observationList;
    while (targetP != NULL)
    {
        if (targetP->uri.objectId == uriP->objectId
         && targetP->uri.flag == uriP->flag
         && targetP->uri.instanceId == uriP->instanceId
         && targetP->uri.resourceId == uriP->resourceId)
        {
            return targetP;
        }

        targetP = targetP->next;
    }

    return targetP;
}

void observation_remove(lwm2m_client_t * clientP,
                        lwm2m_observation_t * observationP)
{
    clientP->observationList = (lwm2m_observation_t *) LWM2M_LIST_RM(clientP->observationList, observationP->id, NULL);
    lwm2m_free(observationP);
}

static void prv_obsRequestCallback(lwm2m_transaction_t * transacP,
                                   void * message)
{
    lwm2m_observation_t * observationP = (lwm2m_observation_t *)transacP->userData;
    coap_packet_t * packet = (coap_packet_t *)message;
    uint8_t code;

    switch (observationP->status)
    {
    case STATE_DEREG_PENDING:
        // Observation was canceled by the user.
        observation_remove(((lwm2m_client_t*)transacP->peerP), observationP);
        return;

    case STATE_REG_PENDING:
        observationP->status = STATE_REGISTERED;
        break;

    default:
        break;
    }

    if (message == NULL)
    {
        code = COAP_503_SERVICE_UNAVAILABLE;
    }
    else if (packet->code == COAP_205_CONTENT
         && !IS_OPTION(packet, COAP_OPTION_OBSERVE))
    {
        code = COAP_405_METHOD_NOT_ALLOWED;
    }
    else
    {
        code = packet->code;
    }

    if (code != COAP_205_CONTENT)
    {
        observationP->callback(((lwm2m_client_t*)transacP->peerP)->internalID,
                               &observationP->uri,
                               code,
                               LWM2M_CONTENT_TEXT, NULL, 0,
                               observationP->userData);
        observation_remove(((lwm2m_client_t*)transacP->peerP), observationP);
    }
    else
    {
        observationP->callback(((lwm2m_client_t*)transacP->peerP)->internalID,
                               &observationP->uri,
                               0,
                               packet->content_type, packet->payload, packet->payload_len,
                               observationP->userData);
    }
}

int lwm2m_observe(lwm2m_context_t * contextP,
                  uint16_t clientID,
                  lwm2m_uri_t * uriP,
                  lwm2m_result_callback_t callback,
                  void * userData)
{
    lwm2m_client_t * clientP;
    lwm2m_transaction_t * transactionP;
    lwm2m_observation_t * observationP;
    uint8_t token[4];

    if (!LWM2M_URI_IS_SET_INSTANCE(uriP) && LWM2M_URI_IS_SET_RESOURCE(uriP)) return COAP_400_BAD_REQUEST;

    clientP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)contextP->clientList, clientID);
    if (clientP == NULL) return COAP_404_NOT_FOUND;

    observationP = (lwm2m_observation_t *)lwm2m_malloc(sizeof(lwm2m_observation_t));
    if (observationP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
    memset(observationP, 0, sizeof(lwm2m_observation_t));

    observationP->id = lwm2m_list_newId((lwm2m_list_t *)clientP->observationList);
    memcpy(&observationP->uri, uriP, sizeof(lwm2m_uri_t));
    observationP->clientP = clientP;
    observationP->status = STATE_REG_PENDING;
    observationP->callback = callback;
    observationP->userData = userData;

    token[0] = clientP->internalID >> 8;
    token[1] = clientP->internalID & 0xFF;
    token[2] = observationP->id >> 8;
    token[3] = observationP->id & 0xFF;

    transactionP = transaction_new(COAP_TYPE_CON, COAP_GET, clientP->altPath, uriP, contextP->nextMID++, 4, token, ENDPOINT_CLIENT, (void *)clientP);
    if (transactionP == NULL)
    {
        lwm2m_free(observationP);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    observationP->clientP->observationList = (lwm2m_observation_t *)LWM2M_LIST_ADD(observationP->clientP->observationList, observationP);

    coap_set_header_observe(transactionP->message, 0);
    coap_set_header_token(transactionP->message, token, sizeof(token));

    transactionP->callback = prv_obsRequestCallback;
    transactionP->userData = (void *)observationP;

    contextP->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(contextP->transactionList, transactionP);

    return transaction_send(contextP, transactionP);
}

int lwm2m_observe_cancel(lwm2m_context_t * contextP,
                         uint16_t clientID,
                         lwm2m_uri_t * uriP,
                         lwm2m_result_callback_t callback,
                         void * userData)
{
    lwm2m_client_t * clientP;
    lwm2m_observation_t * observationP;

    clientP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)contextP->clientList, clientID);
    if (clientP == NULL) return COAP_404_NOT_FOUND;

    observationP = prv_findObservationByURI(clientP, uriP);
    if (observationP == NULL) return COAP_404_NOT_FOUND;

    switch (observationP->status)
    {
    case STATE_REGISTERED:
        observation_remove(clientP, observationP);
        break;

    case STATE_REG_PENDING:
        observationP->status = STATE_DEREG_PENDING;
        break;

    default:
        // Should not happen
        break;
    }

    return 0;
}

bool handle_observe_notify(lwm2m_context_t * contextP,
                           void * fromSessionH,
                           coap_packet_t * message,
        				   coap_packet_t * response)
{
    uint8_t * tokenP;
    int token_len;
    uint16_t clientID;
    uint16_t obsID;
    lwm2m_client_t * clientP;
    lwm2m_observation_t * observationP;
    uint32_t count;

    token_len = coap_get_header_token(message, (const uint8_t **)&tokenP);
    if (token_len != sizeof(uint32_t)) return false;

    if (1 != coap_get_header_observe(message, &count)) return false;

    clientID = (tokenP[0] << 8) | tokenP[1];
    obsID = (tokenP[2] << 8) | tokenP[3];

    clientP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)contextP->clientList, clientID);
    if (clientP == NULL) return false;

    observationP = (lwm2m_observation_t *)lwm2m_list_find((lwm2m_list_t *)clientP->observationList, obsID);
    if (observationP == NULL)
    {
        coap_init_message(response, COAP_TYPE_RST, 0
#if !defined(COAP_TCP)
            , message->mid
#endif
            );
        message_send(contextP, response, fromSessionH);
    }
    else
    {
        if (message->type == COAP_TYPE_CON ) {
            coap_init_message(response, COAP_TYPE_ACK, 0
#if !defined(COAP_TCP)
                , message->mid
#endif
                );
            message_send(contextP, response, fromSessionH);
        }
        observationP->callback(clientID,
                               &observationP->uri,
                               (int)count,
                               message->content_type, message->payload, message->payload_len,
                               observationP->userData);
    }
    return true;
}
#endif
