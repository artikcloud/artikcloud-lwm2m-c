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

static lwm2m_watcher_t * prv_getWatcher(lwm2m_context_t * contextP,
                                        lwm2m_uri_t * uriP,
                                        lwm2m_server_t * serverP)
{
    lwm2m_observed_t * observedP;
    bool allocatedObserver;
    lwm2m_watcher_t * watcherP;

    allocatedObserver = false;

    observedP = prv_findObserved(contextP, uriP);
    if (observedP == NULL)
    {
        observedP = (lwm2m_observed_t *)lwm2m_malloc(sizeof(lwm2m_observed_t));
        if (observedP == NULL) return NULL;
        allocatedObserver = true;
        memset(observedP, 0, sizeof(lwm2m_observed_t));
        memcpy(&(observedP->uri), uriP, sizeof(lwm2m_uri_t));
        observedP->next = contextP->observedList;
        contextP->observedList = observedP;
    }

    watcherP = prv_findWatcher(observedP, serverP);
    if (watcherP == NULL)
    {
        watcherP = (lwm2m_watcher_t *)lwm2m_malloc(sizeof(lwm2m_watcher_t));
        if (watcherP == NULL)
        {
            if (allocatedObserver == true)
            {
                lwm2m_free(observedP);
            }
            return NULL;
        }
        memset(watcherP, 0, sizeof(lwm2m_watcher_t));
        watcherP->active = false;
        watcherP->server = serverP;
        watcherP->next = observedP->watcherList;
        observedP->watcherList = watcherP;
    }

    return watcherP;
}

coap_status_t observe_handleRequest(lwm2m_context_t * contextP,
                                    lwm2m_uri_t * uriP,
                                    lwm2m_server_t * serverP,
                                    int size,
                                    lwm2m_data_t * dataP,
                                    coap_packet_t * message,
                                    coap_packet_t * response)
{
    lwm2m_watcher_t * watcherP;
    uint32_t count;

    LOG("observe_handleRequest()\r\n");

    coap_get_header_observe(message, &count);

    switch (count)
    {
    case 0:
        if (!LWM2M_URI_IS_SET_INSTANCE(uriP) && LWM2M_URI_IS_SET_RESOURCE(uriP)) return COAP_400_BAD_REQUEST;
        if (message->token_len == 0) return COAP_400_BAD_REQUEST;

        watcherP = prv_getWatcher(contextP, uriP, serverP);
        if (watcherP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;

        watcherP->tokenLen = message->token_len;
        memcpy(watcherP->token, message->token, message->token_len);
        watcherP->active = true;
        watcherP->lastTime = lwm2m_gettime();

        if (LWM2M_URI_IS_SET_RESOURCE(uriP))
        {
            switch (dataP->type)
            {
            case LWM2M_TYPE_INTEGER:
                if (1 != lwm2m_data_decode_int(dataP, &(watcherP->lastValue.asInteger))) return COAP_500_INTERNAL_SERVER_ERROR;
                break;
            case LWM2M_TYPE_FLOAT:
                if (1 != lwm2m_data_decode_float(dataP, &(watcherP->lastValue.asFloat))) return COAP_500_INTERNAL_SERVER_ERROR;
                break;
            default:
                break;
            }
        }

        coap_set_header_observe(response, watcherP->counter++);

        return COAP_205_CONTENT;

    case 1:
        // cancellation
        observe_cancel(contextP, LWM2M_MAX_ID, serverP->sessionH);
        return COAP_205_CONTENT;

    default:
        return COAP_400_BAD_REQUEST;
    }
}

void observe_cancel(lwm2m_context_t * contextP,
                    uint16_t mid,
                    void * fromSessionH)
{
    lwm2m_observed_t * observedP;

    LOG("observe_cancel()\r\n");

    for (observedP = contextP->observedList;
         observedP != NULL;
         observedP = observedP->next)
    {
        lwm2m_watcher_t * targetP = NULL;

        if ((LWM2M_MAX_ID == mid || observedP->watcherList->lastMid == mid)
         && lwm2m_session_is_equal(observedP->watcherList->server->sessionH, fromSessionH, contextP->userData))
        {
            targetP = observedP->watcherList;
            observedP->watcherList = observedP->watcherList->next;
        }
        else
        {
            lwm2m_watcher_t * parentP;

            parentP = observedP->watcherList;
            while (parentP->next != NULL
                && (parentP->next->lastMid != mid
                 || lwm2m_session_is_equal(parentP->next->server->sessionH, fromSessionH, contextP->userData)))
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
                lwm2m_free(observedP);
            }
            return;
        }
    }
}

coap_status_t observe_setParameters(lwm2m_context_t * contextP,
                                    lwm2m_uri_t * uriP,
                                    lwm2m_server_t * serverP,
                                    lwm2m_attributes_t * attrP)
{
    uint8_t result;
    lwm2m_watcher_t * watcherP;

    LOG("observe_set_parameters([/%d/%d/%d])\r\n", uriP->objectId, uriP->instanceId, uriP->resourceId);

    if (!LWM2M_URI_IS_SET_INSTANCE(uriP) && LWM2M_URI_IS_SET_RESOURCE(uriP)) return COAP_400_BAD_REQUEST;

    result = object_checkReadable(contextP, uriP);
    if (COAP_205_CONTENT != result) return result;

    if (0 != (attrP->toSet & ATTR_FLAG_NUMERIC))
    {
        result = object_checkNumeric(contextP, uriP);
        if (COAP_205_CONTENT != result) return result;
    }

    watcherP = prv_getWatcher(contextP, uriP, serverP);
    if (watcherP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;

    // Check rule “lt” value + 2*”stp” values < “gt” value
    if ((((attrP->toSet | (watcherP->parameters?watcherP->parameters->toSet:0)) & ~attrP->toClear) & ATTR_FLAG_NUMERIC) == ATTR_FLAG_NUMERIC)
    {
        float gt;
        float lt;
        float stp;

        if (0 != (attrP->toSet & LWM2M_ATTR_FLAG_GREATER_THAN))
        {
            gt = attrP->greaterThan;
        }
        else
        {
            gt = watcherP->parameters->greaterThan;
        }
        if (0 != (attrP->toSet & LWM2M_ATTR_FLAG_LESS_THAN))
        {
            lt = attrP->lessThan;
        }
        else
        {
            lt = watcherP->parameters->lessThan;
        }
        if (0 != (attrP->toSet & LWM2M_ATTR_FLAG_STEP))
        {
            stp = attrP->step;
        }
        else
        {
            stp = watcherP->parameters->step;
        }

        if (lt + (2 * stp) >= gt) return COAP_400_BAD_REQUEST;
    }

    if (watcherP->parameters == NULL)
    {
        if (attrP->toSet != 0)
        {
            watcherP->parameters = (lwm2m_attributes_t *)lwm2m_malloc(sizeof(lwm2m_attributes_t));
            if (watcherP->parameters == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
            memcpy(watcherP->parameters, attrP, sizeof(lwm2m_attributes_t));
        }
    }
    else
    {
        watcherP->parameters->toSet &= ~attrP->toClear;
        if (attrP->toSet & LWM2M_ATTR_FLAG_MIN_PERIOD)
        {
            watcherP->parameters->minPeriod = attrP->minPeriod;
        }
        if (attrP->toSet & LWM2M_ATTR_FLAG_MAX_PERIOD)
        {
            watcherP->parameters->maxPeriod = attrP->maxPeriod;
        }
        if (attrP->toSet & LWM2M_ATTR_FLAG_GREATER_THAN)
        {
            watcherP->parameters->greaterThan = attrP->greaterThan;
        }
        if (attrP->toSet & LWM2M_ATTR_FLAG_LESS_THAN)
        {
            watcherP->parameters->lessThan = attrP->lessThan;
        }
        if (attrP->toSet & LWM2M_ATTR_FLAG_STEP)
        {
            watcherP->parameters->step = attrP->step;
        }
    }

    LOG("PMIN = %d, PMAX = %d)\r\n", attrP->minPeriod, attrP->maxPeriod);
    return COAP_204_CHANGED;
}

lwm2m_observed_t * observe_findByUri(lwm2m_context_t * contextP,
                                     lwm2m_uri_t * uriP)
{
    lwm2m_observed_t * targetP;

    targetP = contextP->observedList;
    while (targetP != NULL)
    {
        if (targetP->uri.objectId == uriP->objectId)
        {
            if ((!LWM2M_URI_IS_SET_INSTANCE(uriP) && !LWM2M_URI_IS_SET_INSTANCE(&(targetP->uri)))
             || (LWM2M_URI_IS_SET_INSTANCE(uriP) && LWM2M_URI_IS_SET_INSTANCE(&(targetP->uri)) && (uriP->instanceId == targetP->uri.instanceId)))
             {
                 if ((!LWM2M_URI_IS_SET_RESOURCE(uriP) && !LWM2M_URI_IS_SET_RESOURCE(&(targetP->uri)))
                     || (LWM2M_URI_IS_SET_RESOURCE(uriP) && LWM2M_URI_IS_SET_RESOURCE(&(targetP->uri)) && (uriP->resourceId == targetP->uri.resourceId)))
                 {
                     return targetP;
                 }
             }
        }
        targetP = targetP->next;
    }

    return NULL;
}

void lwm2m_resource_value_changed(lwm2m_context_t * contextP,
                                  lwm2m_uri_t * uriP)
{
    lwm2m_observed_t * targetP;

    LOG("lwm2m_resource_value_changed(/%d/%d/%d)\n", uriP->objectId, uriP->instanceId, uriP->resourceId);
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
                    lwm2m_watcher_t * watcherP;

                    for (watcherP = targetP->watcherList ; watcherP != NULL ; watcherP = watcherP->next)
                    {
                        if ( watcherP->active == true) watcherP->update = true;
                    }
                }
            }
        }
        targetP = targetP->next;
    }
}

void observe_step(lwm2m_context_t * contextP,
                  time_t currentTime,
                  time_t * timeoutP)
{
    lwm2m_observed_t * targetP;

    for (targetP = contextP->observedList ; targetP != NULL ; targetP = targetP->next)
    {
        lwm2m_watcher_t * watcherP;
        uint8_t * buffer = NULL;
        size_t length = 0;
        lwm2m_data_t * dataP = NULL;
        int size = 0;
        double floatValue = 0;
        int64_t integerValue = 0;
        bool storeValue = false;
        lwm2m_media_type_t format = LWM2M_CONTENT_TEXT;
        coap_packet_t message[1];
        time_t interval;

        if (LWM2M_URI_IS_SET_RESOURCE(&targetP->uri))
        {
            if (COAP_205_CONTENT != object_readData(contextP, &targetP->uri, &size, &dataP)) continue;
            switch (dataP->type)
            {
            case LWM2M_TYPE_INTEGER:
                if (1 != lwm2m_data_decode_int(dataP, &integerValue)) continue;
                storeValue = true;
                break;
            case LWM2M_TYPE_FLOAT:
                if (1 != lwm2m_data_decode_float(dataP, &floatValue)) continue;
                storeValue = true;
                break;
            default:
                break;
            }
        }
        for (watcherP = targetP->watcherList ; watcherP != NULL ; watcherP = watcherP->next)
        {
            if (watcherP->active == true)
            {
                bool notify = false;

                if (watcherP->update == true)
                {
                    // value changed, should we notify the server ?

                    if (watcherP->parameters == NULL || watcherP->parameters->toSet == 0)
                    {
                        // no conditions
                        notify = true;
                        LOG("observation_step(/%d/%d/%d) notify[1] = TRUE\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId);
                    }

                    if (notify == false
                     && watcherP->parameters != NULL
                     && (watcherP->parameters->toSet & ATTR_FLAG_NUMERIC) != 0)
                    {
                        if ((watcherP->parameters->toSet & LWM2M_ATTR_FLAG_LESS_THAN) != 0)
                        {
                            // Did we cross the lower treshold ?
                            switch (dataP->type)
                            {
                            case LWM2M_TYPE_INTEGER:
                                if ((integerValue <= watcherP->parameters->lessThan
                                  && watcherP->lastValue.asInteger > watcherP->parameters->lessThan)
                                 || (integerValue >= watcherP->parameters->lessThan
                                  && watcherP->lastValue.asInteger < watcherP->parameters->lessThan))
                                {
                                    notify = true;
                                }
                                break;
                            case LWM2M_TYPE_FLOAT:
                                if ((floatValue <= watcherP->parameters->lessThan
                                  && watcherP->lastValue.asFloat > watcherP->parameters->lessThan)
                                 || (floatValue >= watcherP->parameters->lessThan
                                  && watcherP->lastValue.asFloat < watcherP->parameters->lessThan))
                                {
                                    notify = true;
                                }
                                break;
                            default:
                                break;
                            }
                            LOG("observation_step(/%d/%d/%d) notify[2] = %s\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId, notify ? "TRUE" : "FALSE");
                        }
                        if ((watcherP->parameters->toSet & LWM2M_ATTR_FLAG_GREATER_THAN) != 0)
                        {
                            // Did we cross the upper treshold ?
                            switch (dataP->type)
                            {
                            case LWM2M_TYPE_INTEGER:
                                if ((integerValue <= watcherP->parameters->greaterThan
                                  && watcherP->lastValue.asInteger > watcherP->parameters->greaterThan)
                                 || (integerValue >= watcherP->parameters->greaterThan
                                  && watcherP->lastValue.asInteger < watcherP->parameters->greaterThan))
                                {
                                    notify = true;
                                }
                                break;
                            case LWM2M_TYPE_FLOAT:
                                if ((floatValue <= watcherP->parameters->greaterThan
                                  && watcherP->lastValue.asFloat > watcherP->parameters->greaterThan)
                                 || (floatValue >= watcherP->parameters->greaterThan
                                  && watcherP->lastValue.asFloat < watcherP->parameters->greaterThan))
                                {
                                    notify = true;
                                }
                                break;
                            default:
                                break;
                            }
                            LOG("observation_step(/%d/%d/%d) notify[3] = %s\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId, notify ? "TRUE" : "FALSE");
                        }
                        if ((watcherP->parameters->toSet & LWM2M_ATTR_FLAG_STEP) != 0)
                        {
                            switch (dataP->type)
                            {
                            case LWM2M_TYPE_INTEGER:
                            {
                                int64_t diff;

                                diff = integerValue - watcherP->lastValue.asInteger;
                                if ((diff < 0 && (0 - diff) >= watcherP->parameters->step)
                                 || (diff >= 0 && diff >= watcherP->parameters->step))
                                {
                                    notify = true;
                                }
                            }
                                break;
                            case LWM2M_TYPE_FLOAT:
                            {
                                double diff;

                                diff = floatValue - watcherP->lastValue.asFloat;
                                if ((diff < 0 && (0 - diff) >= watcherP->parameters->step)
                                 || (diff >= 0 && diff >= watcherP->parameters->step))
                                {
                                    notify = true;
                                }
                            }
                                break;
                            default:
                                break;
                            }
                            LOG("observation_step(/%d/%d/%d) notify[4] = %s\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId, notify? "TRUE" : "FALSE");
                        }
                    }

                    if (watcherP->parameters != NULL
                     && (watcherP->parameters->toSet & LWM2M_ATTR_FLAG_MIN_PERIOD) != 0)
                    {
                        if (watcherP->lastTime + watcherP->parameters->minPeriod > currentTime)
                        {
                            // Minimum Period did not elapse yet
                            interval = watcherP->lastTime + watcherP->parameters->minPeriod - currentTime;
                            if (*timeoutP > interval) *timeoutP = interval;
                            notify = false;
                        }
                        else
                        {
                            notify = true;
                        }
                        LOG("observation_step(/%d/%d/%d) notify[5] = %s\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId, notify ? "TRUE" : "FALSE");
                    }
                }

                // Is the Maximum Period reached ?
                if (notify == false
                 && watcherP->parameters != NULL
                 && (watcherP->parameters->toSet & LWM2M_ATTR_FLAG_MAX_PERIOD) != 0)
                {
                    if (watcherP->lastTime + watcherP->parameters->maxPeriod <= currentTime)
                    {
                        notify = true;
                    }
                    LOG("observation_step(/%d/%d/%d) notify[6] = %s\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId, notify ? "TRUE" : "FALSE");
                }

                if (notify == true)
                {
                    if (buffer == NULL)
                    {
                        if (dataP != NULL)
                        {
                            length = lwm2m_data_serialize(&targetP->uri, size, dataP, &format, &buffer);
                            if (length == 0) break;
                        }
                        else
                        {
                            if (COAP_205_CONTENT != object_read(contextP, &targetP->uri, &format, &buffer, &length))
                            {
                                buffer = NULL;
                                break;
                            }
                        }
                        coap_init_message(message, watcherP->server->protocol, COAP_TYPE_NON, COAP_205_CONTENT, 0);
                        coap_set_header_content_type(message, format);
                        coap_set_payload(message, buffer, length);
                        LOG("Observe Update[/%d/%d/%d]: %.*s\n", targetP->uri.objectId, targetP->uri.instanceId, targetP->uri.resourceId, length, buffer);
                    }
                    watcherP->lastTime = currentTime;
                    watcherP->lastMid = contextP->nextMID++;
                    message->mid = watcherP->lastMid;
                    coap_set_header_token(message, watcherP->token, watcherP->tokenLen);
                    coap_set_header_observe(message, watcherP->counter++);
                    (void)message_send(contextP, message, watcherP->server->sessionH);
                    watcherP->update = false;
                }

                // Store this value
                if (notify == true && storeValue == true)
                {
                    switch (dataP->type)
                    {
                    case LWM2M_TYPE_INTEGER:
                        watcherP->lastValue.asInteger = integerValue;
                        break;
                    case LWM2M_TYPE_FLOAT:
                        watcherP->lastValue.asFloat = floatValue;
                        break;
                    default:
                        break;
                    }
                }

                if (watcherP->parameters != NULL && (watcherP->parameters->toSet & LWM2M_ATTR_FLAG_MAX_PERIOD) != 0)
                {
                    // update timers
                    interval = watcherP->lastTime + watcherP->parameters->maxPeriod - currentTime;
                    if (*timeoutP > interval) *timeoutP = interval;
                }
            }
        }
        if (dataP != NULL) lwm2m_data_free(size, dataP);
        if (buffer != NULL) lwm2m_free(buffer);
    }
}

#endif

#ifdef LWM2M_SERVER_MODE

typedef struct
{
    lwm2m_observation_t * observationP;
    lwm2m_result_callback_t callbackP;
    void * userDataP;
} cancellation_data_t;

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

void observe_remove(lwm2m_client_t * clientP,
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
        observe_remove(((lwm2m_client_t*)transacP->peerP), observationP);
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
        observe_remove(((lwm2m_client_t*)transacP->peerP), observationP);
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


static void prv_obsCancelRequestCallback(lwm2m_transaction_t * transacP,
                                         void * message)
{
    cancellation_data_t * cancelP = (cancellation_data_t *)transacP->userData;
    coap_packet_t * packet = (coap_packet_t *)message;
    uint8_t code;

    if (message == NULL)
    {
        code = COAP_503_SERVICE_UNAVAILABLE;
    }
    else
    {
        code = packet->code;
    }

    if (code != COAP_205_CONTENT)
    {
        cancelP->callbackP(((lwm2m_client_t*)transacP->peerP)->internalID,
                           &cancelP->observationP->uri,
                           code,
                           LWM2M_CONTENT_TEXT, NULL, 0,
                           cancelP->userDataP);
    }
    else
    {
        cancelP->callbackP(((lwm2m_client_t*)transacP->peerP)->internalID,
                           &cancelP->observationP->uri,
                           0,
                           packet->content_type, packet->payload, packet->payload_len,
                           cancelP->userDataP);
    }

    observe_remove(((lwm2m_client_t*)transacP->peerP), cancelP->observationP);

    lwm2m_free(cancelP);
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
    {
        lwm2m_transaction_t * transactionP;
        cancellation_data_t * cancelP;

        transactionP = transaction_new(COAP_TYPE_CON, COAP_GET, clientP->altPath, uriP, contextP->nextMID++, 0, NULL, ENDPOINT_CLIENT, (void *)clientP);
        if (transactionP == NULL)
        {
            return COAP_500_INTERNAL_SERVER_ERROR;
        }
        cancelP = (cancellation_data_t *)lwm2m_malloc(sizeof(cancellation_data_t));
        if (cancelP == NULL)
        {
            lwm2m_free(transactionP);
            return COAP_500_INTERNAL_SERVER_ERROR;
        }

        coap_set_header_observe(transactionP->message, 1);

        cancelP->observationP = observationP;
        cancelP->callbackP = callback;
        cancelP->userDataP = userData;

        transactionP->callback = prv_obsCancelRequestCallback;
        transactionP->userData = (void *)cancelP;

        contextP->transactionList = (lwm2m_transaction_t *)LWM2M_LIST_ADD(contextP->transactionList, transactionP);

        return transaction_send(contextP, transactionP);
    }

    case STATE_REG_PENDING:
        observationP->status = STATE_DEREG_PENDING;
        break;

    default:
        // Should not happen
        break;
    }

    return COAP_NO_ERROR;
}

bool observe_handleNotify(lwm2m_context_t * contextP,
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
        coap_init_message(response, COAP_TYPE_RST, 0, message->mid);
        message_send(contextP, response, fromSessionH);
    }
    else
    {
        if (message->type == COAP_TYPE_CON ) {
            coap_init_message(response, COAP_TYPE_ACK, 0, message->mid);
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
