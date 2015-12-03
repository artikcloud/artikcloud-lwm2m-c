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
 *    Fabien Fleutot - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Pascal Rieux - Please refer to git log
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

/*
Contains code snippets which are:

 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.

*/


#include "internals.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>


static void handle_reset(lwm2m_context_t * contextP,
                         void * fromSessionH,
                         coap_packet_t * message)
{
#ifdef LWM2M_CLIENT_MODE
    cancel_observe(contextP,
#if !defined(COAP_TCP)
        message->mid,
#endif
        fromSessionH);
#endif
}

static coap_status_t handle_request(lwm2m_context_t * contextP,
                                    void * fromSessionH,
                                    coap_packet_t * message,
                                    coap_packet_t * response)
{
    lwm2m_uri_t * uriP;
    coap_status_t result = NOT_FOUND_4_04;

#ifdef LWM2M_CLIENT_MODE
    uriP = lwm2m_decode_uri(contextP->altPath, message->uri_path);
#else
    uriP = lwm2m_decode_uri(NULL, message->uri_path);
#endif

    if (uriP == NULL) return BAD_REQUEST_4_00;

    switch(uriP->flag & LWM2M_URI_MASK_TYPE)
    {
#ifdef LWM2M_CLIENT_MODE
    case LWM2M_URI_FLAG_DM:
        // TODO: Authentify server
        result = handle_dm_request(contextP, uriP, fromSessionH, message, response);
        break;

#ifdef LWM2M_BOOTSTRAP
    case LWM2M_URI_FLAG_DELETE_ALL:
        if (COAP_DELETE != message->code)
        {
            result = BAD_REQUEST_4_00;
        }
        else if (NULL == utils_findBootstrapServer(contextP, fromSessionH))
        {
            result = UNAUTHORIZED_4_01;
        }
        else if (BOOTSTRAP_PENDING == contextP->bsState)
        {
            result = handle_delete_all(contextP);
        }
        else
        {
            result = COAP_IGNORE;
        }
        break;

    case LWM2M_URI_FLAG_BOOTSTRAP:
        result = handle_bootstrap_finish(contextP, fromSessionH);
        break;
#endif
#endif

#ifdef LWM2M_SERVER_MODE
    case LWM2M_URI_FLAG_REGISTRATION:
        result = handle_registration_request(contextP, uriP, fromSessionH, message, response);
        break;
#endif
#ifdef LWM2M_BOOTSTRAP_SERVER_MODE
    case LWM2M_URI_FLAG_BOOTSTRAP:
        result = handle_bootstrap_request(contextP, uriP, fromSessionH, message, response);
        break;
#endif
    default:
        result = COAP_IGNORE;
        break;
    }

    coap_set_status_code(response, result);

    if (COAP_IGNORE < result && result < BAD_REQUEST_4_00)
    {
        result = NO_ERROR;
    }

    lwm2m_free(uriP);
    return result;
}

/* This function is an adaptation of function coap_receive() from Erbium's er-coap-13-engine.c.
 * Erbium is Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 */
void lwm2m_handle_packet(lwm2m_context_t * contextP,
                        uint8_t * buffer,
                        int length,
                        void * fromSessionH)
{
    coap_status_t coap_error_code = NO_ERROR;
    static coap_packet_t message[1];
    static coap_packet_t response[1];

    coap_error_code = coap_parse_message(message, buffer, (uint16_t)length);
    if (coap_error_code == NO_ERROR)
    {
#ifdef WITH_LOGS
        if (message->code >= COAP_GET && message->code <= COAP_DELETE)
        {
#if defined(COAP_TCP)
            LOG("    Parsed: ver %u, type %u, tkl %u, code %u\r\n", message->version, message->type, message->token_len, message->code);
#else
            LOG("    Parsed: ver %u, type %u, tkl %u, code %u, mid %u\r\n", message->version, message->type, message->token_len, message->code, message->mid);
#endif
        }
        else
        {
#if defined(COAP_TCP)
            LOG("    Parsed: ver %u, type %u, tkl %u, code %u.%.2u\r\n", message->version, message->type, message->token_len, message->code >> 5, message->code & 0x1F);
#else
            LOG("    Parsed: ver %u, type %u, tkl %u, code %u.%.2u, mid %u\r\n", message->version, message->type, message->token_len, message->code >> 5, message->code & 0x1F, message->mid);
#endif
        }
        LOG("    Content type: %d\r\n    Payload: %.*s\r\n\n", message->content_type, message->payload_len, message->payload);
#endif
        if (message->code >= COAP_GET && message->code <= COAP_DELETE)
        {
            uint32_t block_num = 0;
            uint16_t block_size = REST_MAX_CHUNK_SIZE;
            uint32_t block_offset = 0;
            int64_t new_offset = 0;

            /* prepare response */
#if defined(COAP_TCP)
            coap_init_message(response, COAP_TYPE_NON, CONTENT_2_05);
#else
            if (message->type == COAP_TYPE_CON)
            {
                /* Reliable CON requests are answered with an ACK. */
                coap_init_message(response, COAP_TYPE_ACK, CONTENT_2_05, message->mid);
            }
            else
            {
                /* Unreliable NON requests are answered with a NON. */
                coap_init_message(response, COAP_TYPE_NON, CONTENT_2_05, contextP->nextMID++);
            }
#endif

            /* mirror token */
            if (message->token_len)
            {
                coap_set_header_token(response, message->token, message->token_len);
            }

            /* get offset for blockwise transfers */
            if (coap_get_header_block2(message, &block_num, NULL, &block_size, &block_offset))
            {
                LOG("Blockwise: block request %u (%u/%u) @ %u bytes\n", block_num, block_size, REST_MAX_CHUNK_SIZE, block_offset);
                block_size = MIN(block_size, REST_MAX_CHUNK_SIZE);
                new_offset = block_offset;
            }

            coap_error_code = handle_request(contextP, fromSessionH, message, response);
            if (coap_error_code==NO_ERROR)
            {
                /* Apply blockwise transfers. */
                if ( IS_OPTION(message, COAP_OPTION_BLOCK1) && response->code<BAD_REQUEST_4_00 && !IS_OPTION(response, COAP_OPTION_BLOCK1) )
                {
                    LOG("Block1 NOT IMPLEMENTED\n");

                    coap_error_code = NOT_IMPLEMENTED_5_01;
                    coap_error_message = "NoBlock1Support";
                }
                else if ( IS_OPTION(message, COAP_OPTION_BLOCK2) )
                {
                    /* unchanged new_offset indicates that resource is unaware of blockwise transfer */
                    if (new_offset==block_offset)
                    {
                        LOG("Blockwise: unaware resource with payload length %u/%u\n", response->payload_len, block_size);
                        if (block_offset >= response->payload_len)
                        {
                            LOG("handle_incoming_data(): block_offset >= response->payload_len\n");

                            response->code = BAD_OPTION_4_02;
                            coap_set_payload(response, "BlockOutOfScope", 15); /* a const char str[] and sizeof(str) produces larger code size */
                        }
                        else
                        {
                            coap_set_header_block2(response, block_num, response->payload_len - block_offset > block_size, block_size);
                            coap_set_payload(response, response->payload+block_offset, MIN(response->payload_len - block_offset, block_size));
                        } /* if (valid offset) */
                    }
                    else
                    {
                        /* resource provides chunk-wise data */
                        LOG("Blockwise: blockwise resource, new offset %d\n", (int) new_offset);
                        coap_set_header_block2(response, block_num, new_offset!=-1 || response->payload_len > block_size, block_size);
                        if (response->payload_len > block_size) coap_set_payload(response, response->payload, block_size);
                    } /* if (resource aware of blockwise) */
                }
                else if (new_offset!=0)
                {
                    LOG("Blockwise: no block option for blockwise resource, using block size %u\n", REST_MAX_CHUNK_SIZE);

                    coap_set_header_block2(response, 0, new_offset!=-1, REST_MAX_CHUNK_SIZE);
                    coap_set_payload(response, response->payload, MIN(response->payload_len, REST_MAX_CHUNK_SIZE));
                } /* if (blockwise request) */

                coap_error_code = message_send(contextP, response, fromSessionH);

                lwm2m_free(response->payload);
                response->payload = NULL;
                response->payload_len = 0;
            }
            else if (coap_error_code != COAP_IGNORE)
            {
                if (1 == coap_set_status_code(response, coap_error_code))
                {
                    coap_error_code = message_send(contextP, response, fromSessionH);
                }
            }
        }
        else
        {
            /* Responses */
            switch (message->type)
            {
            case COAP_TYPE_NON:
            case COAP_TYPE_CON:
                {
                    bool done = transaction_handle_response(contextP, fromSessionH, message, response);

#ifdef LWM2M_SERVER_MODE
                    if (!done && IS_OPTION(message, COAP_OPTION_OBSERVE) &&
                        ((message->code == COAP_204_CHANGED) || (message->code == COAP_205_CONTENT)))
                    {
                        done = handle_observe_notify(contextP, fromSessionH, message, response);
                    }
#endif
                    if (!done && message->type == COAP_TYPE_CON )
                    {
#if defined(COAP_TCP)
                        coap_init_message(response, COAP_TYPE_NON, 0);
#else
                        coap_init_message(response, COAP_TYPE_ACK, 0, message->mid);
#endif
                        coap_error_code = message_send(contextP, response, fromSessionH);
                    }
                }
                break;

            case COAP_TYPE_RST:
                /* Cancel possible subscriptions. */
                handle_reset(contextP, fromSessionH, message);
                transaction_handle_response(contextP, fromSessionH, message, NULL);
                break;

            case COAP_TYPE_ACK:
                transaction_handle_response(contextP, fromSessionH, message, NULL);
                break;

            default:
                break;
            }
        } /* Request or Response */
        coap_free_header(message);
    } /* if (parsed correctly) */
    else
    {
        LOG("Message parsing failed %d\r\n", coap_error_code);
    }

    if (coap_error_code != NO_ERROR && coap_error_code != COAP_IGNORE)
    {
        LOG("ERROR %u: %s\n", coap_error_code, coap_error_message);

        /* Set to sendable error code. */
        if (coap_error_code >= 192)
        {
            coap_error_code = INTERNAL_SERVER_ERROR_5_00;
        }

        /* Reuse input buffer for error message. */
#if defined(COAP_TCP)
        coap_init_message(message, COAP_TYPE_NON, coap_error_code);
#else
        coap_init_message(message, COAP_TYPE_ACK, coap_error_code, message->mid);
#endif
        coap_set_payload(message, coap_error_message, strlen(coap_error_message));
        message_send(contextP, message, fromSessionH);
    }
}


coap_status_t message_send(lwm2m_context_t * contextP,
                           coap_packet_t * message,
                           void * sessionH)
{
    coap_status_t result = INTERNAL_SERVER_ERROR_5_00;
    uint8_t * pktBuffer;
    size_t pktBufferLen = 0;
    size_t allocLen;

    allocLen = COAP_MAX_HEADER_SIZE + message->payload_len;
    pktBuffer = (uint8_t *)lwm2m_malloc(allocLen);
    if (pktBuffer != NULL)
    {
        pktBufferLen = coap_serialize_message(message, pktBuffer);
        if (0 != pktBufferLen)
        {
            result = contextP->bufferSendCallback(sessionH, pktBuffer, pktBufferLen, contextP->userData);
        }
        lwm2m_free(pktBuffer);
    }

    return result;
}

