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
 *    Pascal Rieux - Please refer to git log
 *    
 *******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "connection.h"

int create_socket(const char * portStr)
{
    int s = -1;
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

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

#include "errno.h"
int make_server_socket(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
    {
        printf("*****Failed to make a socket!*****\n");
    }

    else
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        {
            printf("****Failed to bind socket to port:%d!****\n", port);
            return -1;
        }

		if (listen(s, 5) < 0)
		{
			fprintf(stderr, "Error listening on server socket: %d\r\n", errno);
			return -1;
		}
    }

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

connection_t * connection_new_incoming(connection_t * connList,
                                       int sock,
                                       struct sockaddr * addr,
                                       size_t addrLen)
{
    connection_t * connP;

    connP = (connection_t *)malloc(sizeof(connection_t));
    if (connP != NULL)
    {
        connP->sock = sock;
        memcpy(&(connP->addr), addr, addrLen);
        connP->addrLen = addrLen;
        connP->next = connList;
    }

    return connP;
}

connection_t * connection_create(connection_t * connList,
                                 int sock,
                                 char * host,
                                 char * port)
{
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    struct addrinfo *p;
    int s;
    struct sockaddr *sa;
    socklen_t sl;
    connection_t * connP = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (0 != getaddrinfo(host, port, &hints, &servinfo) || servinfo == NULL) return NULL;

    // we test the various addresses
    s = -1;
    for(p = servinfo ; p != NULL && s == -1 ; p = p->ai_next)
    {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s >= 0)
        {
            sa = p->ai_addr;
            sl = p->ai_addrlen;
            if (-1 == connect(s, p->ai_addr, p->ai_addrlen))
            {
                close(s);
                s = -1;
            }
        }
    }
    if (s >= 0)
    {
        connP = connection_new_incoming(connList, sock, sa, sl);
        close(s);
    }
    if (NULL != servinfo) {
        free(servinfo);
    }

    return connP;
}

void connection_free(connection_t * connList)
{
    while (connList != NULL)
    {
        connection_t * nextP;

        nextP = connList->next;
        free(connList);

        connList = nextP;
    }
}

size_t send_short(int client, size_t value)
{
    uint8_t data[2];

	data[0] = (uint8_t) (value >> 8);
	data[1] = (uint8_t) (value >> 0);

	return send(client, data, 2, 0);
}

size_t send_int(int client, size_t value)
{
    uint8_t data[4];

	data[0] = (uint8_t) (value >> 24);
	data[1] = (uint8_t) (value >> 16);
	data[2] = (uint8_t) (value >> 8 );
	data[3] = (uint8_t) (value >> 0 );

	return send(client, data, 4, 0);
}

int connection_send(connection_t *connP,
                    uint8_t * buffer,
                    size_t length)
{
    int nbSent;
    size_t offset;

#ifdef WITH_LOGS
    char s[INET6_ADDRSTRLEN];
    in_port_t port;

    s[0] = 0;

    inet_ntop(connP->addr.sin6_family, &connP->addr.sin6_addr, s, INET6_ADDRSTRLEN);
    port = connP->addr.sin6_port;

    fprintf(stderr, "Sending %d bytes to [%s]:%hu\r\n", length, s, ntohs(port));

    output_buffer(stderr, buffer, length, 0);
#endif

#if defined(COAP_TCP)
    if (2 != send_short(connP->sock, length)) return -1;
#endif

    offset = 0;
    while (offset != length)
    {
        nbSent = sendto(connP->sock, buffer + offset, length - offset, 0, (struct sockaddr *)&(connP->addr), connP->addrLen);
        if (nbSent == -1) return -1;
        offset += nbSent;
    }
    return 0;
}


