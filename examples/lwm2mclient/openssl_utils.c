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
 *    Camille Bégué, Samsung - Please refer to git log
 *
 *******************************************************************************/
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "pem_utils.h"

bool convert_pem_privatekey_to_der(const char *private_key_pem, char **private_key_der, uint16_t *len)
{
	EVP_PKEY *key = NULL;
	BIO *bio = NULL;
	bool ret = false;

	*private_key_der = NULL;

	bio = BIO_new_mem_buf(private_key_pem, -1);
	if (!bio) {
		goto exit;
	}

	key = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
	if (!key) {
		goto exit;
	}

	*len = i2d_PrivateKey(key, (unsigned char **)private_key_der);
	if (len < 0) {
		goto exit;
	}

	ret = true;

exit:
	if (bio) {
		BIO_free(bio);
	}

	if (key) {
		EVP_PKEY_free(key);
	}

	return ret;
}

bool convert_pem_x509_to_der(const char *cert_buffer_pem, char **cert_buffer_der, uint16_t *len)
{
    X509 *x509 = NULL;
    BIO *bio = NULL;
    bool ret = false;

    *cert_buffer_der = NULL;
    bio = BIO_new_mem_buf(cert_buffer_pem, -1);
    if (!bio)
    {
        goto exit;
    }

    x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!x509)
    {
        goto exit;
    }

    *len = i2d_X509(x509, (unsigned char **)cert_buffer_der);
    if (len < 0)
    {
        goto exit;
    }

    ret = true;

exit:
    if (bio)
    {
        BIO_free(bio);
    }

    if (x509)
    {
        X509_free(x509);
    }

    return ret;
}
