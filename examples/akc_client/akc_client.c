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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

static object_security_server akc_server = {
	"coap://coaps-api.artik.cloud:5686", /*serverUri*/
	"76e814d7dce641debc1267ea95e82838",	/*pskId : DEVICE ID*/
	"ba53c07423f842adabbdca76de075a44",	/*psk : DEVICE TOKEN*/
	"76e814d7dce641debc1267ea95e82838", /*name : DEVICE ID*/
	300,			/*lifetime*/
	0,				/*battery*/
	123 			/*serverId*/
};


static object_security_server default_server = {
	"coap://127.0.0.1:5683", /*serverUri*/
	NULL,	/*pskId : DEVICE ID*/
	NULL,	/*psk : DEVICE TOKEN*/
	"defualt_server", /*name : DEVICE ID*/
	300,			/*lifetime*/
	0,				/*battery*/
	123 			/*serverId*/
};

static client_data akc_clinet = {
	"56830",	/*localPort/*
	false		/*IPV6 or IPV4*/
};

static object_device default_device = {
	"SAMSUNG",					/*PRV_MANUFACTURER*/
	"Lightweight M2M Client",	/*PRV_MODEL_NUMBER*/
	"345000123",				/*PRV_SERIAL_NUMBER*/
	"1.0",						/*PRV_FIRMWARE_VERSION*/
	1,							/*PRV_POWER_SOURCE_1*/
	5,							/*PRV_POWER_SOURCE_2*/
	3800,						/*PRV_POWER_VOLTAGE_1*/
	5000,						/*PRV_POWER_VOLTAGE_2*/
	125,						/*PRV_POWER_CURRENT_1*/
	900,						/*PRV_POWER_CURRENT_2*/
	100,						/*PRV_BATTERY_LEVEL*/
	15,							/*PRV_MEMORY_FREE*/
	0,							/*PRV_ERROR_CODE*/
	"Europe/Berlin",			/*PRV_TIME_ZONE*/
	"U"							/*PRV_BINDING_MODE*/
};

static object_firmware default_firmware ={
	1,		/*STATE*/
	false,	/*SUPPORTED*/
	0		/*RESULT*/
};

static object_conn_monitoring default_monitoring = {
	0,					/*VALUE_NETWORK_BEARER_GSM*/
	0,					/*VALUE_AVL_NETWORK_BEARER_1*/
	80,					/*VALUE_RADIO_SIGNAL_STRENGTH*/
	98,					/*VALUE_LINK_QUALITY*/
	"192.168.178.101",	/*VALUE_IP_ADDRESS_1*/
	"192.168.178.102",  /*VALUE_IP_ADDRESS_2*/
	"192.168.178.001",	/*VALUE_ROUTER_IP_ADDRESS_1*/
	"192.168.178.002",  /*VALUE_ROUTER_IP_ADDRESS_2*/
	666,				/*VALUE_LINK_UTILIZATION*/
	"web.vodafone.de",	/*VALUE_APN_1*/
	69696969,			/*VALUE_CELL_ID*/
	33,					/*VALUE_SMNC*/
	44					/*VALUE_SMCC*/
};

static object_location default_location ={
	"27.986065", /*Latitude */
	"86.922623", /*Longitude*/
	"8495.0000", /*Altidude*/
	"0.01"		 /*Uncertainty*/
};

int main(int argc, char *argv[])
{
	int ret;

	char * localPort = "56830";
	bool ipv6 = false;

	object_container init_val_ob;
	init_val_ob.server= akc_server;
	init_val_ob.device = default_device;
	init_val_ob.firmware = default_firmware;
	init_val_ob.monitoring = default_monitoring;
	init_val_ob.location = default_location;

    ret = akc_start(init_val_ob, akc_clinet);
	if (ret == -1 ) {
		 printf("client start fail %d\n",ret);
	}
	if (get_quit() >0) {
		printf("cleint stop\n");
		akc_stop();
	}
	
exit:	
	return 0;
   
}
