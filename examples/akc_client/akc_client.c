
#include "lwm2mclient.h"
#include "liblwm2m.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

static object_security_server akc_server = {
#ifdef COAP_TCP
	"coap+tcp://coap-api.artik.cloud:5688",		/* serverUri */
#else
	"coap://coaps-api.artik.cloud:5686",		/* serverUri */
#endif
	"76e814d7dce641debc1267ea95e82838",			/* pskId : DEVICE ID */
	"ba53c07423f842adabbdca76de075a44",			/* psk : DEVICE TOKEN */
	"76e814d7dce641debc1267ea95e82838", 		/* name : DEVICE ID */
	300,										/* lifetime */
	0,											/* battery */
	123 										/* serverId */
};

static client_data akc_client = {
	"56880",	/* localPort */
	false		/* IPV6 or IPV4 */
};

static object_device default_device = {
	"SAMSUNG",					/* PRV_MANUFACTURER */
	"Lightweight M2M Client",	/* PRV_MODEL_NUMBER */
	"345000123",				/* PRV_SERIAL_NUMBER */
	"1.0",						/* PRV_FIRMWARE_VERSION */
	1,							/* PRV_POWER_SOURCE_1 */
	5,							/* PRV_POWER_SOURCE_2 */
	3800,						/* PRV_POWER_VOLTAGE_1 */
	5000,						/* PRV_POWER_VOLTAGE_2 */
	125,						/* PRV_POWER_CURRENT_1 */
	900,						/* PRV_POWER_CURRENT_2 */
	100,						/* PRV_BATTERY_LEVEL */
	15,							/* PRV_MEMORY_FREE */
	0,							/* PRV_ERROR_CODE */
	"Europe/Berlin",			/* PRV_TIME_ZONE */
#ifdef COAP_TCP
	"C"							/* PRV_BINDING_MODE */
#else
	"U"							/* PRV_BINDING_MODE */
#endif
};

static object_firmware default_firmware ={
	1,		/* STATE */
	false,	/* SUPPORTED */
	0		/* RESULT */
};

static object_conn_monitoring default_monitoring = {
	0,					/* VALUE_NETWORK_BEARER_GSM */
	0,					/* VALUE_AVL_NETWORK_BEARER_1 */
	80,					/* VALUE_RADIO_SIGNAL_STRENGTH */
	98,					/* VALUE_LINK_QUALITY */
	"192.168.178.101",	/* VALUE_IP_ADDRESS_1 */
	"192.168.178.102",  /* VALUE_IP_ADDRESS_2 */
	"192.168.178.001",	/* VALUE_ROUTER_IP_ADDRESS_1 */
	"192.168.178.002",  /* VALUE_ROUTER_IP_ADDRESS_2 */
	666,				/* VALUE_LINK_UTILIZATION */
	"web.vodafone.de",	/* VALUE_APN_1 */
	69696969,			/* VALUE_CELL_ID */
	33,					/* VALUE_SMNC */
	44					/* VALUE_SMCC */
};

static object_location default_location ={
	"27.986065", /* Latitude */
	"86.922623", /* Longitude */
	"8495.0000", /* Altitude */
	"0.01"		 /* Uncertainty */
};

int main(int argc, char *argv[])
{
	int ret = 0;

	object_container init_val_ob;
	init_val_ob.server= akc_server;
	init_val_ob.device = default_device;
	init_val_ob.firmware = default_firmware;
	init_val_ob.monitoring = default_monitoring;
	init_val_ob.location = default_location;

    ret = akc_start(init_val_ob, akc_client);
	if (ret == -1) {
		 printf("Failed to start client (err=%d)\n",ret);
	}

	if (get_quit() > 0) {
		akc_stop();
	}
	
exit:	
	return 0;
   
}
