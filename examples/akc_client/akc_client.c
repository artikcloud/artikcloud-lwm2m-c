#include "lwm2mclient.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define AKC_UUID_LEN    32

extern void cmdline_init(client_handle_t handle);
extern int cmdline_process(int timeout);

static object_security_server akc_server = {
    "coaps+tcp://coap-dev.artik.cloud:5689", /* serverUri */
    "24936ceccdb24a54a58a341ee7c5d1a3",      /* pskId : DEVICE ID */
    "2f1a098e131b4d4c9aaaaf38bb06df87",      /* psk : DEVICE TOKEN */
    "24936ceccdb24a54a58a341ee7c5d1a3",      /* name : DEVICE ID */
    30,                                      /* lifetime */
    0,                                       /* battery */
    123                                      /* serverId */
};

static object_device default_device = {
    "SAMSUNG",                /* PRV_MANUFACTURER */
    "Lightweight M2M Client", /* PRV_MODEL_NUMBER */
    "345000123",              /* PRV_SERIAL_NUMBER */
    "1.0",                    /* PRV_FIRMWARE_VERSION */
    1,                        /* PRV_POWER_SOURCE_1 */
    5,                        /* PRV_POWER_SOURCE_2 */
    3800,                     /* PRV_POWER_VOLTAGE_1 */
    5000,                     /* PRV_POWER_VOLTAGE_2 */
    125,                      /* PRV_POWER_CURRENT_1 */
    900,                      /* PRV_POWER_CURRENT_2 */
    100,                      /* PRV_BATTERY_LEVEL */
    15,                       /* PRV_MEMORY_FREE */
    0,                        /* PRV_ERROR_CODE */
    "Europe/Paris",           /* PRV_TIME_ZONE */
    "+02:00",                 /* PRV_UTC_OFFSET */
    "U",                      /* PRV_BINDING_MODE */
    "DeviceType C SDK",       /* PRV_DEVICE_TYPE */
    "Hardware C SDK",         /* PRV_HARDWARE_VERSION */
    "Software C SDK",         /* PRV_SOFTWARE_VERSION */
    6,                        /* PRV_BATTERY_STATUS */
    128                       /* PRV_MEMORY_TOTAL */
};

static object_firmware default_firmware ={
    false,         /* SUPPORTED */
    "PKG Name",    /* PKG_NAME */
    "PKG Version", /* PKG_VERSION */
};

static object_conn_monitoring default_monitoring = {
    0,                            /* VALUE_NETWORK_BEARER_GSM */
    0,                            /* VALUE_AVL_NETWORK_BEARER_1 */
    80,                           /* VALUE_RADIO_SIGNAL_STRENGTH */
    98,                           /* VALUE_LINK_QUALITY */
    "192.168.178.101",            /* VALUE_IP_ADDRESS_1 */
    "fe80::aebc:32ff:feb8:db5f",  /* VALUE_IP_ADDRESS_2 */
    "192.168.178.001",            /* VALUE_ROUTER_IP_ADDRESS_1 */
    "192.168.178.002",            /* VALUE_ROUTER_IP_ADDRESS_2 */
    666,                          /* VALUE_LINK_UTILIZATION */
    "web.vodafone.de",            /* VALUE_APN_1 */
    69696969,                     /* VALUE_CELL_ID */
    33,                           /* VALUE_SMNC */
    44                            /* VALUE_SMCC */
};

static object_location default_location ={
    "27.986065", /* Latitude */
    "86.922623", /* Longitude */
    "8495.0000", /* Altitude */
    "0.01"       /* Uncertainty */
};

static bool quit = false;

static void usage()
{
    fprintf(stdout, "Usage:\r\n");
    fprintf(stdout, "\takc_client <server URI> <device ID> <device token>\r\n");
}

void handle_sigint(int signum)
{
    quit = true;
}

static void on_reboot(void *param, void *extra)
{
    fprintf(stdout, "REBOOT\r\n");
}

static void on_firmware_update(void *param, void *extra)
{
    fprintf(stdout, "FIRMWARE UPDATE\r\n");
}

static void on_factory_reset(void *param, void *extra)
{
    fprintf(stdout, "FACTORY RESET\r\n");
}

static void on_res_changed_uri(void *param, void *extra)
{
    client_handle_t client = (client_handle_t)param;
    lwm2m_res_changed_params *params = (lwm2m_res_changed_params*)extra;

    fprintf(stdout, "Resource Changed: %s\r\n", params->uri);

    if (!strncmp(params->uri, LWM2M_URI_FIRMWARE_PACKAGE_URI, LWM2M_MAX_URI_LEN))
    {
        char state[] = LWM2M_FIRMWARE_STATE_DOWNLOADING;
        char *filename;

        /* Change state */
        lwm2m_change_object(client, LWM2M_URI_FIRMWARE_STATE, (uint8_t *)state, strlen(state));

        /*
         * Download the package and update status at each step
         */
        filename = strndup((char*)params->buffer, params->length);
        fprintf(stdout, "Downloading: %s\r\n", filename);
        free(filename);
    }
}

int main(int argc, char *argv[])
{
    object_container init_val_ob;
    client_handle_t client = NULL;

    if (argc > 1)
        strncpy(akc_server.serverUri, argv[1], LWM2M_MAX_STR_LEN);

    if (argc > 2)
    {
        if (strlen(argv[2]) != AKC_UUID_LEN)
        {
            fprintf(stderr, "Wrong device ID parameter\r\n");
            usage();
            return -1;
        }

        strncpy(akc_server.bsPskId, argv[2], AKC_UUID_LEN);
        strncpy(akc_server.client_name, argv[2], AKC_UUID_LEN);
    }

    if (argc > 3)
    {
        if (strlen(argv[3]) != AKC_UUID_LEN)
        {
            fprintf(stderr, "Wrong device token parameter\r\n");
            usage();
            return -1;
        }

        strncpy(akc_server.psk, argv[3], AKC_UUID_LEN);
    }

    signal(SIGINT, handle_sigint);

    init_val_ob.server= &akc_server;
    init_val_ob.device = &default_device;
    init_val_ob.firmware = &default_firmware;
    init_val_ob.monitoring = &default_monitoring;
    init_val_ob.location = &default_location;

    client = lwm2m_client_start(&init_val_ob);
    if (!client)
    {
        fprintf(stderr, "Failed to start client\n");
    }

    cmdline_init(client);

    lwm2m_register_callback(client, LWM2M_EXE_FACTORY_RESET, on_factory_reset, (void*)client);
    lwm2m_register_callback(client, LWM2M_EXE_DEVICE_REBOOT, on_reboot, (void*)client);
    lwm2m_register_callback(client, LWM2M_EXE_FIRMWARE_UPDATE, on_firmware_update, (void*)client);
    lwm2m_register_callback(client, LWM2M_NOTIFY_RESOURCE_CHANGED, on_res_changed_uri, (void*)client);

    while (!quit)
    {
        int ret = lwm2m_client_service(client);
        if ((ret == LWM2M_CLIENT_QUIT) || (ret == LWM2M_CLIENT_ERROR))
            break;

        ret = cmdline_process(ret);
        if ((ret == LWM2M_CLIENT_QUIT) || (ret == LWM2M_CLIENT_ERROR))
            break;
    }

    lwm2m_client_stop(client);

    return 0;
}
