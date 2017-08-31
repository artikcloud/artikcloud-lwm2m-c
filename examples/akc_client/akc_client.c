#include "lwm2mclient.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>

#define AKC_UUID_LEN    32

extern void cmdline_init(client_handle_t *handle);
extern int cmdline_process(int timeout);

static object_security_server_t akc_server = {
    "coaps+tcp://coaps-api.artik.cloud:5689", /* serverUri */
    LWM2M_SEC_MODE_PSK,                       /* securityMode: PSK */
    "<Artik Cloud device ID>",                /* pskId : DEVICE ID */
    "<Artik Cloud device token>",             /* token : DEVICE TOKEN */
    NULL,                                     /* privateKey */
    NULL,                                     /* serverCertificate */
    "<Artik Cloud device ID>",                /* name : DEVICE ID */
    30,                                       /* lifetime */
    0,                                        /* battery */
    123,                                      /* serverId */
    true,                                     /* verifyCert */
    0                                         /* localPort */
};

static object_device_t default_device = {
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
    "Europe/Paris",           /* PRV_TIME_ZONE */
    "+02:00",                 /* PRV_UTC_OFFSET */
    "U",                      /* PRV_BINDING_MODE */
    "DeviceType C SDK",       /* PRV_DEVICE_TYPE */
    "Hardware C SDK",         /* PRV_HARDWARE_VERSION */
    "Software C SDK",         /* PRV_SOFTWARE_VERSION */
    6,                        /* PRV_BATTERY_STATUS */
    128                       /* PRV_MEMORY_TOTAL */
};

static object_firmware_t default_firmware ={
    false,         /* SUPPORTED */
    "PKG Name",    /* PKG_NAME */
    "PKG Version", /* PKG_VERSION */
};

static bool quit = false;

static void usage()
{
    fprintf(stdout, "Usage: akc_client [options]\r\n");
    fprintf(stdout, "\t-u <server URI> : LWM2M server URI\r\n");
    fprintf(stdout, "\t-d <device ID> : AKC device ID\r\n");
    fprintf(stdout, "\t-t <device token> : AKC device token\r\n");
    fprintf(stdout, "\t-c <path device certificate> : Device certificate\r\n");
    fprintf(stdout, "\t-k <path device private key> : Device private key\r\n");
    fprintf(stdout, "\t-s <path server certificate> : Server certificate\r\n");
    fprintf(stdout, "\t-n : don't verify SSL certificate\r\n");
    fprintf(stdout, "\t-p <port> : local source port to connect from\r\n");
    fprintf(stdout, "\t-l <lifetime> : lifetime of the client in seconds\r\n");
    fprintf(stdout, "\t-h : display help\r\n");
}

static bool fill_buffer_from_file(const char *file, char **pbuffer)
{
    FILE *stream = NULL;
    long size = 0;
    char *buffer = NULL;
    if (access(file, F_OK) != 0) {
        fprintf(stderr, "cannot access '%s': %s\n", file, strerror(errno));
        return false;
    }

    stream = fopen(file, "r");
    if (!stream) {
        fprintf(stderr, "cannot open '%s': %s\n", file, strerror(errno));
        goto error;
    }

    if (fseek(stream, 0, SEEK_END) != 0) {
        fprintf(stderr, "cannot seek '%s': %s\n", file, strerror(errno));
        goto error;
    }

    size = ftell(stream);
    if (size < 0) {
        fprintf(stderr, "cannot tell '%s': %s\n", file, strerror(errno));
        goto error;
    }

    rewind(stream);
    buffer = malloc(size * sizeof(char));
    if (!buffer) {
        fprintf(stderr, "cannot allocate %ld bytes\n", size);
        goto error;
    }

    fread(buffer, sizeof(char), size, stream);
    fclose(stream);

    *pbuffer = buffer;
    return true;

error:
    if (buffer) {
        free(buffer);
    }

    if (stream) {
        fclose(stream);
    }

	return false;
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

static void on_resource_changed(void *param, void *extra)
{
    client_handle_t *client = (client_handle_t*)param;
    lwm2m_resource_t *params = (lwm2m_resource_t*)extra;

    fprintf(stdout, "Resource Changed: %s\r\n", params->uri);

    if (!strncmp(params->uri, LWM2M_URI_FIRMWARE_PACKAGE_URI, LWM2M_MAX_URI_LEN))
    {
        char *filename;
        lwm2m_resource_t state;

        strncpy(state.uri, LWM2M_URI_FIRMWARE_STATE, strlen(LWM2M_URI_FIRMWARE_STATE));
        state.length = strlen(LWM2M_FIRMWARE_STATE_DOWNLOADING);
        state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_DOWNLOADING, state.length);

        /* Change state */
        lwm2m_write_resource(client, &state);
        free(state.buffer);

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
    int opt;
    object_container_t init_val_ob;
    client_handle_t *client = NULL;

    while ((opt = getopt(argc, argv, "s:c:k:u:d:t:np:l:h")) != -1) {
            switch (opt) {
            case 'u':
                strncpy(akc_server.serverUri, optarg, LWM2M_MAX_STR_LEN);
                break;
            case 'd':
                if (strlen(optarg) != AKC_UUID_LEN)
                {
                    fprintf(stderr, "Wrong device ID parameter\r\n");
                    usage();
                    return -1;
                }

                strncpy(akc_server.client_name, optarg, AKC_UUID_LEN);
                break;
            case 't':
                if (strlen(optarg) != AKC_UUID_LEN)
                {
                    fprintf(stderr, "Wrong device token parameter\r\n");
                    usage();
                    return -1;
                }

                akc_server.token = strdup(optarg);
                break;
            case 'c':
                if (!fill_buffer_from_file(optarg, &akc_server.clientCertificateOrPskId)) {
                    usage();
                    return -1;
                }

                akc_server.securityMode = LWM2M_SEC_MODE_CERT;

                break;
            case 's':
                if (!fill_buffer_from_file(optarg, &akc_server.serverCertificate)) {
                    usage();
                    return -1;
                }

                akc_server.securityMode = LWM2M_SEC_MODE_CERT;
                break;
            case 'k':
                if (!fill_buffer_from_file(optarg, &akc_server.privateKey)) {
                    usage();
                    return -1;
                }

                akc_server.securityMode = LWM2M_SEC_MODE_CERT;
                break;
            case 'n':
                akc_server.verifyCert = false;
                break;
            case 'p':
                akc_server.localPort = atoi(optarg);
                break;
            case 'l':
                akc_server.lifetime = atoi(optarg);
                break;
            case 'h':
                usage();
                return 0;
            default:
                usage();
                return -1;
            }
    }

    if (akc_server.securityMode == LWM2M_SEC_MODE_PSK)
        akc_server.clientCertificateOrPskId = strdup(akc_server.client_name);

    signal(SIGINT, handle_sigint);

    memset(&init_val_ob, 0, sizeof(init_val_ob));
    init_val_ob.server= &akc_server;
    init_val_ob.device = &default_device;
    init_val_ob.firmware = &default_firmware;

    client = lwm2m_client_start(&init_val_ob);
    if (!client)
    {
        fprintf(stderr, "Failed to start client\n");
        return -1;
    }

    cmdline_init(client);

    lwm2m_register_callback(client, LWM2M_EXE_FACTORY_RESET, on_factory_reset, (void*)client);
    lwm2m_register_callback(client, LWM2M_EXE_DEVICE_REBOOT, on_reboot, (void*)client);
    lwm2m_register_callback(client, LWM2M_EXE_FIRMWARE_UPDATE, on_firmware_update, (void*)client);
    lwm2m_register_callback(client, LWM2M_NOTIFY_RESOURCE_CHANGED, on_resource_changed, (void*)client);

    while (!quit)
    {
        int ret = lwm2m_client_service(client, 100);
        if ((ret == LWM2M_CLIENT_QUIT) || (ret == LWM2M_CLIENT_ERROR))
            break;

        ret = cmdline_process(ret);
        if ((ret == LWM2M_CLIENT_QUIT) || (ret == LWM2M_CLIENT_ERROR))
            break;
    }

    lwm2m_client_stop(client);
    free(akc_server.clientCertificateOrPskId);

    return 0;
}
