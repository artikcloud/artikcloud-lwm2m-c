#define _XOPEN_SOURCE 700 /* use strndup and nftw */

#include "lwm2mclient.h"

#include <archive.h>
#include <archive_entry.h>
#include <curl/curl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ftw.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define AKC_UUID_LEN    32

typedef struct {
    pthread_t thread;
    char *file;
    char *uri;
    const char *state;
    bool is_finished;
} ota_download_t;

typedef struct {
    pthread_t thread;
    char *file;
    const char *state;
    char *tmp_directory;
    bool is_finished;
} ota_update_t;

typedef struct {
    client_handle_t client;
    ota_download_t ota_download;
    ota_update_t ota_update;
} ota_updater_t;

static object_security_server_t akc_server = {
    "coaps+tcp://coaps-api.artik.cloud:5689", /* serverUri */
    "<Artik Cloud device ID>",                /* pskId : DEVICE ID */
    "<Artik Cloud device token>",             /* psk : DEVICE TOKEN */
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
    fprintf(stdout, "Usage: akc_ota [options]\r\n");
    fprintf(stdout, "\t-u <server URI> : LWM2M server URI\r\n");
    fprintf(stdout, "\t-d <device ID> : AKC device ID\r\n");
    fprintf(stdout, "\t-t <device token> : AKC device token\r\n");
    fprintf(stdout, "\t-n : don't verify SSL certificate\r\n");
    fprintf(stdout, "\t-p <port> : local source port to connect from\r\n");
    fprintf(stdout, "\t-h : display help\r\n");
}

void handle_sigint(int signum)
{
    quit = true;
}

static int copy_data(struct archive *ar, struct archive *aw)
{
    int r;
    const void *buff;
    size_t size;
    int64_t offset;

    for(;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return (ARCHIVE_OK);

        if (r != ARCHIVE_OK)
            return r;

        r = archive_write_data_block(aw, buff, size, offset);
        if (r != ARCHIVE_OK)
            return r;
    }
}

static bool extract_ota(char *filename, bool do_extract)
{
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    bool ret = false;

    a = archive_read_new();
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext,
                                   ARCHIVE_EXTRACT_PERM
                                   | ARCHIVE_EXTRACT_ACL
                                   | ARCHIVE_EXTRACT_FFLAGS
                                   | ARCHIVE_EXTRACT_TIME);
    archive_write_disk_set_standard_lookup(ext);

    archive_read_support_format_tar(a);

    archive_read_support_filter_xz(a);
    if (archive_read_open_filename(a, filename, 10240)) {
        fprintf(stdout, "Error opening archive %s : %s", filename, archive_error_string(a));
        goto exit;
    }

    for (;;) {
        int needcr = 0;
        int r = archive_read_next_header(a, &entry);
        if (r == ARCHIVE_EOF) {
            break;
        }

        if (r != ARCHIVE_OK) {
            goto exit;
        }

        if (do_extract) {
            r = archive_write_header(ext, entry);
            if (r != ARCHIVE_OK) {
                goto exit;
            }

            r = copy_data(a, ext);
            if (r != ARCHIVE_OK) {
                goto exit;
            }

            r = archive_write_finish_entry(ext);
            if (r != ARCHIVE_OK) {
                goto exit;
            }
        }
    }

    ret = true;

exit:
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);

    return ret;
}

static void init_tmp_directory(ota_update_t *ota_update)
{
    char *tmp_dir = "/tmp/update-";
    ota_update->tmp_directory = malloc(sizeof(char)*(strlen(tmp_dir) + strlen(default_device.serial_number)+ 1));
    strcpy(ota_update->tmp_directory, tmp_dir);
    strcat(ota_update->tmp_directory, default_device.serial_number);
}

static int remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove(fpath);
    return rv;
}

static void * start_updating_ota(void *user_data) {
    ota_update_t *ota_update = user_data;
    ota_update->state = LWM2M_FIRMWARE_UPD_RES_DEFAULT;
    char cwd[PATH_MAX];

    getcwd(cwd, PATH_MAX);
    mkdir(ota_update->tmp_directory, S_IRWXU);
    chdir(ota_update->tmp_directory);

    if (!extract_ota(ota_update->file, true)) {
        fprintf(stdout, "Extract %s failed\n", ota_update->file);
        ota_update->state = LWM2M_FIRMWARE_UPD_RES_DEFAULT;
        goto exit;
    }

    char *script = malloc(sizeof(char)*strlen(ota_update->tmp_directory)+strlen("/updater.sh"));
    strcpy(script, ota_update->tmp_directory);
    strcat(script, "/updater.sh");

    struct stat st;
    int result = stat(script, &st);
    if (result<0) {
        perror(script);
        free(script);
        goto exit;
    }

    fprintf(stdout, "Launch %s\n", script);
    int status = system(script);

    if (WIFEXITED(status))
        if (WEXITSTATUS(status) == 0)
            ota_update->state = LWM2M_FIRMWARE_UPD_RES_SUCCESS;

    free(script);

exit:
    chdir(cwd);
    nftw(ota_update->tmp_directory, remove_cb, 64, FTW_DEPTH);
    ota_update->is_finished = true;
}

static bool download_ota(ota_download_t* ota_download)
{
    CURL *curl = NULL;
    const char *file_path = ota_download->file;
    CURLcode res;
    FILE *fp = NULL;

    fp = fopen(file_path, "wb");
    if (!fp) {
        if (errno == ENOMEM)
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_OOM;
        else
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_URI_ERR;

        ota_download->is_finished = true;
        pthread_exit(NULL);
    }

    curl = curl_easy_init();
    if (!curl) {
        ota_download->state = LWM2M_FIRMWARE_UPD_RES_OOM;
        ota_download->is_finished = true;
        fclose(fp);
        pthread_exit(NULL);
    }

    curl_easy_setopt(curl, CURLOPT_URL, ota_download->uri);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)fp);
    res = curl_easy_perform(curl);

    if (res == CURLE_OK)
        ota_download->state = LWM2M_FIRMWARE_UPD_RES_SUCCESS;
    else {
        if (res == CURLE_URL_MALFORMAT)
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_URI_ERR;
        else if (res == CURLE_OUT_OF_MEMORY)
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_OOM;
        else if (res == CURLE_WRITE_ERROR)
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_SPACE_ERR;
        else
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_CONNE_ERR;

        goto exit;
    }

exit:
    curl_easy_cleanup(curl);
    fclose(fp);
}

static void * start_downloading_ota(void *user_data)
{
    ota_download_t* ota_download = user_data;

    if (!download_ota(ota_download))
        goto exit;

    if (extract_ota(ota_download->file, false))
        ota_download->state = LWM2M_FIRMWARE_UPD_RES_SUCCESS;
    else
        ota_download->state = LWM2M_FIRMWARE_UPD_RES_CRC_ERR;

exit:
    ota_download->is_finished = true;

    pthread_exit(NULL);
}

static void on_firmware_update(void *param, void *extra)
{
    ota_updater_t *ota_updater = (ota_updater_t*) param;

    fprintf(stdout, "Update in progress...\n");

    lwm2m_resource_t state;
    strncpy(state.uri, LWM2M_URI_FIRMWARE_STATE, strlen(LWM2M_URI_FIRMWARE_STATE)+1);
    state.length = strlen(LWM2M_FIRMWARE_STATE_UPDATING);
    state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_UPDATING, state.length);
    lwm2m_write_resource(ota_updater->client, &state);
    free(state.buffer);

    if (pthread_create(&ota_updater->ota_update.thread,
                       NULL,
                       start_updating_ota,
                       &(ota_updater->ota_update))) {
        ota_updater->ota_update.state = LWM2M_FIRMWARE_UPD_RES_OOM;
        ota_updater->ota_update.is_finished = true;
    }
}

static void on_resource_changed(void *param, void *extra)
{
    ota_updater_t* ota_updater = (ota_updater_t*) param;
    ota_download_t* ota_download = &ota_updater->ota_download;
    lwm2m_resource_t *params = (lwm2m_resource_t*) extra;

    fprintf(stdout, "Resource Changed: %s\r\n", params->uri);

    if (!strncmp(params->uri, LWM2M_URI_FIRMWARE_PACKAGE_URI, LWM2M_MAX_URI_LEN))
    {
        lwm2m_resource_t state;
        strncpy(state.uri, LWM2M_URI_FIRMWARE_STATE, strlen(LWM2M_URI_FIRMWARE_STATE)+1);
        state.length = strlen(LWM2M_FIRMWARE_STATE_DOWNLOADING);
        state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_DOWNLOADING, state.length);

        /* Change state */
        lwm2m_write_resource(ota_updater->client, &state);
        free(state.buffer);

        ota_download->uri = strndup((char*)params->buffer, params->length);

        /* Check the URI */
        char *last_slash = strrchr(ota_download->uri, '/');
        if (last_slash == NULL) {
            fprintf(stdout, "Bad uri %s\n", ota_download->uri);
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_URI_ERR;
            ota_download->is_finished = true;
            return;
        }

        if (*(last_slash + 1) == '\0') {
            fprintf(stdout, "Bad uri %s\n", ota_download->uri);
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_URI_ERR;
            ota_download->is_finished = true;
            return;
        }

        char *regexp = "OTA-update-([0-9a-zA-Z\\-]+)-(([0-9]+\\.)+)tar\\.xz$";
        regex_t reg;
        regcomp(&reg, regexp, REG_EXTENDED);
        int match = regexec (&reg, last_slash+1, 0, NULL, 0);
        fprintf(stdout, "match = %d\n", match);
        if (match) {
            fprintf(stdout, "Don't match regex\n");
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_PKG_ERR;
            ota_download->is_finished = true;
            return;
        }

        char *tmp = "/tmp/";
        char *file = malloc(sizeof(char)*(strlen(last_slash)+strlen(tmp)));
        strcpy(file, tmp);
        strcat(file, last_slash+1);

        ota_download->file = file;
        /* Launch the downloading */
        if (pthread_create(&ota_download->thread,
                           NULL,
                           start_downloading_ota,
                           ota_download) != 0) {
            ota_download->state = LWM2M_FIRMWARE_UPD_RES_OOM;
            ota_download->is_finished = true;
        }
    }
}

static void read_obj(char *uri, client_handle_t *handle)
{
    char *end = NULL;
    char *val = NULL;
    lwm2m_resource_t res;
    int i = 0;

    strncpy(res.uri, uri, strlen(uri)+1);

    if (lwm2m_read_resource(handle, &res))
    {
        fprintf(stdout, "Read %s failed !\n", uri);
        return;
    }

    val = strndup((char*)res.buffer, res.length);

    fprintf(stdout, "URI: %s - Value: %s\r\n> ", res.uri, val);

    free(res.buffer);
    free(val);
}

int main(int argc, char *argv[])
{
    int opt;
    object_container_t init_val_ob;
    ota_updater_t ota_updater;
    ota_updater.client = NULL;
    ota_updater.ota_download.file = NULL;
    ota_updater.ota_download.state = LWM2M_FIRMWARE_UPD_RES_DEFAULT;
    ota_updater.ota_download.is_finished = false;
    ota_updater.ota_update.state = LWM2M_FIRMWARE_UPD_RES_DEFAULT;
    ota_updater.ota_update.is_finished = false;

    init_tmp_directory(&(ota_updater.ota_update));
    while ((opt = getopt(argc, argv, "u:d:t:np:h")) != -1) {
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

                strncpy(akc_server.bsPskId, optarg, AKC_UUID_LEN);
                strncpy(akc_server.client_name, optarg, AKC_UUID_LEN);
                break;
            case 't':
                if (strlen(optarg) != AKC_UUID_LEN)
                {
                    fprintf(stderr, "Wrong device token parameter\r\n");
                    usage();
                    return -1;
                }

                strncpy(akc_server.psk, optarg, AKC_UUID_LEN);
                break;
            case 'n':
                akc_server.verifyCert = false;
                break;
            case 'p':
                akc_server.localPort = atoi(optarg);
                break;
            case 'h':
                usage();
                return 0;
            default:
                usage();
                return -1;
            }
    }

    signal(SIGINT, handle_sigint);

    memset(&init_val_ob, 0, sizeof(init_val_ob));
    init_val_ob.server= &akc_server;
    init_val_ob.device = &default_device;
    init_val_ob.firmware = &default_firmware;

    ota_updater.client = lwm2m_client_start(&init_val_ob);
    if (!ota_updater.client)
    {
        fprintf(stderr, "Failed to start client\n");
        return -1;
    }

    lwm2m_register_callback(ota_updater.client,
                            LWM2M_EXE_FIRMWARE_UPDATE,
                            on_firmware_update,
                            (void*)&ota_updater);
    lwm2m_register_callback(ota_updater.client,
                            LWM2M_NOTIFY_RESOURCE_CHANGED,
                            on_resource_changed,
                            (void*)&ota_updater);

    while (!quit)
    {
        int ret = lwm2m_client_service(ota_updater.client);
        if ((ret == LWM2M_CLIENT_QUIT) || (ret == LWM2M_CLIENT_ERROR))
            break;

        read_obj(LWM2M_URI_FIRMWARE_UPDATE_RES, ota_updater.client);
        read_obj(LWM2M_URI_FIRMWARE_STATE, ota_updater.client);
        if (ota_updater.ota_download.is_finished) {
            lwm2m_resource_t state;
            strncpy(state.uri, LWM2M_URI_FIRMWARE_STATE, strlen(LWM2M_URI_FIRMWARE_STATE)+1);
            if (!strcmp(ota_updater.ota_download.state, LWM2M_FIRMWARE_UPD_RES_SUCCESS)) {
                state.length = strlen(LWM2M_FIRMWARE_STATE_DOWNLOADED);
                state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_DOWNLOADED, state.length);
            } else {
                lwm2m_resource_t error;
                strncpy(error.uri,
                        LWM2M_URI_FIRMWARE_UPDATE_RES,
                        strlen(LWM2M_URI_FIRMWARE_UPDATE_RES)+1);
                error.length = strlen(ota_updater.ota_download.state);
                error.buffer = (uint8_t*)strndup(ota_updater.ota_download.state, state.length);
                lwm2m_write_resource(ota_updater.client, &error);
                free(error.buffer);

                state.length = strlen(LWM2M_FIRMWARE_STATE_IDLE);
                state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_IDLE, state.length);
            }

            /* Change state */
            lwm2m_write_resource(ota_updater.client, &state);
            free(state.buffer);

            if (ota_updater.ota_download.file != NULL)
                ota_updater.ota_update.file = strdup(ota_updater.ota_download.file);

            ota_updater.ota_download.state = LWM2M_FIRMWARE_UPD_RES_DEFAULT;
            ota_updater.ota_download.is_finished = false;

            free(ota_updater.ota_download.uri);

            if (ota_updater.ota_download.file != NULL) {
                free(ota_updater.ota_download.file);
                ota_updater.ota_download.file = NULL;
            }
        }

        if (ota_updater.ota_update.is_finished) {
            lwm2m_resource_t state;
            strncpy(state.uri, LWM2M_URI_FIRMWARE_STATE, strlen(LWM2M_URI_FIRMWARE_STATE)+1);
            if (!strcmp(ota_updater.ota_update.state, LWM2M_FIRMWARE_UPD_RES_SUCCESS)) {
                state.length = strlen(LWM2M_FIRMWARE_STATE_IDLE);
                state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_IDLE, state.length);
            } else {
                state.length = strlen(LWM2M_FIRMWARE_STATE_DOWNLOADED);
                state.buffer = (uint8_t*)strndup(LWM2M_FIRMWARE_STATE_DOWNLOADED, state.length);
            }

            lwm2m_write_resource(ota_updater.client, &state);
            free(state.buffer);
            ota_updater.ota_update.state = LWM2M_FIRMWARE_UPD_RES_DEFAULT;
            ota_updater.ota_update.is_finished = false;
        }
        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = ret;

        select(0, NULL, NULL, NULL, &tv);
    }

    lwm2m_client_stop(ota_updater.client);
    free(ota_updater.ota_update.tmp_directory);
    return 0;
}
