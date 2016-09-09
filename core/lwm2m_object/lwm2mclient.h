
#ifndef _LWM2MCLIENT_H_
#define _LWM2MCLIENT_H_

#include <stdint.h>
#include <stdbool.h>

#define LWM2M_MAX_STR_LEN 100

typedef void* client_handle_t;

/*
 * Device object
 */
typedef struct {
    char manufacturer[LWM2M_MAX_STR_LEN];     /*PRV_MANUFACTURER*/
    char model_number[LWM2M_MAX_STR_LEN];     /*PRV_MODEL_NUMBER*/
    char serial_number[LWM2M_MAX_STR_LEN];    /*PRV_SERIAL_NUMBER*/
    char firmware_version[LWM2M_MAX_STR_LEN]; /*PRV_FIRMWARE_VERSION*/
    int power_source_1;                       /*PRV_POWER_SOURCE_1*/
    int power_source_2;                       /*PRV_POWER_SOURCE_2*/
    int power_voltage_1;                      /*PRV_POWER_VOLTAGE_1*/
    int power_voltage_2;                      /*PRV_POWER_VOLTAGE_2*/
    int power_current_1;                      /*PRV_POWER_CURRENT_1*/
    int power_current_2;                      /*PRV_POWER_CURRENT_2*/
    int battery_level;                        /*PRV_BATTERY_LEVEL*/
    int memory_free;                          /*PRV_MEMORY_FREE*/
    int error_code;                           /*PRV_ERROR_CODE*/
    char time_zone[LWM2M_MAX_STR_LEN];        /*PRV_TIME_ZONE*/
    char binding_mode[LWM2M_MAX_STR_LEN];     /*PRV_BINDING_MODE*/
    char device_type[LWM2M_MAX_STR_LEN];      /*PRV_DEVICE_TYPE*/
    char hardware_version[LWM2M_MAX_STR_LEN]; /*PRV_HARDWARE_VERSION*/
    char software_version[LWM2M_MAX_STR_LEN]; /*PRV_SOFTWARE_VERSION*/
    int battery_status;                       /*PRV_BATTERY_STATUS*/
    int memory_total;                         /*PRV_MEMORY_TOTAL*/
} object_device;

/*
 * Firmware update object
 */
typedef struct {
    uint8_t state;                       /*STATE*/
    bool supported;                      /*SUPPORTED*/
    uint8_t result;                      /*RESULT*/
    char pkg_name[LWM2M_MAX_STR_LEN];    /*PKG_NAME*/
    char pkg_version[LWM2M_MAX_STR_LEN]; /*PKG_VERSION*/
}object_firmware;

/*
 * Location object
 */
 typedef struct {
    char  latitude[LWM2M_MAX_STR_LEN];      /*Latitude */
    char  longitude[LWM2M_MAX_STR_LEN];     /*Longitude*/
    char  altidude[LWM2M_MAX_STR_LEN];      /*Altitude*/
    char  uncertainty[LWM2M_MAX_STR_LEN];   /*Uncertainty*/
} object_location;

/*
 * Connectivity monitoring object
 */
typedef struct {
    int  network_bearer;                     /*VALUE_NETWORK_BEARER_GSM*/
    int  avl_network_bearer;                 /*VALUE_AVL_NETWORK_BEARER_1*/
    int  radio_signal_strength;              /*VALUE_RADIO_SIGNAL_STRENGTH*/
    int  link_quality;                       /*VALUE_LINK_QUALITY*/
    char ip_addr[LWM2M_MAX_STR_LEN];         /*VALUE_IP_ADDRESS_1*/
    char ip_addr2[LWM2M_MAX_STR_LEN];        /*VALUE_IP_ADDRESS_2*/
    char router_ip_addr[LWM2M_MAX_STR_LEN];  /*VALUE_ROUTER_IP_ADDRESS_1*/
    char router_ip_addr2[LWM2M_MAX_STR_LEN]; /*VALUE_ROUTER_IP_ADDRESS_2*/
    int  link_utilization;                   /*VALUE_LINK_UTILIZATION*/
    char apn[LWM2M_MAX_STR_LEN];             /*VALUE_APN_1*/
    int  cell_id;                            /*VALUE_CELL_ID*/
    int  smnc;                               /*VALUE_SMNC*/
    int  smcc;                               /*VALUE_SMCC*/
} object_conn_monitoring;

/*
 * LWM2M security object
 */
 typedef struct {
    char serverUri[LWM2M_MAX_STR_LEN];   /*serverUri*/
    char bsPskId[LWM2M_MAX_STR_LEN];     /*pskId : DEVICE ID*/
    char psk[LWM2M_MAX_STR_LEN];         /*psk : DEVICE TOKEN*/
    char client_name[LWM2M_MAX_STR_LEN]; /*name : DEVICE ID*/
    int lifetime;                        /*lifetime*/
    int  batterylevelchanging;           /*battery*/
    int serverId;                        /*serverId*/
} object_security_server;

/*
 * Object container
 */
typedef struct {
    object_security_server* server;
    object_device* device;
    object_firmware* firmware;
    object_location* location;
    object_conn_monitoring* monitoring;
}object_container;

enum lwm2m_object_type {
    LWM2M_OBJ_SECURITY = 0,
    LWM2M_OBJ_SERVER,
    LWM2M_OBJ_ACL,
    LWM2M_OBJ_DEVICE,
    LWM2M_OBJ_CONN_MON,
    LWM2M_OBJ_FIRMWARE,
    LWM2M_OBJ_LOCATION,
    LWM2M_OBJ_CONN_STAT,
    LWM2M_OBJ_COUNT
};

typedef void (*lwm2m_exe_callback)(void*);

enum lwm2m_execute_callback_type {
    LWM2M_EXE_FACTORY_RESET = 0,
    LWM2M_EXE_DEVICE_REBOOT,
    LWM2M_EXE_FIRMWARE_UPDATE,
    LWM2M_EXE_COUNT
};

#define LWM2M_CLIENT_OK     ( 0)
#define LWM2M_CLIENT_ERROR  (-1)
#define LWM2M_CLIENT_QUIT   (-2)

int lwm2m_client_service(client_handle_t handle);
void lwm2m_client_stop(client_handle_t handle);
client_handle_t lwm2m_client_start(object_container *init_val);
void lwm2m_register_callback(client_handle_t handle, enum lwm2m_execute_callback_type type,
        lwm2m_exe_callback callback, void *param);
void lwm2m_unregister_callback(client_handle_t handle, enum lwm2m_execute_callback_type type);
void lwm2m_change_object(client_handle_t handle, const char *uri, uint8_t *buffer, int length);

#endif /* _LWM2MCLIENT_H_ */
