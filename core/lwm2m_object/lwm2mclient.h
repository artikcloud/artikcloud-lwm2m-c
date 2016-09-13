
#ifndef _LWM2MCLIENT_H_
#define _LWM2MCLIENT_H_

#include <stdint.h>
#include <stdbool.h>

#define LWM2M_MAX_URI_LEN 16
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
    char utc_offset[LWM2M_MAX_STR_LEN];       /*PRV_UTC_OFFSET*/
    char binding_mode[LWM2M_MAX_STR_LEN];     /*PRV_BINDING_MODE*/
    char device_type[LWM2M_MAX_STR_LEN];      /*PRV_DEVICE_TYPE*/
    char hardware_version[LWM2M_MAX_STR_LEN]; /*PRV_HARDWARE_VERSION*/
    char software_version[LWM2M_MAX_STR_LEN]; /*PRV_SOFTWARE_VERSION*/
    int battery_status;                       /*PRV_BATTERY_STATUS*/
    int memory_total;                         /*PRV_MEMORY_TOTAL*/
} object_device_t;

/*
 * Firmware update object
 */
typedef struct {
    bool supported;                      /*SUPPORTED*/
    char pkg_name[LWM2M_MAX_STR_LEN];    /*PKG_NAME*/
    char pkg_version[LWM2M_MAX_STR_LEN]; /*PKG_VERSION*/
}object_firmware_t;

/*
 * Location object
 */
 typedef struct {
    char  latitude[LWM2M_MAX_STR_LEN];      /*Latitude */
    char  longitude[LWM2M_MAX_STR_LEN];     /*Longitude*/
    char  altidude[LWM2M_MAX_STR_LEN];      /*Altitude*/
    char  uncertainty[LWM2M_MAX_STR_LEN];   /*Uncertainty*/
} object_location_t;

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
} object_conn_monitoring_t;

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
} object_security_server_t;

/*
 * Object container
 */
typedef struct {
    object_security_server_t* server;
    object_device_t* device;
    object_firmware_t* firmware;
    object_location_t* location;
    object_conn_monitoring_t* monitoring;
}object_container_t;

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

typedef void (*lwm2m_exe_callback)(void*, void*);

enum lwm2m_execute_callback_type {
    LWM2M_EXE_FACTORY_RESET = 0,
    LWM2M_EXE_DEVICE_REBOOT,
    LWM2M_EXE_FIRMWARE_UPDATE,
    LWM2M_NOTIFY_RESOURCE_CHANGED,
    LWM2M_EXE_COUNT
};

typedef struct {
    char uri[LWM2M_MAX_URI_LEN];
    uint8_t *buffer;
    int length;
} lwm2m_resource_t;

#define LWM2M_CLIENT_OK     ( 0)
#define LWM2M_CLIENT_ERROR  (-1)
#define LWM2M_CLIENT_QUIT   (-2)

/*
 * Object: Device
 */
#define LWM2M_URI_DEVICE                 "/3/0"
#define LWM2M_URI_DEVICE_MANUFACTURER    LWM2M_URI_DEVICE"/0"
#define LWM2M_URI_DEVICE_MODEL_NUM       LWM2M_URI_DEVICE"/1"
#define LWM2M_URI_DEVICE_SERIAL_NUM      LWM2M_URI_DEVICE"/2"
#define LWM2M_URI_DEVICE_FW_VERSION      LWM2M_URI_DEVICE"/3"
#define LWM2M_URI_DEVICE_REBOOT          LWM2M_URI_DEVICE"/4"
#define LWM2M_URI_DEVICE_FACTORY_RESET   LWM2M_URI_DEVICE"/5"
#define LWM2M_URI_DEVICE_POWER_SOURCES   LWM2M_URI_DEVICE"/6"
#define LWM2M_URI_DEVICE_POWER_VOLTAGE   LWM2M_URI_DEVICE"/7"
#define LWM2M_URI_DEVICE_POWER_CURRENT   LWM2M_URI_DEVICE"/8"
#define LWM2M_URI_DEVICE_BATT_LEVEL      LWM2M_URI_DEVICE"/9"
#define LWM2M_URI_DEVICE_MEMORY_FREE     LWM2M_URI_DEVICE"/10"
#define LWM2M_URI_DEVICE_ERROR_CODE      LWM2M_URI_DEVICE"/11"
#define LWM2M_URI_DEVICE_RESET_ERR_CODE  LWM2M_URI_DEVICE"/12"
#define LWM2M_URI_DEVICE_CURRENT_TIME    LWM2M_URI_DEVICE"/13"
#define LWM2M_URI_DEVICE_UTC_OFFSET      LWM2M_URI_DEVICE"/14"
#define LWM2M_URI_DEVICE_TIMEZONE        LWM2M_URI_DEVICE"/15"
#define LWM2M_URI_DEVICE_SUPP_BIND_MODES LWM2M_URI_DEVICE"/16"
#define LWM2M_URI_DEVICE_DEVICE_TYPE     LWM2M_URI_DEVICE"/16"
#define LWM2M_URI_DEVICE_HW_VERSION      LWM2M_URI_DEVICE"/18"
#define LWM2M_URI_DEVICE_SW_VERSION      LWM2M_URI_DEVICE"/19"
#define LWM2M_URI_DEVICE_BATT_STATUS     LWM2M_URI_DEVICE"/20"
#define LWM2M_URI_DEVICE_MEMORY_TOTAL    LWM2M_URI_DEVICE"/21"

/*
 * Object: Firmware
 */
#define LWM2M_URI_FIRMWARE               "/5/0"
#define LWM2M_URI_FIRMWARE_PACKAGE       LWM2M_URI_FIRMWARE"/0"
#define LWM2M_URI_FIRMWARE_PACKAGE_URI   LWM2M_URI_FIRMWARE"/1"
#define LWM2M_URI_FIRMWARE_UPDATE        LWM2M_URI_FIRMWARE"/2"
#define LWM2M_URI_FIRMWARE_STATE         LWM2M_URI_FIRMWARE"/3"
#define LWM2M_URI_FIRMWARE_UPD_SUPP_OBJ  LWM2M_URI_FIRMWARE"/4"
#define LWM2M_URI_FIRMWARE_UPDATE_RES    LWM2M_URI_FIRMWARE"/5"
#define LWM2M_URI_FIRMWARE_PKG_NAME      LWM2M_URI_FIRMWARE"/6"
#define LWM2M_URI_FIRMWARE_PKG_URI       LWM2M_URI_FIRMWARE"/7"

/*
 * Object: Firmware
 * Resource: State
 */
#define LWM2M_FIRMWARE_STATE_IDLE        "1"
#define LWM2M_FIRMWARE_STATE_DOWNLOADING "2"
#define LWM2M_FIRMWARE_STATE_DOWNLOADED  "3"

/*
 * Object: Firmware
 * Resource: Update Result
 */
#define LWM2M_FIRMWARE_UPD_RES_DEFAULT   "0"
#define LWM2M_FIRMWARE_UPD_RES_SUCCESS   "1"
#define LWM2M_FIRMWARE_UPD_RES_SPACE_ERR "2"
#define LWM2M_FIRMWARE_UPD_RES_OOM       "3"
#define LWM2M_FIRMWARE_UPD_RES_CONNE_ERR "4"
#define LWM2M_FIRMWARE_UPD_RES_CRC_ERR   "5"
#define LWM2M_FIRMWARE_UPD_RES_PKG_ERR   "6"
#define LWM2M_FIRMWARE_UPD_RES_URI_ERR   "7"

/*
 * Object: Location
 */
#define LWM2M_URI_LOCATION               "/6/0"
#define LWM2M_URI_LOCATION_LATITUDE      LWM2M_URI_LOCATION"/0"
#define LWM2M_URI_LOCATION_LONGITUDE     LWM2M_URI_LOCATION"/1"
#define LWM2M_URI_LOCATION_ALTITUDE      LWM2M_URI_LOCATION"/2"
#define LWM2M_URI_LOCATION_UNCERTAINTY   LWM2M_URI_LOCATION"/3"
#define LWM2M_URI_LOCATION_VELOCITY      LWM2M_URI_LOCATION"/4"
#define LWM2M_URI_LOCATION_TIMESTAMP     LWM2M_URI_LOCATION"/5"

int lwm2m_client_service(client_handle_t handle);
void lwm2m_client_stop(client_handle_t handle);
client_handle_t lwm2m_client_start(object_container_t *init_val);
void lwm2m_register_callback(client_handle_t handle, enum lwm2m_execute_callback_type type,
        lwm2m_exe_callback callback, void *param);
void lwm2m_unregister_callback(client_handle_t handle, enum lwm2m_execute_callback_type type);
int lwm2m_write_resource(client_handle_t handle, lwm2m_resource_t *res);
int lwm2m_read_resource(client_handle_t handle, lwm2m_resource_t *res);

#endif /* _LWM2MCLIENT_H_ */
