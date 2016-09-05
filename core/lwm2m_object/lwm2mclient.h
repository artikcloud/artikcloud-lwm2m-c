/*******************************************************************************
 *
 * Copyright (c) 2014 Bosch Software Innovations GmbH, Germany.
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
 *    Bosch Software Innovations GmbH - Please refer to git log
 *
 *******************************************************************************/
/*
 * lwm2mclient.h
 *
 *  General functions of lwm2m test client.
 *
 *  Created on: 22.01.2015
 *  Author: Achim Kraus
 *  Copyright (c) 2015 Bosch Software Innovations GmbH, Germany. All rights reserved.
 */

#ifndef LWM2MCLIENT_H_
#define LWM2MCLIENT_H_

#include "er-coap-13/er-coap-13.h"
#include "liblwm2m.h"
#include "connection.h"

extern int g_reboot;

#define MAX_LEN 100
#define MAX_PACKET_SIZE 1024
#define OBJ_COUNT 9
#define BACKUP_OBJECT_COUNT 2

typedef struct
{
    lwm2m_object_t * securityObjP;
    lwm2m_object_t * serverObject;
    int sock;
    connection_t * connList;
    lwm2m_context_t * lwm2mH;
    struct sockaddr_storage server_addr;
    size_t server_addrlen;
    SSL *ssl;
    int addressFamily;
    lwm2m_object_t * objArray[OBJ_COUNT];
    lwm2m_object_t * backupObjectArray[BACKUP_OBJECT_COUNT];
} client_data_t;

/*
 * object_device.c
 */
typedef struct {
    char manufacturer[MAX_LEN];     /*PRV_MANUFACTURER*/
    char model_number[MAX_LEN];     /*PRV_MODEL_NUMBER*/
    char serial_number[MAX_LEN];    /*PRV_SERIAL_NUMBER*/
    char firmware_version[MAX_LEN]; /*PRV_FIRMWARE_VERSION*/
    int power_source_1;             /*PRV_POWER_SOURCE_1*/
    int power_source_2;             /*PRV_POWER_SOURCE_2*/
    int power_voltage_1;            /*PRV_POWER_VOLTAGE_1*/
    int power_voltage_2;            /*PRV_POWER_VOLTAGE_2*/
    int power_current_1;            /*PRV_POWER_CURRENT_1*/
    int power_current_2;            /*PRV_POWER_CURRENT_2*/
    int battery_level;              /*PRV_BATTERY_LEVEL*/
    int memory_free;                /*PRV_MEMORY_FREE*/
    int error_code;                 /*PRV_ERROR_CODE*/
    char time_zone[MAX_LEN];        /*PRV_TIME_ZONE*/
    char binding_mode[MAX_LEN];     /*PRV_BINDING_MODE*/
    char device_type[MAX_LEN];      /*PRV_DEVICE_TYPE*/
    char hardware_version[MAX_LEN]; /*PRV_HARDWARE_VERSION*/
    char software_version[MAX_LEN]; /*PRV_SOFTWARE_VERSION*/
    int battery_status;             /*PRV_BATTERY_STATUS*/
    int memory_total;               /*PRV_MEMORY_TOTAL*/
} object_device;

lwm2m_object_t * get_object_device(object_device *default_value);
void free_object_device(lwm2m_object_t * objectP);
uint8_t device_change(lwm2m_data_t * dataArray, lwm2m_object_t * objectP);
void display_device_object(lwm2m_object_t * objectP);
/*
 * object_firmware.c
 */
typedef struct
{
    uint8_t state;             /*STATE*/
    bool supported;            /*SUPPORTED*/
    uint8_t result;            /*RESULT*/
    char pkg_name[MAX_LEN];    /*PKG_NAME*/
    char pkg_version[MAX_LEN]; /*PKG_VERSION*/
}object_firmware;

lwm2m_object_t * get_object_firmware(object_firmware *default_value);
void free_object_firmware(lwm2m_object_t * objectP);
void display_firmware_object(lwm2m_object_t * objectP);
/*
 * object_location.c
 */
 typedef struct {
    char  latitude[MAX_LEN];    /*Latitude */
    char  longitude[MAX_LEN];   /*Longitude*/
    char  altidude[MAX_LEN];    /*Altidude*/
    char  uncertainty[MAX_LEN]; /*Uncertainty*/
} object_location;
lwm2m_object_t * get_object_location(object_location *default_value);
void free_object_location(lwm2m_object_t * object);
void display_location_object(lwm2m_object_t * objectP);
/*
 * object_test.c
 */
#define TEST_OBJECT_ID 1024
lwm2m_object_t * get_test_object(void);
void free_test_object(lwm2m_object_t * object);
void display_test_object(lwm2m_object_t * objectP);
/*
 * object_server.c
 */
lwm2m_object_t * get_server_object(int serverId, const char* binding, int lifetime, bool storing);
void clean_server_object(lwm2m_object_t * object);
void display_server_object(lwm2m_object_t * objectP);
void copy_server_object(lwm2m_object_t * objectDest, lwm2m_object_t * objectSrc);

/*
 * object_connectivity_moni.c
 */
typedef struct {
    int  network_bearer;           /*VALUE_NETWORK_BEARER_GSM*/
    int  avl_network_bearer;       /*VALUE_AVL_NETWORK_BEARER_1*/
    int  radio_signal_strength;    /*VALUE_RADIO_SIGNAL_STRENGTH*/
    int  link_quality;             /*VALUE_LINK_QUALITY*/
    char ip_addr[MAX_LEN];         /*VALUE_IP_ADDRESS_1*/
    char ip_addr2[MAX_LEN];        /*VALUE_IP_ADDRESS_2*/
    char router_ip_addr[MAX_LEN];  /*VALUE_ROUTER_IP_ADDRESS_1*/
    char router_ip_addr2[MAX_LEN]; /*VALUE_ROUTER_IP_ADDRESS_2*/
    int  link_utilization;         /*VALUE_LINK_UTILIZATION*/
    char apn[MAX_LEN];             /*VALUE_APN_1*/
    int  cell_id;                  /*VALUE_CELL_ID*/
    int  smnc;                     /*VALUE_SMNC*/
    int  smcc;                     /*VALUE_SMCC*/
} object_conn_monitoring;
lwm2m_object_t * get_object_conn_m(object_conn_monitoring *default_value);
void free_object_conn_m(lwm2m_object_t * objectP);
uint8_t connectivity_moni_change(lwm2m_data_t * dataArray, lwm2m_object_t * objectP);

/*
 * object_connectivity_stat.c
 */
extern lwm2m_object_t * get_object_conn_s(void);
void free_object_conn_s(lwm2m_object_t * objectP);
extern void conn_s_updateTxStatistic(lwm2m_object_t * objectP, uint16_t txDataByte, bool smsBased);
extern void conn_s_updateRxStatistic(lwm2m_object_t * objectP, uint16_t rxDataByte, bool smsBased);

/*
 * object_access_control.c
 */
lwm2m_object_t* acc_ctrl_create_object(void);
void acl_ctrl_free_object(lwm2m_object_t * objectP);
bool  acc_ctrl_obj_add_inst (lwm2m_object_t* accCtrlObjP, uint16_t instId,
                 uint16_t acObjectId, uint16_t acObjInstId, uint16_t acOwner);
bool  acc_ctrl_oi_add_ac_val(lwm2m_object_t* accCtrlObjP, uint16_t instId,
                 uint16_t aclResId, uint16_t acValue);
/*
 * lwm2mclient.c
 */
void handle_value_changed(lwm2m_context_t* lwm2mH, lwm2m_uri_t* uri, const char * value, size_t valueLength);
/*
 * system_api.c
 */
void init_value_change(lwm2m_context_t * lwm2m);
void system_reboot(void);

/*
 * object_security.c
 */
lwm2m_object_t * get_security_object(int serverId, const char* serverUri, char * bsPskId, char * psk, uint16_t pskLen, bool isBootstrap);
void clean_security_object(lwm2m_object_t * objectP);
char * get_server_uri(lwm2m_object_t * objectP, uint16_t secObjInstID);
void display_security_object(lwm2m_object_t * objectP);
void copy_security_object(lwm2m_object_t * objectDest, lwm2m_object_t * objectSrc);

/*
 * lwm2mclient.c
 */
 typedef struct {
    char serverUri[MAX_LEN];   /*serverUri*/
    char bsPskId[MAX_LEN];     /*pskId : DEVICE ID*/
    char psk[MAX_LEN];         /*psk : DEVICE TOKEN*/
    char client_name[MAX_LEN]; /*name : DEVICE ID*/
    int lifetime;              /*lifetime*/
    int  batterylevelchanging; /*battery*/
    int serverId;              /*serverId*/
} object_security_server;

typedef struct {
    object_security_server* server;
    object_device* device;
    object_firmware* firmware;
    object_location* location;
    object_conn_monitoring* monitoring;
}object_container;

void * lwm2m_connect_server(uint16_t secObjInstID,
                            void * userData);
void lwm2m_close_connection(void * sessionH,
                            void * userData);
int get_quit(void);
void akc_stop(client_data_t* data);
client_data_t* akc_start(object_container *init_val);

#endif /* LWM2MCLIENT_H_ */
