# LWM2M Client API

Functions
=========


**lwm2m_client_start**
-----------------------
```cpp
client_handle_t lwm2m_client_start(object_container_t *init_val);
```

**Description**

This function initializes the LWM2M client with default values passed as parameter, then initiates the connection to the server. It returns a connection-specific handle that can be used by other functions in subsequent calls.

**Parameters**

 - *container* [in]: container object defining the default values
to set to the LWM2M standard resources. These values can be later changed dynamically by calling *lwm2m_write_resource*.

**Return value**

*client_handle_t*:  handle to the client connection, or NULL if an error occured

**lwm2m_client_service**
------------------------

```cpp
int lwm2m_client_service(client_handle_t handle);
```
**Description**

This function has to be called periodically from the application code. It performs necessary updates needed throughout the lifetime of the LWM2M client connection.

**Parameters**

 - *handle* [in]: handle returned by *lwm2m_client_start*

**Return value**

*integer*:  The number of seconds after which the function must be called again. If an error happens, it returns a negative value:

 - *LWM2M_CLIENT_ERROR* in case an error happened
 - *LWM2M_CLIENT_QUIT* in case the connection was terminated

**lwm2m_client_stop**
---------------------

```cpp
void lwm2m_client_stop(client_handle_t handle);
```
**Description**

This function terminates the connection and release all the resources previously created during the call to *lwm2m_client_start*.

**Parameters**

 - *handle* [in]: handle returned by *lwm2m_client_start*

**Return value**

*none*

**lwm2m_register_callback**
---------------------------

```cpp
void lwm2m_register_callback(client_handle_t handle, enum lwm2m_execute_callback_type type,        lwm2m_exe_callback callback, void *param);
```

**Description**

This function registers a callback function linked to events specified by *lwm2m_execute_callback_type*. When the event occurs, the library calls the callback that was previously registered by the application. The application can then take action on this specific event.

The prototype of the callback function must be:

```cpp
void lwm2m_callback(void *param, void *extra)
```

The *param* parameter contains the pointer passed as a parameter to the *lwm2m_register_callback* function. The *extra* parameter contains some event-specific data passed by the library.

 - LWM2M_EXE_FACTORY_RESET, LWM2M_EXE_DEVICE_REBOOT, LWM2M_EXE_FIRMWARE_UPDATE: *extra* is set to NULL.

 - LWM2M_NOTIFY_RESOURCE_CHANGED: contains a pointer to a *lwm2m_resource_t* object containing the URI and data of the resource that has been written by the LWM2M server.

**Parameters**

 - *handle* [in]: handle returned by *lwm2m_client_start*.
 - *type* [in]: event to link to the callback, among:
   * *LWM2M_EXE_FACTORY_RESET*: called when the server executes a factory reset request on the client device
   * *LWM2M_EXE_DEVICE_REBOOT*: called when the server executes a reboot request on the client device
   * *LWM2M_EXE_FIRMWARE_UPDATE*: called when the server executes a firmware update request on the client device
   * *LWM2M_NOTIFY_RESOURCE_CHANGED*: called when server writes a resource to any object on the client device
 - *callback* [in]: callback function pointer to call when the associated event occurs.
 - *param* [in]: pointer to any user data allocated by the calling application. This pointer will be passed back as a parameter to the callback function when calling it on an event.

 **Return value**

*none*

**lwm2m_unregister_callback**
-----------------------------

```cpp
void lwm2m_unregister_callback(client_handle_t handle, enum lwm2m_execute_callback_type type);
```
**Description**

This function unregisters a callback that has been previously registered to match an event. After this call the callback function will no longer be called by the library upon occurrence of the previously associated event.

**Parameters**

 - *handle* [in]: handle returned by *lwm2m_client_start*
 - *type* [in] : event that was previously associated to the callback

**Return value**

*none*

**lwm2m_write_resource**
------------------------

```cpp
int lwm2m_write_resource(client_handle_t handle, lwm2m_resource_t *res);
```
**Description**

This function changes the value of a resource locally. All resources (even those that are not writable according to the LWM2M standard, therefore from the server point of view) can be modified by the application.

**Parameters**

 - *handle* [in]: handle returned by *lwm2m_client_start*
 - *resource* [in]: pointer to a *lwm2m_resource_t* object containing the URI and data of the resource to modify. The *buffer* field of the *lwm2m_resource_t* must be allocated and freed by the calling application.

**Return value**

*integer* : *LWM2M_CLIENT_OK* if no error occurred, *LWM2M_CLIENT_ERROR* otherwise.

**lwm2m_read_resource**
-----------------------

```cpp
int lwm2m_read_resource(client_handle_t handle, lwm2m_resource_t *res);
```
**Description**

This function reads the value of a resource locally. All resources (even those that are not readable according to the LWM2M standard, therefore from the server point of view) can be read by the application.

**Parameters**

 - *handle* [in]: handle returned by *lwm2m_client_start*
 - *res* [inout]: pointer to a *lwm2m_resource_t* object containing the URI of the resource to read. After successful return of the function, this object contains the data read from the resource. The *buffer* field of the *lwm2m_resource_t* is allocated and filled by the library, and must be freed by the calling application.

**Return value**

*integer* : *LWM2M_CLIENT_OK* if no error occurred, *LWM2M_CLIENT_ERROR* otherwise.

**lwm2m_serialize_tlv_string**
-------------------------------

```cpp
int lwm2m_serialize_tlv_string(int num, char **strs, lwm2m_resource_t* res);
```

**Description**

This function fills up a "lwm2m_resource_t" with multiple strings pas as parameters. The generated object follows the binary TLV format. This function is used as an helper routine to format resource objects before writing multiple objects formatted resources.

**Parameters**

 - *num* [in]: number of strings to process.
 - *strs* [in]: pointer to the array of strings to process.
 - *res* [inout]: resource pointer to a *lwm2m_resource_t* object whose *buffer* field will be allocated and filled by the library with the content of the TLV. After usage, the calling application must free the memory allocated for the "buffer" field.

**Return value**

*integer* : *LWM2M_CLIENT_OK* if no error occurred, *LWM2M_CLIENT_ERROR* otherwise.

Structures
==========

**lwm2m_resource_t**
---------------------

```cpp
typedef struct {
    char uri[LWM2M_MAX_URI_LEN];
    uint8_t *buffer;
    int length;
} lwm2m_resource_t;
```

**Description**

This structure describes a LWM2M object.

**Fields**

 - *uri*: URI of the LWM2M resource.
 - *buffer*: data containing the value of the resource.
 - *length*: length of the buffer


**object_device_t**
-------------------

```cpp
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
```

**Description**

This structure describes a LWM2M Device object.

**object_firmware_t**
---------------------

```cpp
typedef struct {
    bool supported;                      /*SUPPORTED*/
    char pkg_name[LWM2M_MAX_STR_LEN];    /*PKG_NAME*/
    char pkg_version[LWM2M_MAX_STR_LEN]; /*PKG_VERSION*/
}object_firmware_t;
```

**Description**

This structure describes a LWM2M Firmware Update object.

**object_location_t**
---------------------

```cpp
 typedef struct {
    char  latitude[LWM2M_MAX_STR_LEN];      /*Latitude */
    char  longitude[LWM2M_MAX_STR_LEN];     /*Longitude*/
    char  altidude[LWM2M_MAX_STR_LEN];      /*Altitude*/
    char  uncertainty[LWM2M_MAX_STR_LEN];   /*Uncertainty*/
} object_location_t;
```

**Description**

This structure describes a LWM2M Location object.

**object_conn_monitoring_t**
----------------------------

```cpp
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
```

**Description**

This structure describes a LWM2M Connectivity Monitoring object.

**object_security_server_t**
----------------------------

```cpp
 typedef struct {
    char serverUri[LWM2M_MAX_STR_LEN];   /*serverUri*/
    char bsPskId[LWM2M_MAX_STR_LEN];     /*pskId*/
    char psk[LWM2M_MAX_STR_LEN];         /*psk*/
    char client_name[LWM2M_MAX_STR_LEN]; /*name*/
    int lifetime;                        /*lifetime*/
    int  batterylevelchanging;           /*battery*/
    int serverId;                        /*serverId*/
} object_security_server_t;
```

**Description**

This structure describes a LWM2M Security object.

**object_container_t**
----------------------------

```cpp
typedef struct {
    object_security_server_t* server;
    object_device_t* device;
    object_firmware_t* firmware;
    object_location_t* location;
    object_conn_monitoring_t* monitoring;
}object_container_t;
```

**Description**

This structure describes a container object linking to LWM2M objects.
