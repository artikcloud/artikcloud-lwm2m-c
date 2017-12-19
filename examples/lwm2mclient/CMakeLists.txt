cmake_minimum_required (VERSION 2.8)

if (CMAKE_MAJOR_VERSION GREATER 2)
	cmake_policy(SET CMP0042 NEW)
endif()

project (wakaama-client)

set(LIB_VERSION_MAJOR "1")
set(LIB_VERSION_MINOR "5")
set(LIB_VERSION_PATCH "0")

set(SOURCES
        lwm2mclient.c
        system_api.c
        object_security.c
        object_server.c
        object_device.c
        object_firmware.c
        object_location.c
        object_connectivity_moni.c
        object_connectivity_stat.c
        object_access_control.c
        openssl_utils.c
    )


add_definitions(-DLWM2M_CLIENT_MODE -DLWM2M_SUPPORT_JSON)
if (LWM2M_USE_EMBEDDED_OPENSSL)
    set(OPENSSL_SRC_DIR "${CMAKE_SOURCE_DIR}/external/openssl")
    set(OPENSSL_LIBRARIES ${OPENSSL_SRC_DIR}/libssl.a ${OPENSSL_SRC_DIR}/libcrypto.a)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_SRC_DIR}/include")
else()
    find_package ( OpenSSL )
endif()


if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(OPENSSL_CONFIG_CMD ./Configure darwin64-x86_64-cc)
else()
    if(NOT (${CMAKE_SYSTEM_PROCESSOR} MATCHES ${CMAKE_HOST_SYSTEM_PROCESSOR}))
        if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
            set(OPENSSL_CONFIG_CMD ./Configure linux-armv4)
        endif()
        if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
            set(OPENSSL_CONFIG_CMD ./Configure linux-aarch64 no-afalgeng)
        endif()
    endif()
    if(NOT DEFINED OPENSSL_CONFIG_CMD)
        if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
            set(OPENSSL_CONFIG_CMD ./config no-afalgeng)
        else()
            set(OPENSSL_CONFIG_CMD ./config)
        endif()
    endif()
    set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES} dl pthread)
    if (${CMAKE_BUILD_TYPE} MATCHES "Debug")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libwakaama-client.version")
    else()
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libwakaama-client.version -Wl,--strip-all")
    endif()
endif()


include_directories(${OPENSSL_INCLUDE_DIR})

add_library(${PROJECT_NAME} SHARED ${WAKAAMA_SOURCES} ${SHARED_SOURCES} ${SOURCES})
add_library(${PROJECT_NAME}Static STATIC ${WAKAAMA_SOURCES} ${SHARED_SOURCES} ${SOURCES})

if (LWM2M_USE_EMBEDDED_OPENSSL)
    add_custom_command(OUTPUT openssl
            COMMAND ${OPENSSL_CONFIG_CMD}
            COMMAND make
            WORKING_DIRECTORY ${OPENSSL_SRC_DIR}
            COMMENT "Building OpenSSL libraries")

    add_custom_target(openssl-libs DEPENDS openssl)
    add_dependencies (${PROJECT_NAME} openssl-libs)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${LIB_VERSION_PATCH}
    SOVERSION ${LIB_VERSION_MAJOR}
    OUTPUT_NAME ${PROJECT_NAME})
set_target_properties(${PROJECT_NAME}Static PROPERTIES
    OUTPUT_NAME ${PROJECT_NAME})


# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})

install (TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (TARGETS ${PROJECT_NAME}Static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (FILES lwm2mclient.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
