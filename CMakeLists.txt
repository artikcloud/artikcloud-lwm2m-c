cmake_minimum_required (VERSION 2.8)

set(LWM2M_USE_EMBEDDED_OPENSSL true CACHE BOOL "Use the embedded openssl (version 1.1.0) that includes the cipher TLS_PSK_WITH_AES_128_CCM_8 needed by ARTIK Cloud")

if (CMAKE_MAJOR_VERSION GREATER 2)
	cmake_policy(SET CMP0042 NEW)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/core/wakaama.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/examples/shared/shared.cmake)

add_definitions(${SHARED_DEFINITIONS} ${WAKAAMA_DEFINITIONS})

include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS})

add_subdirectory(examples/akc_client)
add_subdirectory(examples/akc_ota)
add_subdirectory(examples/lwm2mclient)
