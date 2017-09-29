cmake_minimum_required (VERSION 2.8)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
add_definitions("-fno-omit-frame-pointer")  # Allows the fast unwinder to function properly
add_definitions("-fno-common") # Allows ASan to instrument global variable

# enable address sanitizer
add_definitions("-fsanitize=address")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif ()

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
