cmake_minimum_required (VERSION 2.8)

include(${CMAKE_CURRENT_LIST_DIR}/core/wakaama.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/examples/shared/shared.cmake)

add_definitions(${SHARED_DEFINITIONS} ${WAKAAMA_DEFINITIONS})

include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS})

add_subdirectory(examples/akc_client)
add_subdirectory(examples/lwm2mclient)
