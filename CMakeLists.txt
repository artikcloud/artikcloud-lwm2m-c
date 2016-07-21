cmake_minimum_required (VERSION 3.0)

project (wakaama)

find_package(OpenSSL)

set(ARTIK_LWM2M ON)

include(${CMAKE_CURRENT_LIST_DIR}/core/wakaama.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/examples/shared/shared.cmake)

add_definitions(-DLWM2M_CLIENT_MODE -DLWM2M_SUPPORT_JSON)
add_definitions(${SHARED_DEFINITIONS} ${WAKAAMA_DEFINITIONS})

include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(${PROJECT_NAME} SHARED ${WAKAAMA_SOURCES} ${SHARED_SOURCES})

target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_LIBRARIES})

add_subdirectory(examples/akc_client)

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)
