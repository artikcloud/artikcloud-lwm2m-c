cmake_minimum_required (VERSION 2.8)
cmake_policy(SET CMP0042 NEW)

project (akc_client)

include_directories (${OBJECT_SOURCES_DIR} ../lwm2mclient)

SET(SOURCES
    akc_client.c
    client_cmdline.c
    )

add_executable(${PROJECT_NAME} ${SOURCES})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} wakaama-client)

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)
