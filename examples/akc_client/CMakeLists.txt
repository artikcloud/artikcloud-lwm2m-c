cmake_minimum_required (VERSION 2.8)

if (CMAKE_MAJOR_VERSION GREATER 2)
	cmake_policy(SET CMP0042 NEW)
endif()

project (akc_client)

include_directories (${OBJECT_SOURCES_DIR} ../lwm2mclient)

set (SOURCES
    akc_client.c
    client_cmdline.c
    )

add_executable (${PROJECT_NAME} ${SOURCES})
target_link_libraries (${PROJECT_NAME} wakaama-client)

install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)
