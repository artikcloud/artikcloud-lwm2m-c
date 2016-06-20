cmake_minimum_required (VERSION 3.0)

project (artiklwm2mclient)

include_directories (${OBJECT_SOURCES_DIR})

SET(SOURCES
    artiklwm2mclient.c
    )

add_executable(${PROJECT_NAME} ${SOURCES})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} wakaama )

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)
