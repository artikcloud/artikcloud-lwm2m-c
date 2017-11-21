cmake_minimum_required (VERSION 2.8)

if (CMAKE_MAJOR_VERSION GREATER 2)
	cmake_policy(SET CMP0042 NEW)
endif()

project (akc_ota)

find_package (CURL)
find_package (LibArchive)

include_directories (${OBJECT_SOURCES_DIR} ../lwm2mclient)

set (SOURCES
    akc_ota.c
    )

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC ${CURL_INCLUDE_DIRS} ${LibArchive_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} wakaama-client ${LIBARCHIVE_LIBRARIES} ${CURL_LIBRARIES} ${LibArchive_LIBRARIES})

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)
install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if (NOT ${LibArchive_FOUND} OR NOT ${CURL_FOUND})
	message ( "-- Skipping compilation of ${PROJECT_NAME} due to missing dependencies" )
	set_target_properties(${PROJECT_NAME} PROPERTIES EXCLUDE_FROM_ALL 1)
endif()
