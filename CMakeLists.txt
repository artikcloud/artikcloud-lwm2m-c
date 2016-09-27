cmake_minimum_required (VERSION 2.8)

project (wakaama-client)

set(LIB_VERSION_MAJOR "1")
set(LIB_VERSION_MINOR "0")
set(LIB_VERSION_PATCH "0")

include(${CMAKE_CURRENT_LIST_DIR}/core/wakaama.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/examples/shared/shared.cmake)

add_definitions(-DLWM2M_CLIENT_MODE -DLWM2M_SUPPORT_JSON)
add_definitions(${SHARED_DEFINITIONS} ${WAKAAMA_DEFINITIONS})

include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS})

add_library(${PROJECT_NAME} SHARED ${WAKAAMA_SOURCES} ${SHARED_SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${LIB_VERSION_PATCH}
    SOVERSION ${LIB_VERSION_MAJOR}
    OUTPUT_NAME ${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
add_dependencies (${PROJECT_NAME} openssl-libs)

add_subdirectory(examples/akc_client)

install (TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
install (FILES core/lwm2m_object/lwm2mclient.h DESTINATION /usr/include)

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)
