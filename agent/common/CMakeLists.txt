# Common utilities library
add_library(dlp_common STATIC
    config/Config.cpp
    config/Config.h
    config/config_manager.h
    utils/logging.cpp
    utils/logging.h
    shared/dlp_shared.h
)

target_include_directories(dlp_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/shared
)

# nlohmann/json is required by Config.h; expose it to consumers too.
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_package(nlohmann_json QUIET)
endif()
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(dlp_common PUBLIC nlohmann_json::nlohmann_json)
endif()

if(WIN32)
    target_compile_definitions(dlp_common PRIVATE
        _UNICODE
        UNICODE
        WIN32
        _WIN32
        _WIN64
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0600
    )
endif()
