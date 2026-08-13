# User-mode agent executable.
#
# The single PritrakDLP executable hosts BOTH the SCM service (main.cpp, one
# registration named "PritrakDLP") and the full agent pipeline:
#   - usermode processing loop            (DLPAgent, PolicyEngine)
#   - local classification scanning       (ClassificationService)
#   - bidirectional driver port polling   (KernelComm, notify + command ports)
#   - secure backend communications       (HttpClient/WinHTTP, SecureComm)
#   - telemetry / local outbox            (TelemetryCollector, LocalCache)
#   - non-destructive quarantine          (QuarantineManager)
#
# The legacy service/DLPService.cpp (duplicate SCM registration + own entry
# point) has been removed. main.cpp registers exactly one service named
# "PritrakDLP".
add_executable(PritrakDLP
    core/main.cpp
    core/DLPAgent.cpp
    core/DLPAgent.h
    core/EventTypes.cpp
    core/EventTypes.h
    policy/PolicyEngine.cpp
    policy/PolicyEngine.h
    telemetry/TelemetryCollector.cpp
    telemetry/TelemetryCollector.h
    comms/SecureComm.cpp
    comms/SecureComm.h
    comms/HttpClient.cpp
    comms/HttpClient.h
    comms/HeartbeatManager.cpp
    comms/HeartbeatManager.h
    comms/EventSender.cpp
    comms/EventSender.h
    comms/KernelComm.cpp
    comms/KernelComm.h
    classification/ClassificationService.cpp
    classification/ClassificationService.h
    notification/NotificationService.cpp
    notification/NotificationService.h
    quarantine/QuarantineManager.cpp
    quarantine/QuarantineManager.h
    cache/LocalCache.cpp
    cache/LocalCache.h
)

target_include_directories(PritrakDLP PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/policy
    ${CMAKE_CURRENT_SOURCE_DIR}/telemetry
    ${CMAKE_CURRENT_SOURCE_DIR}/comms
    ${CMAKE_CURRENT_SOURCE_DIR}/classification
    ${CMAKE_CURRENT_SOURCE_DIR}/notification
    ${CMAKE_CURRENT_SOURCE_DIR}/quarantine
    ${CMAKE_CURRENT_SOURCE_DIR}/cache
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/shared
)

target_link_libraries(PritrakDLP
    dlp_common
    fltlib      # Filter Manager usermode API (FilterConnectCommunicationPort, FilterGetMessage)
    ws2_32      # Winsock
    winhttp     # HTTP client (TLS-validated)
    iphlpapi    # IP helper for network info
    advapi32    # Registry, ETW, ACL/security APIs
    user32      # Clipboard
    setupapi    # USB devices
    shlwapi     # Path helpers
    ole32       # GUID generation (quarantine)
    uuid        # GUID_DEVINTERFACE_* device interface GUIDs (USB telemetry)
    SQLite3     # SQLite for local cache
)

# nlohmann/json is required (Config.h and event serialization depend on it).
if(NOT TARGET nlohmann_json::nlohmann_json)
    find_package(nlohmann_json QUIET)
endif()
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(PritrakDLP nlohmann_json::nlohmann_json)
else()
    message(FATAL_ERROR "nlohmann_json is required to build the agent")
endif()

if(WIN32)
    target_compile_definitions(PritrakDLP PRIVATE
        _UNICODE
        UNICODE
        WIN32
        _WIN32
        _WIN64
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0600
    )

    # Security flags
    set_target_properties(PritrakDLP PROPERTIES
        LINK_FLAGS "/DYNAMICBASE /NXCOMPAT"
    )
endif()

# Set output name
set_target_properties(PritrakDLP PROPERTIES
    OUTPUT_NAME "PritrakDLP"
)
