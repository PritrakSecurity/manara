# User-mode agent executable.
#
# The single PritrakDLP executable hosts BOTH the SCM service (main.cpp, one
# registration named "PritrakDLP") and the full agent pipeline:
#   - usermode processing loop            (DLPAgent, PolicyEngine)
#   - local classification scanning       (ClassificationService + DCI)
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
    telemetry/ClipboardMonitor.cpp
    telemetry/ClipboardMonitor.h
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
    classification/DeepContentInspector.cpp
    classification/DeepContentInspector.h
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

# ---------------------------------------------------------------------------
# Third-party dependencies for Deep Content Inspection (DCI)
# ---------------------------------------------------------------------------
# miniz   (MIT)        - ZIP archive reading (OOXML containers) and test fixtures
# pugixml (MIT)        - robust XML parsing (no external-entity/network support)
# re2     (BSD-3-Clause)- linear-time regex engine (ReDoS-safe PII scanning)
#
# Pinned exact versions; fetched via URL (no git clone needed).
# Reused by both this build and the packaging wrapper (build-and-package-agent.ps1).
include(FetchContent)

# miniz/pugixml/re2 declare a CMake minimum older than 3.5, which CMake 4.x
# rejects by default. Allow those old projects to configure anyway.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0")
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
endif()

# DOWNLOAD_EXTRACT_TIMESTAMP is only supported from CMake 3.24 onward.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
    set(DCI_FETCH_TIMESTAMP DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
else()
    set(DCI_FETCH_TIMESTAMP "")
endif()

set(MINIZ_VERSION 3.0.2)
FetchContent_Declare(miniz
    URL https://github.com/richgel999/miniz/archive/refs/tags/${MINIZ_VERSION}.zip
    ${DCI_FETCH_TIMESTAMP}
)

set(PUGIXML_VERSION 1.14)
FetchContent_Declare(pugixml
    URL https://github.com/zeux/pugixml/releases/download/v${PUGIXML_VERSION}/pugixml-${PUGIXML_VERSION}.tar.gz
    ${DCI_FETCH_TIMESTAMP}
)

set(RE2_VERSION 2021-04-01)
FetchContent_Declare(re2
    URL https://github.com/google/re2/archive/refs/tags/${RE2_VERSION}.zip
    ${DCI_FETCH_TIMESTAMP}
)

# re2 is built manually instead of via its own CMakeLists:
#   - modern RE2 releases (2022+) require Abseil, a very large dependency;
#     2021-04-01 is the last self-contained release.
#   - re2's own CMakeLists uses add_definitions() semantics that CMake 4.x
#     rejects, so we compile its pinned sources directly here.
FetchContent_GetProperties(re2)
if(NOT re2_POPULATED)
    FetchContent_Populate(re2)
endif()

add_library(re2 STATIC
    ${re2_SOURCE_DIR}/re2/bitstate.cc
    ${re2_SOURCE_DIR}/re2/compile.cc
    ${re2_SOURCE_DIR}/re2/dfa.cc
    ${re2_SOURCE_DIR}/re2/filtered_re2.cc
    ${re2_SOURCE_DIR}/re2/mimics_pcre.cc
    ${re2_SOURCE_DIR}/re2/nfa.cc
    ${re2_SOURCE_DIR}/re2/onepass.cc
    ${re2_SOURCE_DIR}/re2/parse.cc
    ${re2_SOURCE_DIR}/re2/perl_groups.cc
    ${re2_SOURCE_DIR}/re2/prefilter.cc
    ${re2_SOURCE_DIR}/re2/prefilter_tree.cc
    ${re2_SOURCE_DIR}/re2/prog.cc
    ${re2_SOURCE_DIR}/re2/re2.cc
    ${re2_SOURCE_DIR}/re2/regexp.cc
    ${re2_SOURCE_DIR}/re2/set.cc
    ${re2_SOURCE_DIR}/re2/simplify.cc
    ${re2_SOURCE_DIR}/re2/stringpiece.cc
    ${re2_SOURCE_DIR}/re2/tostring.cc
    ${re2_SOURCE_DIR}/re2/unicode_casefold.cc
    ${re2_SOURCE_DIR}/re2/unicode_groups.cc
    ${re2_SOURCE_DIR}/util/rune.cc
    ${re2_SOURCE_DIR}/util/strutil.cc
)
add_library(re2::re2 ALIAS re2)
target_include_directories(re2 PUBLIC ${re2_SOURCE_DIR})
target_compile_definitions(re2 PRIVATE STRICT _CRT_SECURE_NO_WARNINGS _SCL_SECURE_NO_WARNINGS)
if(MSVC)
    target_compile_options(re2 PRIVATE /utf-8)
endif()

FetchContent_MakeAvailable(miniz pugixml)

# pugixml: propagate its no-exceptions build setting to consumers (the
# library itself compiles with exceptions disabled by default, and pugixml
# never resolves external entities or performs network I/O).
target_compile_definitions(pugixml INTERFACE PUGIXML_NO_EXCEPTIONS)

target_link_libraries(PritrakDLP
    dlp_common
    miniz
    pugixml
    re2::re2
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
