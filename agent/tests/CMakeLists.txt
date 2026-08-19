# Standalone test build for the Deep Content Inspector (DCI) and PII scanner.
#
# This directory is intentionally self-contained: it does NOT require the WDK
# or the full agent executable, so tests can run on any machine with CMake +
# MSVC. It reuses the same pinned FetchContent dependency versions as
# agent/usermode/CMakeLists.txt.
cmake_minimum_required(VERSION 3.20)
project(PritrakDLPTests VERSION 1.0.0 LANGUAGES CXX)

# miniz/pugixml/re2 declare a CMake minimum older than 3.5, which CMake 4.x
# rejects by default. Allow those old projects to configure anyway.
if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0")
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

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

FetchContent_MakeAvailable(miniz pugixml)

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

# pugixml: propagate its no-exceptions build setting to consumers (the
# library itself compiles with exceptions disabled by default, and pugixml
# never resolves external entities or performs network I/O).
target_compile_definitions(pugixml INTERFACE PUGIXML_NO_EXCEPTIONS)

if(WIN32)
    add_definitions(-D_UNICODE -DUNICODE -DWIN32 -D_WIN32 -D_WIN64 -DNOMINMAX -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX- /EHsc")
endif()

add_executable(PritrakDLPTests
    test_main.cpp
    dci_tests.cpp
    pii_tests.cpp
    clipboard_tests.cpp
    ../usermode/classification/DeepContentInspector.cpp
    ../usermode/telemetry/ClipboardMonitor.cpp
    ../common/utils/logging.cpp
)

target_include_directories(PritrakDLPTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../usermode/classification
    ${CMAKE_CURRENT_SOURCE_DIR}/../usermode/telemetry
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/shared
)

target_link_libraries(PritrakDLPTests
    miniz
    pugixml
    re2::re2
)

if(WIN32)
    target_link_libraries(PritrakDLPTests user32)
endif()

enable_testing()
add_test(NAME PritrakDLPTests COMMAND PritrakDLPTests)
