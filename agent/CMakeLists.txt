cmake_minimum_required(VERSION 3.20)
project(EnterpriseDLPAgent VERSION 1.0.0 LANGUAGES CXX C ASM)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Windows-specific settings
if(WIN32)
    add_definitions(-D_UNICODE -DUNICODE -DWIN32 -D_WIN32 -D_WIN64)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX- /EHsc")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi /RTC1")
endif()

# Find Windows SDK and WDK
find_package(windowsSDK REQUIRED)
find_package(wdk REQUIRED)

# Common library
add_subdirectory(common)

# User-mode components
add_subdirectory(usermode)

# Kernel-mode components (requires WDK)
if(WDK_FOUND)
    enable_language(ASM_MASM)
    add_subdirectory(kernel)
else()
    message(WARNING "WDK not found. Kernel-mode components will not be built.")
endif()

# Installer (optional, requires WiX)
option(BUILD_INSTALLER "Build MSI installer" OFF)
if(BUILD_INSTALLER)
    add_subdirectory(installer)
endif()
