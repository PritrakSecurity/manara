# Kernel-mode minifilter driver
if(NOT WDK_FOUND)
    message(FATAL_ERROR "WDK is required for kernel-mode components")
endif()

# Minifilter driver
wdk_add_library(dlp_minifilter STATIC
    minifilter/driver.cpp
    minifilter/driver.h
    minifilter/callback.cpp
    minifilter/callback.h
)

target_include_directories(dlp_minifilter PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/minifilter
)

# WFP callout driver (optional, separate driver)
wdk_add_library(dlp_wfp STATIC
    wfp/callout.cpp
    wfp/callout.h
)

target_include_directories(dlp_wfp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/wfp
)

# Note: Actual driver compilation requires WDK build environment
# This is a skeleton structure
