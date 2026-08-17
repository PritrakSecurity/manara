# Kernel-mode minifilter driver
if(NOT WDK_FOUND)
    message(FATAL_ERROR "WDK is required for kernel-mode components")
endif()

# Minifilter driver (real driver sources only)
wdk_add_library(dlp_minifilter STATIC
    minifilter/dlp_driver_core.c
    minifilter/dlp_policy_cache.c
    minifilter/dlp_process_tracker.c
    minifilter/dlp_kernel_types.h
    minifilter/dlp_process_tracker.h
)

target_include_directories(dlp_minifilter PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/minifilter
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/shared
)
