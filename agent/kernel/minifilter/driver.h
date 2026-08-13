#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

// Driver context structure
typedef struct _DLP_DRIVER_CONTEXT {
    PFLT_FILTER FilterHandle;
    UNICODE_STRING RegistryPath;
} DLP_DRIVER_CONTEXT, *PDLP_DRIVER_CONTEXT;

// Forward declarations
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS DlpFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS DlpInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS DlpInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID DlpInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

VOID DlpInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason
);

// Pre-operation callbacks
FLT_PREOP_CALLBACK_STATUS DlpPreOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

// Post-operation callbacks
FLT_POSTOP_CALLBACK_STATUS DlpPostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Operation-specific callbacks
FLT_PREOP_CALLBACK_STATUS DlpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS DlpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS DlpPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

// Helper functions
NTSTATUS DlpSendMessageToUserMode(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG MessageType,
    _In_opt_ PVOID MessageData,
    _In_ ULONG MessageDataLength
);

BOOLEAN DlpIsSensitiveData(
    _In_ PVOID Buffer,
    _In_ ULONG Length
);

// Constants
#define DLP_FILTER_NAME L"DLPFilter"
#define DLP_INSTANCE_NAME L"DLPInstance"
#define DLP_ALTITUDE L"370030"  // Unique altitude for DLP filter

// Message types for user-mode communication
#define DLP_MSG_FILE_OPERATION 0x0001
#define DLP_MSG_POLICY_CHECK 0x0002
#define DLP_MSG_INCIDENT_LOG 0x0003
