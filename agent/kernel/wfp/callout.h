#pragma once

#include <fwpmk.h>
#include <fwpsk.h>
#include <ntddk.h>

// Callout context structure
typedef struct _DLP_CALLOUT_CONTEXT {
    UINT32 calloutId;
    UINT32 flowId;
    HANDLE engineHandle;
} DLP_CALLOUT_CONTEXT, *PDLP_CALLOUT_CONTEXT;

// Forward declarations
NTSTATUS DlpWfpInitialize(
    _Out_ HANDLE *EngineHandle
);

VOID DlpWfpCleanup(
    _In_ HANDLE EngineHandle
);

NTSTATUS DlpWfpRegisterCallout(
    _In_ HANDLE EngineHandle,
    _Out_ UINT32 *CalloutId
);

NTSTATUS DlpWfpUnregisterCallout(
    _In_ HANDLE EngineHandle,
    _In_ UINT32 CalloutId
);

NTSTATUS DlpWfpAddFilter(
    _In_ HANDLE EngineHandle,
    _In_ UINT32 CalloutId
);

NTSTATUS DlpWfpRemoveFilter(
    _In_ HANDLE EngineHandle
);

// Callout functions
VOID NTAPI DlpWfpCalloutClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Inout_opt_ VOID *layerData,
    _In_opt_ const VOID *classifyContext,
    _In_ const FWPS_FILTER0 *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *classifyOut
);

NTSTATUS NTAPI DlpWfpCalloutNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_opt_ FWPS_FILTER0 *filter
);

VOID NTAPI DlpWfpCalloutFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

// Helper functions
NTSTATUS DlpWfpGetApplicationId(
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    _Out_ PUNICODE_STRING ApplicationPath
);

BOOLEAN DlpWfpIsSensitiveDestination(
    _In_ const FWPS_INCOMING_VALUES0 *inFixedValues
);

NTSTATUS DlpWfpSendMessageToUserMode(
    _In_ ULONG MessageType,
    _In_opt_ PVOID MessageData,
    _In_ ULONG MessageDataLength
);

// Constants
#define DLP_CALLOUT_NAME L"DLP Network Callout"
#define DLP_CALLOUT_DESCRIPTION L"Enterprise DLP Network Filtering Callout"
#define DLP_CALLOUT_GUID {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34}}

// Message types
#define DLP_NET_MSG_CONNECTION_BLOCKED 0x1001
#define DLP_NET_MSG_CONNECTION_ALLOWED 0x1002
#define DLP_NET_MSG_UPLOAD_DETECTED 0x1003
