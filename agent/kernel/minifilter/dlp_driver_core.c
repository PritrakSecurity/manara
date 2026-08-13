/**
 * @file dlp_driver_core.c
 * @brief PRITRAK DLP Minifilter Driver - Core Implementation
 * 
 * PRITRAK Enterprise DLP Agent - Kernel Minifilter Driver
 * 
 * This is the core enforcement engine. It intercepts all file system
 * operations and makes immediate allow/block decisions based on
 * cached policy. Key interceptions:
 * 
 * - IRP_MJ_SET_INFORMATION (FileDispositionInformation) - Delete blocking
 * - IRP_MJ_SET_INFORMATION (FileRenameInformation) - Rename/move blocking
 * - IRP_MJ_WRITE - USB/removable media blocking
 * - IRP_MJ_CREATE (DELETE_ON_CLOSE) - Delete bypass prevention
 * 
 * Design Principles:
 * - Kernel is enforcement only, user-mode is intelligence
 * - No blocking waits in callbacks
 * - No allocations in hot paths
 * - All decisions from cached policy
 * - Fail-closed by default
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#include "dlp_kernel_types.h"
#include "dlp_process_tracker.h"
#include <ntstrsafe.h>
#include <wdm.h>

// ============================================================================
// GLOBAL STATE
// ============================================================================

// The single global state structure
DLP_DRIVER_GLOBALS g_Globals = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

// Driver lifecycle
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DlpFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Instance callbacks
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
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);
VOID DlpInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

// Pre-operation callbacks
FLT_PREOP_CALLBACK_STATUS DlpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);
FLT_PREOP_CALLBACK_STATUS DlpPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);
FLT_PREOP_CALLBACK_STATUS DlpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);
FLT_POSTOP_CALLBACK_STATUS DlpPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);
FLT_PREOP_CALLBACK_STATUS DlpPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

// Post-operation callbacks
FLT_POSTOP_CALLBACK_STATUS DlpPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

// Communication port callbacks
NTSTATUS DlpPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
);
VOID DlpPortDisconnect(_In_opt_ PVOID ConnectionCookie);
NTSTATUS DlpPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

// Helper functions
NTSTATUS DlpGetFileId(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PDLP_FILE_ID FileId
);
NTSTATUS DlpGetVolumeFlags(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG VolumeFlags
);
NTSTATUS DlpIsOperationBlocked(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PDLP_FILE_ID FileId,
    _In_ ULONG OperationType
);
VOID DlpQueueBlockEvent(
    _In_ PDLP_FILE_ID FileId,
    _In_ DLP_OPERATION_TYPE Operation,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ULONG ProcessId
);

// Notify port callbacks (kernel -> usermode event delivery)
NTSTATUS DlpNotifyPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
);
VOID DlpNotifyPortDisconnect(_In_opt_ PVOID ConnectionCookie);
NTSTATUS DlpNotifyPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
);

// Event queue lifecycle
NTSTATUS DlpInitializeEventQueue(_Inout_ PDLP_EVENT_QUEUE Queue);
VOID DlpDestroyEventQueue(_Inout_ PDLP_EVENT_QUEUE Queue);

// Event queue workers
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID DlpNotifyWorker(_In_ PVOID Context);
VOID DlpFlushNotificationQueue(VOID);
VOID DlpSendNotification(_In_ PDLP_NOTIFICATION_RECORD Record);
VOID DlpCaptureProcessContext(_Inout_ PDLP_NOTIFICATION_RECORD Record);

// External declarations
NTSTATUS DlpInitializePolicyCache(
    _Out_ PDLP_POLICY_CACHE Cache,
    _In_ ULONG MaxEntries,
    _In_ ULONG TTLSeconds
);
VOID DlpDestroyPolicyCache(_Inout_ PDLP_POLICY_CACHE Cache);
NTSTATUS DlpLookupPolicy(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_FILE_ID FileId,
    _Out_ PDLP_POLICY_ENTRY PolicyOut
);

// ============================================================================
// FILTER REGISTRATION
// ============================================================================

// Context registration
const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_VOLUME_CONTEXT,
        0,
        NULL,  // Cleanup callback
        DLP_VOLUME_CONTEXT_SIZE,
        DLP_VOLUME_CONTEXT_TAG
    },
    {
        FLT_STREAM_CONTEXT,
        0,
        NULL,
        DLP_STREAM_CONTEXT_SIZE,
        DLP_STREAM_CONTEXT_TAG
    },
    { FLT_CONTEXT_END }
};

// Operation registration
const FLT_OPERATION_REGISTRATION OperationCallbacks[] = {
    // CREATE - For DELETE_ON_CLOSE detection and file identity
    {
        IRP_MJ_CREATE,
        0,
        DlpPreCreate,
        DlpPostCreate
    },
    
    // SET_INFORMATION - For delete and rename blocking (CRITICAL)
    {
        IRP_MJ_SET_INFORMATION,
        0,
        DlpPreSetInformation,
        NULL
    },
    
    // READ - Track processes reading protected files (for USB copy blocking)
    {
        IRP_MJ_READ,
        0,
        NULL,           // No pre-callback needed
        DlpPostRead     // Track after successful read
    },
    
    // WRITE - Block writes of protected content to removable media
    {
        IRP_MJ_WRITE,
        0,
        DlpPreWrite,
        NULL
    },
    
    // CLEANUP - Track when protected files are closed
    {
        IRP_MJ_CLEANUP,
        0,
        DlpPreCleanup,
        NULL
    },
    
    { IRP_MJ_OPERATION_END }
};

// Filter registration structure
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,           // Version
    0,                                  // Flags
    ContextRegistration,                // Context registration
    OperationCallbacks,                 // Operation registration
    DlpFilterUnload,                    // FilterUnloadCallback
    DlpInstanceSetup,                   // InstanceSetupCallback
    DlpInstanceQueryTeardown,           // InstanceQueryTeardownCallback
    DlpInstanceTeardownStart,           // InstanceTeardownStartCallback
    DlpInstanceTeardownComplete,        // InstanceTeardownCompleteCallback
    NULL,                               // GenerateFileNameCallback
    NULL,                               // NormalizeNameComponentCallback
    NULL                                // NormalizeContextCleanupCallback
};

// ============================================================================
// DRIVER ENTRY
// ============================================================================

/**
 * DriverEntry - Main entry point for the minifilter driver
 * 
 * @param DriverObject - Pointer to driver object
 * @param RegistryPath - Driver's registry path
 * 
 * @return STATUS_SUCCESS or error code
 * 
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING commandPortName = RTL_CONSTANT_STRING(DLP_COMMAND_PORT_NAME);
    PSECURITY_DESCRIPTOR sd = NULL;
    UNICODE_STRING securityDescriptorString = RTL_CONSTANT_STRING(L"D:P(A;;0x1;;;SY)(A;;0x1;;;BA)");
    OBJECT_ATTRIBUTES oa;
    
    PAGED_CODE();
    
    // Initialize global state
    RtlZeroMemory(&g_Globals, sizeof(g_Globals));
    g_Globals.DriverObject = DriverObject;
    
    // Copy registry path
    g_Globals.RegistryPath.Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_PAGED,
        RegistryPath->Length + sizeof(WCHAR),
        DLP_POOL_TAG_STRING
    );
    
    if (g_Globals.RegistryPath.Buffer != NULL) {
        g_Globals.RegistryPath.MaximumLength = RegistryPath->Length + sizeof(WCHAR);
        RtlCopyUnicodeString(&g_Globals.RegistryPath, RegistryPath);
    }
    
    // Initialize default configuration
    g_Globals.Config.FailClosedMode = TRUE;     // Block if no policy (safe default)
    g_Globals.Config.AuditMode = FALSE;         // Enforce, don't just log
    g_Globals.Config.DebugMode = FALSE;
    g_Globals.Config.MaxCacheEntries = DLP_DEFAULT_CACHE_SIZE;
    g_Globals.Config.CacheTTLSeconds = DLP_POLICY_DEFAULT_TTL_SEC;
    
    // Initialize policy cache
    status = DlpInitializePolicyCache(
        &g_Globals.PolicyCache,
        g_Globals.Config.MaxCacheEntries,
        g_Globals.Config.CacheTTLSeconds
    );
    
    if (!NT_SUCCESS(status)) {
        goto DriverEntryCleanup;
    }
    
    // Initialize volume table
    ExInitializePushLock(&g_Globals.VolumeTable.Lock);
    RtlZeroMemory(g_Globals.VolumeTable.Entries, sizeof(g_Globals.VolumeTable.Entries));
    
    // Initialize process tracker (CRITICAL for USB copy blocking)
    g_Globals.ProcessTable = (PDLP_PROCESS_TABLE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DLP_PROCESS_TABLE),
        DLP_POOL_TAG_GENERAL
    );
    
    if (g_Globals.ProcessTable != NULL) {
        status = DlpInitializeProcessTracker(g_Globals.ProcessTable);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(g_Globals.ProcessTable, DLP_POOL_TAG_GENERAL);
            g_Globals.ProcessTable = NULL;
            // Non-fatal: continue without process tracking
        }
    }
    
    // Initialize notification events
    KeInitializeEvent(&g_Globals.EventQueue.DataAvailable, NotificationEvent, FALSE);
    KeInitializeEvent(&g_Globals.NotifyThreadStop, NotificationEvent, FALSE);

    // Initialize the event queue (push-lock FIFO + NonPagedPoolNx lookaside)
    status = DlpInitializeEventQueue(&g_Globals.EventQueue);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "PRITRAK DLP: failed to initialize event queue (0x%08X)\n", status));
        goto DriverEntryCleanup;
    }

    // Register the minifilter
    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &g_Globals.FilterHandle
    );
    
    if (!NT_SUCCESS(status)) {
        goto DriverEntryCleanup;
    }
    
    // Create communication port for user-mode service
    status = RtlCreateSecurityDescriptorFromString(&securityDescriptorString, &sd);
    
    if (!NT_SUCCESS(status)) {
        goto DriverEntryCleanup;
    }
    
    InitializeObjectAttributes(
        &oa,
        &commandPortName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
    );
    
    status = FltCreateCommunicationPort(
        g_Globals.FilterHandle,
        &g_Globals.CommandServerPort,
        &oa,
        NULL,  // ServerPortCookie
        DlpPortConnect,
        DlpPortDisconnect,
        DlpPortMessage,
        1      // MaxConnections
    );
    
    ExFreePool(sd);
    sd = NULL;
    
    if (!NT_SUCCESS(status)) {
        goto DriverEntryCleanup;
    }
    
    // Create the notification port for kernel -> usermode event delivery.
    // ACL restricts access strictly to NT AUTHORITY\SYSTEM.
    {
        UNICODE_STRING notifyPortName = RTL_CONSTANT_STRING(DLP_NOTIFICATION_PORT_NAME);
        PSECURITY_DESCRIPTOR notifySd = NULL;
        UNICODE_STRING notifySdString = RTL_CONSTANT_STRING(L"D:P(A;;0x1;;;SY)");
        OBJECT_ATTRIBUTES notifyOa;

        status = RtlCreateSecurityDescriptorFromString(&notifySdString, &notifySd);
        if (NT_SUCCESS(status)) {
            InitializeObjectAttributes(
                &notifyOa,
                &notifyPortName,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                NULL,
                notifySd
            );

            status = FltCreateCommunicationPort(
                g_Globals.FilterHandle,
                &g_Globals.NotifyServerPort,
                &notifyOa,
                NULL,               // ServerPortCookie
                DlpNotifyPortConnect,
                DlpNotifyPortDisconnect,
                DlpNotifyPortMessage,
                1                   // MaxConnections
            );

            ExFreePool(notifySd);
            notifySd = NULL;

            if (!NT_SUCCESS(status)) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "PRITRAK DLP: failed to create notify port (0x%08X)\n", status));
                // Non-fatal: event delivery degrades to dropped-event accounting.
                status = STATUS_SUCCESS;
            }
        }
    }
    
    // Start filtering
    status = FltStartFiltering(g_Globals.FilterHandle);
    
    if (!NT_SUCCESS(status)) {
        goto DriverEntryCleanup;
    }
    
    // Start the notification worker thread that drains the event queue and
    // delivers records to the SCM-hosted usermode service.
    {
        HANDLE workerThreadHandle = NULL;

        status = PsCreateSystemThread(
            &workerThreadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            DlpNotifyWorker,
            &g_Globals.EventQueue
        );

        if (NT_SUCCESS(status)) {
            status = ObReferenceObjectByHandle(
                workerThreadHandle,
                THREAD_ALL_ACCESS,
                NULL,
                KernelMode,
                (PVOID*)&g_Globals.NotifyThread,
                NULL
            );
            ZwClose(workerThreadHandle);

            if (NT_SUCCESS(status)) {
                KeSetPriorityThread(g_Globals.NotifyThread, LOW_REALTIME_PRIORITY);
            } else {
                g_Globals.NotifyThread = NULL;
            }
        } else {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "PRITRAK DLP: failed to start notify worker (0x%08X)\n", status));
        }
    }
    
    // Record load time
    g_Globals.Stats.DriverLoadTime = DlpGetCurrentTime();
    
    return STATUS_SUCCESS;
    
DriverEntryCleanup:
    if (g_Globals.NotifyServerPort != NULL) {
        FltCloseCommunicationPort(g_Globals.NotifyServerPort);
        g_Globals.NotifyServerPort = NULL;
    }

    if (g_Globals.CommandServerPort != NULL) {
        FltCloseCommunicationPort(g_Globals.CommandServerPort);
        g_Globals.CommandServerPort = NULL;
    }
    
    if (g_Globals.FilterHandle != NULL) {
        FltUnregisterFilter(g_Globals.FilterHandle);
        g_Globals.FilterHandle = NULL;
    }
    
    DlpDestroyEventQueue(&g_Globals.EventQueue);
    DlpDestroyPolicyCache(&g_Globals.PolicyCache);
    
    if (g_Globals.RegistryPath.Buffer != NULL) {
        ExFreePoolWithTag(g_Globals.RegistryPath.Buffer, DLP_POOL_TAG_STRING);
    }
    
    return status;
}

// ============================================================================
// FILTER UNLOAD
// ============================================================================

/**
 * DlpFilterUnload - Called when the filter is being unloaded
 * 
 * @param Flags - Unload flags
 * 
 * @return STATUS_SUCCESS
 * 
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
DlpFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    
    // Signal shutdown
    InterlockedExchange(&g_Globals.ShuttingDown, TRUE);
    
    // Stop notification worker thread if running
    KeSetEvent(&g_Globals.NotifyThreadStop, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&g_Globals.EventQueue.DataAvailable, IO_NO_INCREMENT, FALSE);
    
    if (g_Globals.NotifyThread != NULL) {
        KeWaitForSingleObject(
            g_Globals.NotifyThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
        ObDereferenceObject(g_Globals.NotifyThread);
        g_Globals.NotifyThread = NULL;
    }
    
    // Close communication ports
    if (g_Globals.NotifyClientPort != NULL) {
        FltCloseClientPort(g_Globals.FilterHandle, &g_Globals.NotifyClientPort);
    }
    
    if (g_Globals.NotifyServerPort != NULL) {
        FltCloseCommunicationPort(g_Globals.NotifyServerPort);
        g_Globals.NotifyServerPort = NULL;
    }
    
    if (g_Globals.CommandClientPort != NULL) {
        FltCloseClientPort(g_Globals.FilterHandle, &g_Globals.CommandClientPort);
    }
    
    if (g_Globals.CommandServerPort != NULL) {
        FltCloseCommunicationPort(g_Globals.CommandServerPort);
        g_Globals.CommandServerPort = NULL;
    }
    
    // Unregister filter
    if (g_Globals.FilterHandle != NULL) {
        FltUnregisterFilter(g_Globals.FilterHandle);
        g_Globals.FilterHandle = NULL;
    }
    
    // Cleanup event queue (drains and frees any remaining records)
    DlpDestroyEventQueue(&g_Globals.EventQueue);
    
    // Cleanup policy cache
    DlpDestroyPolicyCache(&g_Globals.PolicyCache);
    
    // Cleanup process tracker
    if (g_Globals.ProcessTable != NULL) {
        DlpDestroyProcessTracker(g_Globals.ProcessTable);
        ExFreePoolWithTag(g_Globals.ProcessTable, DLP_POOL_TAG_GENERAL);
        g_Globals.ProcessTable = NULL;
    }
    
    // Free registry path
    if (g_Globals.RegistryPath.Buffer != NULL) {
        ExFreePoolWithTag(g_Globals.RegistryPath.Buffer, DLP_POOL_TAG_STRING);
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

/**
 * DlpInstanceSetup - Called when a new volume is attached
 * 
 * Determines volume type (removable/USB) and stores in context.
 */
NTSTATUS
DlpInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    NTSTATUS status;
    PDLP_VOLUME_CONTEXT volumeContext = NULL;
    ULONG volumeFlags = DLP_VOLUME_FLAG_NONE;
    PDEVICE_OBJECT deviceObject = NULL;
    
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    
    // Skip non-disk file systems
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }
    
    // Skip network file systems for now (can be enabled later)
    if (VolumeFilesystemType == FLT_FSTYPE_LANMAN ||
        VolumeFilesystemType == FLT_FSTYPE_RDPDR ||
        VolumeFilesystemType == FLT_FSTYPE_NFS ||
        VolumeFilesystemType == FLT_FSTYPE_NETWARE ||
        VolumeFilesystemType == FLT_FSTYPE_WEBDAV) {
        volumeFlags |= DLP_VOLUME_FLAG_NETWORK;
    }
    
    // Get the device object to check characteristics
    status = FltGetDiskDeviceObject(FltObjects->Volume, &deviceObject);
    if (NT_SUCCESS(status)) {
        // Check if removable media
        if (deviceObject->Characteristics & FILE_REMOVABLE_MEDIA) {
            volumeFlags |= DLP_VOLUME_FLAG_REMOVABLE;
        }
        
        // Check for USB (simplified - in production use IoGetDeviceProperty)
        if (deviceObject->Characteristics & FILE_DEVICE_IS_MOUNTED) {
            // Additional USB detection would go here
            // For now, assume removable = potential USB
            if (volumeFlags & DLP_VOLUME_FLAG_REMOVABLE) {
                volumeFlags |= DLP_VOLUME_FLAG_USB;
            }
        }
        
        ObDereferenceObject(deviceObject);
    }
    
    // Allocate and set volume context
    status = FltAllocateContext(
        FltObjects->Filter,
        FLT_VOLUME_CONTEXT,
        sizeof(DLP_VOLUME_CONTEXT),
        NonPagedPoolNx,
        (PFLT_CONTEXT*)&volumeContext
    );
    
    if (!NT_SUCCESS(status)) {
        // Continue without context - we'll still filter
        return STATUS_SUCCESS;
    }
    
    // Initialize volume context
    RtlZeroMemory(volumeContext, sizeof(DLP_VOLUME_CONTEXT));
    volumeContext->VolumeFlags = volumeFlags;
    volumeContext->FileSystemType = VolumeFilesystemType;
    volumeContext->DeviceType = VolumeDeviceType;
    
    // Get volume serial number
    UCHAR buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 256];
    PFILE_FS_VOLUME_INFORMATION volumeInfo = (PFILE_FS_VOLUME_INFORMATION)buffer;
    ULONG returnedLength;
    
    status = FltQueryVolumeInformation(
        FltObjects->Instance,
        NULL,
        sizeof(buffer),
        volumeInfo,
        &returnedLength,
        FileFsVolumeInformation
    );
    
    if (NT_SUCCESS(status)) {
        volumeContext->VolumeSerialNumber = volumeInfo->VolumeSerialNumber;
        
        // Copy volume label
        ULONG copyLength = min(
            volumeInfo->VolumeLabelLength,
            sizeof(volumeContext->VolumeNameBuffer) - sizeof(WCHAR)
        );
        RtlCopyMemory(volumeContext->VolumeNameBuffer, volumeInfo->VolumeLabel, copyLength);
        volumeContext->VolumeName.Buffer = volumeContext->VolumeNameBuffer;
        volumeContext->VolumeName.Length = (USHORT)copyLength;
        volumeContext->VolumeName.MaximumLength = sizeof(volumeContext->VolumeNameBuffer);
    }
    
    // Set the context
    status = FltSetVolumeContext(
        FltObjects->Volume,
        FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
        volumeContext,
        NULL
    );
    
    // Release our reference (SetVolumeContext adds its own)
    FltReleaseContext(volumeContext);
    
    // Update volume table
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_Globals.VolumeTable.Lock);
    
    for (ULONG i = 0; i < DLP_MAX_VOLUMES; i++) {
        if (!g_Globals.VolumeTable.Entries[i].InUse) {
            g_Globals.VolumeTable.Entries[i].InUse = TRUE;
            g_Globals.VolumeTable.Entries[i].SerialNumber = volumeContext->VolumeSerialNumber;
            g_Globals.VolumeTable.Entries[i].Flags = volumeFlags;
            g_Globals.VolumeTable.Entries[i].Instance = FltObjects->Instance;
            g_Globals.VolumeTable.Entries[i].Volume = FltObjects->Volume;
            g_Globals.VolumeTable.Count++;
            
            // Update statistics
            InterlockedIncrement((PLONG)&g_Globals.Stats.VolumesMonitored);
            break;
        }
    }
    
    ExReleasePushLock(&g_Globals.VolumeTable.Lock);
    KeLeaveCriticalRegion();
    
    return STATUS_SUCCESS;
}

NTSTATUS
DlpInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    
    return STATUS_SUCCESS;
}

VOID
DlpInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
}

VOID
DlpInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    
    // Remove from volume table
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_Globals.VolumeTable.Lock);
    
    for (ULONG i = 0; i < DLP_MAX_VOLUMES; i++) {
        if (g_Globals.VolumeTable.Entries[i].InUse &&
            g_Globals.VolumeTable.Entries[i].Instance == FltObjects->Instance) {
            
            g_Globals.VolumeTable.Entries[i].InUse = FALSE;
            g_Globals.VolumeTable.Count--;
            InterlockedDecrement((PLONG)&g_Globals.Stats.VolumesMonitored);
            break;
        }
    }
    
    ExReleasePushLock(&g_Globals.VolumeTable.Lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * DlpGetFileId - Get stable file identifier
 * 
 * Uses NTFS File Reference Number for path-independent identification.
 */
NTSTATUS
DlpGetFileId(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PDLP_FILE_ID FileId
)
{
    NTSTATUS status;
    FILE_INTERNAL_INFORMATION internalInfo;
    PDLP_VOLUME_CONTEXT volumeContext = NULL;
    
    RtlZeroMemory(FileId, sizeof(DLP_FILE_ID));
    
    // Get file reference number
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInfo,
        sizeof(internalInfo),
        FileInternalInformation,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    FileId->FileId = (ULONGLONG)internalInfo.IndexNumber.QuadPart;
    
    // Get volume serial number from context
    status = FltGetVolumeContext(
        FltObjects->Filter,
        FltObjects->Volume,
        (PFLT_CONTEXT*)&volumeContext
    );
    
    if (NT_SUCCESS(status)) {
        FileId->VolumeSerialNumber = volumeContext->VolumeSerialNumber;
        FltReleaseContext(volumeContext);
    } else {
        // Fallback: query volume information directly
        UCHAR buffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 256];
        PFILE_FS_VOLUME_INFORMATION volumeInfo = (PFILE_FS_VOLUME_INFORMATION)buffer;
        ULONG returnedLength;
        
        status = FltQueryVolumeInformation(
            FltObjects->Instance,
            NULL,
            sizeof(buffer),
            volumeInfo,
            &returnedLength,
            FileFsVolumeInformation
        );
        
        if (NT_SUCCESS(status)) {
            FileId->VolumeSerialNumber = volumeInfo->VolumeSerialNumber;
        }
    }
    
    return STATUS_SUCCESS;
}

/**
 * DlpGetVolumeFlags - Get volume type flags
 */
NTSTATUS
DlpGetVolumeFlags(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PULONG VolumeFlags
)
{
    NTSTATUS status;
    PDLP_VOLUME_CONTEXT volumeContext = NULL;
    
    *VolumeFlags = DLP_VOLUME_FLAG_NONE;
    
    status = FltGetVolumeContext(
        FltObjects->Filter,
        FltObjects->Volume,
        (PFLT_CONTEXT*)&volumeContext
    );
    
    if (NT_SUCCESS(status)) {
        *VolumeFlags = volumeContext->VolumeFlags;
        FltReleaseContext(volumeContext);
    }
    
    return status;
}

/**
 * DlpIsOperationBlocked - Check if operation should be blocked
 * 
 * This is the core policy decision function. It must be called at
 * IRQL <= APC_LEVEL (pre-operation callbacks run at PASSIVE_LEVEL).
 *
 * Fail-closed semantics:
 *   When FailClosedMode is active and no cached policy exists for the file,
 *   dangerous operations (IRP_MJ_WRITE and IRP_MJ_SET_INFORMATION which covers
 *   delete/rename disposition changes) default to STATUS_ACCESS_DENIED.
 *   All other operations (reads, queries, creates) fail-open so that
 *   unclassified files remain usable while classification is still pending.
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
DlpIsOperationBlocked(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PDLP_FILE_ID FileId,
    _In_ ULONG OperationType
)
{
    DLP_POLICY_ENTRY policy;
    NTSTATUS status;
    ULONG destVolumeFlags = DLP_VOLUME_FLAG_NONE;

    UNREFERENCED_PARAMETER(Data);

    // If in audit mode, never block
    if (g_Globals.Config.AuditMode) {
        return STATUS_SUCCESS;
    }

    // Look up policy in cache
    status = DlpLookupPolicy(&g_Globals.PolicyCache, FileId, &policy);

    if (!NT_SUCCESS(status)) {
        // No cached policy for this file.
        if (g_Globals.Config.FailClosedMode) {
            // Only fail-closed on operations that modify or exfiltrate data.
            // IRP_MJ_SET_INFORMATION covers delete (FileDispositionInformation)
            // and rename/move (FileRenameInformation).
            if (OperationType == IRP_MJ_WRITE ||
                OperationType == IRP_MJ_SET_INFORMATION) {
                return STATUS_ACCESS_DENIED;
            }
        }
        // Fail-open for read/query operations and when not in fail-closed mode.
        return STATUS_SUCCESS;
    }

    // Check if file is protected
    if (!DLP_IS_PROTECTED_CLASS(policy.Classification)) {
        // Public or internal - allow
        return STATUS_SUCCESS;
    }

    // File is protected - check operation type
    switch (OperationType) {
        case IRP_MJ_WRITE:
            // Block writes of protected content to removable/USB media.
            if (NT_SUCCESS(DlpGetVolumeFlags(FltObjects, &destVolumeFlags))) {
                if ((destVolumeFlags & (DLP_VOLUME_FLAG_REMOVABLE | DLP_VOLUME_FLAG_USB)) != 0) {
                    return STATUS_ACCESS_DENIED;
                }
                // Block restricted-class writes to network shares.
                if ((destVolumeFlags & DLP_VOLUME_FLAG_NETWORK) != 0 &&
                    (policy.Classification & DLP_CLASS_RESTRICTED) != 0) {
                    return STATUS_ACCESS_DENIED;
                }
            }
            return STATUS_SUCCESS;

        case IRP_MJ_SET_INFORMATION:
            // Delete/rename/move of protected files is blocked.
            return ((policy.BlockedActions & DLP_ACTION_BLOCK) != 0 ||
                    (policy.Classification & (DLP_CLASS_RESTRICTED | DLP_CLASS_TOP_SECRET)) != 0)
                       ? STATUS_ACCESS_DENIED
                       : STATUS_SUCCESS;

        default:
            // Reads, creates, cleanup and all other operations are allowed.
            return STATUS_SUCCESS;
    }
}

// ============================================================================
// PRE-OPERATION CALLBACKS
// ============================================================================

/**
 * DlpPreCreate - Pre-create callback
 * 
 * Handles DELETE_ON_CLOSE flag which is a delete bypass vector.
 */
FLT_PREOP_CALLBACK_STATUS
DlpPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    ULONG createDisposition;
    ULONG createOptions;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    // Skip kernel-mode requests (they're trusted)
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Skip paging I/O
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get create options
    createDisposition = Data->Iopb->Parameters.Create.Options >> 24;
    createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    
    // Check for DELETE_ON_CLOSE - this is a delete bypass vector!
    if (createOptions & FILE_DELETE_ON_CLOSE) {
        // We need the file object to exist first to check classification
        // Request post-create callback to handle this
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    
    // For regular opens, proceed to post-create for tracking
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/**
 * DlpPostCreate - Post-create callback
 * 
 * Attaches stream context for tracking, handles DELETE_ON_CLOSE.
 */
FLT_POSTOP_CALLBACK_STATUS
DlpPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    DLP_FILE_ID fileId;
    DLP_POLICY_ENTRY policy;
    ULONG createOptions;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    
    // Only process successful creates
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Skip directories
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    
    // Handle DELETE_ON_CLOSE bypass attempt
    if (createOptions & FILE_DELETE_ON_CLOSE) {
        // Get file identity
        status = DlpGetFileId(FltObjects, &fileId);
        if (NT_SUCCESS(status)) {
            // Look up policy
            status = DlpLookupPolicy(&g_Globals.PolicyCache, &fileId, &policy);
            
            if (NT_SUCCESS(status) && DLP_IS_PROTECTED_CLASS(policy.Classification)) {
                // Protected file with DELETE_ON_CLOSE - must cancel the handle!
                // We can't block the create, but we can issue a cancel
                FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
                
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                
                // Queue notification
                DlpQueueBlockEvent(&fileId, DLP_OP_FILE_DELETE, NULL, 
                    (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
                
                InterlockedIncrement64((PLONG64)&g_Globals.Stats.TotalOperationsBlocked);
                
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
        }
    }
    
    InterlockedIncrement64((PLONG64)&g_Globals.Stats.TotalOperationsScanned);
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/**
 * DlpPreSetInformation - Pre-set-information callback
 * 
 * THIS IS THE CRITICAL DELETE/RENAME INTERCEPTION POINT.
 * 
 * Intercepts:
 * - FileDispositionInformation (delete)
 * - FileDispositionInformationEx (delete)
 * - FileRenameInformation (rename/move)
 * - FileRenameInformationEx (rename/move)
 */
FLT_PREOP_CALLBACK_STATUS
DlpPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    FILE_INFORMATION_CLASS fileInfoClass;
    DLP_FILE_ID fileId;
    BOOLEAN blocked = FALSE;
    DLP_OPERATION_TYPE operation = DLP_OP_UNKNOWN;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    // Skip kernel-mode requests
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    fileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    
    // ========== DELETE INTERCEPTION ==========
    if (fileInfoClass == FileDispositionInformation ||
        fileInfoClass == FileDispositionInformationEx) {
        
        // Check if this is actually setting delete flag
        PFILE_DISPOSITION_INFORMATION dispInfo = 
            (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        
        if (dispInfo == NULL || !dispInfo->DeleteFile) {
            // Not a delete operation
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        
        operation = DLP_OP_FILE_DELETE;
        
        // Get file identity (NOT path-based!)
        status = DlpGetFileId(FltObjects, &fileId);
        if (!NT_SUCCESS(status)) {
            // Can't identify file - allow (can't enforce what we can't identify)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        
        // Central fail-closed policy decision. Protected files are always
        // blocked; in FailClosedMode, deletes of uncached/unclassified files
        // are also blocked (never silently allowed).
        if (DlpIsOperationBlocked(Data, FltObjects, &fileId, IRP_MJ_SET_INFORMATION) ==
            STATUS_ACCESS_DENIED) {
            blocked = TRUE;
        }
    }
    
    // ========== RENAME/MOVE INTERCEPTION ==========
    else if (fileInfoClass == FileRenameInformation ||
             fileInfoClass == FileRenameInformationEx) {
        
        operation = DLP_OP_FILE_RENAME;
        
        // Get source file identity
        status = DlpGetFileId(FltObjects, &fileId);
        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        
        // Central fail-closed policy decision. Protected files and (in
        // FailClosedMode) uncached files are blocked from rename/move so a
        // rename cannot be used to evade classification.
        if (DlpIsOperationBlocked(Data, FltObjects, &fileId, IRP_MJ_SET_INFORMATION) ==
            STATUS_ACCESS_DENIED) {
            blocked = TRUE;
        }
    }
    
    // ========== FILE CONTENT MODIFICATION (EOF / Allocation) ==========
    // These change file size/content. Apply policy only if the file is
    // cached and protected — do NOT fail-closed for uncached files (that
    // would break backup software, indexing, and normal OS behavior).
    else if (fileInfoClass == FileEndOfFileInformation ||
             fileInfoClass == FileAllocationInformation) {
        
        operation = DLP_OP_FILE_WRITE;
        
        status = DlpGetFileId(FltObjects, &fileId);
        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        
        DLP_POLICY_ENTRY policy;
        if (NT_SUCCESS(DlpLookupPolicy(&g_Globals.PolicyCache, &fileId, &policy))) {
            if (DLP_IS_PROTECTED_CLASS(policy.Classification)) {
                blocked = TRUE;
            }
        }
    }
    
    // ========== ALL OTHER CLASSES ==========
    // Timestamps, attributes, position, link info etc. are not security-
    // sensitive — allow without consulting the policy cache.
    
    // ========== BLOCK IF NEEDED ==========
    if (blocked) {
        // Block the operation
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        
        // Queue event notification for user-mode
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );
        
        DlpQueueBlockEvent(&fileId, operation, nameInfo,
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        
        if (nameInfo) {
            FltReleaseFileNameInformation(nameInfo);
        }
        
        // Update statistics
        InterlockedIncrement64((PLONG64)&g_Globals.Stats.TotalOperationsBlocked);
        
        return FLT_PREOP_COMPLETE;
    }
    
    InterlockedIncrement64((PLONG64)&g_Globals.Stats.TotalOperationsScanned);
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/**
 * DlpPreWrite - Pre-write callback
 * 
 * CRITICAL: This blocks writes of protected content to removable media.
 * 
 * The challenge: When copying a file, IRP_MJ_WRITE is issued against the
 * DESTINATION file. We need to know if the SOURCE data was protected.
 * 
 * Solution: We use process-level tracking. When a process reads from a
 * protected file (tracked in DlpPostRead), we mark that process as "tainted".
 * When that process tries to write to USB, we block it.
 * 
 * This blocks:
 * - Drag & drop
 * - Copy/paste
 * - robocopy
 * - PowerShell Copy-Item
 * - Any application copying protected content to USB
 */
FLT_PREOP_CALLBACK_STATUS
DlpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    ULONG volumeFlags = 0;
    ULONG classification = DLP_CLASS_PUBLIC;
    HANDLE processId;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    // Skip kernel-mode and paging I/O
    if (Data->RequestorMode == KernelMode ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get destination volume flags
    status = DlpGetVolumeFlags(FltObjects, &volumeFlags);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Only enforce for USB/removable media
    if (!(volumeFlags & (DLP_VOLUME_FLAG_REMOVABLE | DLP_VOLUME_FLAG_USB))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // =========================================================================
    // CRITICAL USB WRITE BLOCKING
    // 
    // This is a write to removable media. Check if the process has recently
    // read protected content. If so, BLOCK the write.
    // =========================================================================
    
    processId = PsGetCurrentProcessId();
    
    // Check 1: Process-level tracking (catches copy operations)
    if (g_Globals.ProcessTable != NULL) {
        if (DlpShouldBlockProcessWrite(g_Globals.ProcessTable, processId, &classification)) {
            // This process has read protected content - BLOCK THE WRITE
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            
            // Get file info for logging
            DLP_FILE_ID fileId = {0};
            DlpGetFileId(FltObjects, &fileId);
            
            DlpQueueBlockEvent(&fileId, DLP_OP_USB_WRITE, NULL,
                (ULONG)(ULONG_PTR)processId);
            
            InterlockedIncrement64((PLONG64)&g_Globals.Stats.TotalOperationsBlocked);
            
            return FLT_PREOP_COMPLETE;
        }
    }
    
    // Check 2: Destination file classification (fallback)
    // This catches cases where a file was already classified on the USB
    DLP_FILE_ID fileId;
    status = DlpGetFileId(FltObjects, &fileId);
    
    if (NT_SUCCESS(status)) {
        DLP_POLICY_ENTRY policy;
        status = DlpLookupPolicy(&g_Globals.PolicyCache, &fileId, &policy);
        
        if (NT_SUCCESS(status) && DLP_IS_PROTECTED_CLASS(policy.Classification)) {
            // Block write of protected content to USB
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            
            DlpQueueBlockEvent(&fileId, DLP_OP_USB_WRITE, NULL,
                (ULONG)(ULONG_PTR)processId);
            
            InterlockedIncrement64((PLONG64)&g_Globals.Stats.TotalOperationsBlocked);
            
            return FLT_PREOP_COMPLETE;
        }
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/**
 * DlpPostRead - Post-read callback
 * 
 * CRITICAL: Tracks processes reading protected files.
 * 
 * When a process reads a protected file, we track it. If that process later
 * tries to write to USB, we block the write. This is how we prevent copying
 * protected content to removable media.
 */
FLT_POSTOP_CALLBACK_STATUS
DlpPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{
    NTSTATUS status;
    DLP_FILE_ID fileId;
    DLP_POLICY_ENTRY policy;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    
    // Only process successful reads
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Information == 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Skip kernel-mode and paging I/O
    if (Data->RequestorMode == KernelMode ||
        FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Skip if process tracker not initialized
    if (g_Globals.ProcessTable == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Get file identity
    status = DlpGetFileId(FltObjects, &fileId);
    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    
    // Look up policy
    status = DlpLookupPolicy(&g_Globals.PolicyCache, &fileId, &policy);
    
    if (NT_SUCCESS(status) && DLP_IS_PROTECTED_CLASS(policy.Classification)) {
        // Protected file was read - track this process!
        HANDLE processId = PsGetCurrentProcessId();
        
        DlpTrackProtectedRead(
            g_Globals.ProcessTable,
            processId,
            &fileId,
            policy.Classification
        );
    }
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/**
 * DlpPreCleanup - Pre-cleanup callback
 * 
 * Called when a file handle is being closed. We use this to untrack
 * protected files that the process no longer has open.
 */
FLT_PREOP_CALLBACK_STATUS
DlpPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    DLP_FILE_ID fileId;
    DLP_POLICY_ENTRY policy;
    
    UNREFERENCED_PARAMETER(CompletionContext);
    
    // Skip if process tracker not initialized
    if (g_Globals.ProcessTable == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Skip kernel-mode
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Get file identity
    status = DlpGetFileId(FltObjects, &fileId);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    
    // Look up policy - only untrack if it was protected
    status = DlpLookupPolicy(&g_Globals.PolicyCache, &fileId, &policy);
    
    if (NT_SUCCESS(status) && DLP_IS_PROTECTED_CLASS(policy.Classification)) {
        HANDLE processId = PsGetCurrentProcessId();
        
        DlpUntrackProtectedFile(
            g_Globals.ProcessTable,
            processId,
            &fileId
        );
    }
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// EVENT QUEUE
// ============================================================================

/**
 * DlpInitializeEventQueue - Initialize the event FIFO and its lookaside pool
 *
 * @irql PASSIVE_LEVEL only
 */
NTSTATUS
DlpInitializeEventQueue(
    _Inout_ PDLP_EVENT_QUEUE Queue
)
{
    NTSTATUS status;

    PAGED_CODE();

    if (Queue == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExInitializePushLock(&Queue->Lock);
    InitializeListHead(&Queue->Head);
    InterlockedExchange(&Queue->Count, 0);
    InterlockedExchange64(&Queue->TotalEvents, 0);
    InterlockedExchange64(&Queue->DroppedEvents, 0);

    // Fixed-size records allocated from a NonPagedPoolNx lookaside list so the
    // hot path never takes the general pool lock.
    status = ExInitializeLookasideListEx(
        &Queue->EventLookaside,
        NULL,                               // Use default allocator
        NULL,                               // Use default deallocator
        NonPagedPoolNx,
        0,                                  // Flags
        sizeof(DLP_NOTIFICATION_RECORD),    // Fixed entry size
        DLP_POOL_TAG_EVENT,
        0                                   // Depth (system default)
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    Queue->LookasideInitialized = TRUE;
    return STATUS_SUCCESS;
}

/**
 * DlpDestroyEventQueue - Drain and destroy the event queue
 *
 * @irql PASSIVE_LEVEL only
 */
VOID
DlpDestroyEventQueue(
    _Inout_ PDLP_EVENT_QUEUE Queue
)
{
    PAGED_CODE();

    if (Queue == NULL) {
        return;
    }

    // Free any records left in the queue (allocation/deallocation pairing).
    while (!IsListEmpty(&Queue->Head)) {
        PLIST_ENTRY entry = RemoveHeadList(&Queue->Head);
        PDLP_NOTIFICATION_RECORD record = CONTAINING_RECORD(
            entry, DLP_NOTIFICATION_RECORD, ListEntry);

        if (Queue->LookasideInitialized) {
            ExFreeToLookasideListEx(&Queue->EventLookaside, record);
        }
    }

    InterlockedExchange(&Queue->Count, 0);

    if (Queue->LookasideInitialized) {
        ExDeleteLookasideListEx(&Queue->EventLookaside);
        Queue->LookasideInitialized = FALSE;
    }
}

/**
 * DlpQueueBlockEvent - Queue a block event for user-mode notification
 *
 * Called from IRP callbacks (IRQL <= DISPATCH_LEVEL). Allocates a fixed-size
 * DLP_NOTIFICATION_RECORD from the event lookaside, copies the file identity,
 * operation, target path, classification and process ID, inserts it into the
 * push-lock protected FIFO and signals the worker thread.
 *
 * The user SID and process name are captured by the PASSIVE_LEVEL worker
 * thread (DlpCaptureProcessContext) because token introspection must not run
 * at elevated IRQL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
DlpQueueBlockEvent(
    _In_ PDLP_FILE_ID FileId,
    _In_ DLP_OPERATION_TYPE Operation,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ULONG ProcessId
)
{
    PDLP_NOTIFICATION_RECORD record = NULL;
    PDLP_EVENT_QUEUE queue = &g_Globals.EventQueue;

    if (g_Globals.ShuttingDown || queue == NULL || !queue->LookasideInitialized) {
        return;
    }

    // Allocate from the NonPagedPoolNx lookaside (zero raw pool allocations).
    record = (PDLP_NOTIFICATION_RECORD)ExAllocateFromLookasideListEx(
        &queue->EventLookaside);

    if (record == NULL) {
        InterlockedIncrement64(&queue->DroppedEvents);
        return;
    }

    RtlZeroMemory(record, sizeof(DLP_NOTIFICATION_RECORD));

    // Fill the structure validation boundary.
    record->Header.Size = sizeof(DLP_NOTIFICATION_RECORD);
    record->Header.Version = DLP_PROTOCOL_VERSION;
    record->Header.Type = DLP_MSG_EVENT_BLOCKED;
    record->Header.Flags = 0;

    if (FileId != NULL) {
        record->FileId = *FileId;
    }

    record->Operation = (ULONG)Operation;
    record->ActionTaken = DLP_ACTION_BLOCK;
    record->ProcessId = ProcessId;
    record->Classification = DLP_CLASS_UNKNOWN;

    // Copy the normalized target path (bounded copy, always NUL terminated).
    if (NameInfo != NULL && NameInfo->Name.Buffer != NULL) {
        SIZE_T copyBytes = min(
            NameInfo->Name.Length,
            sizeof(record->FilePath) - sizeof(WCHAR));
        RtlCopyMemory(record->FilePath, NameInfo->Name.Buffer, copyBytes);
        record->FilePath[copyBytes / sizeof(WCHAR)] = L'\0';
    }

    // Best-effort classification lookup for the record.
    if (FileId != NULL) {
        DLP_POLICY_ENTRY policy;
        if (NT_SUCCESS(DlpLookupPolicy(&g_Globals.PolicyCache, FileId, &policy))) {
            record->Classification = policy.Classification;
        }
    }

    // Insert into the push-lock protected FIFO.
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&queue->Lock);
    InsertTailList(&queue->Head, &record->ListEntry);
    InterlockedIncrement(&queue->Count);
    ExReleasePushLock(&queue->Lock);
    KeLeaveCriticalRegion();

    InterlockedIncrement64(&queue->TotalEvents);

    // Wake the worker thread so the SCM-hosted service is notified.
    KeSetEvent(&queue->DataAvailable, IO_NO_INCREMENT, FALSE);
}

/**
 * DlpNotifyWorker - Drains the event queue and delivers records to usermode
 *
 * Runs as a dedicated system thread at PASSIVE_LEVEL. Waits on the
 * DataAvailable event (with the stop event) and flushes queued records,
 * converting each to a DLP_EVENT_NOTIFICATION and sending it over the notify
 * communication port via FltSendMessage.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DlpNotifyWorker(
    _In_ PVOID Context
)
{
    DLP_EVENT_QUEUE* queue = (PDLP_EVENT_QUEUE)Context;
    PVOID waitObjects[2];
    NTSTATUS waitStatus;

    UNREFERENCED_PARAMETER(Context);

    PAGED_CODE();

    waitObjects[0] = &g_Globals.NotifyThreadStop;
    waitObjects[1] = &queue->DataAvailable;

    for (;;) {
        waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,                // Wait for any object
            Executive,              // Wait reason
            KernelMode,             // Wait mode
            FALSE,                  // Not alertable
            NULL,                   // No timeout
            NULL                    // No wait block
        );

        if (waitStatus == STATUS_WAIT_0) {
            // Stop requested.
            break;
        }

        // Drain until the queue is empty (no lost-wakeup between checks).
        for (;;) {
            BOOLEAN empty;

            DlpFlushNotificationQueue();

            KeEnterCriticalRegion();
            ExAcquirePushLockShared(&queue->Lock);
            empty = IsListEmpty(&queue->Head);
            ExReleasePushLock(&queue->Lock);
            KeLeaveCriticalRegion();

            if (empty) {
                break;
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/**
 * DlpFlushNotificationQueue - Move all queued records to a local list and
 * deliver each one to the usermode service.
 */
VOID
DlpFlushNotificationQueue(VOID)
{
    DLP_EVENT_QUEUE* queue = &g_Globals.EventQueue;
    LIST_ENTRY localHead;
    PLIST_ENTRY entry;

    if (queue == NULL) {
        return;
    }

    InitializeListHead(&localHead);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&queue->Lock);

    while (!IsListEmpty(&queue->Head)) {
        entry = RemoveHeadList(&queue->Head);
        InsertTailList(&localHead, entry);
    }

    InterlockedExchange(&queue->Count, 0);

    ExReleasePushLock(&queue->Lock);
    KeLeaveCriticalRegion();

    while (!IsListEmpty(&localHead)) {
        PDLP_NOTIFICATION_RECORD record;

        entry = RemoveHeadList(&localHead);
        record = CONTAINING_RECORD(entry, DLP_NOTIFICATION_RECORD, ListEntry);

        // Capture process name and user SID at PASSIVE_LEVEL.
        DlpCaptureProcessContext(record);
        DlpSendNotification(record);

        if (queue->LookasideInitialized) {
            ExFreeToLookasideListEx(&queue->EventLookaside, record);
        }
    }
}

/**
 * DlpSendNotification - Send a single record to the usermode service
 *
 * Converts the kernel-internal record into the shared DLP_EVENT_NOTIFICATION
 * wire format and delivers it via FltSendMessage on the notify client port.
 */
VOID
DlpSendNotification(
    _In_ PDLP_NOTIFICATION_RECORD Record
)
{
    DLP_EVENT_NOTIFICATION notification;
    NTSTATUS status;

    if (Record == NULL) {
        return;
    }

    // Structure validation boundary: reject malformed records.
    if (Record->Header.Size != sizeof(DLP_NOTIFICATION_RECORD) ||
        Record->Header.Version != DLP_PROTOCOL_VERSION) {
        InterlockedIncrement64(&g_Globals.EventQueue.DroppedEvents);
        return;
    }

    // No usermode consumer connected yet - account and drop safely.
    if (g_Globals.NotifyClientPort == NULL) {
        InterlockedIncrement64(&g_Globals.EventQueue.DroppedEvents);
        return;
    }

    RtlZeroMemory(&notification, sizeof(notification));

    notification.Header.Size = sizeof(DLP_EVENT_NOTIFICATION);
    notification.Header.Type = DLP_MSG_EVENT_BLOCKED;
    notification.Header.Status = STATUS_SUCCESS;
    notification.Header.Timestamp = DlpGetCurrentTime();
    notification.FileId = Record->FileId;
    notification.Operation = Record->Operation;
    notification.Classification = Record->Classification;
    notification.ActionTaken = Record->ActionTaken;
    notification.ProcessId = Record->ProcessId;
    notification.ThreadId = 0;
    notification.SessionId = 0;
    notification.PathLength = (ULONG)wcslen(Record->FilePath) * sizeof(WCHAR);
    notification.VolumeFlags = 0;
    notification.DestVolumeFlags = 0;

    RtlCopyMemory(notification.FilePath, Record->FilePath, sizeof(notification.FilePath));
    RtlCopyMemory(notification.ProcessName, Record->ProcessName, sizeof(notification.ProcessName));

    status = FltSendMessage(
        g_Globals.FilterHandle,
        &g_Globals.NotifyClientPort,
        &notification,
        sizeof(notification),
        NULL,   // No reply expected
        NULL
    );

    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&g_Globals.EventQueue.DroppedEvents);
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "PRITRAK DLP: FltSendMessage failed (0x%08X)\n", status));
    }
}

/**
 * DlpCaptureProcessContext - Best-effort capture of process image name and the
 * requesting user's SID. Must run at PASSIVE_LEVEL (token introspection).
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DlpCaptureProcessContext(
    _Inout_ PDLP_NOTIFICATION_RECORD Record
)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (Record == NULL) {
        return;
    }

    // Process image name (ANSI -> WCHAR best-effort conversion).
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Record->ProcessId, &process);
    if (NT_SUCCESS(status)) {
        PCCH imageName = PsGetProcessImageFileName(process);
        if (imageName != NULL) {
            SIZE_T nameLen = 0;
            NTSTATUS lenStatus = RtlStringCbLengthA(
                imageName,
                sizeof(Record->ProcessName),
                &nameLen
            );
            if (NT_SUCCESS(lenStatus)) {
                ULONG chars = (ULONG)min(
                    nameLen,
                    (SIZE_T)(ARRAYSIZE(Record->ProcessName) - 1));
                for (ULONG i = 0; i < chars; i++) {
                    Record->ProcessName[i] = (WCHAR)(UCHAR)imageName[i];
                }
                Record->ProcessName[chars] = L'\0';
            }
        }

        // User SID via the process primary token.
        {
            HANDLE tokenHandle = NULL;

            status = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                NULL,
                TOKEN_QUERY,
                SeTokenObjectType,
                KernelMode,
                &tokenHandle
            );

            if (NT_SUCCESS(status)) {
                PTOKEN_USER userInfo = NULL;
                ULONG returnLength = 0;
                NTSTATUS sidStatus;

                sidStatus = SeQueryInformationToken(
                    tokenHandle,
                    TokenUser,
                    &userInfo,
                    0,
                    &returnLength
                );

                if (NT_SUCCESS(sidStatus) && userInfo != NULL && userInfo->User.Sid != NULL) {
                    ULONG sidLength = SeLengthSid(userInfo->User.Sid);
                    if (sidLength <= sizeof(Record->UserSid)) {
                        RtlCopyMemory(Record->UserSid, userInfo->User.Sid, sidLength);
                        Record->UserSidLength = sidLength;
                    }
                }

                if (userInfo != NULL) {
                    ExFreePool(userInfo);
                }

                ZwClose(tokenHandle);
            }
        }

        ObDereferenceObject(process);
    }
}

// ============================================================================
// COMMUNICATION PORT CALLBACKS
// ============================================================================

/**
 * DlpPortConnect - Handle user-mode service connection
 */
NTSTATUS
DlpPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    
    PAGED_CODE();
    
    // Only allow one connection
    if (g_Globals.CommandClientPort != NULL) {
        return STATUS_CONNECTION_REFUSED;
    }
    
    g_Globals.CommandClientPort = ClientPort;
    *ConnectionPortCookie = NULL;
    
    InterlockedExchange(&g_Globals.ServiceConnected, TRUE);
    
    return STATUS_SUCCESS;
}

/**
 * DlpPortDisconnect - Handle user-mode service disconnection
 */
VOID
DlpPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();
    
    InterlockedExchange(&g_Globals.ServiceConnected, FALSE);
    
    // Close our handle to the client port
    FltCloseClientPort(g_Globals.FilterHandle, &g_Globals.CommandClientPort);
}

/**
 * DlpPortMessage - Handle messages from user-mode service
 */
NTSTATUS
DlpPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PDLP_MESSAGE_HEADER header;
    
    UNREFERENCED_PARAMETER(PortCookie);
    PAGED_CODE();
    
    // ---- Never trust usermode input: validate lengths and structural offsets ----
    if (InputBuffer == NULL ||
        InputBufferLength < sizeof(DLP_MESSAGE_HEADER) ||
        InputBufferLength > sizeof(DLP_POLICY_BULK_UPDATE_MSG)) {
        return STATUS_INVALID_PARAMETER;
    }
    
    header = (PDLP_MESSAGE_HEADER)InputBuffer;
    
    // The header Size field must describe a valid structure within the buffer.
    if (header->Size == 0 ||
        header->Size > InputBufferLength ||
        header->Size < sizeof(DLP_MESSAGE_HEADER)) {
        InterlockedIncrement64((PLONG64)&g_Globals.Stats.CommunicationErrors);
        return STATUS_INVALID_BUFFER_SIZE;
    }
    
    switch (header->Type) {
        case DLP_MSG_POLICY_UPDATE: {
            // Single policy entry update - full structure must be present.
            if (InputBufferLength >= sizeof(DLP_POLICY_UPDATE_MSG) &&
                header->Size >= sizeof(DLP_POLICY_UPDATE_MSG)) {
                PDLP_POLICY_UPDATE_MSG updateMsg = (PDLP_POLICY_UPDATE_MSG)InputBuffer;
                status = DlpInsertPolicy(&g_Globals.PolicyCache, &updateMsg->Entry);
                InterlockedIncrement64((PLONG64)&g_Globals.Stats.PolicyUpdates);
            } else {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
        }
        
        case DLP_MSG_POLICY_BULK_UPDATE: {
            // Bulk policy update - validate header, count, and array bounds.
            if (InputBufferLength >= sizeof(DLP_POLICY_BULK_UPDATE_MSG) &&
                header->Size >= sizeof(DLP_POLICY_BULK_UPDATE_MSG)) {
                PDLP_POLICY_BULK_UPDATE_MSG bulkMsg = (PDLP_POLICY_BULK_UPDATE_MSG)InputBuffer;
                if (bulkMsg->EntryCount > DLP_MAX_BULK_ENTRIES) {
                    status = STATUS_INVALID_BUFFER_SIZE;
                    break;
                }
                for (ULONG i = 0; i < bulkMsg->EntryCount; i++) {
                    DlpInsertPolicy(&g_Globals.PolicyCache, &bulkMsg->Entries[i]);
                }
                InterlockedIncrement64((PLONG64)&g_Globals.Stats.PolicyUpdates);
            } else {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
        }
        
        case DLP_MSG_POLICY_REMOVE: {
            // Remove policy entry
            if (InputBufferLength >= sizeof(DLP_POLICY_REMOVE_MSG) &&
                header->Size >= sizeof(DLP_POLICY_REMOVE_MSG)) {
                PDLP_POLICY_REMOVE_MSG removeMsg = (PDLP_POLICY_REMOVE_MSG)InputBuffer;
                status = DlpRemovePolicy(&g_Globals.PolicyCache, &removeMsg->FileId);
            } else {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
        }
        
        case DLP_MSG_POLICY_CLEAR: {
            // Clear all policy entries
            if (header->Size >= sizeof(DLP_MESSAGE_HEADER)) {
                DlpClearCache(&g_Globals.PolicyCache);
            } else {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
        }
        
        case DLP_MSG_CONFIG_UPDATE: {
            // Update configuration
            if (InputBufferLength >= sizeof(DLP_CONFIG_UPDATE_MSG) &&
                header->Size >= sizeof(DLP_CONFIG_UPDATE_MSG)) {
                PDLP_CONFIG_UPDATE_MSG configMsg = (PDLP_CONFIG_UPDATE_MSG)InputBuffer;
                g_Globals.Config.FailClosedMode = (BOOLEAN)configMsg->FailClosedMode;
                g_Globals.Config.AuditMode = (BOOLEAN)configMsg->AuditMode;
                if (configMsg->MaxCacheEntries > 0 &&
                    configMsg->MaxCacheEntries <= DLP_MAX_CACHE_SIZE) {
                    g_Globals.PolicyCache.MaxEntries = configMsg->MaxCacheEntries;
                }
                if (configMsg->CacheEntryTTL > 0) {
                    g_Globals.PolicyCache.EntryTTLSec = configMsg->CacheEntryTTL;
                }
            } else {
                status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
        }
        
        case DLP_MSG_PING: {
            // Keepalive ping - respond with pong
            if (OutputBuffer && OutputBufferLength >= sizeof(DLP_MESSAGE_HEADER)) {
                PDLP_MESSAGE_HEADER pong = (PDLP_MESSAGE_HEADER)OutputBuffer;
                pong->Size = sizeof(DLP_MESSAGE_HEADER);
                pong->Type = DLP_MSG_PONG;
                pong->Status = STATUS_SUCCESS;
                *ReturnOutputBufferLength = sizeof(DLP_MESSAGE_HEADER);
            }
            break;
        }
        
        default:
            InterlockedIncrement64((PLONG64)&g_Globals.Stats.CommunicationErrors);
            status = STATUS_INVALID_PARAMETER;
            break;
    }
    
    if (ReturnOutputBufferLength && *ReturnOutputBufferLength == 0) {
        *ReturnOutputBufferLength = 0;
    }
    
    return status;
}

/**
 * DlpNotifyPortConnect - Accept a connection from the SCM-hosted service
 *
 * The notify port ACL restricts access to NT AUTHORITY\SYSTEM, so only the
 * LocalSystem service can attach here.
 */
NTSTATUS
DlpNotifyPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    PAGED_CODE();

    // Only one usermode consumer is supported.
    if (g_Globals.NotifyClientPort != NULL) {
        return STATUS_CONNECTION_REFUSED;
    }

    g_Globals.NotifyClientPort = ClientPort;
    *ConnectionPortCookie = NULL;

    return STATUS_SUCCESS;
}

/**
 * DlpNotifyPortDisconnect - Release the notify client port
 */
VOID
DlpNotifyPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();

    if (g_Globals.NotifyClientPort != NULL) {
        FltCloseClientPort(g_Globals.FilterHandle, &g_Globals.NotifyClientPort);
    }
}

/**
 * DlpNotifyPortMessage - Validate unsolicited usermode messages on the notify
 * port. The notify port is outbound-only; inbound payloads are rejected.
 */
NTSTATUS
DlpNotifyPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    PAGED_CODE();

    if (ReturnOutputBufferLength != NULL) {
        *ReturnOutputBufferLength = 0;
    }

    return STATUS_INVALID_DEVICE_REQUEST;
}

// External function declaration for policy cache
NTSTATUS DlpInsertPolicy(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_POLICY_ENTRY Policy
);

NTSTATUS DlpRemovePolicy(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_FILE_ID FileId
);

VOID DlpClearCache(_Inout_ PDLP_POLICY_CACHE Cache);
