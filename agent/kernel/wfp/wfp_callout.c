/**
 * DLP WFP Callout Driver
 * Intercepts network traffic for DLP policy enforcement
 * 
 * Reference: Microsoft WFP samples
 * Layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connections)
 */

#include <fwpmk.h>
#include <fwpsk.h>
#include <ntddk.h>

// Callout GUID (must be unique, registered with Microsoft)
DEFINE_GUID(WFP_CALLOUT_GUID,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34);

// Sublayer GUID
DEFINE_GUID(WFP_SUBLAYER_GUID,
    0x87654321, 0x4321, 0x4321, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21, 0x43, 0x21);

// Global engine handle
HANDLE gEngineHandle = NULL;

// Callout ID
UINT32 gCalloutId = 0;

/**
 * Classify function for WFP callout
 * Called for each network connection to evaluate policy
 */
VOID NTAPI ClassifyHTTPUpload(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
)
{
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Check if this is an outbound connection
    if (inFixedValues->layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        return;
    }

    // Get remote address
    FWP_VALUE0 remoteAddress = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value;
    
    // Get process ID
    UINT64 processId = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID].value.uint64;

    // Get application name from process ID (simplified - would query process info)
    // In production, would use PsLookupProcessByProcessId and get image name

    // Check if this is an HTTPS upload (port 443)
    USHORT remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    
    if (remotePort == 443 || remotePort == 80) {
        // This is HTTP/HTTPS traffic
        // Check if destination is blocked domain
        BOOLEAN isBlocked = IsBlockedDomain(remoteAddress);
        
        if (isBlocked) {
            // Block the connection
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            
            // Log the blocked connection
            LogBlockedConnection(remoteAddress, remotePort, processId);
        }
    }
}

/**
 * Check if domain is in blocked list
 * In production, would query policy engine
 */
BOOLEAN IsBlockedDomain(_In_ FWP_VALUE0 remoteAddress)
{
    // Simplified check - production would:
    // 1. Resolve IP to domain name
    // 2. Check against policy blocked domains list
    // 3. Query user-mode agent for policy decision
    
    // For now, check against hardcoded blocked IPs/ranges
    // Production would use DNS reverse lookup and policy engine
    
    return FALSE;
}

/**
 * Log blocked connection
 */
VOID LogBlockedConnection(
    _In_ FWP_VALUE0 remoteAddress,
    _In_ USHORT remotePort,
    _In_ UINT64 processId
)
{
    // Send event to user-mode agent for logging
    // In production, would use FltSendMessage or similar IPC
    UNREFERENCED_PARAMETER(remoteAddress);
    UNREFERENCED_PARAMETER(remotePort);
    UNREFERENCED_PARAMETER(processId);
}

/**
 * Flow delete notification
 */
VOID NTAPI NotifyHTTPUpload(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_opt_ FWPS_FILTER0* filter
)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
}

/**
 * Register WFP callout
 */
NTSTATUS RegisterWFPCallout()
{
    NTSTATUS status;
    FWPS_CALLOUT0 callout = {0};
    FWPM_CALLOUT0 callout0 = {0};
    FWPM_SUBLAYER0 sublayer = {0};

    // Open filter engine
    status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        NULL,
        &gEngineHandle
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Register sublayer
    sublayer.subLayerKey = WFP_SUBLAYER_GUID;
    sublayer.displayData.name = L"DLP Sublayer";
    sublayer.displayData.description = L"Data Loss Prevention sublayer";
    sublayer.weight = 0x100;

    status = FwpmSubLayerAdd0(gEngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(gEngineHandle);
        return status;
    }

    // Register callout
    callout.calloutKey = WFP_CALLOUT_GUID;
    callout.classifyFn = ClassifyHTTPUpload;
    callout.notifyFn = NotifyHTTPUpload;
    callout.flowDeleteFn = NULL;

    callout0.calloutKey = WFP_CALLOUT_GUID;
    callout0.displayData.name = L"DLP HTTP Upload Callout";
    callout0.displayData.description = L"Blocks HTTP/HTTPS uploads based on DLP policy";
    callout0.flags = 0;
    callout0.providerKey = NULL;
    callout0.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(gEngineHandle, &callout0, NULL, &gCalloutId);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(gEngineHandle);
        return status;
    }

    // Add filter to use the callout
    FWPM_FILTER0 filter = {0};
    filter.filterKey = WFP_CALLOUT_GUID;
    filter.displayData.name = L"DLP HTTP Upload Filter";
    filter.displayData.description = L"Filters HTTP/HTTPS uploads for DLP";
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = WFP_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.weight.uint8 = 0;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = WFP_CALLOUT_GUID;
    filter.numFilterConditions = 0;

    UINT64 filterId = 0;
    status = FwpmFilterAdd0(gEngineHandle, &filter, NULL, &filterId);
    if (!NT_SUCCESS(status)) {
        FwpmCalloutDeleteById0(gEngineHandle, gCalloutId);
        FwpmEngineClose0(gEngineHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

/**
 * Unregister WFP callout
 */
VOID UnregisterWFPCallout()
{
    if (gEngineHandle) {
        // Delete filter
        // Delete callout
        FwpmCalloutDeleteById0(gEngineHandle, gCalloutId);
        
        // Close engine
        FwpmEngineClose0(gEngineHandle);
        gEngineHandle = NULL;
    }
}

/**
 * DriverEntry for WFP callout driver
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    return RegisterWFPCallout();
}
