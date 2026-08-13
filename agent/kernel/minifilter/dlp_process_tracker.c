/**
 * @file dlp_process_tracker.c
 * @brief Process-level tracking for DLP enforcement
 * 
 * PRITRAK Enterprise DLP Agent - Process Tracker Implementation
 * 
 * Implements process tracking for USB copy blocking.
 * 
 * KEY INSIGHT:
 * When copying a protected file to USB:
 * 1. Explorer (or copy tool) opens source file for READ
 * 2. Explorer opens destination file on USB for WRITE
 * 3. Explorer reads from source, writes to destination
 * 
 * We intercept step 1 and track that Explorer has accessed protected content.
 * When step 3 (write) happens, we check if the process is "tainted" with
 * protected data and block the write.
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#include "dlp_process_tracker.h"
#include <ntstrsafe.h>

// ============================================================================
// INITIALIZATION / TEARDOWN
// ============================================================================

/**
 * Initialize the process tracker
 */
NTSTATUS
DlpInitializeProcessTracker(
    _Out_ PDLP_PROCESS_TABLE Table
)
{
    NTSTATUS status;
    
    PAGED_CODE();
    
    RtlZeroMemory(Table, sizeof(DLP_PROCESS_TABLE));
    
    // Initialize all buckets
    for (ULONG i = 0; i < DLP_PROCESS_TABLE_SIZE; i++) {
        ExInitializePushLock(&Table->Buckets[i].Lock);
        InitializeListHead(&Table->Buckets[i].Head);
        Table->Buckets[i].Count = 0;
    }
    
    // Initialize lookaside list for entries
    status = ExInitializeLookasideListEx(
        &Table->EntryLookaside,
        NULL,                       // Allocate function
        NULL,                       // Free function
        NonPagedPoolNx,
        0,                          // Flags
        sizeof(DLP_PROCESS_ENTRY),
        DLP_PROCESS_ENTRY_TAG,
        0                           // Depth (0 = system decides)
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    Table->LookasideInitialized = TRUE;
    
    // Register for process exit notifications
    // This allows us to clean up when a process exits
    status = PsSetCreateProcessNotifyRoutineEx(
        (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)DlpProcessNotifyCallback,
        FALSE  // Register
    );
    
    if (!NT_SUCCESS(status)) {
        // Propagate the error so the caller can clean up. The lookaside was
        // already initialized above, so we must tear it down before returning.
        ExDeleteLookasideListEx(&Table->EntryLookaside);
        Table->LookasideInitialized = FALSE;
        return status;
    }
    
    return STATUS_SUCCESS;
}

/**
 * Process notification callback
 */
VOID
DlpProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    
    // Only care about process exit (CreateInfo == NULL)
    if (CreateInfo != NULL) {
        return;
    }
    
    // Clean up tracking for this process. Guard against the table not being
    // initialized yet or already torn down.
    if (g_Globals.ProcessTable != NULL) {
        DlpProcessExitCallback(g_Globals.ProcessTable, ProcessId);
    }
}

/**
 * Destroy the process tracker
 */
VOID
DlpDestroyProcessTracker(
    _Inout_ PDLP_PROCESS_TABLE Table
)
{
    PAGED_CODE();
    
    // Unregister process notification
    PsSetCreateProcessNotifyRoutineEx(
        (PCREATE_PROCESS_NOTIFY_ROUTINE_EX)DlpProcessNotifyCallback,
        TRUE  // Remove
    );
    
    // Free all entries
    for (ULONG i = 0; i < DLP_PROCESS_TABLE_SIZE; i++) {
        PDLP_PROCESS_BUCKET bucket = &Table->Buckets[i];
        
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&bucket->Lock);
        
        while (!IsListEmpty(&bucket->Head)) {
            PLIST_ENTRY entry = RemoveHeadList(&bucket->Head);
            PDLP_PROCESS_ENTRY procEntry = CONTAINING_RECORD(
                entry, DLP_PROCESS_ENTRY, HashLink);
            
            ExFreeToLookasideListEx(&Table->EntryLookaside, procEntry);
        }
        
        ExReleasePushLock(&bucket->Lock);
        KeLeaveCriticalRegion();
    }
    
    // Destroy lookaside list
    if (Table->LookasideInitialized) {
        ExDeleteLookasideListEx(&Table->EntryLookaside);
        Table->LookasideInitialized = FALSE;
    }
}

// ============================================================================
// TRACKING OPERATIONS
// ============================================================================

/**
 * Find or create an entry for a process
 */
static PDLP_PROCESS_ENTRY
DlpFindOrCreateProcessEntry(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
)
{
    ULONG hash = DlpHashProcessId(ProcessId);
    PDLP_PROCESS_BUCKET bucket = &Table->Buckets[hash];
    PDLP_PROCESS_ENTRY entry = NULL;
    PLIST_ENTRY listEntry;
    
    // First try to find existing entry with shared lock
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&bucket->Lock);
    
    for (listEntry = bucket->Head.Flink;
         listEntry != &bucket->Head;
         listEntry = listEntry->Flink) {
        
        PDLP_PROCESS_ENTRY current = CONTAINING_RECORD(
            listEntry, DLP_PROCESS_ENTRY, HashLink);
        
        if (current->ProcessId == ProcessId) {
            entry = current;
            InterlockedIncrement(&entry->RefCount);
            break;
        }
    }
    
    ExReleasePushLock(&bucket->Lock);
    KeLeaveCriticalRegion();
    
    if (entry != NULL || !CreateIfNotFound) {
        return entry;
    }
    
    // Need to create - allocate outside the lock
    PDLP_PROCESS_ENTRY newEntry = (PDLP_PROCESS_ENTRY)ExAllocateFromLookasideListEx(
        &Table->EntryLookaside);
    
    if (newEntry == NULL) {
        return NULL;
    }
    
    // Initialize new entry
    RtlZeroMemory(newEntry, sizeof(DLP_PROCESS_ENTRY));
    newEntry->ProcessId = ProcessId;
    newEntry->RefCount = 1;
    newEntry->FirstProtectedReadTime = DlpGetCurrentTime();
    
    // Try to get process start time for PID reuse detection
    PEPROCESS process;
    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
        KERNEL_USER_TIMES times;
        if (NT_SUCCESS(ZwQueryInformationProcess(
                NtCurrentProcess(), ProcessTimes, &times, sizeof(times), NULL))) {
            newEntry->ProcessStartTime = times.CreateTime.QuadPart;
        }
        ObDereferenceObject(process);
    }
    
    // Insert with exclusive lock
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&bucket->Lock);
    
    // Check again if someone else inserted while we were allocating
    for (listEntry = bucket->Head.Flink;
         listEntry != &bucket->Head;
         listEntry = listEntry->Flink) {
        
        PDLP_PROCESS_ENTRY current = CONTAINING_RECORD(
            listEntry, DLP_PROCESS_ENTRY, HashLink);
        
        if (current->ProcessId == ProcessId) {
            // Someone else inserted - use theirs
            entry = current;
            InterlockedIncrement(&entry->RefCount);
            
            ExReleasePushLock(&bucket->Lock);
            KeLeaveCriticalRegion();
            
            // Free our unused allocation
            ExFreeToLookasideListEx(&Table->EntryLookaside, newEntry);
            
            return entry;
        }
    }
    
    // Insert our new entry
    InsertHeadList(&bucket->Head, &newEntry->HashLink);
    bucket->Count++;
    InterlockedIncrement(&Table->ActiveEntries);
    
    entry = newEntry;
    
    ExReleasePushLock(&bucket->Lock);
    KeLeaveCriticalRegion();
    
    return entry;
}

/**
 * Release reference to a process entry
 */
static VOID
DlpReleaseProcessEntry(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ PDLP_PROCESS_ENTRY Entry
)
{
    UNREFERENCED_PARAMETER(Table);
    
    // Just decrement ref count - cleanup happens on process exit
    if (Entry != NULL) {
        InterlockedDecrement(&Entry->RefCount);
    }
}

/**
 * Record that a process has read a protected file
 */
NTSTATUS
DlpTrackProtectedRead(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _In_ PDLP_FILE_ID FileId,
    _In_ ULONG Classification
)
{
    PDLP_PROCESS_ENTRY entry = DlpFindOrCreateProcessEntry(
        Table, ProcessId, TRUE);
    
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Update tracking state
    entry->LastProtectedReadTime = DlpGetCurrentTime();
    
    // Track highest (most restrictive) classification
    if (Classification > entry->HighestClassification) {
        InterlockedExchange((PLONG)&entry->HighestClassification, Classification);
    }
    
    // Add to protected files list if not already there
    if (entry->ProtectedFileCount < ARRAYSIZE(entry->ProtectedFiles)) {
        BOOLEAN found = FALSE;
        
        for (ULONG i = 0; i < entry->ProtectedFileCount; i++) {
            if (DLP_FILE_ID_EQUAL(entry->ProtectedFiles[i], *FileId)) {
                found = TRUE;
                break;
            }
        }
        
        if (!found) {
            entry->ProtectedFiles[entry->ProtectedFileCount++] = *FileId;
        }
    }
    
    InterlockedIncrement(&entry->ActiveProtectedReads);
    InterlockedIncrement64(&Table->TotalTrackedReads);
    
    DlpReleaseProcessEntry(Table, entry);
    
    return STATUS_SUCCESS;
}

/**
 * Record that a process has closed a protected file
 */
VOID
DlpUntrackProtectedFile(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _In_ PDLP_FILE_ID FileId
)
{
    PDLP_PROCESS_ENTRY entry = DlpFindOrCreateProcessEntry(
        Table, ProcessId, FALSE);
    
    if (entry == NULL) {
        return;
    }
    
    // Decrement active read count
    if (entry->ActiveProtectedReads > 0) {
        InterlockedDecrement(&entry->ActiveProtectedReads);
    }
    
    // Remove from protected files list
    for (ULONG i = 0; i < entry->ProtectedFileCount; i++) {
        if (DLP_FILE_ID_EQUAL(entry->ProtectedFiles[i], *FileId)) {
            // Shift remaining entries
            for (ULONG j = i + 1; j < entry->ProtectedFileCount; j++) {
                entry->ProtectedFiles[j - 1] = entry->ProtectedFiles[j];
            }
            entry->ProtectedFileCount--;
            break;
        }
    }
    
    DlpReleaseProcessEntry(Table, entry);
}

/**
 * Check if a process should be blocked from writing to USB
 */
BOOLEAN
DlpShouldBlockProcessWrite(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG ClassificationOut
)
{
    PDLP_PROCESS_ENTRY entry = DlpFindOrCreateProcessEntry(
        Table, ProcessId, FALSE);
    
    if (entry == NULL) {
        // Process not tracked - no protected reads
        if (ClassificationOut) {
            *ClassificationOut = DLP_CLASS_PUBLIC;
        }
        return FALSE;
    }
    
    BOOLEAN shouldBlock = FALSE;
    
    // Check if tracking is still valid
    ULONGLONG now = DlpGetCurrentTime();
    ULONGLONG elapsed = now - entry->LastProtectedReadTime;
    
    if (elapsed < DLP_PROCESS_TRACKING_WINDOW) {
        // Within tracking window - check if any protected data was accessed
        if (DLP_IS_PROTECTED_CLASS(entry->HighestClassification)) {
            shouldBlock = TRUE;
            
            if (ClassificationOut) {
                *ClassificationOut = entry->HighestClassification;
            }
            
            // Update statistics
            InterlockedIncrement64(&Table->BlockedWrites);
        }
    }
    
    DlpReleaseProcessEntry(Table, entry);
    
    return shouldBlock;
}

/**
 * Process exit callback - clean up tracking
 */
VOID
DlpProcessExitCallback(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId
)
{
    ULONG hash;
    PDLP_PROCESS_BUCKET bucket;
    PDLP_PROCESS_ENTRY entryToFree = NULL;
    PLIST_ENTRY listEntry;

    if (Table == NULL || Table->LookasideInitialized == FALSE) {
        return;
    }

    hash = DlpHashProcessId(ProcessId);
    bucket = &Table->Buckets[hash];
    
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&bucket->Lock);
    
    for (listEntry = bucket->Head.Flink;
         listEntry != &bucket->Head;
         listEntry = listEntry->Flink) {
        
        PDLP_PROCESS_ENTRY entry = CONTAINING_RECORD(
            listEntry, DLP_PROCESS_ENTRY, HashLink);
        
        if (entry->ProcessId == ProcessId) {
            // Remove from list
            RemoveEntryList(listEntry);
            bucket->Count--;
            InterlockedDecrement(&Table->ActiveEntries);
            
            entryToFree = entry;
            break;
        }
    }
    
    ExReleasePushLock(&bucket->Lock);
    KeLeaveCriticalRegion();
    
    // Free outside the lock
    if (entryToFree != NULL) {
        ExFreeToLookasideListEx(&Table->EntryLookaside, entryToFree);
    }
}

