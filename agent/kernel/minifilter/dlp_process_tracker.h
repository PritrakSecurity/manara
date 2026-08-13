/**
 * @file dlp_process_tracker.h
 * @brief Process-level tracking for DLP enforcement
 * 
 * PRITRAK Enterprise DLP Agent - Process Tracker
 * 
 * This module tracks which processes have accessed protected content.
 * When a process reads a protected file, it is flagged. Any subsequent
 * write by that process to removable media is blocked.
 * 
 * This solves the fundamental copy blocking problem:
 * - IRP_MJ_WRITE to USB is for the DESTINATION file
 * - We need to know if the SOURCE data was protected
 * - Solution: Track processes that read protected files
 * 
 * Design:
 * - Hash table keyed by ProcessId
 * - Tracks most restrictive classification accessed
 * - Entries expire when process exits
 * - Lock-striped for scalability
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#ifndef _DLP_PROCESS_TRACKER_H_
#define _DLP_PROCESS_TRACKER_H_

#include "dlp_kernel_types.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define DLP_PROCESS_TABLE_SIZE      1024    // Must be power of 2
#define DLP_PROCESS_TABLE_MASK      (DLP_PROCESS_TABLE_SIZE - 1)
#define DLP_PROCESS_ENTRY_TAG       'pLDP'

// How long to track process after last protected read (in 100ns intervals)
#define DLP_PROCESS_TRACKING_WINDOW (5LL * 60LL * 10000000LL)  // 5 minutes

// ============================================================================
// PROCESS ENTRY
// ============================================================================

/**
 * @struct DLP_PROCESS_ENTRY
 * @brief Tracks protected content access by a process
 */
typedef struct _DLP_PROCESS_ENTRY {
    LIST_ENTRY          HashLink;           // Hash chain
    
    // Process identification
    HANDLE              ProcessId;
    ULONGLONG           ProcessStartTime;   // For handling PID reuse
    
    // Tracking state
    ULONG               HighestClassification;  // Most restrictive class accessed
    ULONG               ActiveProtectedReads;   // Count of open protected files
    ULONGLONG           LastProtectedReadTime;  // When last protected read occurred
    ULONGLONG           FirstProtectedReadTime; // When tracking started
    
    // Source file tracking (up to 16 files)
    DLP_FILE_ID         ProtectedFiles[16];
    ULONG               ProtectedFileCount;
    
    // Reference count
    volatile LONG       RefCount;
    
} DLP_PROCESS_ENTRY, *PDLP_PROCESS_ENTRY;

// ============================================================================
// PROCESS TABLE BUCKET
// ============================================================================

typedef struct _DLP_PROCESS_BUCKET {
    EX_PUSH_LOCK        Lock;
    LIST_ENTRY          Head;
    volatile LONG       Count;
} DLP_PROCESS_BUCKET, *PDLP_PROCESS_BUCKET;

// ============================================================================
// PROCESS TABLE
// ============================================================================

typedef struct _DLP_PROCESS_TABLE {
    DLP_PROCESS_BUCKET  Buckets[DLP_PROCESS_TABLE_SIZE];
    
    // Memory management
    LOOKASIDE_LIST_EX   EntryLookaside;
    BOOLEAN             LookasideInitialized;
    
    // Statistics
    volatile LONG       ActiveEntries;
    volatile LONG64     TotalTrackedReads;
    volatile LONG64     BlockedWrites;
    
    // Cleanup callback registration
    PVOID               ProcessNotifyHandle;
    
} DLP_PROCESS_TABLE, *PDLP_PROCESS_TABLE;

// ============================================================================
// API FUNCTIONS
// ============================================================================

/**
 * Initialize the process tracker
 */
NTSTATUS
DlpInitializeProcessTracker(
    _Out_ PDLP_PROCESS_TABLE Table
);

/**
 * Destroy the process tracker
 */
VOID
DlpDestroyProcessTracker(
    _Inout_ PDLP_PROCESS_TABLE Table
);

/**
 * Record that a process has read a protected file
 * 
 * @param ProcessId - ID of the process
 * @param FileId - Identity of the protected file
 * @param Classification - Classification level of the file
 * 
 * This should be called from IRP_MJ_READ post-callback for protected files.
 */
NTSTATUS
DlpTrackProtectedRead(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _In_ PDLP_FILE_ID FileId,
    _In_ ULONG Classification
);

/**
 * Record that a process has closed a protected file
 */
VOID
DlpUntrackProtectedFile(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _In_ PDLP_FILE_ID FileId
);

/**
 * Check if a process should be blocked from writing to USB
 * 
 * @param ProcessId - ID of the process
 * @param ClassificationOut - Receives the classification if blocked
 * 
 * @return TRUE if write should be blocked
 */
BOOLEAN
DlpShouldBlockProcessWrite(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG ClassificationOut
);

/**
 * Process exit callback - clean up tracking
 */
VOID
DlpProcessExitCallback(
    _In_ PDLP_PROCESS_TABLE Table,
    _In_ HANDLE ProcessId
);

// ============================================================================
// INLINE HELPERS
// ============================================================================

/**
 * Hash function for process ID
 */
__forceinline ULONG
DlpHashProcessId(
    _In_ HANDLE ProcessId
)
{
    ULONG_PTR pid = (ULONG_PTR)ProcessId;
    ULONG hash = (ULONG)pid;
    
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    
    return hash & DLP_PROCESS_TABLE_MASK;
}

#endif // _DLP_PROCESS_TRACKER_H_

