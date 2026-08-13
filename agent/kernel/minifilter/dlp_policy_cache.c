/**
 * @file dlp_policy_cache.c
 * @brief High-performance kernel policy cache implementation
 * 
 * PRITRAK Enterprise DLP Agent - Kernel Policy Cache
 * 
 * Design Goals:
 * - O(1) average lookup by File ID
 * - Lock-striped hash table for high concurrency
 * - LRU eviction when cache is full
 * - No allocations in hot path (lookaside list)
 * - Thread-safe at IRQL <= APC_LEVEL
 * 
 * This is the core enforcement lookup mechanism. Every file operation
 * that needs policy evaluation queries this cache. Performance is critical.
 */

#include "dlp_kernel_types.h"
#include <ntstrsafe.h>

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PDLP_CACHE_ENTRY
DlpAllocateCacheEntry(
    _In_ PDLP_POLICY_CACHE Cache
);

static VOID
DlpFreeCacheEntry(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_CACHE_ENTRY Entry
);

static VOID
DlpEvictOldestEntry(
    _In_ PDLP_POLICY_CACHE Cache
);

static VOID
DlpTouchEntry(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_CACHE_ENTRY Entry
);

// ============================================================================
// CACHE INITIALIZATION
// ============================================================================

/**
 * DlpInitializePolicyCache - Initialize the policy cache
 * 
 * @param Cache - Pointer to cache structure
 * @param MaxEntries - Maximum number of entries
 * @param TTLSeconds - Default entry TTL in seconds
 * 
 * @return STATUS_SUCCESS or error code
 * 
 * @irql PASSIVE_LEVEL only
 */
NTSTATUS
DlpInitializePolicyCache(
    _Out_ PDLP_POLICY_CACHE Cache,
    _In_ ULONG MaxEntries,
    _In_ ULONG TTLSeconds
)
{
    NTSTATUS status;
    
    PAGED_CODE();
    
    if (Cache == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Validate parameters
    if (MaxEntries < DLP_MIN_CACHE_SIZE) {
        MaxEntries = DLP_MIN_CACHE_SIZE;
    } else if (MaxEntries > DLP_MAX_CACHE_SIZE) {
        MaxEntries = DLP_MAX_CACHE_SIZE;
    }
    
    // Initialize structure
    RtlZeroMemory(Cache, sizeof(DLP_POLICY_CACHE));
    
    Cache->MaxEntries = MaxEntries;
    Cache->EntryTTLSec = (TTLSeconds > 0) ? TTLSeconds : DLP_POLICY_DEFAULT_TTL_SEC;
    
    // Initialize LRU list
    ExInitializePushLock(&Cache->LruLock);
    InitializeListHead(&Cache->LruHead);
    
    // Initialize all hash buckets
    for (ULONG i = 0; i < DLP_CACHE_HASH_BUCKETS; i++) {
        ExInitializePushLock(&Cache->Buckets[i].Lock);
        InitializeListHead(&Cache->Buckets[i].Head);
        Cache->Buckets[i].Count = 0;
    }
    
    // Initialize lookaside list for allocation-free hot path
    status = ExInitializeLookasideListEx(
        &Cache->EntryLookaside,
        NULL,                           // Allocate function (use default)
        NULL,                           // Free function (use default)
        NonPagedPoolNx,                 // Pool type (NX for security)
        0,                              // Flags
        sizeof(DLP_CACHE_ENTRY),        // Entry size
        DLP_POOL_TAG_LOOKASIDE,         // Pool tag
        0                               // Depth (0 = system default)
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    Cache->LookasideInitialized = TRUE;
    Cache->Version = 1;
    
    return STATUS_SUCCESS;
}

/**
 * DlpDestroyPolicyCache - Cleanup and destroy the policy cache
 * 
 * @param Cache - Pointer to cache structure
 * 
 * @irql PASSIVE_LEVEL only
 */
VOID
DlpDestroyPolicyCache(
    _Inout_ PDLP_POLICY_CACHE Cache
)
{
    PAGED_CODE();
    
    if (Cache == NULL) {
        return;
    }
    
    // Free all entries in each bucket. Entries were allocated strictly from
    // the lookaside list, so they MUST be returned via ExFreeToLookasideListEx
    // (correct allocation/deallocation pairing).
    for (ULONG i = 0; i < DLP_CACHE_HASH_BUCKETS; i++) {
        PDLP_CACHE_BUCKET bucket = &Cache->Buckets[i];
        
        DlpAcquireBucketExclusive(bucket);
        
        while (!IsListEmpty(&bucket->Head)) {
            PLIST_ENTRY listEntry = RemoveHeadList(&bucket->Head);
            PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
                listEntry,
                DLP_CACHE_ENTRY,
                HashLink
            );
            
            DlpFreeCacheEntry(Cache, entry);
        }
        
        bucket->Count = 0;
        InterlockedExchange(&Cache->CurrentEntries, 0);
        
        DlpReleaseBucket(bucket);
    }
    
    // Destroy lookaside list
    if (Cache->LookasideInitialized) {
        ExDeleteLookasideListEx(&Cache->EntryLookaside);
        Cache->LookasideInitialized = FALSE;
    }
}

// ============================================================================
// CACHE LOOKUP (HOT PATH - MUST BE FAST)
// ============================================================================

/**
 * DlpLookupPolicy - Look up policy for a file
 * 
 * This is the PRIMARY HOT PATH. Every file operation that needs
 * policy evaluation calls this function. It must be:
 * - Fast (O(1) average case)
 * - Lock-minimal (shared lock only)
 * - Allocation-free
 * 
 * @param Cache - Policy cache
 * @param FileId - File identifier
 * @param PolicyOut - Output policy entry (copied, not referenced)
 * 
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND if not in cache
 * 
 * @irql <= APC_LEVEL
 */
NTSTATUS
DlpLookupPolicy(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_FILE_ID FileId,
    _Out_ PDLP_POLICY_ENTRY PolicyOut
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PDLP_CACHE_BUCKET bucket;
    PLIST_ENTRY listEntry;
    BOOLEAN expired = FALSE;
    
    if (Cache == NULL || FileId == NULL || PolicyOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Calculate hash bucket
    ULONG bucketIndex = DlpHashFileId(FileId);
    bucket = &Cache->Buckets[bucketIndex];
    
    // Pass 1: fast shared-lock scan to find the entry.
    DlpAcquireBucketShared(bucket);
    
    listEntry = bucket->Head.Flink;
    while (listEntry != &bucket->Head) {
        PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
            listEntry,
            DLP_CACHE_ENTRY,
            HashLink
        );
        
        if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, *FileId)) {
            expired = DlpIsEntryExpired(entry);
            break;
        }
        
        listEntry = listEntry->Flink;
    }
    
    DlpReleaseBucket(bucket);
    
    // Pass 2: on a hit, upgrade to the bucket's exclusive push lock so the LRU
    // list (LastAccessTime update + physical reordering) can be mutated safely
    // via DlpTouchEntry. The entry is re-matched by FileId because the pointer
    // found in pass 1 may have been removed and freed concurrently.
    if (listEntry != &bucket->Head && !expired) {
        DlpAcquireBucketExclusive(bucket);
        
        listEntry = bucket->Head.Flink;
        while (listEntry != &bucket->Head) {
            PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
                listEntry,
                DLP_CACHE_ENTRY,
                HashLink
            );
            
            if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, *FileId)) {
                if (!DlpIsEntryExpired(entry)) {
                    RtlCopyMemory(PolicyOut, &entry->Policy, sizeof(DLP_POLICY_ENTRY));
                    
                    // Safely touch LRU (LastAccessTime + move to MRU tail).
                    DlpTouchEntry(Cache, entry);
                    
                    InterlockedIncrement64(&Cache->Hits);
                    status = STATUS_SUCCESS;
                } else {
                    InterlockedIncrement64(&Cache->Misses);
                }
                break;
            }
            
            listEntry = listEntry->Flink;
        }
        
        DlpReleaseBucket(bucket);
    }
    
    // Update miss statistics
    if (status == STATUS_NOT_FOUND) {
        InterlockedIncrement64(&Cache->Misses);
    }
    
    return status;
}

/**
 * DlpQuickLookupClassification - Quick classification lookup
 * 
 * Even faster path when we only need classification, not full policy.
 * 
 * @param Cache - Policy cache
 * @param FileId - File identifier
 * @param ClassificationOut - Output classification
 * 
 * @return STATUS_SUCCESS if found, STATUS_NOT_FOUND if not cached
 * 
 * @irql <= APC_LEVEL
 */
NTSTATUS
DlpQuickLookupClassification(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_FILE_ID FileId,
    _Out_ PULONG ClassificationOut
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    
    if (Cache == NULL || FileId == NULL || ClassificationOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    ULONG bucketIndex = DlpHashFileId(FileId);
    PDLP_CACHE_BUCKET bucket = &Cache->Buckets[bucketIndex];
    
    DlpAcquireBucketShared(bucket);
    
    PLIST_ENTRY listEntry = bucket->Head.Flink;
    while (listEntry != &bucket->Head) {
        
        PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
            listEntry,
            DLP_CACHE_ENTRY,
            HashLink
        );
        
        if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, *FileId)) {
            if (!DlpIsEntryExpired(entry)) {
                *ClassificationOut = entry->Policy.Classification;
                status = STATUS_SUCCESS;
                InterlockedIncrement64(&Cache->Hits);
            } else {
                InterlockedIncrement64(&Cache->Misses);
            }
            break;
        }
        
        listEntry = listEntry->Flink;
    }
    
    DlpReleaseBucket(bucket);
    
    if (status == STATUS_NOT_FOUND) {
        InterlockedIncrement64(&Cache->Misses);
    }
    
    return status;
}

// ============================================================================
// CACHE INSERTION AND UPDATE
// ============================================================================

/**
 * DlpInsertPolicy - Insert or update policy entry
 * 
 * @param Cache - Policy cache
 * @param Policy - Policy entry to insert/update
 * 
 * @return STATUS_SUCCESS or error code
 * 
 * @irql <= APC_LEVEL
 */
NTSTATUS
DlpInsertPolicy(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_POLICY_ENTRY Policy
)
{
    BOOLEAN inserted = FALSE;
    PDLP_CACHE_ENTRY newEntry = NULL;
    PDLP_CACHE_ENTRY existingEntry = NULL;
    
    if (Cache == NULL || Policy == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Check if we need to evict before inserting
    LONG currentCount = InterlockedCompareExchange(
        &Cache->CurrentEntries, 0, 0);
    
    if ((ULONG)currentCount >= Cache->MaxEntries) {
        DlpEvictOldestEntry(Cache);
    }
    
    // Calculate bucket
    ULONG bucketIndex = DlpHashFileId(&Policy->FileId);
    PDLP_CACHE_BUCKET bucket = &Cache->Buckets[bucketIndex];
    
    // First, check if entry already exists (with shared lock)
    DlpAcquireBucketShared(bucket);
    
    PLIST_ENTRY listEntry = bucket->Head.Flink;
    while (listEntry != &bucket->Head) {
        PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
            listEntry,
            DLP_CACHE_ENTRY,
            HashLink
        );
        
        if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, Policy->FileId)) {
            existingEntry = entry;
            break;
        }
        
        listEntry = listEntry->Flink;
    }
    
    DlpReleaseBucket(bucket);
    
    // If exists, update in-place with exclusive lock
    if (existingEntry != NULL) {
        DlpAcquireBucketExclusive(bucket);
        
        // Re-verify entry is still there
        listEntry = bucket->Head.Flink;
        while (listEntry != &bucket->Head) {
            PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
                listEntry,
                DLP_CACHE_ENTRY,
                HashLink
            );
            
            if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, Policy->FileId)) {
                // Update in place
                RtlCopyMemory(&entry->Policy, Policy, sizeof(DLP_POLICY_ENTRY));
                entry->Policy.LastAccessTime = DlpGetCurrentTime();
                
                // Set expiration if not permanent
                if (!(entry->Policy.Flags & DLP_ENTRY_FLAG_PERMANENT)) {
                    entry->Policy.ExpirationTime = DlpGetCurrentTime() +
                        ((ULONGLONG)Cache->EntryTTLSec * 10000000ULL);
                }
                
                inserted = TRUE;
                break;
            }
            
            listEntry = listEntry->Flink;
        }
        
        DlpReleaseBucket(bucket);
        
        if (inserted) {
            return STATUS_SUCCESS;
        }
    }
    
    // Need to insert new entry
    newEntry = DlpAllocateCacheEntry(Cache);
    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Initialize new entry
    RtlCopyMemory(&newEntry->Policy, Policy, sizeof(DLP_POLICY_ENTRY));
    newEntry->Policy.LastAccessTime = DlpGetCurrentTime();
    newEntry->Policy.Flags |= DLP_ENTRY_FLAG_VALID;
    
    // Set expiration
    if (!(newEntry->Policy.Flags & DLP_ENTRY_FLAG_PERMANENT)) {
        newEntry->Policy.ExpirationTime = DlpGetCurrentTime() +
            ((ULONGLONG)Cache->EntryTTLSec * 10000000ULL);
    }
    
    newEntry->RefCount = 1;
    newEntry->Flags = 0;
    InitializeListHead(&newEntry->LruLink);
    
    // Insert into bucket with exclusive lock
    DlpAcquireBucketExclusive(bucket);
    
    // Double-check entry wasn't added while we allocated
    listEntry = bucket->Head.Flink;
    while (listEntry != &bucket->Head) {
        PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
            listEntry,
            DLP_CACHE_ENTRY,
            HashLink
        );
        
        if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, Policy->FileId)) {
            // Someone else added it - update and return
            RtlCopyMemory(&entry->Policy, Policy, sizeof(DLP_POLICY_ENTRY));
            DlpReleaseBucket(bucket);
            DlpFreeCacheEntry(Cache, newEntry);
            return STATUS_SUCCESS;
        }
        
        listEntry = listEntry->Flink;
    }
    
    // Insert at head of bucket
    InsertHeadList(&bucket->Head, &newEntry->HashLink);
    InterlockedIncrement(&bucket->Count);
    
    DlpReleaseBucket(bucket);
    
    // Add to LRU list
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Cache->LruLock);
    
    InsertTailList(&Cache->LruHead, &newEntry->LruLink);
    
    ExReleasePushLock(&Cache->LruLock);
    KeLeaveCriticalRegion();
    
    // Update statistics
    LONG newCount = InterlockedIncrement(&Cache->CurrentEntries);
    LONG maxUsed = InterlockedCompareExchange(&Cache->MaxEntriesUsed, 0, 0);
    if (newCount > maxUsed) {
        InterlockedCompareExchange(&Cache->MaxEntriesUsed, newCount, maxUsed);
    }
    
    return STATUS_SUCCESS;
}

// ============================================================================
// CACHE REMOVAL
// ============================================================================

/**
 * DlpRemovePolicy - Remove policy entry from cache
 * 
 * @param Cache - Policy cache
 * @param FileId - File identifier to remove
 * 
 * @return STATUS_SUCCESS if removed, STATUS_NOT_FOUND if not present
 * 
 * @irql <= APC_LEVEL
 */
NTSTATUS
DlpRemovePolicy(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_FILE_ID FileId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PDLP_CACHE_ENTRY entryToFree = NULL;
    
    if (Cache == NULL || FileId == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    ULONG bucketIndex = DlpHashFileId(FileId);
    PDLP_CACHE_BUCKET bucket = &Cache->Buckets[bucketIndex];
    
    DlpAcquireBucketExclusive(bucket);
    
    PLIST_ENTRY listEntry = bucket->Head.Flink;
    while (listEntry != &bucket->Head) {
        PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
            listEntry,
            DLP_CACHE_ENTRY,
            HashLink
        );
        
        if (DLP_FILE_ID_EQUAL(entry->Policy.FileId, *FileId)) {
            // Found it - remove from hash bucket
            RemoveEntryList(&entry->HashLink);
            InterlockedDecrement(&bucket->Count);
            
            entryToFree = entry;
            status = STATUS_SUCCESS;
            break;
        }
        
        listEntry = listEntry->Flink;
    }
    
    DlpReleaseBucket(bucket);
    
    // Remove from LRU and free
    if (entryToFree != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Cache->LruLock);
        
        if (!IsListEmpty(&entryToFree->LruLink)) {
            RemoveEntryList(&entryToFree->LruLink);
        }
        
        ExReleasePushLock(&Cache->LruLock);
        KeLeaveCriticalRegion();
        
        InterlockedDecrement(&Cache->CurrentEntries);
        DlpFreeCacheEntry(Cache, entryToFree);
    }
    
    return status;
}

/**
 * DlpClearCache - Remove all entries from cache
 * 
 * @param Cache - Policy cache
 * 
 * @irql PASSIVE_LEVEL only
 */
VOID
DlpClearCache(
    _Inout_ PDLP_POLICY_CACHE Cache
)
{
    PAGED_CODE();
    
    if (Cache == NULL) {
        return;
    }
    
    // Process each bucket
    for (ULONG i = 0; i < DLP_CACHE_HASH_BUCKETS; i++) {
        PDLP_CACHE_BUCKET bucket = &Cache->Buckets[i];
        
        DlpAcquireBucketExclusive(bucket);
        
        while (!IsListEmpty(&bucket->Head)) {
            PLIST_ENTRY listEntry = RemoveHeadList(&bucket->Head);
            PDLP_CACHE_ENTRY entry = CONTAINING_RECORD(
                listEntry,
                DLP_CACHE_ENTRY,
                HashLink
            );
            
            DlpFreeCacheEntry(Cache, entry);
        }
        
        bucket->Count = 0;
        
        DlpReleaseBucket(bucket);
    }
    
    // Clear LRU list
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Cache->LruLock);
    InitializeListHead(&Cache->LruHead);
    ExReleasePushLock(&Cache->LruLock);
    KeLeaveCriticalRegion();
    
    // Reset statistics
    InterlockedExchange(&Cache->CurrentEntries, 0);
    InterlockedIncrement(&Cache->Version);
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * Allocate a cache entry from the lookaside list.
 *
 * No fallback to the general pool: every entry allocated via
 * ExAllocateFromLookasideListEx is returned strictly via
 * ExFreeToLookasideListEx, guaranteeing a correct allocation/deallocation
 * pairing that Driver Verifier can validate. If the lookaside cannot satisfy
 * the request we fail gracefully (STATUS_INSUFFICIENT_RESOURCES) rather than
 * mixing allocation sources.
 */
static PDLP_CACHE_ENTRY
DlpAllocateCacheEntry(
    _In_ PDLP_POLICY_CACHE Cache
)
{
    PDLP_CACHE_ENTRY entry = NULL;
    
    if (!Cache->LookasideInitialized) {
        return NULL;
    }
    
    entry = (PDLP_CACHE_ENTRY)ExAllocateFromLookasideListEx(
        &Cache->EntryLookaside
    );
    
    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(DLP_CACHE_ENTRY));
    }
    
    return entry;
}

/**
 * Free a cache entry back to the lookaside list
 */
static VOID
DlpFreeCacheEntry(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_CACHE_ENTRY Entry
)
{
    if (Entry == NULL) {
        return;
    }
    
    if (!Cache->LookasideInitialized) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "PRITRAK DLP: cache free attempted with uninitialized lookaside\n"));
        return;
    }
    
    ExFreeToLookasideListEx(&Cache->EntryLookaside, Entry);
}

/**
 * Evict the oldest (LRU) entry from cache
 */
static VOID
DlpEvictOldestEntry(
    _In_ PDLP_POLICY_CACHE Cache
)
{
    PDLP_CACHE_ENTRY entryToEvict = NULL;
    DLP_FILE_ID fileIdToRemove = {0};
    
    // Get oldest entry from LRU list
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Cache->LruLock);
    
    if (!IsListEmpty(&Cache->LruHead)) {
        PLIST_ENTRY listEntry = Cache->LruHead.Flink;
        entryToEvict = CONTAINING_RECORD(
            listEntry,
            DLP_CACHE_ENTRY,
            LruLink
        );
        
        // Don't evict pinned entries
        while ((entryToEvict->Policy.Flags & DLP_ENTRY_FLAG_PINNED) &&
               listEntry->Flink != &Cache->LruHead) {
            listEntry = listEntry->Flink;
            entryToEvict = CONTAINING_RECORD(
                listEntry,
                DLP_CACHE_ENTRY,
                LruLink
            );
        }
        
        if (!(entryToEvict->Policy.Flags & DLP_ENTRY_FLAG_PINNED)) {
            // Copy file ID for removal (can't hold LRU lock while removing from hash)
            fileIdToRemove = entryToEvict->Policy.FileId;
        } else {
            entryToEvict = NULL;
        }
    }
    
    ExReleasePushLock(&Cache->LruLock);
    KeLeaveCriticalRegion();
    
    // Remove entry from hash table
    if (entryToEvict != NULL) {
        DlpRemovePolicy(Cache, &fileIdToRemove);
        InterlockedIncrement64(&Cache->Evictions);
    }
}

/**
 * Update entry access time and move to end of LRU list
 */
static VOID
DlpTouchEntry(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_ PDLP_CACHE_ENTRY Entry
)
{
    // Update access time
    Entry->Policy.LastAccessTime = DlpGetCurrentTime();
    
    // Move to end of LRU list (most recently used)
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Cache->LruLock);
    
    if (!IsListEmpty(&Entry->LruLink)) {
        RemoveEntryList(&Entry->LruLink);
        InsertTailList(&Cache->LruHead, &Entry->LruLink);
    }
    
    ExReleasePushLock(&Cache->LruLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// BULK OPERATIONS
// ============================================================================

/**
 * DlpBulkInsertPolicies - Insert multiple policies efficiently
 * 
 * @param Cache - Policy cache
 * @param Entries - Array of policy entries
 * @param Count - Number of entries
 * 
 * @return Number of entries successfully inserted
 * 
 * @irql <= APC_LEVEL
 */
ULONG
DlpBulkInsertPolicies(
    _In_ PDLP_POLICY_CACHE Cache,
    _In_reads_(Count) PDLP_POLICY_ENTRY Entries,
    _In_ ULONG Count
)
{
    ULONG inserted = 0;
    
    if (Cache == NULL || Entries == NULL || Count == 0) {
        return 0;
    }
    
    for (ULONG i = 0; i < Count; i++) {
        NTSTATUS status = DlpInsertPolicy(Cache, &Entries[i]);
        if (NT_SUCCESS(status)) {
            inserted++;
        }
    }
    
    return inserted;
}

/**
 * DlpGetCacheStatistics - Get cache statistics
 * 
 * @param Cache - Policy cache
 * @param HitsOut - Output hit count
 * @param MissesOut - Output miss count
 * @param EntriesOut - Output current entry count
 * @param EvictionsOut - Output eviction count
 */
VOID
DlpGetCacheStatistics(
    _In_ PDLP_POLICY_CACHE Cache,
    _Out_opt_ PLONG64 HitsOut,
    _Out_opt_ PLONG64 MissesOut,
    _Out_opt_ PLONG EntriesOut,
    _Out_opt_ PLONG64 EvictionsOut
)
{
    if (Cache == NULL) {
        return;
    }
    
    if (HitsOut) {
        *HitsOut = InterlockedCompareExchange64(&Cache->Hits, 0, 0);
    }
    if (MissesOut) {
        *MissesOut = InterlockedCompareExchange64(&Cache->Misses, 0, 0);
    }
    if (EntriesOut) {
        *EntriesOut = InterlockedCompareExchange(&Cache->CurrentEntries, 0, 0);
    }
    if (EvictionsOut) {
        *EvictionsOut = InterlockedCompareExchange64(&Cache->Evictions, 0, 0);
    }
}
