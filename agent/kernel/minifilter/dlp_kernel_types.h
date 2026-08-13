/**
 * @file dlp_kernel_types.h
 * @brief Kernel-specific type definitions for DLP minifilter
 * 
 * PRITRAK Enterprise DLP Agent - Kernel Types
 * 
 * This header provides kernel-safe type definitions, pool tags,
 * and internal structures used only within the kernel driver.
 */

#ifndef _DLP_KERNEL_TYPES_H_
#define _DLP_KERNEL_TYPES_H_

#include <fltKernel.h>
#include <ntddk.h>
#include "../common/shared/dlp_shared.h"

// Forward declare process table (defined in dlp_process_tracker.h)
typedef struct _DLP_PROCESS_TABLE DLP_PROCESS_TABLE, *PDLP_PROCESS_TABLE;

// ============================================================================
// POOL TAGS (For memory tracking and debugging)
// ============================================================================

#define DLP_POOL_TAG_GENERAL        'pLDG'  // General allocations
#define DLP_POOL_TAG_CACHE          'pLDC'  // Policy cache
#define DLP_POOL_TAG_STRING         'pLDS'  // String allocations
#define DLP_POOL_TAG_CONTEXT        'pLDX'  // Context allocations
#define DLP_POOL_TAG_EVENT          'pLDE'  // Event ring buffer
#define DLP_POOL_TAG_LOOKASIDE      'pLDL'  // Lookaside lists

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

// Cache configuration
#define DLP_DEFAULT_CACHE_SIZE          65536   // Default max cache entries
#define DLP_MIN_CACHE_SIZE              1024    // Minimum cache size
#define DLP_MAX_CACHE_SIZE              1000000 // Maximum cache size

// Hash table configuration (must be power of 2)
#define DLP_CACHE_HASH_BUCKETS          4096    // Number of hash buckets
#define DLP_CACHE_HASH_MASK             (DLP_CACHE_HASH_BUCKETS - 1)

// Event ring buffer
#define DLP_EVENT_RING_SIZE             4096    // Events in ring buffer
#define DLP_EVENT_RING_MASK             (DLP_EVENT_RING_SIZE - 1)

// Timeouts
#define DLP_MESSAGE_TIMEOUT_MS          100     // Max time to wait for user-mode
#define DLP_POLICY_DEFAULT_TTL_SEC      300     // 5 minute default TTL

// Volume tracking
#define DLP_MAX_VOLUMES                 128     // Maximum monitored volumes

// Maximum binary SID length (SECURITY_MAX_SID_SIZE)
#define DLP_MAX_SID_LENGTH              68

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

typedef struct _DLP_DRIVER_GLOBALS DLP_DRIVER_GLOBALS, *PDLP_DRIVER_GLOBALS;
typedef struct _DLP_CACHE_ENTRY DLP_CACHE_ENTRY, *PDLP_CACHE_ENTRY;
typedef struct _DLP_CACHE_BUCKET DLP_CACHE_BUCKET, *PDLP_CACHE_BUCKET;
typedef struct _DLP_POLICY_CACHE DLP_POLICY_CACHE, *PDLP_POLICY_CACHE;
typedef struct _DLP_VOLUME_CONTEXT DLP_VOLUME_CONTEXT, *PDLP_VOLUME_CONTEXT;
typedef struct _DLP_STREAM_CONTEXT DLP_STREAM_CONTEXT, *PDLP_STREAM_CONTEXT;
typedef struct _DLP_EVENT_QUEUE DLP_EVENT_QUEUE, *PDLP_EVENT_QUEUE;

// ============================================================================
// CACHE ENTRY (Internal representation)
// ============================================================================

/**
 * @struct DLP_CACHE_ENTRY
 * @brief Internal cache entry with list linkage
 * 
 * This structure wraps DLP_POLICY_ENTRY with list links for hash table
 * chaining and LRU management.
 */
typedef struct _DLP_CACHE_ENTRY {
    LIST_ENTRY          HashLink;           // Hash bucket chain
    LIST_ENTRY          LruLink;            // LRU chain for eviction
    DLP_POLICY_ENTRY    Policy;             // The actual policy data
    volatile LONG       RefCount;           // Reference count
    volatile LONG       Flags;              // Entry flags
} DLP_CACHE_ENTRY, *PDLP_CACHE_ENTRY;

// Cache entry internal flags
#define DLP_CACHE_ENTRY_LOCKED      0x00010000
#define DLP_CACHE_ENTRY_REMOVING    0x00020000

// ============================================================================
// CACHE BUCKET (Lock-striped for concurrency)
// ============================================================================

/**
 * @struct DLP_CACHE_BUCKET
 * @brief Single hash bucket with its own lock
 * 
 * Uses lock striping to minimize contention. Each bucket has its own
 * reader-writer lock allowing concurrent reads.
 */
typedef struct _DLP_CACHE_BUCKET {
    EX_PUSH_LOCK        Lock;               // Per-bucket R/W lock
    LIST_ENTRY          Head;               // Entry list head
    volatile LONG       Count;              // Entries in bucket
} DLP_CACHE_BUCKET, *PDLP_CACHE_BUCKET;

// ============================================================================
// POLICY CACHE (Main structure)
// ============================================================================

/**
 * @struct DLP_POLICY_CACHE
 * @brief Main policy cache with hash table and LRU eviction
 * 
 * Design goals:
 * - O(1) lookup by file ID
 * - Lock-striped for concurrent access
 * - LRU eviction when cache is full
 * - No allocations in hot path (uses lookaside list)
 */
typedef struct _DLP_POLICY_CACHE {
    // Configuration
    ULONG               MaxEntries;         // Maximum cache size
    ULONG               EntryTTLSec;        // Default TTL in seconds
    
    // Statistics (using interlocked operations)
    volatile LONG64     Hits;
    volatile LONG64     Misses;
    volatile LONG64     Evictions;
    volatile LONG       CurrentEntries;
    volatile LONG       MaxEntriesUsed;
    
    // Hash table
    DLP_CACHE_BUCKET    Buckets[DLP_CACHE_HASH_BUCKETS];
    
    // LRU management
    EX_PUSH_LOCK        LruLock;            // Global LRU lock
    LIST_ENTRY          LruHead;            // LRU list (head = least recent)
    
    // Memory management
    LOOKASIDE_LIST_EX   EntryLookaside;     // Pre-allocated entry pool
    BOOLEAN             LookasideInitialized;
    
    // Policy version (for invalidation)
    volatile LONG       Version;
    
} DLP_POLICY_CACHE, *PDLP_POLICY_CACHE;

// ============================================================================
// VOLUME CONTEXT
// ============================================================================

/**
 * @struct DLP_VOLUME_CONTEXT
 * @brief Per-volume context attached to each monitored volume
 */
typedef struct _DLP_VOLUME_CONTEXT {
    // Volume identification
    ULONG               VolumeSerialNumber;
    ULONG               VolumeFlags;        // DLP_VOLUME_FLAGS
    
    // Volume properties
    FLT_FILESYSTEM_TYPE FileSystemType;
    DEVICE_TYPE         DeviceType;
    ULONG               DeviceCharacteristics;
    ULONG               SectorSize;
    
    // Volume name (for logging)
    UNICODE_STRING      VolumeName;
    WCHAR               VolumeNameBuffer[64];
    
    // Device path
    UNICODE_STRING      DevicePath;
    WCHAR               DevicePathBuffer[DLP_MAX_PATH_LENGTH];
    
} DLP_VOLUME_CONTEXT, *PDLP_VOLUME_CONTEXT;

// Context registration
#define DLP_VOLUME_CONTEXT_SIZE     sizeof(DLP_VOLUME_CONTEXT)
#define DLP_VOLUME_CONTEXT_TAG      DLP_POOL_TAG_CONTEXT

// ============================================================================
// STREAM CONTEXT (Per-file stream)
// ============================================================================

/**
 * @struct DLP_STREAM_CONTEXT
 * @brief Per-file-stream context for tracking file state
 * 
 * Attached to file streams to track classification status
 * without needing to query the cache on every operation.
 */
typedef struct _DLP_STREAM_CONTEXT {
    // File identity
    DLP_FILE_ID         FileId;
    
    // Cached classification (may be stale, check version)
    ULONG               Classification;
    ULONG               CacheVersion;       // Version when cached
    ULONGLONG           LastCheckedTime;    // When we last validated
    
    // Flags
    volatile LONG       Flags;
    
    // Reference to cached policy (if any)
    PDLP_CACHE_ENTRY    CachedPolicy;
    
} DLP_STREAM_CONTEXT, *PDLP_STREAM_CONTEXT;

// Stream context flags
#define DLP_STREAM_FLAG_CLASSIFIED      0x00000001
#define DLP_STREAM_FLAG_PROTECTED       0x00000002
#define DLP_STREAM_FLAG_DELETE_PENDING  0x00000004

#define DLP_STREAM_CONTEXT_SIZE     sizeof(DLP_STREAM_CONTEXT)
#define DLP_STREAM_CONTEXT_TAG      DLP_POOL_TAG_CONTEXT

// ============================================================================
// NOTIFICATION RECORD (Kernel -> Usermode event)
// ============================================================================

/**
 * @struct DLP_NOTIFY_HEADER
 * @brief Fixed-size header for kernel->usermode notification records.
 *
 * The Size and Version fields form the structure validation boundary:
 * usermode consumers must reject any record whose Size does not match the
 * expected DLP_NOTIFICATION_RECORD layout or whose Version does not match
 * DLP_PROTOCOL_VERSION.
 */
typedef struct _DLP_NOTIFY_HEADER {
    ULONG       Size;                   // sizeof(DLP_NOTIFICATION_RECORD)
    ULONG       Version;                // DLP_PROTOCOL_VERSION
    ULONG       Type;                   // DLP_MESSAGE_TYPE (DLP_MSG_EVENT_BLOCKED)
    ULONG       Flags;                  // Reserved, must be zero
} DLP_NOTIFY_HEADER, *PDLP_NOTIFY_HEADER;

/**
 * @struct DLP_NOTIFICATION_RECORD
 * @brief Kernel-internal event tracking record.
 *
 * The fixed prefix (ListEntry/Header/FilePath/ProcessId/ActionTaken) is the
 * documented structure validation boundary. The trailing fields carry the
 * extended context captured by DlpQueueBlockEvent (file identity, operation,
 * classification, process name and the requesting user's SID).
 */
typedef struct _DLP_NOTIFICATION_RECORD {
    LIST_ENTRY          ListEntry;              // Queue linkage
    DLP_NOTIFY_HEADER   Header;                 // Structure validation boundary
    WCHAR               FilePath[DLP_MAX_PATH_LENGTH];  // 520 WCHARs
    ULONG               ProcessId;
    ULONG               ActionTaken;            // DLP_ACTION

    // Extended context (kernel-internal, appended after the validated prefix)
    DLP_FILE_ID         FileId;
    ULONG               Operation;              // DLP_OPERATION_TYPE
    ULONG               Classification;         // DLP_CLASSIFICATION flags
    WCHAR               ProcessName[DLP_MAX_FILENAME_LENGTH];
    ULONG               UserSidLength;
    UCHAR               UserSid[DLP_MAX_SID_LENGTH];
} DLP_NOTIFICATION_RECORD, *PDLP_NOTIFICATION_RECORD;

// ============================================================================
// EVENT QUEUE (Push-lock protected FIFO)
// ============================================================================

/**
 * @struct DLP_EVENT_QUEUE
 * @brief Push-lock protected FIFO queue for event notifications.
 *
 * Producers (IRP callbacks at IRQL <= DISPATCH_LEVEL) insert
 * DLP_NOTIFICATION_RECORD entries allocated from a NonPagedPoolNx lookaside
 * list. A dedicated worker thread (PASSIVE_LEVEL) drains the queue and
 * delivers records to the SCM-hosted usermode service via the notify port.
 */
typedef struct _DLP_EVENT_QUEUE {
    // Push-lock protected FIFO of DLP_NOTIFICATION_RECORD entries
    EX_PUSH_LOCK        Lock;
    LIST_ENTRY          Head;
    volatile LONG       Count;

    // Statistics
    volatile LONG64     TotalEvents;
    volatile LONG64     DroppedEvents;

    // Notification event (wakes the notification worker thread)
    KEVENT              DataAvailable;

    // Memory management (NonPagedPoolNx lookaside for event records)
    LOOKASIDE_LIST_EX   EventLookaside;
    BOOLEAN             LookasideInitialized;

} DLP_EVENT_QUEUE, *PDLP_EVENT_QUEUE;

// ============================================================================
// VOLUME TRACKING
// ============================================================================

typedef struct _DLP_VOLUME_ENTRY {
    BOOLEAN             InUse;
    ULONG               SerialNumber;
    ULONG               Flags;
    PFLT_INSTANCE       Instance;
    PFLT_VOLUME         Volume;
} DLP_VOLUME_ENTRY, *PDLP_VOLUME_ENTRY;

typedef struct _DLP_VOLUME_TABLE {
    EX_PUSH_LOCK        Lock;
    DLP_VOLUME_ENTRY    Entries[DLP_MAX_VOLUMES];
    ULONG               Count;
} DLP_VOLUME_TABLE, *PDLP_VOLUME_TABLE;

// ============================================================================
// DRIVER GLOBALS
// ============================================================================

/**
 * @struct DLP_DRIVER_GLOBALS
 * @brief Main driver global state
 * 
 * All global driver state is contained in this single structure
 * for better organization and testability.
 */
typedef struct _DLP_DRIVER_GLOBALS {
    // Driver identity
    PFLT_FILTER         FilterHandle;
    PDRIVER_OBJECT      DriverObject;
    UNICODE_STRING      RegistryPath;
    
    // Communication ports
    PFLT_PORT           CommandServerPort;      // For commands from user-mode
    PFLT_PORT           CommandClientPort;      // Current client connection
    PFLT_PORT           NotifyServerPort;       // For notifications to user-mode
    PFLT_PORT           NotifyClientPort;       // Current client connection
    
    // Policy cache
    DLP_POLICY_CACHE    PolicyCache;
    
    // Volume table
    DLP_VOLUME_TABLE    VolumeTable;
    
    // Event queue
    DLP_EVENT_QUEUE     EventQueue;
    
    // Process tracker (for USB copy blocking)
    DLP_PROCESS_TABLE*  ProcessTable;
    
    // Configuration
    struct {
        BOOLEAN         FailClosedMode;         // Block if no policy? (default: true)
        BOOLEAN         AuditMode;              // Log only, don't block
        BOOLEAN         DebugMode;              // Verbose logging
        ULONG           MaxCacheEntries;
        ULONG           CacheTTLSeconds;
    } Config;
    
    // Statistics
    DLP_STATISTICS      Stats;
    
    // State flags
    volatile LONG       ServiceConnected;       // User-mode service connected
    volatile LONG       ShuttingDown;           // Driver is unloading
    
    // Notification worker thread
    PKTHREAD            NotifyThread;
    KEVENT              NotifyThreadStop;
    
} DLP_DRIVER_GLOBALS, *PDLP_DRIVER_GLOBALS;

// Global instance (defined in dlp_driver_core.c)
extern DLP_DRIVER_GLOBALS g_Globals;

// ============================================================================
// INLINE HELPER FUNCTIONS
// ============================================================================

/**
 * Hash function for file ID
 * Uses FNV-1a variant for good distribution
 */
__forceinline ULONG
DlpHashFileId(
    _In_ PDLP_FILE_ID FileId
)
{
    ULONG hash = 2166136261;  // FNV offset basis
    
    hash ^= FileId->VolumeSerialNumber;
    hash *= 16777619;  // FNV prime
    
    hash ^= (ULONG)(FileId->FileId & 0xFFFFFFFF);
    hash *= 16777619;
    
    hash ^= (ULONG)(FileId->FileId >> 32);
    hash *= 16777619;
    
    return hash & DLP_CACHE_HASH_MASK;
}

/**
 * Get current time in 100-nanosecond intervals
 */
__forceinline ULONGLONG
DlpGetCurrentTime(void)
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return (ULONGLONG)time.QuadPart;
}

/**
 * Check if cache entry has expired
 */
__forceinline BOOLEAN
DlpIsEntryExpired(
    _In_ PDLP_CACHE_ENTRY Entry
)
{
    if (Entry->Policy.Flags & DLP_ENTRY_FLAG_PERMANENT) {
        return FALSE;
    }
    
    ULONGLONG now = DlpGetCurrentTime();
    return (now > Entry->Policy.ExpirationTime);
}

/**
 * Acquire bucket lock for reading
 */
__forceinline VOID
DlpAcquireBucketShared(
    _In_ PDLP_CACHE_BUCKET Bucket
)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Bucket->Lock);
}

/**
 * Acquire bucket lock for writing
 */
__forceinline VOID
DlpAcquireBucketExclusive(
    _In_ PDLP_CACHE_BUCKET Bucket
)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);
}

/**
 * Release bucket lock
 */
__forceinline VOID
DlpReleaseBucket(
    _In_ PDLP_CACHE_BUCKET Bucket
)
{
    ExReleasePushLock(&Bucket->Lock);
    KeLeaveCriticalRegion();
}

#endif // _DLP_KERNEL_TYPES_H_
