/**
 * @file dlp_shared.h
 * @brief Shared definitions between kernel minifilter and user-mode service
 * 
 * PRITRAK Enterprise DLP Agent
 * Production-grade shared header for kernel/user-mode communication
 * 
 * Copyright (C) 2026 Pritrak Security
 * 
 * This header defines all structures, constants, and protocols used for
 * communication between the kernel-mode minifilter driver and user-mode
 * DLP service. It follows Windows kernel-safe conventions.
 */

#ifndef _DLP_SHARED_H_
#define _DLP_SHARED_H_

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// VERSIONING
// ============================================================================

#define DLP_PROTOCOL_VERSION_MAJOR      2
#define DLP_PROTOCOL_VERSION_MINOR      0
#define DLP_PROTOCOL_VERSION_PATCH      0

#define DLP_MAKE_VERSION(major, minor, patch) \
    (((major) << 16) | ((minor) << 8) | (patch))

#define DLP_PROTOCOL_VERSION \
    DLP_MAKE_VERSION(DLP_PROTOCOL_VERSION_MAJOR, DLP_PROTOCOL_VERSION_MINOR, DLP_PROTOCOL_VERSION_PATCH)

// ============================================================================
// PORT AND FILTER NAMES
// ============================================================================

#define DLP_FILTER_NAME             L"PritrakDLPFilter"
#define DLP_FILTER_ALTITUDE         L"370030"

// Communication port names
#define DLP_COMMAND_PORT_NAME       L"\\PritrakDLPCommandPort"
#define DLP_NOTIFICATION_PORT_NAME  L"\\PritrakDLPNotifyPort"

// Registry paths
#define DLP_REGISTRY_PATH           L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\PritrakDLP"
#define DLP_POLICY_REGISTRY_KEY     L"PolicyCache"

// ============================================================================
// CLASSIFICATION LEVELS (Bit flags for efficiency)
// ============================================================================

typedef enum _DLP_CLASSIFICATION {
    DLP_CLASS_UNKNOWN       = 0x00000000,  // Not yet classified
    DLP_CLASS_PUBLIC        = 0x00000001,  // Public data - no restrictions
    DLP_CLASS_INTERNAL      = 0x00000002,  // Internal use only
    DLP_CLASS_CONFIDENTIAL  = 0x00000004,  // Confidential - limited sharing
    DLP_CLASS_RESTRICTED    = 0x00000008,  // Restricted - strict controls
    DLP_CLASS_TOP_SECRET    = 0x00000010,  // Top secret - maximum protection
    DLP_CLASS_PII           = 0x00000100,  // Contains PII
    DLP_CLASS_PCI           = 0x00000200,  // Contains PCI data
    DLP_CLASS_PHI           = 0x00000400,  // Contains PHI (HIPAA)
    DLP_CLASS_FINGERPRINTED = 0x00001000,  // Fingerprinted document
    DLP_CLASS_ENCRYPTED     = 0x00002000,  // Encrypted content
} DLP_CLASSIFICATION;

// Macro to check if classification requires protection
#define DLP_IS_PROTECTED_CLASS(c) \
    (((c) & (DLP_CLASS_RESTRICTED | DLP_CLASS_TOP_SECRET | DLP_CLASS_PII | DLP_CLASS_PCI | DLP_CLASS_PHI)) != 0)

// ============================================================================
// ENFORCEMENT ACTIONS (Bit flags)
// ============================================================================

typedef enum _DLP_ACTION {
    DLP_ACTION_ALLOW            = 0x00000000,  // Allow operation
    DLP_ACTION_BLOCK            = 0x00000001,  // Block operation
    DLP_ACTION_AUDIT            = 0x00000002,  // Log only
    DLP_ACTION_WARN             = 0x00000004,  // Warn user but allow
    DLP_ACTION_ENCRYPT          = 0x00000008,  // Force encryption
    DLP_ACTION_QUARANTINE       = 0x00000010,  // Move to quarantine
    DLP_ACTION_NOTIFY_USER      = 0x00000100,  // Show user notification
    DLP_ACTION_NOTIFY_ADMIN     = 0x00000200,  // Alert administrator
    DLP_ACTION_NOTIFY_SIEM      = 0x00000400,  // Send to SIEM
} DLP_ACTION;

// ============================================================================
// OPERATION TYPES
// ============================================================================

typedef enum _DLP_OPERATION_TYPE {
    DLP_OP_UNKNOWN              = 0,
    
    // File operations
    DLP_OP_FILE_CREATE          = 1,
    DLP_OP_FILE_OPEN            = 2,
    DLP_OP_FILE_READ            = 3,
    DLP_OP_FILE_WRITE           = 4,
    DLP_OP_FILE_DELETE          = 5,
    DLP_OP_FILE_RENAME          = 6,
    DLP_OP_FILE_MOVE            = 7,
    DLP_OP_FILE_COPY            = 8,
    DLP_OP_FILE_CLOSE           = 9,
    
    // Device operations
    DLP_OP_USB_WRITE            = 20,
    DLP_OP_USB_MOUNT            = 21,
    DLP_OP_NETWORK_WRITE        = 22,
    DLP_OP_CLOUD_UPLOAD         = 23,
    DLP_OP_PRINT                = 24,
    
    // Clipboard operations (future)
    DLP_OP_CLIPBOARD_COPY       = 30,
    DLP_OP_CLIPBOARD_PASTE      = 31,
    DLP_OP_SCREENSHOT           = 32,
    
} DLP_OPERATION_TYPE;

// ============================================================================
// VOLUME/DEVICE FLAGS
// ============================================================================

typedef enum _DLP_VOLUME_FLAGS {
    DLP_VOLUME_FLAG_NONE        = 0x00000000,
    DLP_VOLUME_FLAG_REMOVABLE   = 0x00000001,  // Removable media
    DLP_VOLUME_FLAG_USB         = 0x00000002,  // USB device
    DLP_VOLUME_FLAG_NETWORK     = 0x00000004,  // Network share
    DLP_VOLUME_FLAG_CLOUD       = 0x00000008,  // Cloud storage
    DLP_VOLUME_FLAG_ENCRYPTED   = 0x00000010,  // Encrypted volume
    DLP_VOLUME_FLAG_TRUSTED     = 0x00000100,  // Admin-approved device
    DLP_VOLUME_FLAG_READONLY    = 0x00000200,  // Read-only volume
} DLP_VOLUME_FLAGS;

// ============================================================================
// FILE IDENTITY (Critical: NOT path-based)
// ============================================================================

/**
 * @struct DLP_FILE_ID
 * @brief Unique, stable file identifier using NTFS File Reference Number
 * 
 * This structure provides a path-independent way to identify files.
 * The combination of VolumeSerialNumber and FileId is globally unique
 * and stable across renames and moves on the same volume.
 */
typedef struct _DLP_FILE_ID {
    ULONG       VolumeSerialNumber;     // Volume serial number
    ULONGLONG   FileId;                 // NTFS File Reference Number (FILE_INTERNAL_INFORMATION)
} DLP_FILE_ID, *PDLP_FILE_ID;

// Helper macro to compare file IDs
#define DLP_FILE_ID_EQUAL(a, b) \
    (((a).VolumeSerialNumber == (b).VolumeSerialNumber) && ((a).FileId == (b).FileId))

// ============================================================================
// POLICY ENTRY (Kernel Cache Entry)
// ============================================================================

/**
 * @struct DLP_POLICY_ENTRY
 * @brief Single policy entry stored in kernel cache
 * 
 * This is the cached policy information for a single file.
 * Size is kept small (64 bytes) for cache efficiency.
 */
#pragma pack(push, 8)
typedef struct _DLP_POLICY_ENTRY {
    DLP_FILE_ID         FileId;             // 12 bytes: Unique file identifier
    ULONG               Classification;      // 4 bytes: DLP_CLASSIFICATION flags
    ULONG               AllowedActions;      // 4 bytes: What's allowed (delete, copy, etc.)
    ULONG               BlockedActions;      // 4 bytes: What's blocked
    ULONG               Flags;               // 4 bytes: Additional flags
    ULONGLONG           ExpirationTime;      // 8 bytes: When this entry expires (100ns intervals)
    ULONGLONG           LastAccessTime;      // 8 bytes: For LRU eviction
    ULONG               RuleId;              // 4 bytes: Which rule matched
    ULONG               Reserved;            // 4 bytes: Alignment/future use
    // Total: 52 bytes -> padded to 64 bytes
} DLP_POLICY_ENTRY, *PDLP_POLICY_ENTRY;
#pragma pack(pop)

// Entry flags
#define DLP_ENTRY_FLAG_VALID        0x00000001
#define DLP_ENTRY_FLAG_PERMANENT    0x00000002  // Never expires
#define DLP_ENTRY_FLAG_PINNED       0x00000004  // Cannot be evicted
#define DLP_ENTRY_FLAG_PENDING      0x00000008  // Classification pending

// Default entry expiration: 5 minutes (in 100ns intervals)
#define DLP_DEFAULT_ENTRY_TTL       (5LL * 60LL * 10000000LL)

// ============================================================================
// MESSAGE TYPES (Kernel <-> User-Mode)
// ============================================================================

typedef enum _DLP_MESSAGE_TYPE {
    // User-mode -> Kernel commands (0x0001 - 0x00FF)
    DLP_MSG_POLICY_UPDATE       = 0x0001,  // Update single policy entry
    DLP_MSG_POLICY_BULK_UPDATE  = 0x0002,  // Update multiple entries
    DLP_MSG_POLICY_REMOVE       = 0x0003,  // Remove policy entry
    DLP_MSG_POLICY_CLEAR        = 0x0004,  // Clear all policy entries
    DLP_MSG_VOLUME_UPDATE       = 0x0005,  // Update volume flags
    DLP_MSG_CONFIG_UPDATE       = 0x0006,  // Update driver configuration
    DLP_MSG_PING                = 0x000F,  // Keepalive ping
    
    // Kernel -> User-mode notifications (0x0100 - 0x01FF)
    DLP_MSG_EVENT_BLOCKED       = 0x0100,  // Operation was blocked
    DLP_MSG_EVENT_ALLOWED       = 0x0101,  // Operation was allowed (audit)
    DLP_MSG_EVENT_PENDING       = 0x0102,  // Need classification decision
    DLP_MSG_VOLUME_MOUNTED      = 0x0103,  // New volume mounted
    DLP_MSG_VOLUME_DISMOUNTED   = 0x0104,  // Volume dismounted
    DLP_MSG_DRIVER_STATUS       = 0x0105,  // Driver status update
    DLP_MSG_PONG                = 0x010F,  // Keepalive response
    
} DLP_MESSAGE_TYPE;

// ============================================================================
// MESSAGE STRUCTURES
// ============================================================================

// Maximum path length in messages (Unicode characters)
#define DLP_MAX_PATH_LENGTH         520
#define DLP_MAX_FILENAME_LENGTH     256
#define DLP_MAX_BULK_ENTRIES        128

/**
 * @struct DLP_MESSAGE_HEADER
 * @brief Common header for all kernel/user-mode messages
 */
typedef struct _DLP_MESSAGE_HEADER {
    ULONG       Size;               // Total message size including header
    ULONG       Type;               // DLP_MESSAGE_TYPE
    ULONG       SequenceNumber;     // For request/response correlation
    ULONG       Status;             // NTSTATUS for responses
    ULONGLONG   Timestamp;          // Message timestamp (100ns intervals since boot)
} DLP_MESSAGE_HEADER, *PDLP_MESSAGE_HEADER;

/**
 * @struct DLP_EVENT_NOTIFICATION
 * @brief Event notification from kernel to user-mode
 */
typedef struct _DLP_EVENT_NOTIFICATION {
    DLP_MESSAGE_HEADER  Header;
    DLP_FILE_ID         FileId;
    ULONG               Operation;          // DLP_OPERATION_TYPE
    ULONG               Classification;     // Current classification
    ULONG               ActionTaken;        // DLP_ACTION
    ULONG               ProcessId;
    ULONG               ThreadId;
    ULONG               SessionId;
    ULONG               PathLength;         // Length in bytes
    ULONG               DestPathLength;     // For rename/copy operations
    ULONG               VolumeFlags;        // Source volume flags
    ULONG               DestVolumeFlags;    // Destination volume flags
    WCHAR               FilePath[DLP_MAX_PATH_LENGTH];
    WCHAR               DestPath[DLP_MAX_PATH_LENGTH];  // For rename/move
    WCHAR               ProcessName[DLP_MAX_FILENAME_LENGTH];
} DLP_EVENT_NOTIFICATION, *PDLP_EVENT_NOTIFICATION;

/**
 * @struct DLP_POLICY_UPDATE_MSG
 * @brief Single policy update from user-mode to kernel
 */
typedef struct _DLP_POLICY_UPDATE_MSG {
    DLP_MESSAGE_HEADER  Header;
    DLP_POLICY_ENTRY    Entry;
    WCHAR               FilePath[DLP_MAX_PATH_LENGTH];  // For logging only
} DLP_POLICY_UPDATE_MSG, *PDLP_POLICY_UPDATE_MSG;

/**
 * @struct DLP_POLICY_BULK_UPDATE_MSG
 * @brief Bulk policy update (efficient for large updates)
 */
typedef struct _DLP_POLICY_BULK_UPDATE_MSG {
    DLP_MESSAGE_HEADER  Header;
    ULONG               EntryCount;
    ULONG               Version;            // Policy version number
    DLP_POLICY_ENTRY    Entries[DLP_MAX_BULK_ENTRIES];
} DLP_POLICY_BULK_UPDATE_MSG, *PDLP_POLICY_BULK_UPDATE_MSG;

/**
 * @struct DLP_POLICY_REMOVE_MSG
 * @brief Remove policy entry
 */
typedef struct _DLP_POLICY_REMOVE_MSG {
    DLP_MESSAGE_HEADER  Header;
    DLP_FILE_ID         FileId;
} DLP_POLICY_REMOVE_MSG, *PDLP_POLICY_REMOVE_MSG;

/**
 * @struct DLP_VOLUME_UPDATE_MSG
 * @brief Volume flags update
 */
typedef struct _DLP_VOLUME_UPDATE_MSG {
    DLP_MESSAGE_HEADER  Header;
    ULONG               VolumeSerialNumber;
    ULONG               VolumeFlags;        // DLP_VOLUME_FLAGS
    WCHAR               VolumeLabel[64];
    WCHAR               DevicePath[DLP_MAX_PATH_LENGTH];
} DLP_VOLUME_UPDATE_MSG, *PDLP_VOLUME_UPDATE_MSG;

/**
 * @struct DLP_CONFIG_UPDATE_MSG
 * @brief Driver configuration update
 */
typedef struct _DLP_CONFIG_UPDATE_MSG {
    DLP_MESSAGE_HEADER  Header;
    ULONG               FailClosedMode;     // 1 = block if no policy, 0 = allow
    ULONG               AuditMode;          // 1 = log only, don't block
    ULONG               MaxCacheEntries;    // Maximum policy cache size
    ULONG               CacheEntryTTL;      // Default TTL in seconds
    ULONG               Reserved[4];        // Future use
} DLP_CONFIG_UPDATE_MSG, *PDLP_CONFIG_UPDATE_MSG;

/**
 * @struct DLP_CLASSIFICATION_REQUEST
 * @brief Request for classification (kernel -> user-mode)
 */
typedef struct _DLP_CLASSIFICATION_REQUEST {
    DLP_MESSAGE_HEADER  Header;
    DLP_FILE_ID         FileId;
    ULONG               Operation;          // What operation triggered this
    ULONG               ProcessId;
    ULONG               PathLength;
    WCHAR               FilePath[DLP_MAX_PATH_LENGTH];
} DLP_CLASSIFICATION_REQUEST, *PDLP_CLASSIFICATION_REQUEST;

/**
 * @struct DLP_CLASSIFICATION_RESPONSE
 * @brief Classification response (user-mode -> kernel)
 */
typedef struct _DLP_CLASSIFICATION_RESPONSE {
    DLP_MESSAGE_HEADER  Header;
    DLP_POLICY_ENTRY    Entry;              // Complete policy entry to cache
} DLP_CLASSIFICATION_RESPONSE, *PDLP_CLASSIFICATION_RESPONSE;

// ============================================================================
// DRIVER STATISTICS
// ============================================================================

typedef struct _DLP_STATISTICS {
    ULONGLONG   TotalOperationsScanned;
    ULONGLONG   TotalOperationsBlocked;
    ULONGLONG   TotalOperationsAllowed;
    ULONGLONG   TotalOperationsAudited;
    ULONGLONG   CacheHits;
    ULONGLONG   CacheMisses;
    ULONGLONG   CacheEvictions;
    ULONGLONG   PolicyUpdates;
    ULONGLONG   CommunicationErrors;
    ULONGLONG   DriverLoadTime;
    ULONG       CurrentCacheEntries;
    ULONG       MaxCacheEntriesUsed;
    ULONG       VolumesMonitored;
    ULONG       Reserved;
} DLP_STATISTICS, *PDLP_STATISTICS;

// ============================================================================
// IOCTL CODES (Alternative to filter message ports for some operations)
// ============================================================================

#define DLP_DEVICE_TYPE     0x8A30  // Custom device type

#define DLP_IOCTL_GET_STATS \
    CTL_CODE(DLP_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define DLP_IOCTL_FLUSH_CACHE \
    CTL_CODE(DLP_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define DLP_IOCTL_SET_CONFIG \
    CTL_CODE(DLP_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define DLP_IOCTL_GET_CONFIG \
    CTL_CODE(DLP_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

// ============================================================================
// ERROR CODES
// ============================================================================

// Custom NTSTATUS codes (Severity=Error, Customer=1, Facility=0x0A3)
#define DLP_STATUS_BASE                 0xE0A30000

#define DLP_STATUS_CACHE_FULL           (DLP_STATUS_BASE | 0x0001)
#define DLP_STATUS_ENTRY_NOT_FOUND      (DLP_STATUS_BASE | 0x0002)
#define DLP_STATUS_INVALID_VERSION      (DLP_STATUS_BASE | 0x0003)
#define DLP_STATUS_SERVICE_NOT_READY    (DLP_STATUS_BASE | 0x0004)
#define DLP_STATUS_POLICY_EXPIRED       (DLP_STATUS_BASE | 0x0005)

// ============================================================================
// HELPER MACROS
// ============================================================================

// Initialize message header
#define DLP_INIT_MESSAGE_HEADER(msg, msgType) \
    do { \
        (msg)->Header.Size = sizeof(*(msg)); \
        (msg)->Header.Type = (msgType); \
        (msg)->Header.Status = 0; \
    } while (0)

// Check if operation type is a write operation
#define DLP_IS_WRITE_OPERATION(op) \
    (((op) == DLP_OP_FILE_WRITE) || \
     ((op) == DLP_OP_FILE_DELETE) || \
     ((op) == DLP_OP_FILE_RENAME) || \
     ((op) == DLP_OP_FILE_MOVE) || \
     ((op) == DLP_OP_USB_WRITE))

// Check if operation should be blocked for protected files
#define DLP_SHOULD_BLOCK_FOR_PROTECTED(op) \
    (((op) == DLP_OP_FILE_DELETE) || \
     ((op) == DLP_OP_FILE_RENAME) || \
     ((op) == DLP_OP_FILE_MOVE) || \
     ((op) == DLP_OP_USB_WRITE))

#ifdef __cplusplus
}
#endif

#endif // _DLP_SHARED_H_
