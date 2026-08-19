/**
 * @file ClipboardMonitor.h
 * @brief Phase 1 Clipboard Visibility - DETECTION ONLY.
 *
 * PRITRAK Enterprise DLP Agent
 *
 * This component detects clipboard changes via a message-only window and
 * AddClipboardFormatListener, then captures a BOUNDED copy of the clipboard
 * text and runs it through the existing DCI/PII engine for privacy-safe
 * telemetry.
 *
 * DETECTION ONLY:
 *   - It never blocks, empties, replaces, delays or otherwise modifies the
 *     clipboard.
 *   - It never identifies the future paste destination. AddClipboardFormatListener
 *     reports clipboard changes but does not reliably identify which process
 *     will paste next.
 *
 * SESSION LIMITATION (NOT IMPLEMENTED in Session 0):
 *   AddClipboardFormatListener only reports clipboard changes that occur in the
 *   session where the listener window lives. The normal SCM service deployment
 *   runs in Session 0, which never receives interactive-session clipboard
 *   events. Clipboard visibility is therefore ONLY supported in interactive
 *   (non-Session-0) mode (e.g. `--console`). In Session 0 this component logs a
 *   privacy-safe warning and stays disabled. Production deployment requires a
 *   per-user companion process / user-session agent (out of scope for this
 *   change; no service-to-user process spawning is performed).
 *
 * Architecture:
 *   - A dedicated, joinable listener thread owns a unique window class, a
 *     message-only window (HWND_MESSAGE) and the clipboard format listener.
 *   - The window procedure is intentionally lightweight: on WM_CLIPBOARDUPDATE
 *     it only records the sequence number into a bounded latest-value queue.
 *   - A dedicated worker thread drains that queue and performs clipboard
 *     capture, bounded UTF-16 -> UTF-8 conversion and classification. All
 *     clipboard access and classification happen OFF the listener message loop
 *     and only while the clipboard is closed.
 */

#pragma once

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Pritrak {
namespace DLP {

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Conservative, bounded configuration for clipboard monitoring. Values are
 * validated by ValidateClipboardConfig() before use; invalid values fall back
 * to defaults rather than being used unsafely.
 */
struct ClipboardConfig {
    bool enabled            = true;                 // master switch
    size_t maxUtf16Bytes    = 256ULL * 1024;        // 256 KiB default cap
    int    openRetryCount   = 5;                    // bounded open retries
    int    openRetryDelayMs = 50;                   // 25-50ms recommended
    size_t maxQueuedEvents  = 1;                    // latest-value coalescing slot(s)
    int    scanTimeoutMs    = 2000;                 // classification guard
};

// ============================================================================
// OUTCOMES (STEP 7 - explicit internal outcomes)
// ============================================================================

enum class ClipboardOutcome {
    Scanned,           // content captured and classified
    Empty,             // clipboard text is empty
    UnsupportedFormat, // CF_UNICODETEXT not available
    Oversized,         // content exceeded the configured byte cap
    Busy,              // clipboard locked by another process
    TimedOut,          // classification exceeded the scan timeout
    Unavailable,       // clipboard data could not be retrieved
    InvalidInput,      // malformed UTF-16 / conversion failure
    ScanError,         // PII scanner failed (never treated as clean)
    Cancelled          // aborted because shutdown began
};

// ============================================================================
// RESULT METADATA (privacy-safe: never holds content)
// ============================================================================

/**
 * Structured, content-free result of a clipboard scan. Only counts, types,
 * strength flags and the sequence number are recorded - never the text itself.
 */
struct ClipboardScanMetadata {
    ClipboardOutcome outcome        = ClipboardOutcome::Scanned;
    int      findingCount           = 0;
    bool     hardEvidence           = false;
    bool     sensitiveDetected      = false;
    std::vector<std::string> entityTypes;   // e.g. "CREDIT_CARD", "SSN", "API_KEY"
    long long durationMs            = 0;
    unsigned int sequenceNumber     = 0;
};

// ============================================================================
// PURE, UNIT-TESTABLE HELPERS
// ============================================================================

/**
 * Boundedly extract a UTF-16 string from raw clipboard memory. Never reads
 * beyond sizeBytes. Stops at the first null terminator. GlobalSize does NOT
 * prove a null terminator exists, so this scans the allocation. If no
 * terminator is found within maxBytes the content is oversized (truncated=true)
 * and the copy is capped (without splitting a surrogate pair); if no terminator
 * exists in the whole allocation, missingNull=true.
 */
std::wstring ClipUtf16ToWstring(const void* ptr, SIZE_T sizeBytes,
                                size_t maxBytes, bool* truncated, bool* missingNull);

/** Bounded UTF-16 -> UTF-8 conversion using WideCharToMultiByte. Returns an
 *  empty string on invalid UTF-16 (WC_ERR_INVALID_CHARS). Never throws. */
std::string Utf16ToUtf8(const std::wstring& wide);

/** Validate a ClipboardConfig; on failure writes a reason and returns false. */
bool ValidateClipboardConfig(const ClipboardConfig& cfg, std::string* reason);

/**
 * Format a privacy-safe sensitive-data event string. The result contains only
 * counts/types/strength flags - NEVER clipboard content. Returns "" when not
 * sensitive.
 */
std::string FormatClipboardEvent(const ClipboardScanMetadata& meta, bool sensitive);

/**
 * Bounded latest-value / coalescing sequence queue.
 *
 * Clipboard updates become stale quickly, so a large FIFO is wrong: a worker
 * processing an old sequence could read content from a newer one. This keeps
 * only the LATEST notified sequence and coalesces any newer notification over
 * a still-pending one, so stale intermediate updates are never scanned.
 */
struct BoundedSeqQueue {
    explicit BoundedSeqQueue(size_t capacity);
    /** Record the latest sequence. Returns true if it changed the pending
     *  value (i.e. should be processed); false for an exact duplicate of the
     *  currently pending value. */
    bool Update(unsigned int seq);
    /** Retrieve the latest pending sequence; false when none pending. */
    bool Take(unsigned int& out);
    /** True when a pending (latest) value exists. */
    bool HasPending() const;
    size_t Size() const;             // 0 or 1
    size_t Capacity() const { return max_; }
    size_t CoalescedCount() const;   // how many updates were coalesced (diagnostics)

private:
    size_t max_;
    unsigned int pending_ = 0;
    bool hasPending_ = false;
    size_t coalesced_ = 0;
};

// ============================================================================
// CLIPBOARD MONITOR
// ============================================================================

/**
 * Clipboard change listener with bounded, privacy-safe detection.
 *
 * Lifecycle is idempotent: Start()/Stop() may be called repeatedly and both
 * threads are always joined (never detached). Clipboard visibility is only
 * active in interactive (non-Session-0) sessions.
 */
class ClipboardMonitor {
public:
    ClipboardMonitor();
    ~ClipboardMonitor();

    ClipboardMonitor(const ClipboardMonitor&) = delete;
    ClipboardMonitor& operator=(const ClipboardMonitor&) = delete;

    /** Set configuration. Must be called before Start(). */
    void Configure(const ClipboardConfig& cfg);

    /**
     * Start monitoring. Returns true only when: enabled, running in an
     * interactive (non-Session-0) session, AND the listener thread, message-only
     * window and format listener were all created successfully. Returns false
     * (safely, with a privacy-safe diagnostic) when disabled, in Session 0, or
     * on any initialization failure - nothing is leaked.
     */
    bool Start();

    /** Idempotent shutdown: posts a private WM_APP message, joins both threads,
     *  and cleans up the window/class/listener on the listener thread. All waits
     *  are shutdown-aware. */
    void Stop();

    bool IsRunning() const { return started_.load(); }
    /** True when monitoring is actually effective in this session. */
    bool IsActiveInSession() const;

    /** Number of pending (latest) queue entries; test seam. */
    size_t PendingQueueSize();

private:
    // Listener thread (owns window + class + listener registration).
    void ListenerThread(std::shared_ptr<std::promise<bool>> ready);
    // Worker thread (capture + convert + classify, off the message loop).
    void WorkerThread();

    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    LRESULT HandleMessage(HWND hwnd, UINT msg);

    void OnClipboardUpdate();
    void Schedule(unsigned int seq);
    void ProcessClipboard(unsigned int seq);
    ClipboardScanMetadata RunClassification(const std::string& utf8,
                                             const ClipboardScanMetadata& meta) const;
    void EmitDiagnostic(const ClipboardScanMetadata& meta) const;
    bool IsInteractiveSession() const;
    void CleanupListener();

    std::atomic<bool> running_{false};
    std::atomic<bool> started_{false};
    std::thread listenerThread_;
    std::thread workerThread_;
    std::mutex lifecycleMutex_;

    HWND hwnd_{nullptr};
    std::wstring windowClassName_;
    bool classOwned_ = false;

    // Signaled by Stop() to interrupt retry sleeps (shutdown-aware waits).
    HANDLE shutdownEvent_ = nullptr;

    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    BoundedSeqQueue queue_{1};

    ClipboardConfig cfg_;
};

} // namespace DLP
} // namespace Pritrak
